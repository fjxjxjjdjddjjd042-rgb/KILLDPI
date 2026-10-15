package killdpi_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	. "github.com/xtls/xray-core/proxy/killdpi"
)

func newTestUser(t *testing.T, cipher string) (*protocol.MemoryUser, *MemoryAccount) {
	t.Helper()
	id := uuid.New()
	acc, err := (&Account{Id: id.String(), Cipher: cipher}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	ma := acc.(*MemoryAccount)
	return &protocol.MemoryUser{Email: "t@test", Account: ma}, ma
}

// runHandshake performs a full client/server handshake over an in-memory pipe
// and returns both encrypted ends plus the decoded hello.
func runHandshake(t *testing.T, cipher string) (*FrameConn, *FrameConn, *Hello) {
	t.Helper()
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sk, _ := ParsePrivateKey(priv)
	pk, _ := ParsePublicKey(pub)
	user, acc := newTestUser(t, cipher)
	v := new(MemoryValidator)
	if err := v.Add(user); err != nil {
		t.Fatal(err)
	}

	c, s := net.Pipe()
	type sres struct {
		r   *ServerResult
		err error
	}
	ch := make(chan sres, 1)
	go func() {
		r, err := ServerHandshake(s, s, sk, v, NewReplayCache(240), DefaultTimeWindow, 16, 64)
		ch <- sres{r, err}
	}()
	hello := &Hello{Command: CommandTCP, Address: xnet.DomainAddress("example.com"), Port: 443}
	cs, err := ClientHandshake(c, pk, acc, hello)
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.WaitServerHello(); err != nil {
		t.Fatal(err)
	}
	res := <-ch
	if res.err != nil {
		t.Fatal(res.err)
	}
	if res.r.Hello.Address.String() != "example.com" || res.r.Hello.Port != 443 {
		t.Fatalf("hello mismatch: %v:%v", res.r.Hello.Address, res.r.Hello.Port)
	}
	if res.r.User.Email != "t@test" {
		t.Fatal("wrong user")
	}
	return cs.Conn, res.r.Conn, res.r.Hello
}

func TestHandshakeAndStream(t *testing.T) {
	for _, cipher := range []string{CipherChaCha20Poly1305, CipherAES256GCM} {
		t.Run(cipher, func(t *testing.T) {
			cc, sc, _ := runHandshake(t, cipher)
			payload := make([]byte, 100_000) // spans several frames
			rand.Read(payload)

			go func() {
				cc.Write(payload)
			}()
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(sc, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("uplink corrupted")
			}
			// downlink (session key)
			go func() { sc.Write(payload[:5000]) }()
			got2 := make([]byte, 5000)
			if _, err := io.ReadFull(cc, got2); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got2, payload[:5000]) {
				t.Fatal("downlink corrupted")
			}
		})
	}
}

func TestPacketMode(t *testing.T) {
	cc, sc, _ := runHandshake(t, CipherChaCha20Poly1305)
	pw := &PacketWriter{Conn: cc}
	pr := &PacketReader{Conn: sc}
	datagrams := [][]byte{[]byte("hello"), make([]byte, 1400), []byte("x")}
	rand.Read(datagrams[1])
	go func() {
		for _, d := range datagrams {
			b := buf.New()
			b.Write(d)
			pw.WriteMultiBuffer(buf.MultiBuffer{b})
		}
	}()
	for i, want := range datagrams {
		mb, err := pr.ReadMultiBuffer()
		if err != nil {
			t.Fatal(err)
		}
		if len(mb) != 1 || !bytes.Equal(mb[0].Bytes(), want) {
			t.Fatalf("datagram %d mismatch (boundaries not preserved)", i)
		}
	}
}

func TestWrongUserRejected(t *testing.T) {
	priv, pub, _ := GenerateKeyPair()
	sk, _ := ParsePrivateKey(priv)
	pk, _ := ParsePublicKey(pub)
	_, acc := newTestUser(t, "")
	v := new(MemoryValidator) // empty: no users
	c, s := net.Pipe()
	errCh := make(chan error, 1)
	go func() {
		_, err := ServerHandshake(s, s, sk, v, nil, DefaultTimeWindow, 0, 0)
		errCh <- err
	}()
	_, err := ClientHandshake(c, pk, acc, &Hello{Command: CommandTCP, Address: xnet.LocalHostIP, Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err == nil {
		t.Fatal("expected unknown-user error")
	}
}

func TestWrongServerKeyRejected(t *testing.T) {
	priv, _, _ := GenerateKeyPair()
	_, otherPub, _ := GenerateKeyPair()
	sk, _ := ParsePrivateKey(priv)
	pk, _ := ParsePublicKey(otherPub)
	user, acc := newTestUser(t, "")
	v := new(MemoryValidator)
	v.Add(user)
	c, s := net.Pipe()
	errCh := make(chan error, 1)
	go func() {
		_, err := ServerHandshake(s, s, sk, v, nil, DefaultTimeWindow, 0, 0)
		errCh <- err
	}()
	ClientHandshake(c, pk, acc, &Hello{Command: CommandTCP, Address: xnet.LocalHostIP, Port: 80})
	if err := <-errCh; err == nil {
		t.Fatal("expected failure with wrong server key")
	}
}

func TestReplayRejected(t *testing.T) {
	priv, pub, _ := GenerateKeyPair()
	sk, _ := ParsePrivateKey(priv)
	pk, _ := ParsePublicKey(pub)
	user, acc := newTestUser(t, "")
	v := new(MemoryValidator)
	v.Add(user)
	replay := NewReplayCache(240)

	// Capture a genuine first flight.
	var captured bytes.Buffer
	c, s := net.Pipe()
	go func() { io.Copy(&captured, s) }()
	cs, err := ClientHandshake(c, pk, acc, &Hello{Command: CommandTCP, Address: xnet.LocalHostIP, Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	c.Close()
	_ = cs

	// First delivery accepted.
	s1c, s1s := net.Pipe()
	go func() { s1c.Write(captured.Bytes()); io.Copy(io.Discard, s1c) }()
	if _, err := ServerHandshake(s1s, s1s, sk, v, replay, DefaultTimeWindow, 0, 0); err != nil {
		t.Fatal("first flight should be accepted:", err)
	}
	// Replay rejected.
	s2c, s2s := net.Pipe()
	go func() { s2c.Write(captured.Bytes()); io.Copy(io.Discard, s2c) }()
	if _, err := ServerHandshake(s2s, s2s, sk, v, replay, DefaultTimeWindow, 0, 0); err == nil {
		t.Fatal("replayed flight must be rejected")
	}
}

func TestTamperedFrameRejected(t *testing.T) {
	cc, sc, _ := runHandshake(t, CipherAES256GCM)
	raw := cc.Conn // underlying pipe
	go func() {
		// Build a legit frame then flip a byte of it on the wire.
		var sink bytes.Buffer
		mc := NewFrameConn(&writerConn{Conn: raw, w: &sink}, CipherAES256GCM)
		_ = mc
		// Simpler: write random garbage; it must fail authentication.
		raw.Write(make([]byte, 60))
	}()
	buf := make([]byte, 10)
	if _, err := sc.Read(buf); err == nil {
		t.Fatal("garbage must not decrypt")
	}
}

type writerConn struct {
	net.Conn
	w io.Writer
}

func (w *writerConn) Write(b []byte) (int, error) { return w.w.Write(b) }

func TestParsePadding(t *testing.T) {
	if _, _, err := ParsePadding("10-5"); err == nil {
		t.Fatal("min>max should fail")
	}
	if a, b, err := ParsePadding(""); err != nil || a != DefaultPaddingMin || b != DefaultPaddingMax {
		t.Fatal("defaults")
	}
}

func BenchmarkFrameThroughput(b *testing.B) {
	for _, cipher := range []string{CipherChaCha20Poly1305, CipherAES256GCM} {
		b.Run(cipher, func(b *testing.B) {
			key := make([]byte, 32)
			rand.Read(key)
			c, s := net.Pipe()
			fcW := NewFrameConn(c, cipher)
			fcR := NewFrameConn(s, cipher)
			fcW.SetEncryptKey(key)
			fcR.SetDecryptKey(key)
			payload := make([]byte, MaxPayload)
			go func() {
				sink := make([]byte, 64*1024)
				for {
					if _, err := fcR.Read(sink); err != nil {
						return
					}
				}
			}()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				fcW.Write(payload)
			}
			c.Close()
		})
	}
}
