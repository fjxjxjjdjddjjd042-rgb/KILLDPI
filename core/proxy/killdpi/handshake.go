package killdpi

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

// Request commands (inside the encrypted HELLO).
const (
	CommandTCP byte = 1
	CommandUDP byte = 2
	CommandMux byte = 3
)

// ClientPrefixLen is the number of plaintext bytes preceding the first frame
// on the client->server direction: ephemeral public key + masked user id.
const ClientPrefixLen = 32 + 16

var addrParser = protocol.NewAddressParser(
	protocol.AddressFamilyByte(0x01, xnet.AddressFamilyIPv4),
	protocol.AddressFamilyByte(0x02, xnet.AddressFamilyDomain),
	protocol.AddressFamilyByte(0x03, xnet.AddressFamilyIPv6),
	protocol.PortThenAddress(),
)

// Hello is the decrypted content of the client's first frame.
type Hello struct {
	Timestamp int64
	Command   byte
	Address   xnet.Address
	Port      xnet.Port
}

func randInt(min, max int) int {
	if max <= min {
		return min
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return min
	}
	return min + int(n.Int64())
}

// encodeHello serialises a Hello followed by random padding.
func encodeHello(h *Hello, padMin, padMax int) ([]byte, error) {
	b := buf.New()
	defer b.Release()
	b.WriteByte(Version)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(h.Timestamp))
	b.Write(ts[:])
	b.WriteByte(h.Command)
	if h.Command != CommandMux {
		if err := addrParser.WriteAddressPort(b, h.Address, h.Port); err != nil {
			return nil, err
		}
	}
	padLen := randInt(padMin, padMax)
	if int(b.Len())+2+padLen > MaxPayload {
		padLen = MaxPayload - int(b.Len()) - 2
	}
	var pl [2]byte
	binary.BigEndian.PutUint16(pl[:], uint16(padLen))
	b.Write(pl[:])
	b.Write(randomBytes(padLen))
	out := make([]byte, b.Len())
	copy(out, b.Bytes())
	return out, nil
}

func decodeHello(p []byte) (*Hello, error) {
	if len(p) < 1+8+1 {
		return nil, errors.New("KILLDPI: HELLO too short")
	}
	if p[0] != Version {
		return nil, errors.New("KILLDPI: unsupported version ", p[0])
	}
	h := &Hello{
		Timestamp: int64(binary.BigEndian.Uint64(p[1:9])),
		Command:   p[9],
	}
	rest := p[10:]
	switch h.Command {
	case CommandTCP, CommandUDP:
		r := buf.New()
		defer r.Release()
		r.Write(rest)
		addr, port, err := addrParser.ReadAddressPort(nil, r)
		if err != nil {
			return nil, errors.New("KILLDPI: invalid HELLO address").Base(err)
		}
		h.Address, h.Port = addr, port
		rest = r.Bytes()
	case CommandMux:
		h.Address = xnet.DomainAddress("v1.mux.cool")
		h.Port = 0
	default:
		return nil, errors.New("KILLDPI: unknown command ", h.Command)
	}
	if len(rest) < 2 {
		return nil, errors.New("KILLDPI: HELLO missing padding length")
	}
	padLen := int(binary.BigEndian.Uint16(rest))
	if len(rest)-2 != padLen {
		return nil, errors.New("KILLDPI: HELLO padding length mismatch")
	}
	return h, nil
}

// ---------------- Client side ----------------

// ClientSession is the client's view of one connection.
type ClientSession struct {
	Conn   *FrameConn
	c2s    []byte
	s2c    []byte
	once   sync.Once
	ready  chan struct{}
	finish func(serverEph []byte) error
}

// ClientHandshake prepares the 0-RTT first flight on conn. The returned
// FrameConn can be written to immediately; reads block until the server's
// reply has been processed by WaitServerHello (call it from the read side).
func ClientHandshake(conn net.Conn, serverPub *ecdh.PublicKey, account *MemoryAccount, h *Hello) (*ClientSession, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared0, err := eph.ECDH(serverPub)
	if err != nil {
		return nil, err
	}
	id := account.ID.UUID()
	masked := maskUUID(shared0, id)

	fc := NewFrameConn(conn, account.Cipher)
	if err := fc.SetEncryptKey(zeroRTTKey(shared0, id)); err != nil {
		return nil, err
	}
	prefix := make([]byte, 0, ClientPrefixLen)
	prefix = append(prefix, eph.PublicKey().Bytes()...)
	prefix = append(prefix, masked[:]...)
	fc.Prepend(prefix)

	if h.Timestamp == 0 {
		h.Timestamp = time.Now().Unix()
	}
	helloBytes, err := encodeHello(h, account.PaddingMin, account.PaddingMax)
	if err != nil {
		return nil, err
	}
	if err := fc.WriteFrame(FrameHello, helloBytes); err != nil {
		return nil, errors.New("KILLDPI: failed to send HELLO").Base(err)
	}

	cs := &ClientSession{Conn: fc, ready: make(chan struct{})}
	// Session keys depend on the server's ephemeral key, which arrives later;
	// the closure keeps the ephemeral private key alive until then.
	cs.finish = func(serverEph []byte) error {
		pub, err := ecdh.X25519().NewPublicKey(serverEph)
		if err != nil {
			return err
		}
		shared1, err := eph.ECDH(pub)
		if err != nil {
			return err
		}
		c2s, s2c := sessionKeys(shared0, shared1, id)
		cs.c2s, cs.s2c = c2s, s2c
		return nil
	}
	return cs, nil
}

// WaitServerHello reads the server's ephemeral key + SERVER_HELLO frame,
// installs the forward-secret keys and tells the server to switch keys.
// Must be called exactly once, from the goroutine that reads from the server.
func (cs *ClientSession) WaitServerHello() error {
	var err error
	cs.once.Do(func() {
		var serverEph [32]byte
		if _, err = io.ReadFull(cs.Conn.Conn, serverEph[:]); err != nil {
			err = errors.New("KILLDPI: failed to read server ephemeral key").Base(err)
			return
		}
		if err = cs.finish(serverEph[:]); err != nil {
			return
		}
		if err = cs.Conn.SetDecryptKey(cs.s2c); err != nil {
			return
		}
		ftype, _, e := cs.Conn.ReadFrame()
		if e != nil {
			err = errors.New("KILLDPI: failed to read SERVER_HELLO").Base(e)
			return
		}
		if ftype != FrameServerHello {
			err = errors.New("KILLDPI: expected SERVER_HELLO, got frame ", ftype)
			return
		}
		// Switch our sending key: send KEY_SWITCH under old key, then use c2s.
		err = cs.Conn.switchEncryptKey(cs.c2s)
		close(cs.ready)
	})
	return err
}

// switchEncryptKey atomically emits KEY_SWITCH with the current key and
// installs the new one for all subsequent frames.
func (c *FrameConn) switchEncryptKey(newKey []byte) error {
	st, err := newAEADState(c.cipherName, newKey)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.enc == nil {
		return errors.New("KILLDPI: encrypt key not set")
	}
	bodyLen := 1 + tagSize
	out := make([]byte, 0, len(c.pendingWrite)+headerLen+bodyLen)
	out = append(out, c.pendingWrite...)
	c.pendingWrite = nil
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(bodyLen))
	out = c.enc.seal(out, lb[:])
	out = c.enc.seal(out, []byte{FrameKeySwitch})
	if _, err := c.Conn.Write(out); err != nil {
		return err
	}
	c.enc = st
	return nil
}

// ---------------- Server side ----------------

// ReplayCache remembers client ephemeral keys for a limited time.
type ReplayCache struct {
	mu   sync.Mutex
	seen map[[32]byte]int64
	ttl  int64
	last int64
}

// NewReplayCache creates a cache with the given TTL in seconds.
func NewReplayCache(ttl int64) *ReplayCache {
	return &ReplayCache{seen: make(map[[32]byte]int64), ttl: ttl}
}

// Check returns false if key was already seen within TTL, and records it.
func (r *ReplayCache) Check(key [32]byte) bool {
	now := time.Now().Unix()
	r.mu.Lock()
	defer r.mu.Unlock()
	if now-r.last > 30 { // periodic sweep
		for k, t := range r.seen {
			if now-t > r.ttl {
				delete(r.seen, k)
			}
		}
		r.last = now
	}
	if _, ok := r.seen[key]; ok {
		return false
	}
	r.seen[key] = now
	return true
}

// ServerResult is what a successful server handshake yields.
type ServerResult struct {
	Conn  *FrameConn
	User  *protocol.MemoryUser
	Hello *Hello
}

// ServerHandshake consumes the client's first flight from reader (which must
// deliver the raw bytes of conn, possibly pre-buffered) and completes the
// handshake on conn. On authentication failure it returns an error and the
// caller may fall back; nothing has been written to conn in that case.
func ServerHandshake(conn net.Conn, reader io.Reader, priv *ecdh.PrivateKey, validator Validator, replay *ReplayCache, timeWindow int64, padMin, padMax int) (*ServerResult, error) {
	var prefix [ClientPrefixLen]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return nil, errors.New("KILLDPI: short first flight").Base(err)
	}
	var ephBytes [32]byte
	copy(ephBytes[:], prefix[:32])
	clientEph, err := ecdh.X25519().NewPublicKey(ephBytes[:])
	if err != nil {
		return nil, errors.New("KILLDPI: invalid client ephemeral key").Base(err)
	}
	shared0, err := priv.ECDH(clientEph)
	if err != nil {
		return nil, errors.New("KILLDPI: ECDH failed").Base(err)
	}
	var masked [16]byte
	copy(masked[:], prefix[32:48])
	id := maskUUID(shared0, masked) // XOR is its own inverse
	uid := uuid.UUID(id)
	user := validator.Get(uid)
	if user == nil {
		return nil, errors.New("KILLDPI: unknown user ", uid.String())
	}
	account := user.Account.(*MemoryAccount)

	fc := NewFrameConn(&prefixedConn{Conn: conn, r: reader}, account.Cipher)
	if err := fc.SetDecryptKey(zeroRTTKey(shared0, id)); err != nil {
		return nil, err
	}
	ftype, payload, err := fc.ReadFrame()
	if err != nil {
		return nil, errors.New("KILLDPI: HELLO decrypt failed").Base(err)
	}
	if ftype != FrameHello {
		return nil, errors.New("KILLDPI: first frame is not HELLO")
	}
	hello, err := decodeHello(payload)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	if d := now - hello.Timestamp; d > timeWindow || d < -timeWindow {
		return nil, errors.New("KILLDPI: HELLO timestamp outside window (clock skew or replay)")
	}
	if replay != nil && !replay.Check(ephBytes) {
		return nil, errors.New("KILLDPI: replayed handshake rejected")
	}

	// Our ephemeral key -> session keys.
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared1, err := eph.ECDH(clientEph)
	if err != nil {
		return nil, err
	}
	c2s, s2c := sessionKeys(shared0, shared1, id)
	if err := fc.SetEncryptKey(s2c); err != nil {
		return nil, err
	}
	if err := fc.SetNextDecryptKey(c2s); err != nil {
		return nil, err
	}
	fc.Prepend(eph.PublicKey().Bytes())
	pad := randomBytes(randInt(padMin, padMax))
	if err := fc.WriteFrame(FrameServerHello, pad); err != nil {
		return nil, errors.New("KILLDPI: failed to send SERVER_HELLO").Base(err)
	}
	return &ServerResult{Conn: fc, User: user, Hello: hello}, nil
}

// prefixedConn reads from r (a buffered reader over Conn) and writes to Conn.
type prefixedConn struct {
	net.Conn
	r io.Reader
}

func (p *prefixedConn) Read(b []byte) (int, error) { return p.r.Read(b) }
