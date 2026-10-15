package killdpi

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"net"
	"sync"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
)

// Frame types. Everything after the 48-byte client prefix / 32-byte server
// prefix is a sequence of frames, so the type byte is never visible on the wire.
const (
	FrameHello       byte = 0x01 // client -> server, first frame (0-RTT key)
	FrameServerHello byte = 0x02 // server -> client, first frame (session key)
	FrameData        byte = 0x03 // payload (stream chunk or one UDP datagram)
	FramePadding     byte = 0x04 // ignored by receiver
	FramePing        byte = 0x05 // keep-alive request
	FramePong        byte = 0x06 // keep-alive reply
	FrameKeySwitch   byte = 0x07 // client -> server: following frames use session key
	FrameClose       byte = 0x08 // graceful end of stream
)

const (
	// MaxPayload is the largest plaintext payload carried by one frame.
	// Chosen to match TLS record size so KILLDPI-over-TLS does not fragment.
	MaxPayload = 16384
	// headerLen is the encrypted 2-byte length plus its tag.
	headerLen = 2 + tagSize
	// maxWire is the largest ciphertext body we are willing to read.
	maxWire = 1 + MaxPayload + tagSize
)

// aeadState is a unidirectional AEAD with an incrementing 96-bit nonce.
type aeadState struct {
	aead  cipher.AEAD
	nonce [nonceSize]byte
}

func newAEADState(cipherName string, key []byte) (*aeadState, error) {
	a, err := newAEAD(cipherName, key)
	if err != nil {
		return nil, err
	}
	return &aeadState{aead: a}, nil
}

func (s *aeadState) next() []byte {
	// Big-endian counter in the low 8 bytes; upper 4 bytes stay zero.
	n := binary.BigEndian.Uint64(s.nonce[4:])
	binary.BigEndian.PutUint64(s.nonce[4:], n+1)
	return s.nonce[:]
}

func (s *aeadState) seal(dst, plaintext []byte) []byte {
	return s.aead.Seal(dst, s.next(), plaintext, nil)
}

func (s *aeadState) open(dst, ciphertext []byte) ([]byte, error) {
	return s.aead.Open(dst, s.next(), ciphertext, nil)
}

// FrameConn is an encrypted framed connection over any net.Conn
// (raw TCP, TLS, WebSocket, gRPC stream ...).
type FrameConn struct {
	net.Conn

	cipherName string

	wmu sync.Mutex
	enc *aeadState
	// pendingWrite is prepended to the next write (ephemeral keys, etc.)
	pendingWrite []byte

	rmu sync.Mutex
	dec *aeadState
	// nextDec, when non-nil, replaces dec after a KEY_SWITCH frame (server side).
	nextDec *aeadState

	// stream-mode read buffer
	rbuf    []byte
	rhead   []byte // scratch for header
	leftover []byte

	onKeySwitch func() // optional hook
	closed      bool
}

// NewFrameConn wraps conn. enc/dec may be nil until the handshake sets them.
func NewFrameConn(conn net.Conn, cipherName string) *FrameConn {
	return &FrameConn{
		Conn:       conn,
		cipherName: cipherName,
		rbuf:       make([]byte, maxWire),
		rhead:      make([]byte, headerLen),
	}
}

// SetEncryptKey installs the sending key.
func (c *FrameConn) SetEncryptKey(key []byte) error {
	st, err := newAEADState(c.cipherName, key)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	c.enc = st
	c.wmu.Unlock()
	return nil
}

// SetDecryptKey installs the receiving key.
func (c *FrameConn) SetDecryptKey(key []byte) error {
	st, err := newAEADState(c.cipherName, key)
	if err != nil {
		return err
	}
	c.rmu.Lock()
	c.dec = st
	c.rmu.Unlock()
	return nil
}

// SetNextDecryptKey arms the key that becomes active after FrameKeySwitch.
func (c *FrameConn) SetNextDecryptKey(key []byte) error {
	st, err := newAEADState(c.cipherName, key)
	if err != nil {
		return err
	}
	c.rmu.Lock()
	c.nextDec = st
	c.rmu.Unlock()
	return nil
}

// Prepend queues raw bytes to be sent before the next frame (same syscall).
func (c *FrameConn) Prepend(b []byte) {
	c.wmu.Lock()
	c.pendingWrite = append(c.pendingWrite, b...)
	c.wmu.Unlock()
}

// WriteFrame encrypts and sends one frame. payload must be <= MaxPayload.
func (c *FrameConn) WriteFrame(ftype byte, payload []byte) error {
	if len(payload) > MaxPayload {
		return errors.New("KILLDPI: frame payload too large")
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.enc == nil {
		return errors.New("KILLDPI: encrypt key not set")
	}
	bodyLen := 1 + len(payload) + tagSize
	out := make([]byte, 0, len(c.pendingWrite)+headerLen+bodyLen)
	out = append(out, c.pendingWrite...)
	c.pendingWrite = nil

	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(bodyLen))
	out = c.enc.seal(out, lb[:])

	// type || payload sealed in place (avoid an extra alloc for small frames)
	body := make([]byte, 0, 1+len(payload))
	body = append(body, ftype)
	body = append(body, payload...)
	out = c.enc.seal(out, body)

	_, err := c.Conn.Write(out)
	return err
}

// WriteFrames sends several DATA frames in one syscall (used for MultiBuffer).
func (c *FrameConn) WriteDataFrames(chunks [][]byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.enc == nil {
		return errors.New("KILLDPI: encrypt key not set")
	}
	total := len(c.pendingWrite)
	for _, ch := range chunks {
		total += headerLen + 1 + len(ch) + tagSize
	}
	out := make([]byte, 0, total)
	out = append(out, c.pendingWrite...)
	c.pendingWrite = nil
	var lb [2]byte
	for _, ch := range chunks {
		if len(ch) > MaxPayload {
			return errors.New("KILLDPI: frame payload too large")
		}
		bodyLen := 1 + len(ch) + tagSize
		binary.BigEndian.PutUint16(lb[:], uint16(bodyLen))
		out = c.enc.seal(out, lb[:])
		body := make([]byte, 0, 1+len(ch))
		body = append(body, FrameData)
		body = append(body, ch...)
		out = c.enc.seal(out, body)
	}
	_, err := c.Conn.Write(out)
	return err
}

// ReadFrame reads and decrypts the next frame. The returned payload aliases an
// internal buffer and is only valid until the next ReadFrame call.
// Control frames (PING/PONG/PADDING/KEY_SWITCH) are handled internally.
func (c *FrameConn) ReadFrame() (byte, []byte, error) {
	for {
		ftype, payload, err := c.readRawFrame()
		if err != nil {
			return 0, nil, err
		}
		switch ftype {
		case FramePadding, FramePong:
			continue
		case FramePing:
			// best-effort reply; ignore errors (writer may be closed)
			go c.WriteFrame(FramePong, nil) //nolint:errcheck
			continue
		case FrameKeySwitch:
			c.rmu.Lock()
			if c.nextDec != nil {
				c.dec = c.nextDec
				c.nextDec = nil
			}
			c.rmu.Unlock()
			if c.onKeySwitch != nil {
				c.onKeySwitch()
			}
			continue
		case FrameClose:
			return ftype, nil, io.EOF
		}
		return ftype, payload, nil
	}
}

func (c *FrameConn) readRawFrame() (byte, []byte, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if c.dec == nil {
		return 0, nil, errors.New("KILLDPI: decrypt key not set")
	}
	if _, err := io.ReadFull(c.Conn, c.rhead); err != nil {
		return 0, nil, err
	}
	lenPlain, err := c.dec.open(c.rhead[:0], c.rhead)
	if err != nil {
		return 0, nil, errors.New("KILLDPI: bad frame header (wrong key or tampering)").Base(err)
	}
	bodyLen := int(binary.BigEndian.Uint16(lenPlain))
	if bodyLen < 1+tagSize || bodyLen > maxWire {
		return 0, nil, errors.New("KILLDPI: invalid frame length ", bodyLen)
	}
	body := c.rbuf[:bodyLen]
	if _, err := io.ReadFull(c.Conn, body); err != nil {
		return 0, nil, err
	}
	plain, err := c.dec.open(body[:0], body)
	if err != nil {
		return 0, nil, errors.New("KILLDPI: frame authentication failed").Base(err)
	}
	return plain[0], plain[1:], nil
}

// ---- net.Conn stream adapter (TCP mode) ----

// Read implements io.Reader: returns DATA payload bytes as a byte stream.
func (c *FrameConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if len(c.leftover) > 0 {
		n := copy(b, c.leftover)
		c.leftover = c.leftover[n:]
		return n, nil
	}
	for {
		ftype, payload, err := c.ReadFrame()
		if err != nil {
			return 0, err
		}
		if ftype != FrameData {
			// Unexpected handshake frame in stream mode: skip it.
			continue
		}
		if len(payload) == 0 {
			continue
		}
		n := copy(b, payload)
		if n < len(payload) {
			// keep remainder; must copy because payload aliases rbuf
			c.leftover = append(c.leftover[:0], payload[n:]...)
		}
		return n, nil
	}
}

// Write implements io.Writer, splitting into MaxPayload-sized DATA frames.
func (c *FrameConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	var chunks [][]byte
	for off := 0; off < len(b); off += MaxPayload {
		end := off + MaxPayload
		if end > len(b) {
			end = len(b)
		}
		chunks = append(chunks, b[off:end])
	}
	if err := c.WriteDataFrames(chunks); err != nil {
		return 0, err
	}
	return len(b), nil
}

// WriteMultiBuffer implements buf.Writer efficiently (one syscall per MultiBuffer).
func (c *FrameConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	chunks := make([][]byte, 0, len(mb))
	for _, b := range mb {
		if b.IsEmpty() {
			continue
		}
		chunks = append(chunks, b.Bytes())
	}
	if len(chunks) == 0 {
		return nil
	}
	return c.WriteDataFrames(chunks)
}

// Close sends a CLOSE frame (best effort) then closes the transport.
func (c *FrameConn) Close() error {
	c.wmu.Lock()
	already := c.closed
	c.closed = true
	c.wmu.Unlock()
	if !already && c.enc != nil {
		_ = c.WriteFrame(FrameClose, nil)
	}
	return c.Conn.Close()
}

// ---- UDP (packet) adapters: one DATA frame == one datagram ----

// PacketReader turns DATA frames into individual buffers.
type PacketReader struct {
	Conn *FrameConn
}

// ReadMultiBuffer implements buf.Reader.
func (r *PacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	for {
		ftype, payload, err := r.Conn.ReadFrame()
		if err != nil {
			return nil, err
		}
		if ftype != FrameData {
			continue
		}
		b := buf.New()
		b.Write(payload)
		return buf.MultiBuffer{b}, nil
	}
}

// PacketWriter sends every buffer as one DATA frame.
type PacketWriter struct {
	Conn *FrameConn
}

// WriteMultiBuffer implements buf.Writer.
func (w *PacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	chunks := make([][]byte, 0, len(mb))
	for _, b := range mb {
		if b.IsEmpty() || b.Len() > MaxPayload {
			continue // drop oversized/empty datagrams (cannot fragment UDP)
		}
		chunks = append(chunks, b.Bytes())
	}
	if len(chunks) == 0 {
		return nil
	}
	return w.Conn.WriteDataFrames(chunks)
}
