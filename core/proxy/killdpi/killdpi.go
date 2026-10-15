// Package killdpi implements the KILLDPI proxy protocol for Xray-core.
//
// KILLDPI is a VLESS-like stream protocol with mandatory, transport-independent
// authenticated encryption. The handshake follows the Noise "IK"-style idea
// used by WireGuard (client knows the server's static X25519 key in advance):
//
//	Client -> Server : c_eph_pub(32) | Frame_k0(HELLO) | Frame_k0(DATA)*
//	Server -> Client : s_eph_pub(32) | Frame_sess(SERVER_HELLO) | Frame_sess(DATA)*
//	Client -> Server : Frame_sess(DATA)*            (after SERVER_HELLO is seen)
//
//	k0   = HKDF-SHA256(ikm = X25519(c_eph, S_static), salt = uuid, info = "killdpi v1 k0")
//	sess = HKDF-SHA256(ikm = X25519(c_eph, S_static) || X25519(c_eph, s_eph), salt = uuid, info = "killdpi v1 sess")
//
// Every frame is: [2-byte length, AEAD-encrypted with its own nonce][AEAD(type||payload)].
// Nothing except the two random-looking 32-byte ephemeral keys is observable
// in plaintext; there are no magic bytes, fixed lengths or plaintext UUIDs.
//
// Replay of the first flight is rejected using a HELLO timestamp window plus
// a cache of recently seen ephemeral public keys. A failed handshake can be
// transparently forwarded to a fallback (e.g. a real web server) to resist
// active probing.
package killdpi

import (
	"strconv"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"google.golang.org/protobuf/proto"
)

const (
	// Version of the wire protocol.
	Version = byte(1)

	CipherChaCha20Poly1305 = "chacha20-poly1305"
	CipherAES256GCM        = "aes-256-gcm"

	DefaultPaddingMin = 64
	DefaultPaddingMax = 512
	// DefaultTimeWindow is the accepted clock skew (seconds) for the HELLO timestamp.
	DefaultTimeWindow = 120
)

// MemoryAccount is the in-memory form of a KILLDPI account.
type MemoryAccount struct {
	ID         *protocol.ID
	Cipher     string
	PaddingMin int
	PaddingMax int
}

// AsAccount implements protocol.Account.AsAccount().
func (a *Account) AsAccount() (protocol.Account, error) {
	id, err := uuid.ParseString(a.Id)
	if err != nil {
		return nil, errors.New("failed to parse KILLDPI id").Base(err)
	}
	cipher, err := NormalizeCipher(a.Cipher)
	if err != nil {
		return nil, err
	}
	pmin, pmax, err := ParsePadding(a.Padding)
	if err != nil {
		return nil, err
	}
	return &MemoryAccount{
		ID:         protocol.NewID(id),
		Cipher:     cipher,
		PaddingMin: pmin,
		PaddingMax: pmax,
	}, nil
}

// NormalizeCipher validates a cipher name and applies the default.
func NormalizeCipher(c string) (string, error) {
	switch strings.ToLower(c) {
	case "", CipherChaCha20Poly1305, "chacha20":
		return CipherChaCha20Poly1305, nil
	case CipherAES256GCM, "aes", "aes-gcm":
		return CipherAES256GCM, nil
	}
	return "", errors.New("unsupported KILLDPI cipher: " + c + ` (use "chacha20-poly1305" or "aes-256-gcm")`)
}

// ParsePadding parses "min-max" (bytes). Empty string returns the defaults.
func ParsePadding(s string) (int, int, error) {
	if s == "" {
		return DefaultPaddingMin, DefaultPaddingMax, nil
	}
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return 0, 0, errors.New(`KILLDPI padding must be "min-max", got: ` + s)
	}
	pmin, err1 := strconv.Atoi(parts[0])
	pmax, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || pmin < 0 || pmax < pmin || pmax > 4096 {
		return 0, 0, errors.New("KILLDPI padding range invalid (0 <= min <= max <= 4096): " + s)
	}
	return pmin, pmax, nil
}

// Equals implements protocol.Account.Equals().
func (a *MemoryAccount) Equals(account protocol.Account) bool {
	other, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.ID.Equals(other.ID)
}

// ToProto implements protocol.Account.ToProto().
func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{
		Id:      a.ID.String(),
		Cipher:  a.Cipher,
		Padding: strconv.Itoa(a.PaddingMin) + "-" + strconv.Itoa(a.PaddingMax),
	}
}

// Validator stores valid KILLDPI users.
type Validator interface {
	Get(id uuid.UUID) *protocol.MemoryUser
	Add(u *protocol.MemoryUser) error
	Del(email string) error
	GetByEmail(email string) *protocol.MemoryUser
	GetAll() []*protocol.MemoryUser
	GetCount() int64
}

// MemoryValidator is a Validator backed by sync.Map.
type MemoryValidator struct {
	email sync.Map
	users sync.Map
}

// Add a user. Email must be empty or unique.
func (v *MemoryValidator) Add(u *protocol.MemoryUser) error {
	if u.Email != "" {
		if _, loaded := v.email.LoadOrStore(strings.ToLower(u.Email), u); loaded {
			return errors.New("User ", u.Email, " already exists.")
		}
	}
	v.users.Store(u.Account.(*MemoryAccount).ID.UUID(), u)
	return nil
}

// Del a user by email.
func (v *MemoryValidator) Del(e string) error {
	if e == "" {
		return errors.New("Email must not be empty.")
	}
	le := strings.ToLower(e)
	u, _ := v.email.Load(le)
	if u == nil {
		return errors.New("User ", e, " not found.")
	}
	v.email.Delete(le)
	v.users.Delete(u.(*protocol.MemoryUser).Account.(*MemoryAccount).ID.UUID())
	return nil
}

// Get a user by UUID.
func (v *MemoryValidator) Get(id uuid.UUID) *protocol.MemoryUser {
	u, _ := v.users.Load(id)
	if u != nil {
		return u.(*protocol.MemoryUser)
	}
	return nil
}

// GetByEmail returns a user by email.
func (v *MemoryValidator) GetByEmail(email string) *protocol.MemoryUser {
	u, _ := v.email.Load(strings.ToLower(email))
	if u != nil {
		return u.(*protocol.MemoryUser)
	}
	return nil
}

// GetAll returns all users.
func (v *MemoryValidator) GetAll() []*protocol.MemoryUser {
	var all []*protocol.MemoryUser
	v.users.Range(func(_, value any) bool {
		all = append(all, value.(*protocol.MemoryUser))
		return true
	})
	return all
}

// GetCount returns the number of users.
func (v *MemoryValidator) GetCount() int64 {
	var n int64
	v.users.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}
