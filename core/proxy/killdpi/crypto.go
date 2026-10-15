package killdpi

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"io"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	keySize   = 32
	nonceSize = 12
	tagSize   = 16
	// Labels used for HKDF domain separation. Changing any of them breaks
	// wire compatibility and MUST be accompanied by a Version bump.
	labelHint = "killdpi v1 hint"
	labelK0   = "killdpi v1 k0 c2s"
	labelC2S  = "killdpi v1 sess c2s"
	labelS2C  = "killdpi v1 sess s2c"
)

// GenerateKeyPair creates a fresh X25519 key pair encoded in base64 RawURL.
func GenerateKeyPair() (privateKey, publicKey string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(k.Bytes()),
		base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// ParsePrivateKey decodes a base64 RawURL X25519 private key.
func ParsePrivateKey(s string) (*ecdh.PrivateKey, error) {
	b, err := decodeKey(s)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPrivateKey(b)
}

// ParsePublicKey decodes a base64 RawURL X25519 public key.
func ParsePublicKey(s string) (*ecdh.PublicKey, error) {
	b, err := decodeKey(s)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPublicKey(b)
}

func decodeKey(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("KILLDPI: key is empty")
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		// Be tolerant: accept standard / padded base64 too.
		if b2, err2 := base64.StdEncoding.DecodeString(s); err2 == nil {
			b = b2
		} else {
			return nil, errors.New("KILLDPI: key is not valid base64").Base(err)
		}
	}
	if len(b) != keySize {
		return nil, errors.New("KILLDPI: key must be 32 bytes")
	}
	return b, nil
}

// deriveKey runs HKDF-SHA256(ikm, salt, label) -> 32 bytes.
func deriveKey(ikm, salt []byte, label string) []byte {
	k, err := hkdf.Key(sha256.New, ikm, salt, label, keySize)
	if err != nil {
		panic(err) // only fails on bad parameters, which are constants here
	}
	return k
}

// maskUUID derives the 16-byte one-time pad used to hide the user id in the
// first flight: mask = HKDF(shared0, "hint")[:16] XOR uuid.
func maskUUID(shared0 []byte, id [16]byte) [16]byte {
	pad := deriveKey(shared0, nil, labelHint)
	var out [16]byte
	subtle.XORBytes(out[:], id[:], pad[:16])
	return out
}

// newAEAD instantiates the negotiated AEAD with a 32-byte key.
func newAEAD(cipherName string, key []byte) (cipher.AEAD, error) {
	switch cipherName {
	case CipherAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	default:
		return chacha20poly1305.New(key)
	}
}

// sessionKeys returns the forward-secret bidirectional keys.
func sessionKeys(shared0, shared1 []byte, id [16]byte) (c2s, s2c []byte) {
	ikm := make([]byte, 0, 64)
	ikm = append(ikm, shared0...)
	ikm = append(ikm, shared1...)
	return deriveKey(ikm, id[:], labelC2S), deriveKey(ikm, id[:], labelS2C)
}

// zeroRTTKey returns the client->server key used before the server's
// ephemeral key is known.
func zeroRTTKey(shared0 []byte, id [16]byte) []byte {
	return deriveKey(shared0, id[:], labelK0)
}

// randomBytes fills a slice from crypto/rand.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	return b
}
