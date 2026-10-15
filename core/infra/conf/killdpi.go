package conf

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/killdpi"
	"github.com/xtls/xray-core/proxy/killdpi/inbound"
	"github.com/xtls/xray-core/proxy/killdpi/outbound"
	"google.golang.org/protobuf/proto"
)

// KillDPIInboundFallback mirrors the VLESS fallback structure.
type KillDPIInboundFallback struct {
	Name string          `json:"name"`
	Alpn string          `json:"alpn"`
	Path string          `json:"path"`
	Type string          `json:"type"`
	Dest json.RawMessage `json:"dest"`
	Xver uint64          `json:"xver"`
}

// KillDPIInboundConfig is the JSON "settings" of a killdpi inbound.
//
//	{
//	  "clients": [{"id": "<uuid>", "email": "a@b", "cipher": "chacha20-poly1305", "padding": "64-512"}],
//	  "privateKey": "<base64url x25519 private key>",
//	  "timeWindow": 120,
//	  "fallbacks": [{"dest": 8080}]
//	}
type KillDPIInboundConfig struct {
	Users      []json.RawMessage         `json:"users"`
	Clients    []json.RawMessage         `json:"clients"`
	PrivateKey string                    `json:"privateKey"`
	TimeWindow uint32                    `json:"timeWindow"`
	Fallbacks  []*KillDPIInboundFallback `json:"fallbacks"`
}

// Build implements Buildable.
func (c *KillDPIInboundConfig) Build() (proto.Message, error) {
	config := new(inbound.Config)
	if c.Clients != nil {
		c.Users = c.Clients
	}
	if len(c.Users) == 0 {
		return nil, errors.New(`KILLDPI settings: "clients" must contain at least one user`)
	}
	if c.PrivateKey == "" {
		return nil, errors.New(`KILLDPI settings: "privateKey" is required (generate with: xray killdpi-keygen)`)
	}
	if _, err := killdpi.ParsePrivateKey(c.PrivateKey); err != nil {
		return nil, errors.New(`KILLDPI settings: invalid "privateKey"`).Base(err)
	}
	config.PrivateKey = c.PrivateKey
	config.TimeWindow = c.TimeWindow

	config.Users = make([]*protocol.User, len(c.Users))
	for idx, rawUser := range c.Users {
		user := new(protocol.User)
		if err := json.Unmarshal(rawUser, user); err != nil {
			return nil, errors.New(`KILLDPI clients: invalid user`).Base(err)
		}
		account := new(killdpi.Account)
		if err := json.Unmarshal(rawUser, account); err != nil {
			return nil, errors.New(`KILLDPI clients: invalid user`).Base(err)
		}
		u, err := uuid.ParseString(account.Id)
		if err != nil {
			return nil, errors.New(`KILLDPI clients: invalid "id"`).Base(err)
		}
		account.Id = u.String()
		if account.Cipher, err = killdpi.NormalizeCipher(account.Cipher); err != nil {
			return nil, err
		}
		if _, _, err := killdpi.ParsePadding(account.Padding); err != nil {
			return nil, err
		}
		user.Account = serial.ToTypedMessage(account)
		config.Users[idx] = user
	}

	for _, fb := range c.Fallbacks {
		var i uint16
		var s string
		if err := json.Unmarshal(fb.Dest, &i); err == nil {
			s = strconv.Itoa(int(i))
		} else {
			_ = json.Unmarshal(fb.Dest, &s)
		}
		config.Fallbacks = append(config.Fallbacks, &inbound.Fallback{
			Name: fb.Name, Alpn: fb.Alpn, Path: fb.Path, Type: fb.Type, Dest: s, Xver: fb.Xver,
		})
	}
	for _, fb := range config.Fallbacks {
		if fb.Path != "" && fb.Path[0] != '/' {
			return nil, errors.New(`KILLDPI fallbacks: "path" must be empty or start with "/"`)
		}
		if fb.Type == "" && fb.Dest != "" {
			if filepath.IsAbs(fb.Dest) || fb.Dest[0] == '@' {
				fb.Type = "unix"
				if len(fb.Dest) > 1 && fb.Dest[:2] == "@@" && (runtime.GOOS == "linux" || runtime.GOOS == "android") {
					fullAddr := make([]byte, len(syscall.RawSockaddrUnix{}.Path))
					copy(fullAddr, fb.Dest[1:])
					fb.Dest = string(fullAddr)
				}
			} else {
				if _, err := strconv.Atoi(fb.Dest); err == nil {
					fb.Dest = "localhost:" + fb.Dest
				}
				if _, _, err := net.SplitHostPort(fb.Dest); err == nil {
					fb.Type = "tcp"
				}
			}
		}
		if fb.Type == "" {
			return nil, errors.New(`KILLDPI fallbacks: please fill in a valid value for every "dest"`)
		}
		if fb.Xver > 2 {
			return nil, errors.New(`KILLDPI fallbacks: invalid PROXY protocol version, "xver" only accepts 0, 1, 2`)
		}
	}
	return config, nil
}

// KillDPIOutboundVnext is one server entry in "vnext".
type KillDPIOutboundVnext struct {
	Address *Address          `json:"address"`
	Port    uint16            `json:"port"`
	Users   []json.RawMessage `json:"users"`
}

// KillDPIOutboundConfig is the JSON "settings" of a killdpi outbound.
// Supports both the simplified style:
//
//	{"address": "example.com", "port": 443, "id": "<uuid>", "publicKey": "<pk>", "cipher": "aes-256-gcm"}
//
// and the classic vnext style:
//
//	{"vnext": [{"address": "...", "port": 443, "users": [{"id": "...", "cipher": "..."}]}], "publicKey": "<pk>"}
type KillDPIOutboundConfig struct {
	Address   *Address                `json:"address"`
	Port      uint16                  `json:"port"`
	Level     uint32                  `json:"level"`
	Email     string                  `json:"email"`
	Id        string                  `json:"id"`
	Cipher    string                  `json:"cipher"`
	Padding   string                  `json:"padding"`
	PublicKey string                  `json:"publicKey"`
	Keepalive uint32                  `json:"keepalive"`
	Vnext     []*KillDPIOutboundVnext `json:"vnext"`
}

// Build implements Buildable.
func (c *KillDPIOutboundConfig) Build() (proto.Message, error) {
	config := new(outbound.Config)
	if c.Address != nil {
		c.Vnext = []*KillDPIOutboundVnext{{Address: c.Address, Port: c.Port, Users: []json.RawMessage{{}}}}
	}
	if len(c.Vnext) != 1 {
		return nil, errors.New(`KILLDPI settings: "vnext" should have one and only one member`)
	}
	if c.PublicKey == "" {
		return nil, errors.New(`KILLDPI settings: "publicKey" is required`)
	}
	if _, err := killdpi.ParsePublicKey(c.PublicKey); err != nil {
		return nil, errors.New(`KILLDPI settings: invalid "publicKey"`).Base(err)
	}
	config.PublicKey = c.PublicKey
	config.Keepalive = c.Keepalive

	rec := c.Vnext[0]
	if rec.Address == nil {
		return nil, errors.New(`KILLDPI vnext: "address" is not set`)
	}
	if len(rec.Users) != 1 {
		return nil, errors.New(`KILLDPI vnext: "users" should have one and only one member`)
	}
	spec := &protocol.ServerEndpoint{Address: rec.Address.Build(), Port: uint32(rec.Port)}
	user := new(protocol.User)
	account := new(killdpi.Account)
	if c.Address != nil {
		user.Level, user.Email = c.Level, c.Email
		account.Id, account.Cipher, account.Padding = c.Id, c.Cipher, c.Padding
	} else {
		if err := json.Unmarshal(rec.Users[0], user); err != nil {
			return nil, errors.New(`KILLDPI users: invalid user`).Base(err)
		}
		if err := json.Unmarshal(rec.Users[0], account); err != nil {
			return nil, errors.New(`KILLDPI users: invalid user`).Base(err)
		}
		c.Address = rec.Address // for transport-security validation
	}
	u, err := uuid.ParseString(account.Id)
	if err != nil {
		return nil, errors.New(`KILLDPI users: invalid "id"`).Base(err)
	}
	account.Id = u.String()
	if account.Cipher, err = killdpi.NormalizeCipher(account.Cipher); err != nil {
		return nil, err
	}
	if _, _, err := killdpi.ParsePadding(account.Padding); err != nil {
		return nil, err
	}
	user.Account = serial.ToTypedMessage(account)
	spec.User = user
	config.Vnext = spec
	return config, nil
}
