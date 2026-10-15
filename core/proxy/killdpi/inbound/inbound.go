package inbound

import (
	"context"
	"crypto/ecdh"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/killdpi"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		c := config.(*Config)
		validator := new(killdpi.MemoryValidator)
		for _, user := range c.Users {
			u, err := user.ToMemoryUser()
			if err != nil {
				return nil, errors.New("failed to get KILLDPI user").Base(err)
			}
			if err := validator.Add(u); err != nil {
				return nil, errors.New("failed to initiate user").Base(err)
			}
		}
		return New(ctx, c, validator)
	}))
}

// Handler is the KILLDPI inbound handler.
type Handler struct {
	policyManager policy.Manager
	validator     killdpi.Validator
	privateKey    *ecdh.PrivateKey
	replay        *killdpi.ReplayCache
	timeWindow    int64
	fallbacks     map[string]map[string]map[string]*Fallback // name -> alpn -> path
}

// New creates a KILLDPI inbound handler.
func New(ctx context.Context, config *Config, validator killdpi.Validator) (*Handler, error) {
	v := core.MustFromContext(ctx)
	priv, err := killdpi.ParsePrivateKey(config.PrivateKey)
	if err != nil {
		return nil, errors.New(`KILLDPI inbound: invalid "privateKey"`).Base(err)
	}
	tw := int64(config.TimeWindow)
	if tw == 0 {
		tw = killdpi.DefaultTimeWindow
	}
	h := &Handler{
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		validator:     validator,
		privateKey:    priv,
		replay:        killdpi.NewReplayCache(tw * 2),
		timeWindow:    tw,
	}
	if config.Fallbacks != nil {
		h.fallbacks = make(map[string]map[string]map[string]*Fallback)
		for _, fb := range config.Fallbacks {
			if h.fallbacks[fb.Name] == nil {
				h.fallbacks[fb.Name] = make(map[string]map[string]*Fallback)
			}
			if h.fallbacks[fb.Name][fb.Alpn] == nil {
				h.fallbacks[fb.Name][fb.Alpn] = make(map[string]*Fallback)
			}
			h.fallbacks[fb.Name][fb.Alpn][fb.Path] = fb
		}
		// inherit defaults ("" name / "" alpn) into specific entries
		if h.fallbacks[""] != nil {
			for name, apfb := range h.fallbacks {
				if name == "" {
					continue
				}
				for alpn, pfb := range h.fallbacks[""] {
					if apfb[alpn] == nil {
						apfb[alpn] = make(map[string]*Fallback)
					}
					for path, fb := range pfb {
						if apfb[alpn][path] == nil {
							apfb[alpn][path] = fb
						}
					}
				}
			}
		}
		for _, apfb := range h.fallbacks {
			if apfb[""] != nil {
				for alpn, pfb := range apfb {
					if alpn == "" {
						continue
					}
					for path, fb := range apfb[""] {
						if pfb[path] == nil {
							pfb[path] = fb
						}
					}
				}
			}
		}
	}
	return h, nil
}

// Close implements common.Closable.
func (h *Handler) Close() error { return errors.Combine(common.Close(h.validator)) }

// AddUser implements proxy.UserManager.
func (h *Handler) AddUser(ctx context.Context, u *protocol.MemoryUser) error { return h.validator.Add(u) }

// RemoveUser implements proxy.UserManager.
func (h *Handler) RemoveUser(ctx context.Context, e string) error { return h.validator.Del(e) }

// GetUser implements proxy.UserManager.
func (h *Handler) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	return h.validator.GetByEmail(email)
}

// GetUsers implements proxy.UserManager.
func (h *Handler) GetUsers(ctx context.Context) []*protocol.MemoryUser { return h.validator.GetAll() }

// GetUsersCount implements proxy.UserManager.
func (h *Handler) GetUsersCount(context.Context) int64 { return h.validator.GetCount() }

// Network implements proxy.Inbound.
func (*Handler) Network() []net.Network { return []net.Network{net.Network_TCP, net.Network_UNIX} }

// Process implements proxy.Inbound.
func (h *Handler) Process(ctx context.Context, network net.Network, connection stat.Connection, dispatch routing.Dispatcher) error {
	iConn := stat.TryUnwrapStatsConn(connection)
	sessionPolicy := h.policyManager.ForLevel(0)
	if err := connection.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)); err != nil {
		return errors.New("unable to set read deadline").Base(err)
	}

	// Buffer the first read so we can hand the raw bytes to a fallback if the
	// handshake fails (active-probe resistance).
	first := buf.FromBytes(make([]byte, buf.Size))
	first.Clear()
	firstLen, err := first.ReadFrom(connection)
	if err != nil {
		return err
	}
	reader := &buf.BufferedReader{
		Reader: buf.NewReader(connection),
		Buffer: buf.MultiBuffer{first},
	}

	account0 := killdpi.DefaultPaddingMin
	account1 := killdpi.DefaultPaddingMax
	var result *killdpi.ServerResult
	if h.fallbacks != nil && firstLen < killdpi.ClientPrefixLen+2+16 {
		err = errors.New("first flight too short, fallback directly")
	} else {
		result, err = killdpi.ServerHandshake(connection, reader, h.privateKey, h.validator, h.replay, h.timeWindow, account0, account1)
	}
	if err != nil {
		if h.fallbacks != nil {
			return h.doFallback(ctx, connection, iConn, reader, sessionPolicy, err)
		}
		if errors.Cause(err) != io.EOF {
			log.Record(&log.AccessMessage{From: connection.RemoteAddr(), To: "", Status: log.AccessRejected, Reason: err})
			err = errors.New("invalid request from ", connection.RemoteAddr()).Base(err)
		}
		return err
	}
	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		errors.LogWarningInner(ctx, err, "unable to set back read deadline")
	}

	hello := result.Hello
	user := result.User
	fc := result.Conn

	var dest net.Destination
	switch hello.Command {
	case killdpi.CommandTCP:
		dest = net.TCPDestination(hello.Address, hello.Port)
	case killdpi.CommandUDP:
		dest = net.UDPDestination(hello.Address, hello.Port)
	case killdpi.CommandMux:
		dest = net.TCPDestination(net.DomainAddress("v1.mux.cool"), 0)
	}
	errors.LogInfo(ctx, "received request for ", dest)

	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		panic("no inbound metadata")
	}
	inbound.Name = "killdpi"
	inbound.User = user
	inbound.CanSpliceCopy = 3 // we always encrypt; splice is impossible

	if hello.Command != killdpi.CommandMux {
		ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
			From: connection.RemoteAddr(), To: dest, Status: log.AccessAccepted, Email: user.Email,
		})
	}

	sessionPolicy = h.policyManager.ForLevel(user.Level)
	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)

	var clientReader buf.Reader
	var clientWriter buf.Writer
	if hello.Command == killdpi.CommandUDP {
		clientReader = &killdpi.PacketReader{Conn: fc}
		clientWriter = &killdpi.PacketWriter{Conn: fc}
	} else {
		clientReader = buf.NewReader(fc)
		clientWriter = fc
	}

	if err := dispatch.DispatchLink(ctx, dest, &transport.Link{Reader: clientReader, Writer: clientWriter}); err != nil {
		return errors.New("failed to dispatch request").Base(err)
	}
	return nil
}

// doFallback forwards the already-read bytes plus the rest of the connection
// to the configured fallback destination (mirrors VLESS semantics).
func (h *Handler) doFallback(ctx context.Context, connection stat.Connection, iConn net.Conn, reader buf.Reader, sessionPolicy policy.Session, cause error) error {
	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		errors.LogWarningInner(ctx, err, "unable to set back read deadline")
	}
	errors.LogInfoInner(ctx, cause, "fallback starts")

	name, alpn := "", ""
	if tlsConn, ok := iConn.(*tls.Conn); ok {
		cs := tlsConn.ConnectionState()
		name, alpn = cs.ServerName, cs.NegotiatedProtocol
	} else if realityConn, ok := iConn.(*reality.Conn); ok {
		cs := realityConn.ConnectionState()
		name, alpn = cs.ServerName, cs.NegotiatedProtocol
	}
	name = strings.ToLower(name)
	alpn = strings.ToLower(alpn)
	napfb := h.fallbacks
	if len(napfb) > 1 || napfb[""] == nil {
		if name != "" && napfb[name] == nil {
			match := ""
			for n := range napfb {
				if n != "" && strings.Contains(name, n) && len(n) > len(match) {
					match = n
				}
			}
			name = match
		}
	}
	if napfb[name] == nil {
		name = ""
	}
	apfb := napfb[name]
	if apfb == nil {
		return errors.New(`failed to find the default "name" fallback`)
	}
	if apfb[alpn] == nil {
		alpn = ""
	}
	pfb := apfb[alpn]
	if pfb == nil {
		return errors.New(`failed to find the default "alpn" fallback`)
	}
	fb := pfb[""]
	if fb == nil {
		for _, f := range pfb {
			fb = f
			break
		}
	}
	if fb == nil {
		return errors.New(`failed to find a fallback`)
	}

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)
	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)

	var conn net.Conn
	if err := retry.ExponentialBackoff(5, 100).On(func() error {
		var dialer net.Dialer
		var err error
		conn, err = dialer.DialContext(ctx, fb.Type, fb.Dest)
		return err
	}); err != nil {
		return errors.New("failed to dial fallback " + fb.Dest).Base(err)
	}
	defer conn.Close()

	serverReader := buf.NewReader(conn)
	serverWriter := buf.NewWriter(conn)
	postRequest := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		if fb.Xver != 0 {
			if err := writeProxyProtocol(serverWriter, connection, fb.Xver); err != nil {
				return err
			}
		}
		return buf.Copy(reader, serverWriter, buf.UpdateActivity(timer))
	}
	writer := buf.NewWriter(connection)
	getResponse := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(serverReader, writer, buf.UpdateActivity(timer))
	}
	if err := task.Run(ctx, task.OnSuccess(postRequest, task.Close(serverWriter)), task.OnSuccess(getResponse, task.Close(writer))); err != nil {
		common.Interrupt(serverReader)
		common.Interrupt(serverWriter)
		return errors.New("fallback ends").Base(err)
	}
	return nil
}

func writeProxyProtocol(w buf.Writer, connection net.Conn, xver uint64) error {
	remoteAddr, remotePort, err1 := net.SplitHostPort(connection.RemoteAddr().String())
	localAddr, localPort, err2 := net.SplitHostPort(connection.LocalAddr().String())
	pro := buf.New()
	defer pro.Release()
	if err1 != nil || err2 != nil {
		if xver == 1 {
			pro.Write([]byte("PROXY UNKNOWN\r\n"))
		} else {
			pro.Write([]byte("\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x20\x00\x00\x00"))
		}
		return w.WriteMultiBuffer(buf.MultiBuffer{pro})
	}
	ip6 := strings.Contains(remoteAddr, ":")
	switch xver {
	case 1:
		fam := "TCP4"
		if ip6 {
			fam = "TCP6"
		}
		pro.Write([]byte("PROXY " + fam + " " + remoteAddr + " " + localAddr + " " + remotePort + " " + localPort + "\r\n"))
	case 2:
		pro.Write([]byte("\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"))
		if !ip6 {
			pro.Write([]byte("\x21\x11\x00\x0C"))
			pro.Write(net.ParseIP(remoteAddr).To4())
			pro.Write(net.ParseIP(localAddr).To4())
		} else {
			pro.Write([]byte("\x21\x21\x00\x24"))
			pro.Write(net.ParseIP(remoteAddr).To16())
			pro.Write(net.ParseIP(localAddr).To16())
		}
		p1, _ := strconv.ParseUint(remotePort, 10, 16)
		p2, _ := strconv.ParseUint(localPort, 10, 16)
		pro.Write([]byte{byte(p1 >> 8), byte(p1), byte(p2 >> 8), byte(p2)})
	}
	return w.WriteMultiBuffer(buf.MultiBuffer{pro})
}
