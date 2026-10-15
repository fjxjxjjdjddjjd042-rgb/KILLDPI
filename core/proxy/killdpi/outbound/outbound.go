package outbound

import (
	"context"
	"crypto/ecdh"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/killdpi"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}

// Handler is the KILLDPI outbound handler.
type Handler struct {
	server        *protocol.ServerSpec
	policyManager policy.Manager
	publicKey     *ecdh.PublicKey
	keepalive     time.Duration
}

// New creates a KILLDPI outbound handler.
func New(ctx context.Context, config *Config) (*Handler, error) {
	if config.Vnext == nil {
		return nil, errors.New("KILLDPI outbound: no server specified")
	}
	server, err := protocol.NewServerSpecFromPB(config.Vnext)
	if err != nil {
		return nil, errors.New("failed to get server spec").Base(err)
	}
	pub, err := killdpi.ParsePublicKey(config.PublicKey)
	if err != nil {
		return nil, errors.New(`KILLDPI outbound: invalid "publicKey"`).Base(err)
	}
	v := core.MustFromContext(ctx)
	return &Handler{
		server:        server,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		publicKey:     pub,
		keepalive:     time.Duration(config.Keepalive) * time.Second,
	}, nil
}

// Process implements proxy.Outbound.
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "killdpi"
	ob.CanSpliceCopy = 3
	target := ob.Target
	rec := h.server

	// Connection with exponential back-off: survives short network blips.
	var conn stat.Connection
	if err := retry.ExponentialBackoff(5, 200).On(func() error {
		var err error
		conn, err = dialer.Dial(ctx, rec.Destination)
		return err
	}); err != nil {
		return errors.New("failed to connect to KILLDPI server").Base(err)
	}
	defer conn.Close()
	errors.LogInfo(ctx, "tunneling request to ", target, " via ", rec.Destination.NetAddr())

	account := rec.User.Account.(*killdpi.MemoryAccount)
	hello := &killdpi.Hello{Command: killdpi.CommandTCP, Address: target.Address, Port: target.Port}
	if target.Network == net.Network_UDP {
		hello.Command = killdpi.CommandUDP
	}
	if target.Address.Family().IsDomain() && target.Address.Domain() == "v1.mux.cool" {
		hello.Command = killdpi.CommandMux
	}

	cs, err := killdpi.ClientHandshake(conn, h.publicKey, account, hello)
	if err != nil {
		return errors.New("KILLDPI handshake failed").Base(err)
	}
	fc := cs.Conn

	sessionPolicy := h.policyManager.ForLevel(rec.User.Level)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	var serverWriter buf.Writer
	var serverReader buf.Reader
	if hello.Command == killdpi.CommandUDP {
		serverWriter = &killdpi.PacketWriter{Conn: fc}
		serverReader = &killdpi.PacketReader{Conn: fc}
	} else {
		serverWriter = fc
		serverReader = buf.NewReader(fc)
	}

	if h.keepalive > 0 {
		go h.keepaliveLoop(ctx, fc)
	}

	postRequest := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		// 0-RTT: coalesce the first payload with the HELLO flight when it
		// arrives quickly (saves a round-trip for HTTP/TLS client-first protocols).
		if tr, ok := link.Reader.(buf.TimeoutReader); ok {
			mb, err := tr.ReadMultiBufferTimeout(100 * time.Millisecond)
			if err == nil {
				if err := serverWriter.WriteMultiBuffer(mb); err != nil {
					return err
				}
			} else if err != buf.ErrReadTimeout {
				return err
			}
		}
		if err := buf.Copy(link.Reader, serverWriter, buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to transfer request payload").Base(err)
		}
		return nil
	}

	getResponse := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		if err := cs.WaitServerHello(); err != nil {
			return err
		}
		if err := buf.Copy(serverReader, link.Writer, buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to transfer response payload").Base(err)
		}
		return nil
	}

	if err := task.Run(ctx, postRequest, task.OnSuccess(getResponse, task.Close(link.Writer))); err != nil {
		return errors.New("connection ends").Base(err)
	}
	return nil
}

func (h *Handler) keepaliveLoop(ctx context.Context, fc *killdpi.FrameConn) {
	t := time.NewTicker(h.keepalive)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := fc.WriteFrame(killdpi.FramePing, nil); err != nil {
				return
			}
		}
	}
}
