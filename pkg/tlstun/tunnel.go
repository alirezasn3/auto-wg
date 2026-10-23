package tlstun

import (
	"context"
	"net/netip"
	"time"

	"auto-wg/pkg/config"
	"auto-wg/pkg/logger"
)

// Deps are the pieces of the surrounding tunnel the TLS path needs.
type Deps struct {
	Log         *logger.Logger
	Iface       string
	WGPort      func() int                             // current WireGuard listen port
	AvoidRanges []string                               // UDP port ranges the relay port must stay out of
	Redirect    func(portRange string, port int) error // installs the TCP REDIRECT of the local range; may be nil
}

// Status is a snapshot of the TLS path for the dashboard.
type Status struct {
	Connected    bool      `json:"connected"`
	Direction    string    `json:"direction,omitempty"` // "dialed" or "accepted"
	Remote       string    `json:"remote,omitempty"`
	Since        time.Time `json:"since,omitempty"`
	ListenPort   int       `json:"listen_port"`
	RelayPort    int       `json:"relay_port"`
	BytesRx      uint64    `json:"bytes_rx"`
	BytesTx      uint64    `json:"bytes_tx"`
	PacketsRx    uint64    `json:"packets_rx"`
	PacketsTx    uint64    `json:"packets_tx"`
	Dropped      uint64    `json:"dropped"`
	Dials        uint64    `json:"dials"`
	AuthFailures uint64    `json:"auth_failures"`
	LastError    string    `json:"last_error,omitempty"`
}

// Tunnel is the TLS path of one WireGuard tunnel: a Link (listener, dialer, connection) and the loopback
// relay WireGuard is pointed at while the path is active.
type Tunnel struct {
	cfg  config.TLSConfig
	deps Deps

	link  *Link
	relay *relay
}

func New(cfg config.TLSConfig, deps Deps) *Tunnel {
	t := &Tunnel{cfg: cfg, deps: deps}
	t.link = newLink(cfg, deps.Iface, deps.Log, func(p []byte) {
		if t.relay != nil {
			t.relay.deliver(p)
		}
	}, deps.Redirect)
	return t
}

// Start binds the relay socket and the TLS listener and starts dialing.
func (t *Tunnel) Start(ctx context.Context) error {
	wgPort := t.deps.WGPort
	if wgPort == nil {
		wgPort = func() int { return 0 }
	}
	r, err := newRelay(t.cfg.RelayPort, t.deps.AvoidRanges, wgPort, t.link.Send)
	if err != nil {
		return err
	}
	t.relay = r
	if err := t.link.Start(ctx); err != nil {
		r.close()
		t.relay = nil
		return err
	}
	go r.run()
	t.deps.Log.Info("TLS", "[%s] TLS path ready: relay 127.0.0.1:%d, dialing TCP range %s", t.deps.Iface, r.port, t.cfg.RemotePortRange)
	return nil
}

// Stop closes the link and the relay.
func (t *Tunnel) Stop() {
	t.link.Stop()
	if t.relay != nil {
		t.relay.close()
	}
}

func (t *Tunnel) Connected() bool        { return t.link.Connected() }
func (t *Tunnel) DownFor() time.Duration { return t.link.DownFor() }
func (t *Tunnel) SetPrimary(p bool)      { t.link.SetPrimary(p) }
func (t *Tunnel) SetTargets(r []string)  { t.link.SetTargets(r) }
func (t *Tunnel) Reconnect()             { t.link.Reconnect() }

// RelayAddr is the loopback endpoint WireGuard must use while the TLS path is active.
func (t *Tunnel) RelayAddr() netip.AddrPort {
	if t.relay == nil {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(t.relay.port))
}

func (t *Tunnel) Status() Status {
	s := Status{
		BytesRx:      t.link.st.rxBytes.Load(),
		BytesTx:      t.link.st.txBytes.Load(),
		PacketsRx:    t.link.st.rxPkts.Load(),
		PacketsTx:    t.link.st.txPkts.Load(),
		Dropped:      t.link.st.dropped.Load(),
		Dials:        t.link.st.dials.Load(),
		AuthFailures: t.link.st.authFails.Load(),
	}
	if t.relay != nil {
		s.RelayPort = t.relay.port
	}
	t.link.mu.Lock()
	s.ListenPort = t.link.listenPort
	s.LastError = t.link.lastErr
	t.link.mu.Unlock()
	if c := t.link.active.Load(); c != nil {
		s.Connected, s.Direction, s.Remote, s.Since = true, c.direction(), c.remote, c.since
	}
	return s
}
