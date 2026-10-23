package hunter

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"auto-wg/pkg/config"
	"auto-wg/pkg/logger"
	"auto-wg/pkg/tlstun"
	"auto-wg/pkg/wg"
)

// fakeBackend is a WireGuard device whose state the test controls. UpdatePeerEndpoint moves the endpoint
// like the real thing does.
type fakeBackend struct {
	mu        sync.Mutex
	dev       wg.DeviceInfo
	endpoints []string
	ports     []int
}

func (f *fakeBackend) GetDeviceInfo(iface, peer string) (*wg.DeviceInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := f.dev
	return &d, nil
}

func (f *fakeBackend) UpdateListenPort(iface string, port int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ports = append(f.ports, port)
	f.dev.ListenPort = port
	return nil
}

func (f *fakeBackend) UpdatePeerEndpoint(iface, key, endpoint string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.endpoints = append(f.endpoints, endpoint)
	host, portStr, _ := net.SplitHostPort(endpoint)
	port, _ := strconv.Atoi(portStr)
	f.dev.PeerEndpoint, f.dev.PeerEndpointIP, f.dev.PeerPort = endpoint, host, port
	return nil
}

func (f *fakeBackend) calls() (endpoints []string, ports []int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.endpoints...), append([]int(nil), f.ports...)
}

func (f *fakeBackend) setDead() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dev.LastHandshake, f.dev.HandshakeAge = time.Time{}, 0
}

func (f *fakeBackend) setAlive() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dev.LastHandshake, f.dev.HandshakeAge = time.Now(), time.Second
	f.dev.ReceiveBytes += 1000
}

func (f *fakeBackend) setEndpoint(ip string, port int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dev.PeerEndpointIP, f.dev.PeerPort = ip, port
	f.dev.PeerEndpoint = net.JoinHostPort(ip, strconv.Itoa(port))
}

type fakeTunnel struct {
	mu          sync.Mutex
	connected   bool
	downFor     time.Duration
	started     bool
	stopped     bool
	reconnects  int
	primary     bool
	targets     []string
	relay       netip.AddrPort
	statusExtra tlstun.Status
}

func (f *fakeTunnel) Start(ctx context.Context) error {
	f.mu.Lock()
	f.started = true
	f.mu.Unlock()
	return nil
}
func (f *fakeTunnel) Stop()                     { f.mu.Lock(); f.stopped = true; f.mu.Unlock() }
func (f *fakeTunnel) Connected() bool           { f.mu.Lock(); defer f.mu.Unlock(); return f.connected }
func (f *fakeTunnel) DownFor() time.Duration    { f.mu.Lock(); defer f.mu.Unlock(); return f.downFor }
func (f *fakeTunnel) RelayAddr() netip.AddrPort { return f.relay }
func (f *fakeTunnel) SetPrimary(p bool)         { f.mu.Lock(); f.primary = p; f.mu.Unlock() }
func (f *fakeTunnel) SetTargets(t []string) {
	f.mu.Lock()
	f.targets = append([]string(nil), t...)
	f.mu.Unlock()
}
func (f *fakeTunnel) Reconnect() { f.mu.Lock(); f.reconnects++; f.mu.Unlock() }
func (f *fakeTunnel) Status() tlstun.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.statusExtra
	s.Connected = f.connected
	return s
}

func (f *fakeTunnel) set(connected bool, down time.Duration) {
	f.mu.Lock()
	f.connected, f.downFor = connected, down
	f.mu.Unlock()
}

type pathRig struct {
	h   *Hunter
	be  *fakeBackend
	tun *fakeTunnel
	now time.Time
}

func (r *pathRig) advance(d time.Duration) { r.now = r.now.Add(d) }
func (r *pathRig) tick()                   { r.h.tick(context.Background()) }

func newPathRig(t *testing.T) *pathRig {
	t.Helper()
	be := &fakeBackend{dev: wg.DeviceInfo{
		Name: "wg0", PublicKey: "LOCAL", PeerPublicKey: "PEER", ListenPort: 20050,
		PeerEndpoint: "198.51.100.1:24000", PeerEndpointIP: "198.51.100.1", PeerPort: 24000,
	}}
	tun := &fakeTunnel{relay: netip.MustParseAddrPort("127.0.0.1:41000")}
	hunting := true
	cfg := config.TunnelConfig{
		Interface: "wg0", Name: "wg0", HistoryFile: "off", Hunting: &hunting,
		PortRange: "20000-20100", RemotePortRange: "24000-24100",
		TargetIPs: []string{"198.51.100.1"}, TargetIP: "198.51.100.1",
		HandshakeTimeout: 60 * time.Second, CheckInterval: 3 * time.Second, CycleTimeout: 8 * time.Second,
		TLS: config.TLSConfig{Enabled: true, Secret: "0123456789abcdef", PortRange: "20000-20100", RemotePortRange: "24000-24100",
			FallbackAfter: 15 * time.Second, DialInterval: time.Second},
	}
	h := New(cfg, be, nil, logger.New(io.Discard, logger.LevelDebug, 100), nil)
	r := &pathRig{h: h, be: be, tun: tun, now: time.Unix(1_700_000_000, 0)}
	h.now = func() time.Time { return r.now }
	h.newTunnel = func(config.TLSConfig, tlstun.Deps) tlsLink { return tun }
	h.ctx = context.Background()
	h.startTLS()
	if h.tun == nil || !tun.started {
		t.Fatal("tunnel was not started")
	}
	be.setDead()
	return r
}

func (r *pathRig) path() string {
	r.h.mu.RLock()
	defer r.h.mu.RUnlock()
	return r.h.activePath
}

// lastDirectBeforeRelay is the last direct endpoint WireGuard was given before it was moved to a relay
// (direct hunting during the dead period rotates it, so tests cannot assume the initial one).
func lastDirectBeforeRelay(endpoints []string) string {
	last := "198.51.100.1:24000" // the device's initial endpoint when no hunt happened first
	for _, e := range endpoints {
		if len(e) > 10 && e[:10] == "127.0.0.1:" {
			return last
		}
		last = e
	}
	return last
}

func TestFailoverToTLSOnlyAfterFallbackAndWithLink(t *testing.T) {
	r := newPathRig(t)
	r.tun.set(true, 0)

	r.tick() // starts the dead timer
	r.advance(10 * time.Second)
	r.tick()
	if r.path() != PathDirect {
		t.Fatal("must not switch before fallback_after has passed")
	}

	r.advance(6 * time.Second) // 16s dead
	r.tick()
	if r.path() != PathTLS {
		t.Fatalf("expected the TLS path after 16s dead, got %s", r.path())
	}
	eps, _ := r.be.calls()
	if eps[len(eps)-1] != "127.0.0.1:41000" {
		t.Fatalf("endpoint must point at the relay, calls: %v", eps)
	}
	st := r.h.GetStatus()
	if st.Path != PathTLS || !st.TLSEnabled || st.LastPathSwitch.IsZero() {
		t.Fatalf("status does not show the switch: %+v", st)
	}
	if ev := r.h.events[0]; ev.Type != EventPath || ev.Direction != "DIRECT → TLS" || ev.Initiator != "Local Host" {
		t.Fatalf("path switch event missing or wrong: %+v", ev)
	}
}

func TestNoSwitchToTLSWithoutALink(t *testing.T) {
	r := newPathRig(t)
	r.tun.set(false, 30*time.Second)
	r.tick()
	r.advance(60 * time.Second)
	r.tick()
	if r.path() != PathDirect {
		t.Fatal("must keep hunting directly while the TLS link is down")
	}
	eps, _ := r.be.calls()
	for _, e := range eps {
		if e == "127.0.0.1:41000" {
			t.Fatal("endpoint must not be moved to a relay without a link")
		}
	}
}

func TestDirectHuntingIsHeldBackWhileOnTLS(t *testing.T) {
	r := newPathRig(t)
	r.tun.set(true, 0)
	r.tick()
	r.advance(16 * time.Second)
	r.tick() // switches to TLS
	if r.path() != PathTLS {
		t.Fatal("setup: expected TLS path")
	}
	epsBefore, portsBefore := r.be.calls()

	for i := 0; i < 4; i++ { // dead on the TLS path, still inside its fallback window
		r.advance(2 * time.Second)
		r.tick()
	}
	epsAfter, portsAfter := r.be.calls()
	if len(epsAfter) != len(epsBefore) || len(portsAfter) != len(portsBefore) {
		t.Fatalf("direct hunting must not touch the endpoint or listen port while on TLS: %v -> %v", epsBefore, epsAfter)
	}
	if r.path() != PathTLS {
		t.Fatal("path flipped back too early")
	}
}

func TestFallsBackToDirectWhenTLSStaysDead(t *testing.T) {
	r := newPathRig(t)
	r.tun.set(true, 0)
	r.tick()
	r.advance(16 * time.Second)
	r.tick() // TLS
	r.advance(16 * time.Second)
	r.tick() // TLS dead for a full window
	if r.path() != PathDirect {
		t.Fatalf("expected the direct path again, got %s", r.path())
	}
	eps, _ := r.be.calls()
	if got, want := eps[len(eps)-1], lastDirectBeforeRelay(eps); got != want {
		t.Fatalf("expected the last direct endpoint %s to be restored, calls: %v", want, eps)
	}
}

func TestTLSLinkDropFallsBackAfterGrace(t *testing.T) {
	r := newPathRig(t)
	r.tun.set(true, 0)
	r.tick()
	r.advance(16 * time.Second)
	r.tick() // TLS
	if r.path() != PathTLS {
		t.Fatal("setup: expected TLS path")
	}

	r.tun.set(false, time.Second) // just dropped: inside the grace period
	r.advance(2 * time.Second)
	r.tick()
	if r.path() != PathTLS {
		t.Fatal("a freshly dropped link gets a grace period")
	}

	r.tun.set(false, 4*time.Second)
	r.advance(2 * time.Second)
	r.tick()
	if r.path() != PathDirect {
		t.Fatal("a link that stayed down must send us back to the direct path without waiting for fallback_after")
	}
}

func TestPeerDrivenSwitchIsFollowed(t *testing.T) {
	r := newPathRig(t)
	r.tun.set(true, 0)
	r.be.setAlive()
	r.tick()
	if r.path() != PathDirect {
		t.Fatal("setup: expected direct")
	}

	// The peer switched to TLS: its packets arrive over the link and WireGuard roams onto the relay.
	r.be.setEndpoint("127.0.0.1", 41000)
	r.be.setAlive()
	r.tick()
	if r.path() != PathTLS {
		t.Fatalf("our path must follow the endpoint, got %s", r.path())
	}
	if ev := r.h.events[0]; ev.Type != EventPath || ev.Initiator != "Remote Peer" {
		t.Fatalf("expected a peer-initiated path event, got %+v", ev)
	}
	st := r.h.GetStatus()
	if st.TargetIP != "198.51.100.1" || st.RemotePort != 24000 {
		t.Fatalf("the relay must never replace the direct target: ip=%s port=%d", st.TargetIP, st.RemotePort)
	}

	// And back: the peer returns to the direct path.
	r.be.setEndpoint("198.51.100.1", 24055)
	r.be.setAlive()
	r.tick()
	if r.path() != PathDirect {
		t.Fatalf("expected direct again, got %s", r.path())
	}
}

func TestLoopbackEndpointNeverBecomesTheTarget(t *testing.T) {
	r := newPathRig(t)
	r.be.setEndpoint("127.0.0.1", 9999) // loopback, but not our relay
	r.be.setAlive()
	r.tick()
	st := r.h.GetStatus()
	if st.TargetIP != "198.51.100.1" {
		t.Fatalf("a loopback endpoint must not be adopted as the target, got %s", st.TargetIP)
	}
	if st.RemotePort == 9999 {
		t.Fatal("a loopback endpoint must not become the remote port")
	}
}

func TestHealthyLinkResetsTheDeadTimer(t *testing.T) {
	r := newPathRig(t)
	r.tun.set(true, 0)
	r.tick()
	r.advance(10 * time.Second)
	r.tick() // dead for 10s

	r.be.setAlive()
	r.advance(time.Second)
	r.tick() // healthy again
	r.be.setDead()
	r.advance(3 * time.Second)
	r.tick() // a new dead period starts here
	r.advance(10 * time.Second)
	r.tick()
	if r.path() != PathDirect {
		t.Fatal("the earlier dead time must not count towards the fallback of a new dead period")
	}
	r.advance(6 * time.Second)
	r.tick()
	if r.path() != PathTLS {
		t.Fatal("expected a switch after a full dead period")
	}
}

func TestTunnelGetsRoleAndTargets(t *testing.T) {
	r := newPathRig(t)
	r.be.setAlive()
	r.tick()
	r.tun.mu.Lock()
	defer r.tun.mu.Unlock()
	if !r.tun.primary { // "LOCAL" < "PEER"
		t.Error("primary role was not passed to the TLS link")
	}
	if len(r.tun.targets) != 1 || r.tun.targets[0] != "198.51.100.1" {
		t.Errorf("targets were not passed to the TLS link: %v", r.tun.targets)
	}
}

func TestHuntAndRebindReconnectTLSWhenItIsActive(t *testing.T) {
	r := newPathRig(t)
	r.tun.set(true, 0)
	r.tick()
	r.advance(16 * time.Second)
	r.tick() // TLS
	epsBefore, portsBefore := r.be.calls()

	r.h.executeHunt("manual")
	if err := r.h.TriggerRebind(); err != nil {
		t.Fatal(err)
	}
	if r.tun.reconnects != 2 {
		t.Fatalf("expected both buttons to reconnect the link, got %d reconnects", r.tun.reconnects)
	}
	epsAfter, portsAfter := r.be.calls()
	if len(epsAfter) != len(epsBefore) || len(portsAfter) != len(portsBefore) {
		t.Fatal("the buttons must not rotate direct ports while the TLS path is active")
	}
}

func TestUpdateConfigRebuildsAndRemovesTheTunnel(t *testing.T) {
	r := newPathRig(t)
	first := r.tun
	second := &fakeTunnel{relay: netip.MustParseAddrPort("127.0.0.1:41001")}
	r.h.newTunnel = func(config.TLSConfig, tlstun.Deps) tlsLink { return second }

	changed := r.h.cfg
	changed.TLS.Secret = "a-completely-new-secret"
	r.h.UpdateConfig(changed)
	if !first.stopped || !second.started || r.h.tun == nil {
		t.Fatal("a changed TLS config must stop the old tunnel and start a new one")
	}

	// Unchanged config leaves the tunnel alone.
	third := &fakeTunnel{}
	r.h.newTunnel = func(config.TLSConfig, tlstun.Deps) tlsLink { return third }
	r.h.UpdateConfig(changed)
	if third.started || second.stopped {
		t.Fatal("an unchanged TLS config must not rebuild the tunnel")
	}

	// Turning TLS off while it carries traffic puts WireGuard back on the direct endpoint.
	second.set(true, 0)
	r.be.setDead()
	r.tick()
	r.advance(16 * time.Second)
	r.tick()
	if r.path() != PathTLS {
		t.Fatal("setup: expected TLS path")
	}
	off := changed
	off.TLS = config.TLSConfig{}
	r.h.UpdateConfig(off)
	if !second.stopped || r.h.tun != nil || r.path() != PathDirect {
		t.Fatalf("disabling TLS must stop the tunnel and return to direct (tun=%v path=%s)", r.h.tun, r.path())
	}
	eps, _ := r.be.calls()
	if got, want := eps[len(eps)-1], lastDirectBeforeRelay(eps); got != want {
		t.Fatalf("direct endpoint %s not restored: %v", want, eps)
	}
}

func TestStatusReportsTLSLink(t *testing.T) {
	r := newPathRig(t)
	r.tun.statusExtra = tlstun.Status{Direction: "dialed", Remote: "198.51.100.1:24512", ListenPort: 20077, RelayPort: 41000, BytesRx: 10, BytesTx: 20}
	r.tun.set(true, 0)
	st := r.h.GetStatus()
	if !st.TLSEnabled || !st.TLSConnected || st.TLSDirection != "dialed" || st.TLSRemote != "198.51.100.1:24512" ||
		st.TLSListenPort != 20077 || st.TLSRelayPort != 41000 || st.TLSBytesRx != 10 || st.TLSBytesTx != 20 || st.Path != PathDirect {
		t.Fatalf("unexpected status: %+v", st)
	}
}
