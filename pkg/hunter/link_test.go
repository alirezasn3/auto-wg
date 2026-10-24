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
	"auto-wg/pkg/transport"
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
	resets      int
	primary     bool
	targets     []string
	relay       netip.AddrPort
	statusExtra transport.Status
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
func (f *fakeTunnel) ResetConn() bool {
	f.mu.Lock()
	f.resets++
	f.mu.Unlock()
	return true
}
func (f *fakeTunnel) Status() transport.Status {
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

func (f *fakeTunnel) resetCount() int { f.mu.Lock(); defer f.mu.Unlock(); return f.resets }
func (f *fakeTunnel) reconnectCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reconnects
}

type linkRig struct {
	h   *Hunter
	be  *fakeBackend
	tun *fakeTunnel
	now time.Time
}

func (r *linkRig) advance(d time.Duration) { r.now = r.now.Add(d) }
func (r *linkRig) tick()                   { r.h.tick(context.Background()) }

func linkedCfg(transportName string) config.TunnelConfig {
	hunting := true
	cfg := config.TunnelConfig{
		Interface: "wg0", Name: "wg0", HistoryFile: "off", Hunting: &hunting, Transport: transportName,
		PortRange: "20000-20100", RemotePortRange: "24000-24100",
		TargetIPs: []string{"198.51.100.1"}, TargetIP: "198.51.100.1",
		HandshakeTimeout: 60 * time.Second, CheckInterval: 3 * time.Second, CycleTimeout: 8 * time.Second,
	}
	link := config.LinkConfig{Secret: "0123456789abcdef", ReconnectAfter: 10 * time.Second, DialInterval: time.Second}
	switch transportName {
	case config.TransportTLS:
		cfg.TLS.LinkConfig = link
	case config.TransportSSH:
		cfg.SSH.LinkConfig = link
	}
	return cfg
}

func newLinkRig(t *testing.T, transportName string) *linkRig {
	t.Helper()
	be := &fakeBackend{dev: wg.DeviceInfo{
		Name: "wg0", PublicKey: "LOCAL", PeerPublicKey: "PEER", ListenPort: 51820,
		PeerEndpoint: "198.51.100.1:24000", PeerEndpointIP: "198.51.100.1", PeerPort: 24000,
	}}
	tun := &fakeTunnel{relay: netip.MustParseAddrPort("127.0.0.1:41000")}
	h := New(linkedCfg(transportName), be, nil, logger.New(io.Discard, logger.LevelDebug, 100), nil)
	r := &linkRig{h: h, be: be, tun: tun, now: time.Unix(1_700_000_000, 0)}
	h.now = func() time.Time { return r.now }
	h.newTunnel = func(transport.Options, transport.Deps) linkTunnel { return tun }
	h.ctx = context.Background()
	h.startLink()
	if transportName != config.TransportDirect && (h.tun == nil || !tun.started) {
		t.Fatal("tunnel was not started")
	}
	be.setDead()
	return r
}

func TestDirectTransportStartsNoLink(t *testing.T) {
	r := newLinkRig(t, config.TransportDirect)
	if r.h.tun != nil || r.tun.started {
		t.Fatal("a direct tunnel must not start a link")
	}
	if st := r.h.GetStatus(); st.Transport != config.TransportDirect {
		t.Fatalf("status transport = %q", st.Transport)
	}
}

func TestLinkedTunnelPointsWireGuardAtTheRelay(t *testing.T) {
	for _, name := range []string{config.TransportTLS, config.TransportSSH} {
		r := newLinkRig(t, name)
		r.tick()
		eps, _ := r.be.calls()
		if len(eps) != 1 || eps[0] != "127.0.0.1:41000" {
			t.Fatalf("%s: expected the endpoint to be set to the relay once, got %v", name, eps)
		}
		r.tick()
		if eps2, _ := r.be.calls(); len(eps2) != 1 {
			t.Fatalf("%s: endpoint already on the relay must not be rewritten: %v", name, eps2)
		}
		if st := r.h.GetStatus(); st.Transport != name || st.TargetIP != "198.51.100.1" {
			t.Fatalf("%s: unexpected status %+v", name, st)
		}
	}
}

func TestLinkedTunnelNeverHuntsUDPPorts(t *testing.T) {
	r := newLinkRig(t, config.TransportTLS)
	r.tun.set(true, 0)
	r.tick()
	_, portsBefore := r.be.calls()
	for i := 0; i < 20; i++ {
		r.advance(time.Second)
		r.tick()
	}
	_, ports := r.be.calls()
	if len(ports) != len(portsBefore) {
		t.Fatalf("a linked tunnel must not rotate WireGuard's listen port: %v", ports)
	}
	eps, _ := r.be.calls()
	for _, e := range eps {
		if e != "127.0.0.1:41000" {
			t.Fatalf("endpoint moved off the relay: %v", eps)
		}
	}
}

// WireGuard dead on a link that passes its probes: rebuild the connection after reconnect_after, then
// again only after another reconnect_after.
func TestDeadWireGuardOnHealthyLinkRebuildsTheConnectionPeriodically(t *testing.T) {
	r := newLinkRig(t, config.TransportTLS)
	r.tun.set(true, 0)
	r.tick() // starts the dead timer
	r.advance(6 * time.Second)
	r.tick()
	if r.tun.resetCount() != 0 {
		t.Fatal("must wait for reconnect_after before rebuilding")
	}
	r.advance(5 * time.Second) // 11s dead
	r.tick()
	if r.tun.resetCount() != 1 || r.tun.reconnectCount() != 0 {
		t.Fatalf("expected one connection reset, got resets=%d reconnects=%d", r.tun.resetCount(), r.tun.reconnectCount())
	}
	r.advance(5 * time.Second)
	r.tick()
	if r.tun.resetCount() != 1 {
		t.Fatal("a second rebuild needs another full reconnect_after")
	}
	r.advance(6 * time.Second)
	r.tick()
	if r.tun.resetCount() != 2 {
		t.Fatalf("expected a second rebuild, got %d", r.tun.resetCount())
	}
}

// The dead timer starts when WireGuard first looks dead, possibly long before the link comes up; a fresh
// connection must still get its whole reconnect_after to let WireGuard handshake.
func TestFreshConnectionGetsItsFullWindow(t *testing.T) {
	r := newLinkRig(t, config.TransportTLS)
	r.tun.set(false, 0)
	r.tick() // dead timer starts, no link yet
	r.advance(30 * time.Second)
	r.tick() // no connection for long: the listener rotates
	rotations := r.tun.reconnectCount()
	r.advance(20 * time.Second) // long enough that the rotation no longer holds the next action back

	r.tun.statusExtra = transport.Status{Since: r.now}
	r.tun.set(true, 0) // the link comes up just now
	r.advance(4 * time.Second)
	r.tick()
	if r.tun.resetCount() != 0 {
		t.Fatal("a connection that just came up must not be dropped for WireGuard having been dead before it existed")
	}
	r.advance(7 * time.Second) // 11s since the link came up
	r.tick()
	if r.tun.resetCount() != 1 {
		t.Fatalf("expected the reset once the connection had its full window, got %d (rotations before: %d)", r.tun.resetCount(), rotations)
	}
}

func TestDeadWireGuardWithoutConnectionRotatesTheListener(t *testing.T) {
	r := newLinkRig(t, config.TransportSSH)
	r.tun.set(false, 30*time.Second)
	r.tick()
	r.advance(11 * time.Second)
	r.tick()
	if r.tun.reconnectCount() != 1 || r.tun.resetCount() != 0 {
		t.Fatalf("expected a listener rotation, got resets=%d reconnects=%d", r.tun.resetCount(), r.tun.reconnectCount())
	}
}

func TestRecoveryAllowsAnotherRebuildInTheNextDeadPeriod(t *testing.T) {
	r := newLinkRig(t, config.TransportTLS)
	r.tun.set(true, 0)
	r.tick()
	r.advance(11 * time.Second)
	r.tick()
	if r.tun.resetCount() != 1 {
		t.Fatalf("setup: expected one rebuild, got %d", r.tun.resetCount())
	}
	r.be.setAlive()
	r.advance(time.Second)
	r.tick()
	r.be.setDead()
	r.advance(2 * time.Second)
	r.tick() // new dead period
	r.advance(11 * time.Second)
	r.tick()
	if r.tun.resetCount() != 2 {
		t.Fatalf("a new dead period must allow another rebuild, got %d", r.tun.resetCount())
	}
}

func TestLinkedTunnelGetsRoleAndTargets(t *testing.T) {
	r := newLinkRig(t, config.TransportTLS)
	r.be.setAlive()
	r.tick()
	r.tun.mu.Lock()
	defer r.tun.mu.Unlock()
	if !r.tun.primary { // "LOCAL" < "PEER"
		t.Error("primary role was not passed to the link")
	}
	if len(r.tun.targets) != 1 || r.tun.targets[0] != "198.51.100.1" {
		t.Errorf("targets were not passed to the link: %v", r.tun.targets)
	}
}

func TestHuntAndRebindReconnectTheLink(t *testing.T) {
	r := newLinkRig(t, config.TransportSSH)
	r.tick()
	epsBefore, portsBefore := r.be.calls()
	r.h.executeHunt("manual")
	if err := r.h.TriggerRebind(); err != nil {
		t.Fatal(err)
	}
	if r.tun.reconnectCount() != 2 {
		t.Fatalf("expected both buttons to reconnect the link, got %d", r.tun.reconnectCount())
	}
	epsAfter, portsAfter := r.be.calls()
	if len(epsAfter) != len(epsBefore) || len(portsAfter) != len(portsBefore) {
		t.Fatal("the buttons must not rotate UDP ports on a linked tunnel")
	}
}

func TestDirectHuntStillRotatesPorts(t *testing.T) {
	r := newLinkRig(t, config.TransportDirect)
	r.h.executeHunt("manual")
	if r.tun.reconnectCount() != 0 {
		t.Fatal("a direct tunnel has no link to reconnect")
	}
	if _, ports := r.be.calls(); len(ports) == 0 {
		t.Fatal("a direct hunt must change the listen port")
	}
}

func TestLinkedDirectionFollowsWhoDialed(t *testing.T) {
	r := newLinkRig(t, config.TransportTLS)
	r.tun.statusExtra = transport.Status{Direction: "dialed"}
	if d, i := r.h.determineDirection(0); d != "Local → Remote" || i != "Local Host" {
		t.Fatalf("dialed: %s / %s", d, i)
	}
	r.tun.statusExtra = transport.Status{Direction: "accepted"}
	if d, i := r.h.determineDirection(0); d != "Remote → Local" || i != "Remote Peer" {
		t.Fatalf("accepted: %s / %s", d, i)
	}
}

func TestUpdateConfigRebuildsAndRemovesTheLink(t *testing.T) {
	r := newLinkRig(t, config.TransportTLS)
	first := r.tun
	second := &fakeTunnel{relay: netip.MustParseAddrPort("127.0.0.1:41001")}
	r.h.newTunnel = func(transport.Options, transport.Deps) linkTunnel { return second }

	changed := r.h.cfg
	changed.TLS.Secret = "a-completely-new-secret"
	r.h.UpdateConfig(changed)
	if !first.stopped || !second.started || r.h.tun == nil {
		t.Fatal("a changed link config must stop the old link and start a new one")
	}

	third := &fakeTunnel{}
	r.h.newTunnel = func(transport.Options, transport.Deps) linkTunnel { return third }
	r.h.UpdateConfig(changed)
	if third.started || second.stopped {
		t.Fatal("an unchanged link config must not rebuild the link")
	}

	// Going back to direct stops the link and restores a direct endpoint.
	r.tick() // WireGuard now points at the relay
	off := changed
	off.Transport = config.TransportDirect
	r.h.UpdateConfig(off)
	if !second.stopped || r.h.tun != nil {
		t.Fatal("switching to direct must stop the link")
	}
	eps, _ := r.be.calls()
	if got := eps[len(eps)-1]; got == "127.0.0.1:41000" || got == "127.0.0.1:41001" {
		t.Fatalf("the relay endpoint was not replaced: %v", eps)
	}
}

func TestStatusReportsTheLink(t *testing.T) {
	r := newLinkRig(t, config.TransportSSH)
	r.tun.statusExtra = transport.Status{Direction: "dialed", Remote: "198.51.100.1:24512", RelayPort: 41000, BytesRx: 10, BytesTx: 20,
		RTTMs: 42.5, ProbeFails: 3, VerifyFails: 2, Resets: 1, Verifying: true}
	r.tun.set(true, 0)
	st := r.h.GetStatus()
	if st.Transport != config.TransportSSH || !st.LinkConnected || st.LinkDirection != "dialed" || st.LinkRemote != "198.51.100.1:24512" ||
		st.LinkRelayPort != 41000 || st.LinkBytesRx != 10 || st.LinkBytesTx != 20 ||
		st.LinkRTTMs != 42.5 || st.LinkProbeFails != 3 || st.LinkVerifyFails != 2 || st.LinkResets != 1 || !st.LinkVerifying {
		t.Fatalf("unexpected status: %+v", st)
	}
}

// Every hunt must move both the source (listen) port and the destination port, never keeping either one.
func TestEveryHuntChangesBothPorts(t *testing.T) {
	r := newLinkRig(t, config.TransportDirect)
	r.h.cfg.PortRange, r.h.cfg.RemotePortRange = "20000-20004", "24000-24004" // tiny ranges make repeats likely
	prevPort, prevEP := r.be.dev.ListenPort, r.be.dev.PeerEndpoint
	r.h.setLocalPort(prevPort)
	r.h.remotePort = r.be.dev.PeerPort

	for i := 0; i < 60; i++ {
		r.h.executeHunt("test")
		r.be.mu.Lock()
		port, ep := r.be.dev.ListenPort, r.be.dev.PeerEndpoint
		r.be.mu.Unlock()
		if port == prevPort {
			t.Fatalf("hunt %d kept the source port %d", i, port)
		}
		if ep == prevEP {
			t.Fatalf("hunt %d kept the destination %s", i, ep)
		}
		prevPort, prevEP = port, ep
	}
}
