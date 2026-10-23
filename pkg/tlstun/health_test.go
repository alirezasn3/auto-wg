package tlstun

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"auto-wg/pkg/config"
)

// stallProxy is a TCP proxy that can be told to silently swallow everything, like a middlebox that lets
// the start of a flow through and then blackholes it: connections stay open, nothing arrives.
type stallProxy struct {
	ln       net.Listener
	target   string
	stalled  atomic.Bool
	mu       sync.Mutex
	accepted int
}

func newStallProxy(t *testing.T, target string) *stallProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &stallProxy{ln: ln, target: target}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			p.accepted++
			p.mu.Unlock()
			go p.serve(c)
		}
	}()
	return p
}

func (p *stallProxy) port() int { return p.ln.Addr().(*net.TCPAddr).Port }

func (p *stallProxy) connections() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.accepted
}

func (p *stallProxy) serve(client net.Conn) {
	server, err := net.Dial("tcp", p.target)
	if err != nil {
		client.Close()
		return
	}
	pipe := func(dst, src net.Conn) {
		buf := make([]byte, 8192)
		for {
			n, err := src.Read(buf)
			if n > 0 && !p.stalled.Load() {
				_, _ = dst.Write(buf[:n])
			}
			if err != nil {
				dst.Close()
				src.Close()
				return
			}
		}
	}
	go pipe(server, client)
	go pipe(client, server)
}

// healthCfg returns a TLS config with fast probes so the tests do not take minutes.
func healthCfg(local, remote string) config.TLSConfig {
	return testCfg(local, remote, "shared-secret-1234")
}

// proxiedPair starts B (listener only) and A, whose dials go through a stall proxy to B.
func proxiedPair(t *testing.T) (a, b *Link, proxy *stallProxy, ra, rb *recorder) {
	t.Helper()
	aRange, bRange := portBlock(1, 1)
	ra, rb = &recorder{}, &recorder{}
	b = newLink(healthCfg(bRange, "9-9"), "b", testLog(), rb.add, nil)
	b.SetPrimary(false)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); b.Stop() })
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	bAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(b.listenPort))
	b.mu.Unlock()

	proxy = newStallProxy(t, bAddr)
	pr := strconv.Itoa(proxy.port())
	a = newLink(healthCfg(aRange, pr+"-"+pr), "a", testLog(), ra.add, nil)
	a.SetTargets([]string{"127.0.0.1"})
	a.SetPrimary(true)
	t.Cleanup(func() { a.Stop() })
	if err := a.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return
}

// setHook installs the test hook that runs when a connection becomes the active one.
func setHook(l *Link, f func(*conn)) { l.onInstalled.Store(&f) }

func TestNewLinkIsVerifiedAndMeasured(t *testing.T) {
	a, b, _, _ := pair(t, 1, "", "", "shared-secret-1234", "shared-secret-1234")
	waitFor(t, 5*time.Second, "both links verified", func() bool { return a.Connected() && b.Connected() })

	ta, tb := &Tunnel{link: a}, &Tunnel{link: b}
	for name, tn := range map[string]*Tunnel{"a": ta, "b": tb} {
		st := tn.Status()
		if !st.Connected || st.Verifying {
			t.Errorf("%s: a verified link must report connected, not verifying: %+v", name, st)
		}
		if st.RTTMs <= 0 || st.RTTMs > 2000 {
			t.Errorf("%s: implausible round trip %.3fms", name, st.RTTMs)
		}
		if st.Probes < uint64(len(verifyProbeSizes)) {
			t.Errorf("%s: expected at least the %d verification probes to be counted, got %d", name, len(verifyProbeSizes), st.Probes)
		}
	}
}

func TestPeriodicProbesKeepAHealthyLinkUp(t *testing.T) {
	a, b, ra, rb := pair(t, 1, "", "", "shared-secret-1234", "shared-secret-1234")
	waitFor(t, 5*time.Second, "link up", func() bool { return a.Connected() && b.Connected() })
	before := a.st.probes.Load()
	time.Sleep(1500 * time.Millisecond)

	if !a.Connected() || !b.Connected() {
		t.Fatal("a healthy link must survive many probe rounds")
	}
	if a.st.probes.Load() <= before+3 {
		t.Fatalf("expected periodic probes, counted %d -> %d", before, a.st.probes.Load())
	}
	if a.st.probeFails.Load() != 0 || b.st.probeFails.Load() != 0 {
		t.Fatalf("no probe may fail on a healthy link: a=%d b=%d", a.st.probeFails.Load(), b.st.probeFails.Load())
	}
	// Probes are control traffic: they must never reach WireGuard.
	if ra.count() != 0 || rb.count() != 0 {
		t.Fatalf("probe frames leaked into the packet stream: a=%d b=%d", ra.count(), rb.count())
	}
}

// The reported failure: the TLS connection is up, then everything on it stalls. Tiny keepalives would
// not notice; the probes must, and the dial loop must then build a working connection.
func TestStalledConnectionIsDetectedAndReplaced(t *testing.T) {
	a, b, proxy, _, rb := proxiedPair(t)
	waitFor(t, 5*time.Second, "link through the proxy", func() bool { return a.Connected() && b.Connected() })
	first := proxy.connections()

	if !a.Send([]byte("before-the-stall")) {
		t.Fatal("send must work on a healthy link")
	}
	waitFor(t, 3*time.Second, "first packet delivered", func() bool { return rb.has("before-the-stall") })

	proxy.stalled.Store(true)
	waitFor(t, 8*time.Second, "the stall to be detected", func() bool { return !a.Connected() })
	// Either end may be the first to give up (the other one then sees the connection close).
	if got := a.st.probeFails.Load() + b.st.probeFails.Load(); got < uint64(a.cfg.HealthFailures) {
		t.Fatalf("expected at least %d unanswered probe rounds before dropping the link, got %d", a.cfg.HealthFailures, got)
	}

	proxy.stalled.Store(false)
	waitFor(t, 8*time.Second, "a new working connection", func() bool { return a.Connected() && b.Connected() })
	if proxy.connections() <= first {
		t.Fatalf("recovery must use a new TCP connection (%d -> %d)", first, proxy.connections())
	}
	if !a.Send([]byte("after-the-stall")) {
		t.Fatal("send must work on the new connection")
	}
	waitFor(t, 3*time.Second, "packet over the new connection", func() bool { return rb.has("after-the-stall") })
}

// The other reported shape: authentication and the first frames pass, the rest of the flow does not. A new
// connection must prove itself before it is used.
func TestConnectionThatStallsRightAfterAuthIsNeverUsed(t *testing.T) {
	a, b, proxy, _, _ := proxiedPair(t)
	// Stall the proxy at the moment the connection becomes active, before verification starts.
	var once sync.Once
	setHook(a, func(*conn) { once.Do(func() { proxy.stalled.Store(true) }) })

	// Wait for the verification failure; the link must never have been reported usable.
	deadline := time.Now().Add(8 * time.Second)
	for a.st.verifyFails.Load() == 0 {
		if a.Connected() {
			t.Fatal("a connection that cannot echo probes must not be reported as connected")
		}
		if time.Now().After(deadline) {
			t.Fatal("verification never failed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if a.Send([]byte("must-not-go-out")) {
		t.Fatal("packets must not be sent on a connection that failed verification")
	}

	proxy.stalled.Store(false)
	waitFor(t, 8*time.Second, "a verified connection after the path recovers", func() bool { return a.Connected() && b.Connected() })
}

func TestSendIsRefusedUntilVerified(t *testing.T) {
	aRange, bRange := portBlock(1, 1)
	a := newLink(healthCfg(aRange, bRange), "a", testLog(), nil, nil)
	b := newLink(healthCfg(bRange, aRange), "b", testLog(), nil, nil)
	a.SetTargets([]string{"127.0.0.1"})
	b.SetTargets([]string{"127.0.0.1"})
	a.SetPrimary(true)
	b.SetPrimary(false)

	// Hold the connection unverified by swallowing pongs on A's side.
	var sawUnverified atomic.Bool
	setHook(a, func(c *conn) {
		go func() {
			if c.verified.Load() {
				return
			}
			if a.Send([]byte("too-early")) {
				t.Error("Send must refuse packets while the connection is unverified")
			}
			sawUnverified.Store(true)
		}()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, l := range []*Link{a, b} {
		if err := l.Start(ctx); err != nil {
			t.Fatal(err)
		}
		defer l.Stop()
	}
	waitFor(t, 5*time.Second, "link up", func() bool { return a.Connected() })
	waitFor(t, time.Second, "the early send attempt", func() bool { return sawUnverified.Load() })
}

// The wire protocol of the probes, spoken by a bare TLS client like a peer would.
func TestPingIsEchoedByteForByte(t *testing.T) {
	aRange, _ := portBlock(1, 1)
	l := newLink(healthCfg(aRange, "9-9"), "x", testLog(), nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := l.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer l.Stop()
	l.mu.Lock()
	port := l.listenPort
	l.mu.Unlock()

	raw, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(raw, clientTLS("", nil))
	defer tc.Close()
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := authenticate(tc, "shared-secret-1234", true); err != nil {
		t.Fatal(err)
	}

	// The link verifies us first with its own probes; answer them like a real peer, then ping it ourselves.
	probe := newProbe(0x1122334455667788, 777)
	if err := writeControl(tc, probe); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, maxFrame)
	for {
		p, ctrl, err := readFrame(tc, buf)
		if err != nil {
			t.Fatalf("no pong for our ping: %v", err)
		}
		if !ctrl || len(p) < probeHeader {
			continue
		}
		if p[0] == ctrlPing { // its verification probe: echo it
			pong := append([]byte(nil), p...)
			pong[0] = ctrlPong
			if err := writeControl(tc, pong); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if p[0] == ctrlPong && binary.BigEndian.Uint64(p[1:probeHeader]) == 0x1122334455667788 {
			if len(p) != len(probe) || string(p[probeHeader:]) != string(probe[probeHeader:]) {
				t.Fatal("the pong must echo the ping's padding unchanged")
			}
			return
		}
	}
}

func TestResetConnDropsOnlyTheConnection(t *testing.T) {
	a, b, _, _ := pair(t, 3, "", "", "shared-secret-1234", "shared-secret-1234")
	waitFor(t, 5*time.Second, "link up", func() bool { return a.Connected() && b.Connected() })
	a.mu.Lock()
	portBefore := a.listenPort
	a.mu.Unlock()

	if !a.ResetConn() {
		t.Fatal("ResetConn must report that it dropped a connection")
	}
	waitFor(t, 2*time.Second, "link dropped", func() bool { return !a.Connected() || !b.Connected() })
	waitFor(t, 6*time.Second, "link rebuilt", func() bool { return a.Connected() && b.Connected() })

	a.mu.Lock()
	portAfter := a.listenPort
	a.mu.Unlock()
	if portAfter != portBefore {
		t.Fatalf("ResetConn must keep the listener port (%d -> %d)", portBefore, portAfter)
	}
	if a.st.resets.Load() != 1 {
		t.Fatalf("reset counter = %d", a.st.resets.Load())
	}

	idle := newLink(testCfg("30000-30001", "9-9", "shared-secret-1234"), "z", testLog(), nil, nil)
	if idle.ResetConn() {
		t.Fatal("ResetConn with no connection must report false")
	}
}

func TestProbeSizes(t *testing.T) {
	for i := 0; i < 200; i++ {
		if sz := steadySize(); sz < 24 || sz > 600 {
			t.Fatalf("steady probe size %d out of range", sz)
		}
	}
	want := map[int]bool{148: true, 92: true, 32: true}
	for _, s := range verifyProbeSizes {
		delete(want, s)
		if s > maxFrame {
			t.Fatalf("probe size %d exceeds the frame limit", s)
		}
	}
	if len(want) != 0 {
		t.Fatalf("verification must probe WireGuard's fixed message sizes, missing %v", want)
	}
}

// A duplicate connection that loses the tie-break (or any connection closed while it is being verified) is
// not a verification failure and must not be counted or logged as one.
func TestClosedDuringVerificationIsNotAFailure(t *testing.T) {
	aRange, bRange := portBlock(1, 1)
	a := newLink(healthCfg(aRange, bRange), "a", testLog(), nil, nil)
	b := newLink(healthCfg(bRange, aRange), "b", testLog(), nil, nil)
	a.SetTargets([]string{"127.0.0.1"})
	b.SetTargets([]string{"127.0.0.1"})
	a.SetPrimary(true)
	b.SetPrimary(false)

	// Close every connection the moment it is installed, before verification can finish.
	setHook(a, func(c *conn) { c.close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, l := range []*Link{a, b} {
		if err := l.Start(ctx); err != nil {
			t.Fatal(err)
		}
		defer l.Stop()
	}
	time.Sleep(1200 * time.Millisecond)
	if got := a.st.verifyFails.Load(); got != 0 {
		t.Fatalf("a connection closed while being verified was counted as %d verification failures", got)
	}
}
