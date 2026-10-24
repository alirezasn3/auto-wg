package transport

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"auto-wg/pkg/config"
	"auto-wg/pkg/logger"
)

func testLog() *logger.Logger { return logger.New(io.Discard, logger.LevelDebug, 100) }

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// portBlock returns two non-overlapping TCP port ranges for the two peers of one test. Unit tests have no
// iptables REDIRECT mapping a whole range onto the listener, so the ranges are narrow: a dial only lands
// when the random remote port happens to be the listener's.
func portBlock(widthA, widthB int) (a, b string) {
	base := 20000 + rand.IntN(30000)
	return fmt.Sprintf("%d-%d", base, base+widthA-1), fmt.Sprintf("%d-%d", base+100, base+100+widthB-1)
}

func testCfg(local, remote, secret string) Options {
	return Options{
		Kind: config.TransportTLS, PortRange: local, RemotePortRange: remote,
		Link: config.LinkConfig{
			Secret: secret, DialInterval: 100 * time.Millisecond, Padding: "off",
			// Fast probes so stall detection takes a second or two in tests instead of tens of seconds.
			HealthInterval: 150 * time.Millisecond, HealthTimeout: 400 * time.Millisecond, HealthFailures: 3,
		},
	}
}

type recorder struct {
	mu   sync.Mutex
	pkts [][]byte
}

func (r *recorder) add(p []byte) {
	r.mu.Lock()
	r.pkts = append(r.pkts, append([]byte(nil), p...))
	r.mu.Unlock()
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pkts)
}

func (r *recorder) has(p string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, x := range r.pkts {
		if string(x) == p {
			return true
		}
	}
	return false
}

// pair starts two links on loopback. A dials into B's range and B into A's, unless a dial range is given
// as "9-9" (nothing listens there), which models a peer that cannot dial out.
func pair(t *testing.T, widthA int, aRemote, bRemote, secretA, secretB string) (a, b *Link, ra, rb *recorder) {
	t.Helper()
	aRange, bRange := portBlock(widthA, 1)
	if aRemote == "" {
		aRemote = bRange
	}
	if bRemote == "" {
		bRemote = aRange
	}
	ra, rb = &recorder{}, &recorder{}
	a = newLink(testCfg(aRange, aRemote, secretA), "a", testLog(), ra.add, nil)
	b = newLink(testCfg(bRange, bRemote, secretB), "b", testLog(), rb.add, nil)
	a.SetTargets([]string{"127.0.0.1"})
	b.SetTargets([]string{"127.0.0.1"})
	a.SetPrimary(true)
	b.SetPrimary(false)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		a.Stop()
		b.Stop()
	})
	if err := a.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return
}

func TestPreferNew(t *testing.T) {
	dialed := &conn{dialed: true}
	accepted := &conn{dialed: false}
	cases := []struct {
		name        string
		cur, nw     *conn
		primary, ok bool
		want        bool
	}{
		{"primary keeps its own dial over an accepted one", dialed, accepted, true, true, false},
		{"primary replaces an accepted conn with its own dial", accepted, dialed, true, true, true},
		{"secondary keeps the accepted conn", accepted, dialed, false, true, false},
		{"secondary replaces its own dial with the accepted one", dialed, accepted, false, true, true},
		{"same kind never replaces", dialed, dialed, true, true, false},
		{"unknown roles keep the existing connection", dialed, accepted, true, false, false},
	}
	for _, c := range cases {
		if got := preferNew(c.cur, c.nw, c.primary, c.ok); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestBothSidesDialAndTieBreakConverges(t *testing.T) {
	a, b, ra, rb := pair(t, 1, "", "", "shared-secret-1234", "shared-secret-1234")

	waitFor(t, 5*time.Second, "both links up", func() bool { return a.Connected() && b.Connected() })
	// Both peers dial constantly, so duplicates are expected; they must settle on one connection.
	time.Sleep(1500 * time.Millisecond)
	if !a.Connected() || !b.Connected() {
		t.Fatal("link must stay up once the duplicate is resolved")
	}
	// Whichever connection survived, both ends must be holding the same one: one side dialed it and the
	// other accepted it. (Which side dialed depends on who got in first; the primary-dialed preference only
	// decides between connections that are up at the same moment, see TestPreferNew.)
	ca, cb := a.active.Load(), b.active.Load()
	if ca.dialed == cb.dialed {
		t.Fatalf("the two peers hold different connections: a.dialed=%v b.dialed=%v", ca.dialed, cb.dialed)
	}

	if !a.Send([]byte("from-a")) || !b.Send([]byte("from-b")) {
		t.Fatal("send must be accepted while connected")
	}
	waitFor(t, 3*time.Second, "packets delivered", func() bool { return rb.has("from-a") && ra.has("from-b") })
}

func TestOnlyOneSideCanDial(t *testing.T) {
	// B cannot dial (nothing listens in its remote range); A's dial must be enough.
	a, b, _, _ := pair(t, 3, "", "9-9", "shared-secret-1234", "shared-secret-1234")
	waitFor(t, 5*time.Second, "link up through A's dial", func() bool { return a.Connected() && b.Connected() })
	if !a.active.Load().dialed || b.active.Load().dialed {
		t.Fatal("expected A to be the dialer")
	}
	// The dial must have used a source port from A's local range.
	_, portStr, _ := net.SplitHostPort(b.active.Load().remote)
	port, _ := strconv.Atoi(portStr)
	start, end, _ := config.ParsePortRange(a.opts.PortRange)
	if port < start || port > end {
		t.Fatalf("source port %d outside the local range %d-%d", port, start, end)
	}
}

func TestOtherSideCanDialToo(t *testing.T) {
	// Now A cannot dial; B's dial must be enough, which is the "both sides try" property.
	a, b, _, _ := pair(t, 1, "9-9", "", "shared-secret-1234", "shared-secret-1234")
	waitFor(t, 5*time.Second, "link up through B's dial", func() bool { return a.Connected() && b.Connected() })
	if a.active.Load().dialed || !b.active.Load().dialed {
		t.Fatal("expected B to be the dialer")
	}
}

func TestWrongSecretNeverConnects(t *testing.T) {
	a, b, _, _ := pair(t, 1, "", "", "shared-secret-1234", "different-secret-xyz")
	waitFor(t, 5*time.Second, "an authentication failure", func() bool {
		return a.st.authFails.Load()+b.st.authFails.Load() > 0
	})
	time.Sleep(500 * time.Millisecond)
	if a.Connected() || b.Connected() {
		t.Fatal("peers with different secrets must never get a link")
	}
	if sa := a.st.authFails.Load() + b.st.authFails.Load(); sa == 0 {
		t.Fatal("expected authentication failures to be counted")
	}
}

func TestReconnectRecovers(t *testing.T) {
	a, b, ra, rb := pair(t, 3, "", "", "shared-secret-1234", "shared-secret-1234")
	waitFor(t, 5*time.Second, "link up", func() bool { return a.Connected() && b.Connected() })

	a.Reconnect()
	waitFor(t, 2*time.Second, "link dropped", func() bool { return !a.Connected() || !b.Connected() })
	waitFor(t, 6*time.Second, "link back up", func() bool { return a.Connected() && b.Connected() })

	start, end, _ := config.ParsePortRange(a.opts.PortRange)
	a.mu.Lock()
	port := a.car.listenPort()
	a.mu.Unlock()
	if port < start || port > end {
		t.Fatalf("rotated listener port %d outside %d-%d", port, start, end)
	}

	a.Send([]byte("after-reconnect-a"))
	b.Send([]byte("after-reconnect-b"))
	waitFor(t, 3*time.Second, "traffic after reconnect", func() bool {
		return rb.has("after-reconnect-a") && ra.has("after-reconnect-b")
	})
}

func TestSendDropsWithoutLinkAndDownForTracks(t *testing.T) {
	aRange, _ := portBlock(3, 1)
	l := newLink(testCfg(aRange, "9-9", "shared-secret-1234"), "x", testLog(), nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := l.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer l.Stop()

	if l.Send([]byte("nobody listening")) {
		t.Fatal("Send must report a drop when no link is up")
	}
	time.Sleep(150 * time.Millisecond)
	if d := l.DownFor(); d < 100*time.Millisecond {
		t.Fatalf("DownFor should count from start while never connected, got %v", d)
	}
}

func TestPreAuthLimit(t *testing.T) {
	aRange, _ := portBlock(3, 1)
	l := newLink(testCfg(aRange, "9-9", "shared-secret-1234"), "x", testLog(), nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := l.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer l.Stop()

	l.mu.Lock()
	port := l.car.listenPort()
	l.mu.Unlock()

	// Hold maxPreAuth silent connections; the next one must be closed straight away.
	var held []net.Conn
	for i := 0; i < maxPreAuth; i++ {
		c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	time.Sleep(200 * time.Millisecond)

	extra, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	_ = extra.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := extra.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the extra pre-auth connection to be closed")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("the extra pre-auth connection was left open")
	}
}

// Both peers dialing each other at the same moment is the normal case when the tunnel comes up, so the
// tie-break must always leave both sides on the connection the primary peer dialed.
func TestSimultaneousDialsKeepThePrimaryDialedConnection(t *testing.T) {
	for i := 0; i < 15; i++ {
		aRange, bRange := portBlock(1, 1)
		// A huge dial interval and unreachable remote ranges keep the background dial loops out of the way;
		// the test makes the two dials itself.
		cfgA := testCfg(aRange, "9-9", "shared-secret-1234")
		cfgB := testCfg(bRange, "9-9", "shared-secret-1234")
		cfgA.Link.DialInterval, cfgB.Link.DialInterval = time.Hour, time.Hour
		a := newLink(cfgA, "a", testLog(), nil, nil)
		b := newLink(cfgB, "b", testLog(), nil, nil)
		a.SetPrimary(true)
		b.SetPrimary(false)
		ctx, cancel := context.WithCancel(context.Background())
		if err := a.Start(ctx); err != nil {
			t.Fatal(err)
		}
		if err := b.Start(ctx); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond) // let the loops' first (failing) attempts finish

		aPort, bPort := a.car.listenPort(), b.car.listenPort()

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); <-start; a.dialTo("127.0.0.1", bPort) }()
		go func() { defer wg.Done(); <-start; b.dialTo("127.0.0.1", aPort) }()
		close(start)
		wg.Wait()

		waitFor(t, 3*time.Second, "one connection on each side", func() bool { return a.Connected() && b.Connected() })
		time.Sleep(100 * time.Millisecond)
		ca, cb := a.active.Load(), b.active.Load()
		if ca == nil || cb == nil || !ca.dialed || cb.dialed {
			t.Fatalf("round %d: both sides must hold the connection A (primary) dialed: a=%+v b=%+v", i, ca != nil && ca.dialed, cb != nil && !cb.dialed)
		}
		cancel()
		a.Stop()
		b.Stop()
	}
}

func TestStopDoesNotWaitForHalfOpenHandshakes(t *testing.T) {
	aRange, _ := portBlock(3, 1)
	l := newLink(testCfg(aRange, "9-9", "shared-secret-1234"), "x", testLog(), nil, nil)
	if err := l.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	l.mu.Lock()
	port := l.car.listenPort()
	l.mu.Unlock()

	// A peer that connects and then says nothing sits in the TLS handshake for up to authTimeout.
	silent, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	time.Sleep(100 * time.Millisecond)

	done := make(chan struct{})
	go func() { l.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop waited for a half-open handshake")
	}
}

// Failed attempts leave TIME_WAIT sockets behind on their source port. With a small local range the dialer
// must keep using ports of that range anyway instead of falling back to ephemeral ports.
func TestDialKeepsUsingTheLocalRangeAfterTimeWait(t *testing.T) {
	// One remote listener per attempt, so every attempt has a different 4-tuple like it has with a random
	// remote port (a narrow local range cannot supply unique tuples towards a single remote port).
	var addrs []string
	for i := 0; i < 24; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() { _, _ = io.Copy(io.Discard, c); c.Close() }()
			}
		}()
		addrs = append(addrs, ln.Addr().String())
	}

	local, _ := portBlock(3, 1)
	l := newLink(testCfg(local, "9-9", "shared-secret-1234"), "x", testLog(), nil, nil)
	l.ctx = context.Background()
	start, end, _ := config.ParsePortRange(local)

	for i := 0; i < 24; i++ {
		c, err := l.dialTCP(addrs[i])
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		port := c.LocalAddr().(*net.TCPAddr).Port
		if port < start || port > end {
			c.Close()
			t.Fatalf("dial %d used source port %d outside the local range %d-%d", i, port, start, end)
		}
		c.Close() // the closing side keeps the port in TIME_WAIT
	}
}

// Padding changes only the bytes on the wire: probes, verification and packets still pass.
func TestPaddedLinksCarryTraffic(t *testing.T) {
	for _, mode := range []string{"bucket", "random"} {
		aRange, bRange := portBlock(1, 1)
		optsA, optsB := testCfg(aRange, bRange, "shared-secret-1234"), testCfg(bRange, aRange, "shared-secret-1234")
		optsA.Link.Padding, optsB.Link.Padding = mode, mode
		ra, rb := &recorder{}, &recorder{}
		a := newLink(optsA, "a", testLog(), ra.add, nil)
		b := newLink(optsB, "b", testLog(), rb.add, nil)
		a.SetTargets([]string{"127.0.0.1"})
		b.SetTargets([]string{"127.0.0.1"})
		a.SetPrimary(true)
		b.SetPrimary(false)
		ctx, cancel := context.WithCancel(context.Background())
		if err := a.Start(ctx); err != nil {
			t.Fatal(err)
		}
		if err := b.Start(ctx); err != nil {
			t.Fatal(err)
		}
		waitFor(t, 5*time.Second, mode+": links up", func() bool { return a.Connected() && b.Connected() })
		big := string(make([]byte, 1300))
		for i := 0; i < 20; i++ {
			a.Send([]byte("from-a"))
			b.Send([]byte(big))
		}
		waitFor(t, 3*time.Second, mode+": packets delivered", func() bool { return rb.has("from-a") && ra.has(big) })
		a.Stop()
		b.Stop()
		cancel()
	}
}
