package tlstun

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

// wgSocket stands in for a WireGuard listen socket on loopback.
func wgSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func udpPort(c *net.UDPConn) int { return c.LocalAddr().(*net.UDPAddr).Port }

func TestRelayEndToEnd(t *testing.T) {
	wgA, wgB := wgSocket(t), wgSocket(t)
	aRange, bRange := portBlock(1, 1)

	ta := New(testCfg(aRange, bRange, "shared-secret-1234"), Deps{Log: testLog(), Iface: "a", WGPort: func() int { return udpPort(wgA) }})
	tb := New(testCfg(bRange, aRange, "shared-secret-1234"), Deps{Log: testLog(), Iface: "b", WGPort: func() int { return udpPort(wgB) }})
	ta.SetTargets([]string{"127.0.0.1"})
	tb.SetTargets([]string{"127.0.0.1"})
	ta.SetPrimary(true)
	tb.SetPrimary(false)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := ta.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer ta.Stop()
	if err := tb.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer tb.Stop()

	if ta.RelayAddr().Addr() != netip.MustParseAddr("127.0.0.1") || ta.RelayAddr().Port() == 0 {
		t.Fatalf("bad relay address %v", ta.RelayAddr())
	}

	// Before the link is up a packet is simply lost, like on a dead UDP path.
	_, _ = wgA.WriteToUDP([]byte("lost"), net.UDPAddrFromAddrPort(ta.RelayAddr()))

	waitFor(t, 5*time.Second, "TLS link", func() bool { return ta.Connected() && tb.Connected() })

	// WireGuard A -> relay A -> TLS -> relay B -> WireGuard B. WireGuard B must see the packet coming
	// from relay B's address, which is what makes its endpoint roam onto the relay.
	want := []byte("wireguard handshake bytes")
	if _, err := wgA.WriteToUDP(want, net.UDPAddrFromAddrPort(ta.RelayAddr())); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	_ = wgB.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, from, err := wgB.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(want) {
		t.Fatalf("payload corrupted: %q", buf[:n])
	}
	if from != tb.RelayAddr() {
		t.Fatalf("WireGuard B saw the packet from %v, want relay B %v", from, tb.RelayAddr())
	}

	// And back, using the reply path that WireGuard B would take.
	if _, err := wgB.WriteToUDP([]byte("reply"), net.UDPAddrFromAddrPort(tb.RelayAddr())); err != nil {
		t.Fatal(err)
	}
	_ = wgA.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, from, err = wgA.ReadFromUDPAddrPort(buf)
	if err != nil || string(buf[:n]) != "reply" || from != ta.RelayAddr() {
		t.Fatalf("reply: n=%d from=%v err=%v", n, from, err)
	}

	st := ta.Status()
	if !st.Connected || st.PacketsTx == 0 || st.PacketsRx == 0 || st.RelayPort != int(ta.RelayAddr().Port()) || st.ListenPort == 0 {
		t.Fatalf("status does not reflect the traffic: %+v", st)
	}
}

func TestRelayPortAvoidsRanges(t *testing.T) {
	for i := 0; i < 20; i++ {
		r, err := newRelay(0, []string{"40000-44999"}, func() int { return 0 }, func([]byte) bool { return true })
		if err != nil {
			t.Fatal(err)
		}
		if r.port < 45000 || r.port > 49999 {
			t.Fatalf("relay port %d inside the avoided range", r.port)
		}
		r.close()
	}
}

func TestStopIsClean(t *testing.T) {
	aRange, bRange := portBlock(1, 1)
	tn := New(testCfg(aRange, bRange, "shared-secret-1234"), Deps{Log: testLog(), Iface: "x"})
	if err := tn.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { tn.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop hung")
	}
}
