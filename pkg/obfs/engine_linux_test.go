//go:build linux

package obfs

import (
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"auto-wg/pkg/config"
	"auto-wg/pkg/iptables"
	"auto-wg/pkg/logger"
)

// The engine test needs root, iptables and NFQUEUE support, so it is skipped everywhere else.
func startEngine(t *testing.T, cfg config.ObfuscationConfig) (*Engine, *net.UDPConn, *net.UDPConn) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("iptables not installed")
	}
	log := logger.Default()
	ipt := iptables.NewManager(log)
	const queue = 4299
	e, err := NewEngine("test0", queue, cfg, log)
	if err != nil {
		t.Skipf("nfqueue unavailable: %v", err)
	}
	if err := ipt.ApplyQueueRules("test0", "24000-24010", queue); err != nil {
		e.Close()
		t.Skipf("cannot install NFQUEUE rules: %v", err)
	}
	t.Cleanup(func() {
		ipt.RemoveQueueRules("test0")
		e.Close()
	})

	recv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 25000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { recv.Close() })
	send, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 24000}, recv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { send.Close() })
	return e, send, recv
}

func drain(t *testing.T, c *net.UDPConn, wait time.Duration) [][]byte {
	t.Helper()
	var out [][]byte
	buf := make([]byte, 2048)
	for {
		_ = c.SetReadDeadline(time.Now().Add(wait))
		n, _, err := c.ReadFromUDP(buf)
		if err != nil {
			return out
		}
		out = append(out, append([]byte(nil), buf[:n]...))
	}
}

func TestEngineDecoysPrecedeHandshake(t *testing.T) {
	cfg := config.ObfuscationConfig{Enabled: true, Decoys: 3, DecoyMinSize: 50, DecoyMaxSize: 60}
	e, send, recv := startEngine(t, cfg)

	hs := handshakePayload(InitiationSize, 1)
	if _, err := send.Write(hs); err != nil {
		t.Fatal(err)
	}
	got := drain(t, recv, 500*time.Millisecond)
	if len(got) != 4 {
		t.Fatalf("expected 3 decoys + handshake, got %d packets", len(got))
	}
	for i := 0; i < 3; i++ {
		if len(got[i]) < 50 || len(got[i]) > 61 || got[i][0] <= 4 {
			t.Fatalf("packet %d is not a decoy (len %d, first byte %d)", i, len(got[i]), got[i][0])
		}
	}
	if string(got[3]) != string(hs) {
		t.Fatal("the real handshake must arrive last and unmodified")
	}
	if s := e.Status(); s.Handshakes != 1 || s.Decoys != 3 {
		t.Fatalf("unexpected counters: %+v", s)
	}

	// Anything that is not a handshake must pass untouched, even at the same size.
	data := handshakePayload(InitiationSize, 4)
	_, _ = send.Write(data)
	got = drain(t, recv, 300*time.Millisecond)
	if len(got) != 1 || string(got[0]) != string(data) {
		t.Fatalf("non-handshake packet was altered: %d packets", len(got))
	}
}

func TestEngineFragmentsHandshake(t *testing.T) {
	cfg := config.ObfuscationConfig{Enabled: true, Decoys: 1, DecoyMinSize: 50, DecoyMaxSize: 50, Fragment: true, FragmentSplit: 8}
	e, send, recv := startEngine(t, cfg)

	hs := handshakePayload(InitiationSize, 1)
	if _, err := send.Write(hs); err != nil {
		t.Fatal(err)
	}
	got := drain(t, recv, 500*time.Millisecond)
	if len(got) != 2 {
		t.Fatalf("expected decoy + reassembled handshake, got %d packets", len(got))
	}
	if string(got[1]) != string(hs) {
		t.Fatal("fragments did not reassemble into the original handshake")
	}
	if s := e.Status(); s.Fragmented != 1 {
		t.Fatalf("expected one fragmented handshake: %+v", s)
	}
}

func TestEngineDisabledPassesThrough(t *testing.T) {
	e, send, recv := startEngine(t, config.ObfuscationConfig{Enabled: true, Decoys: 3, DecoyMinSize: 50, DecoyMaxSize: 50})
	e.Update(config.ObfuscationConfig{Enabled: false})

	hs := handshakePayload(ResponseSize, 2)
	_, _ = send.Write(hs)
	got := drain(t, recv, 300*time.Millisecond)
	if len(got) != 1 || string(got[0]) != string(hs) {
		t.Fatalf("expected the bare handshake, got %d packets", len(got))
	}
}
