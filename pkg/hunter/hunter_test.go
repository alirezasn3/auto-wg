package hunter

import (
	"io"
	"path/filepath"
	"testing"
	"time"

	"auto-wg/pkg/config"
	"auto-wg/pkg/iptables"
	"auto-wg/pkg/logger"
	"auto-wg/pkg/wg"
)

func TestHunterStatusReportAndConfigUpdate(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	cfg := &config.Config{
		WireGuard: config.WireGuardConfig{
			Interface: "wg0",
			Mode:      "cli",
			Command:   "wg",
		},
		Iptables: config.IptablesConfig{
			Enabled:   false,
			PortRange: "20000-30000",
		},
		Hunter: config.HunterConfig{
			RemotePortRange:  "20000-30000",
			CheckInterval:    3 * time.Second,
			HandshakeTimeout: 15 * time.Second,
			CycleTimeout:     8 * time.Second,
		},
		Web: config.WebConfig{
			Enabled:    true,
			ListenAddr: "127.0.0.1:8080",
		},
	}
	if err := config.SaveConfig(cfgPath, cfg); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	log := logger.New(io.Discard, logger.LevelDebug, 100)
	wgCtrl, _ := wg.NewController("cli", "wg", log)
	iptMgr := iptables.NewManager(log)

	h := New(cfgPath, cfg, wgCtrl, iptMgr, log)

	status := h.GetStatus()
	if status.Interface != "wg0" {
		t.Errorf("Expected interface wg0, got %s", status.Interface)
	}
	if status.State != StateUnknown {
		t.Errorf("Expected initial state %s, got %s", StateUnknown, status.State)
	}

	// Test update config
	newCfg := *cfg
	newCfg.Hunter.HandshakeTimeout = 40 * time.Second
	if err := h.UpdateConfig(&newCfg); err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	readBack := h.GetConfig()
	if readBack.Hunter.HandshakeTimeout != 40*time.Second {
		t.Errorf("Expected updated timeout 40s, got %v", readBack.Hunter.HandshakeTimeout)
	}

	newCfg.Hunter.TunnelPing.TargetIP = "10.0.0.5"
	if err := h.UpdateConfig(&newCfg); err != nil {
		t.Fatalf("UpdateConfig with TargetIP failed: %v", err)
	}

	readBack = h.GetConfig()
	if readBack.Hunter.TunnelPing.TargetIP != "10.0.0.5" {
		t.Errorf("Expected updated TargetIP 10.0.0.5, got %s", readBack.Hunter.TunnelPing.TargetIP)
	}
}

func TestHunterEventsAndDirection(t *testing.T) {
	log := logger.New(io.Discard, logger.LevelDebug, 100)
	wgCtrl, _ := wg.NewController("cli", "wg", log)
	iptMgr := iptables.NewManager(log)
	cfg := &config.Config{
		WireGuard: config.WireGuardConfig{Interface: "wg0"},
	}
	h := New("", cfg, wgCtrl, iptMgr, log)
	h.localPubKey = "AAAA"
	h.peerPubKey = "BBBB"

	// 1. Initial State
	st := h.GetStatus()
	if st.LastDirection != "Peer A ⇄ Peer B" {
		t.Errorf("expected default direction 'Peer A ⇄ Peer B', got %q", st.LastDirection)
	}
	if len(st.Events) != 0 {
		t.Errorf("expected 0 events, got %d", len(st.Events))
	}

	// 2. Local is Peer A (isPrimary = true)
	// Case A: Local dialed the remote port recently -> Peer A -> Peer B
	h.lastDialedRemotePort = 25000
	h.lastDialedAt = time.Now()
	dir, init := h.determineDirection(true, 25000)
	if dir != "Peer A → Peer B" || init != "Peer A" {
		t.Errorf("expected Peer A → Peer B (init Peer A), got %s (init %s)", dir, init)
	}

	// Case B: Remote initiated (different port or not dialed recently) -> Peer B -> Peer A
	dir, init = h.determineDirection(true, 26000)
	if dir != "Peer B → Peer A" || init != "Peer B" {
		t.Errorf("expected Peer B → Peer A (init Peer B), got %s (init %s)", dir, init)
	}

	// 3. Local is Peer B (isPrimary = false)
	// Case C: Local dialed the remote port recently -> Peer B -> Peer A
	dir, init = h.determineDirection(false, 25000)
	if dir != "Peer B → Peer A" || init != "Peer B" {
		t.Errorf("expected Peer B → Peer A (init Peer B), got %s (init %s)", dir, init)
	}

	// Case D: Remote initiated -> Peer A -> Peer B
	dir, init = h.determineDirection(false, 26000)
	if dir != "Peer A → Peer B" || init != "Peer A" {
		t.Errorf("expected Peer A → Peer B (init Peer A), got %s (init %s)", dir, init)
	}

	// 4. Test addEvent and cap at 50
	for i := 0; i < 60; i++ {
		h.addEvent(StateConnected, "Peer A → Peer B", "Peer A", "test", float64(i))
	}
	st = h.GetStatus()
	if len(st.Events) != 50 {
		t.Errorf("expected events capped at 50, got %d", len(st.Events))
	}
	// Most recent event is at index 0
	if st.Events[0].DurationSec != 59 {
		t.Errorf("expected newest event duration 59, got %v", st.Events[0].DurationSec)
	}
}
