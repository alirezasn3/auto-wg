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
	if st.LastDirection != "Local ⇄ Remote" {
		t.Errorf("expected default direction 'Local ⇄ Remote', got %q", st.LastDirection)
	}
	if len(st.Events) != 0 {
		t.Errorf("expected 0 events, got %d", len(st.Events))
	}

	// 2. Case A: Local dialed the remote port recently -> Local -> Remote
	h.lastDialedRemotePort = 25000
	h.lastDialedAt = time.Now()
	dir, init := h.determineDirection(25000)
	if dir != "Local → Remote" || init != "Local Host" {
		t.Errorf("expected Local → Remote (init Local Host), got %s (init %s)", dir, init)
	}

	// 3. Case B: Remote initiated (different port or not dialed recently) -> Remote -> Local
	dir, init = h.determineDirection(26000)
	if dir != "Remote → Local" || init != "Remote Peer" {
		t.Errorf("expected Remote → Local (init Remote Peer), got %s (init %s)", dir, init)
	}

	// 4. Test addEvent and cap at 50
	for i := 0; i < 60; i++ {
		h.addEvent(StateConnected, "Local → Remote", "Local Host", "test", float64(i))
	}
	st = h.GetStatus()
	if len(st.Events) != 50 {
		t.Errorf("expected events capped at 50, got %d", len(st.Events))
	}
	// Most recent event is at index 0
	if st.Events[0].DurationSec != 59 {
		t.Errorf("expected newest event duration 59, got %v", st.Events[0].DurationSec)
	}
	if st.Events[0].LocalRole != "Primary" {
		t.Errorf("expected LocalRole Primary, got %s", st.Events[0].LocalRole)
	}
}

func TestHunterHistoryPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	histFile := filepath.Join(tmpDir, "history.json")

	log := logger.New(io.Discard, logger.LevelDebug, 100)
	wgCtrl, _ := wg.NewController("cli", "wg", log)
	iptMgr := iptables.NewManager(log)

	cfg := &config.Config{
		WireGuard: config.WireGuardConfig{Interface: "wg0"},
		Hunter: config.HunterConfig{
			HistoryFile: histFile,
		},
	}

	// Instance 1: Generate some events and stats
	h1 := New("", cfg, wgCtrl, iptMgr, log)
	h1.localPubKey = "PEER_A"
	h1.peerPubKey = "PEER_B"
	connectedTime := time.Now().Add(-2 * time.Hour)
	h1.mu.Lock()
	h1.lastConnectedAt = connectedTime
	h1.totalHunts = 12
	h1.successfulHunts = 9
	h1.mu.Unlock()

	h1.addEvent(StateConnected, "Local → Remote", "Local Host", "test conn 1", 30.5)
	h1.addEvent(StateDisconnected, "Local → Remote", "Local Host", "test disc 1", 3600.0)

	if err := h1.SaveHistory(); err != nil {
		t.Fatalf("SaveHistory failed: %v", err)
	}

	// Instance 2: Start new hunter with same config and history file
	h2 := New("", cfg, wgCtrl, iptMgr, log)
	st2 := h2.GetStatus()

	if st2.TotalHunts != 12 {
		t.Errorf("expected TotalHunts 12, got %d", st2.TotalHunts)
	}
	if st2.SuccessfulHunts != 9 {
		t.Errorf("expected SuccessfulHunts 9, got %d", st2.SuccessfulHunts)
	}
	if st2.LastConnectedAt.Unix() != connectedTime.Unix() {
		t.Errorf("expected LastConnectedAt %v, got %v", connectedTime, st2.LastConnectedAt)
	}
	if len(st2.Events) != 2 {
		t.Fatalf("expected 2 events restored, got %d", len(st2.Events))
	}
	if st2.Events[0].Type != StateDisconnected || st2.Events[1].Type != StateConnected {
		t.Errorf("unexpected restored events order or types: %+v", st2.Events)
	}

	// Add event on instance 2 to verify nextEventID doesn't clash
	h2.addEvent(StateConnected, "Remote → Local", "Remote Peer", "reconnected", 15.0)
	st2Updated := h2.GetStatus()
	if len(st2Updated.Events) != 3 {
		t.Fatalf("expected 3 events after adding new one, got %d", len(st2Updated.Events))
	}
	if st2Updated.Events[0].ID <= st2Updated.Events[1].ID {
		t.Errorf("expected new event ID %d > previous event ID %d", st2Updated.Events[0].ID, st2Updated.Events[1].ID)
	}
}

