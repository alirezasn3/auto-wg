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

func TestHunterStatusReportAndBasics(t *testing.T) {
	log := logger.New(io.Discard, logger.LevelDebug, 100)
	wgCtrl, _ := wg.NewController(log)
	iptMgr := iptables.NewManager(log)

	tunnelCfg := config.TunnelConfig{
		Interface:        "wg0",
		Name:             "Client-A",
		PortRange:        "20000-30000",
		RemotePortRange:  "20000-30000",
		CheckInterval:    3 * time.Second,
		HandshakeTimeout: 15 * time.Second,
		CycleTimeout:     8 * time.Second,
		HistoryFile:      "off",
	}

	var stateChanges []string
	handler := func(h *Hunter, oldState, newState string) {
		stateChanges = append(stateChanges, newState)
	}

	h := New(tunnelCfg, wgCtrl, iptMgr, log, handler)

	status := h.GetStatus()
	if status.Interface != "wg0" {
		t.Errorf("Expected interface wg0, got %s", status.Interface)
	}
	if status.Name != "Client-A" {
		t.Errorf("Expected name Client-A, got %s", status.Name)
	}
	if status.State != StateUnknown {
		t.Errorf("Expected initial state %s, got %s", StateUnknown, status.State)
	}

	h.setState(StateConnected)
	time.Sleep(10 * time.Millisecond) // wait for async state callback
	if h.GetState() != StateConnected {
		t.Errorf("Expected state %s, got %s", StateConnected, h.GetState())
	}
	if len(stateChanges) == 0 || stateChanges[len(stateChanges)-1] != StateConnected {
		t.Errorf("Expected stateChange event CONNECTED, got: %v", stateChanges)
	}
}

func TestHunterEventsAndDirection(t *testing.T) {
	log := logger.New(io.Discard, logger.LevelDebug, 100)
	wgCtrl, _ := wg.NewController(log)
	iptMgr := iptables.NewManager(log)
	tunnelCfg := config.TunnelConfig{
		Interface:   "wg0",
		HistoryFile: "off",
	}
	h := New(tunnelCfg, wgCtrl, iptMgr, log, nil)
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
	wgCtrl, _ := wg.NewController(log)
	iptMgr := iptables.NewManager(log)

	tunnelCfg := config.TunnelConfig{
		Interface:   "wg0",
		HistoryFile: histFile,
	}

	// Instance 1: Generate some events and stats
	h1 := New(tunnelCfg, wgCtrl, iptMgr, log, nil)
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

	// Instance 2: Start new hunter with same history file
	h2 := New(tunnelCfg, wgCtrl, iptMgr, log, nil)
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

func TestHunterMultiDestinationRotation(t *testing.T) {
	log := logger.New(io.Discard, logger.LevelDebug, 100)
	wgCtrl, _ := wg.NewController(log)
	iptMgr := iptables.NewManager(log)

	tunnelCfg := config.TunnelConfig{
		Interface:       "wg0",
		TargetIPs:       []string{"198.51.100.1", "2001:db8::1"},
		PortRange:       "20000-21000",
		RemotePortRange: "20000-21000",
		HistoryFile:     "off",
	}

	h := New(tunnelCfg, wgCtrl, iptMgr, log, nil)

	st0 := h.GetStatus()
	if st0.TargetIP != "198.51.100.1" {
		t.Errorf("expected initial TargetIP 198.51.100.1, got %s", st0.TargetIP)
	}
	if len(st0.TargetIPs) != 2 || st0.TargetIPs[0] != "198.51.100.1" || st0.TargetIPs[1] != "2001:db8::1" {
		t.Errorf("unexpected TargetIPs in StatusReport: %v", st0.TargetIPs)
	}

	// 1st Hunt -> Should rotate to IPv6 (2001:db8::1)
	h.executeHunt("dpi_drop_ipv4")
	st1 := h.GetStatus()
	if st1.TargetIP != "2001:db8::1" {
		t.Errorf("expected TargetIP after 1st hunt to be 2001:db8::1, got %s", st1.TargetIP)
	}
	if st1.TotalHunts != 1 {
		t.Errorf("expected TotalHunts 1, got %d", st1.TotalHunts)
	}

	// 2nd Hunt -> Should rotate back to IPv4 (198.51.100.1)
	h.executeHunt("dpi_drop_ipv6")
	st2 := h.GetStatus()
	if st2.TargetIP != "198.51.100.1" {
		t.Errorf("expected TargetIP after 2nd hunt to be 198.51.100.1, got %s", st2.TargetIP)
	}
	if st2.TotalHunts != 2 {
		t.Errorf("expected TotalHunts 2, got %d", st2.TotalHunts)
	}

	// 3rd Hunt -> Should rotate to IPv6 again (2001:db8::1)
	h.executeHunt("handshake_expired")
	st3 := h.GetStatus()
	if st3.TargetIP != "2001:db8::1" {
		t.Errorf("expected TargetIP after 3rd hunt to be 2001:db8::1, got %s", st3.TargetIP)
	}
}

func TestServerModeBidirectionalHuntingWithoutNAT(t *testing.T) {
	log := logger.New(io.Discard, logger.LevelDebug, 100)
	wgCtrl, _ := wg.NewController(log)
	iptMgr := iptables.NewManager(log)

	// Server config with client's public IPv4 and IPv6
	serverTunnelCfg := config.TunnelConfig{
		Interface:       "wg0",
		Name:            "Client-Alpha",
		TargetIPs:       []string{"203.0.113.10", "2001:db8::10"},
		PortRange:       "20000-24999",
		RemotePortRange: "20000-24999",
		HistoryFile:     "off",
	}

	h := New(serverTunnelCfg, wgCtrl, iptMgr, log, nil)

	// Verify server knows client's candidate target IPs initially
	st := h.GetStatus()
	if st.TargetIP != "203.0.113.10" {
		t.Errorf("expected initial TargetIP 203.0.113.10, got %s", st.TargetIP)
	}

	// Server initiates hunt when link is dead
	h.executeHunt("no_handshake_ever")
	st1 := h.GetStatus()
	if st1.TargetIP != "2001:db8::10" {
		t.Errorf("expected TargetIP after 1st hunt to be 2001:db8::10, got %s", st1.TargetIP)
	}

	// Server rotates back to IPv4 on next hunt
	h.executeHunt("handshake_expired")
	st2 := h.GetStatus()
	if st2.TargetIP != "203.0.113.10" {
		t.Errorf("expected TargetIP after 2nd hunt to be 203.0.113.10, got %s", st2.TargetIP)
	}
}

func TestPassiveTunnelNoHunting(t *testing.T) {
	log := logger.New(io.Discard, logger.LevelDebug, 100)
	wgCtrl, _ := wg.NewController(log)
	iptMgr := iptables.NewManager(log)

	tunnelCfg := config.TunnelConfig{
		Interface:   "wg-mikrotik",
		Passive:     true,
		HistoryFile: "off",
	}

	h := New(tunnelCfg, wgCtrl, iptMgr, log, nil)
	if h.huntingEnabled {
		t.Fatalf("expected huntingEnabled to be false for passive tunnel")
	}

	st := h.GetStatus()
	if st.Hunting {
		t.Errorf("expected Hunting to be false in StatusReport")
	}

	// Trigger hunt should be rejected
	h.TriggerHunt("manual_test")
	if h.totalHunts != 0 {
		t.Errorf("expected 0 hunts on passive tunnel, got %d", h.totalHunts)
	}

	// Trigger rebind should return error
	if err := h.TriggerRebind(); err == nil {
		t.Errorf("expected error from TriggerRebind on passive tunnel, got nil")
	}
}



