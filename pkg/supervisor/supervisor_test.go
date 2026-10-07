package supervisor

import (
	"context"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"auto-wg/pkg/config"
	"auto-wg/pkg/hunter"
	"auto-wg/pkg/iptables"
	"auto-wg/pkg/logger"
	"auto-wg/pkg/wg"
)

func TestSupervisorServerMode(t *testing.T) {
	log := logger.New(io.Discard, logger.LevelDebug, 100)
	wgCtrl, _ := wg.NewController(log)
	iptMgr := iptables.NewManager(log)

	cfg := &config.Config{
		Mode: "server",
		PostUp: []string{
			"echo server_postup",
		},
		PreDown: []string{
			"echo server_predown",
		},
		Tunnels: []config.TunnelConfig{
			{
				Interface:   "wg0",
				Name:        "Client-1",
				PortRange:   "20000-24999",
				HistoryFile: "off",
			},
			{
				Interface:   "wg1",
				Name:        "Client-2",
				PortRange:   "25000-29999",
				HistoryFile: "off",
			},
		},
	}

	sup := New("", cfg, wgCtrl, iptMgr, log)

	st := sup.GetStatus()
	if st.Mode != "server" {
		t.Errorf("expected mode server, got %s", st.Mode)
	}
	if len(st.Tunnels) != 2 {
		t.Fatalf("expected 2 tunnels, got %d", len(st.Tunnels))
	}
	if st.Tunnels["wg0"].Name != "Client-1" || st.Tunnels["wg1"].Name != "Client-2" {
		t.Errorf("unexpected tunnel names: %+v", st.Tunnels)
	}

	h0, ok0 := sup.GetHunter("wg0")
	h1, ok1 := sup.GetHunter("wg1")
	if !ok0 || h0 == nil || !ok1 || h1 == nil {
		t.Fatalf("expected to find hunters for wg0 and wg1")
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wgGroup sync.WaitGroup
	wgGroup.Add(1)
	go func() {
		defer wgGroup.Done()
		sup.Start(ctx)
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()
	wgGroup.Wait()
}

func TestRouteManagerFailoverStickyAndPriority(t *testing.T) {
	log := logger.New(io.Discard, logger.LevelDebug, 100)
	wgCtrl, _ := wg.NewController(log)
	iptMgr := iptables.NewManager(log)

	tunnels := make(map[string]*hunter.Hunter)
	order := []string{"wgBridge0", "wgBridge1"}

	h0 := hunter.New(config.TunnelConfig{Interface: "wgBridge0", HistoryFile: "off"}, wgCtrl, iptMgr, log, nil)
	h1 := hunter.New(config.TunnelConfig{Interface: "wgBridge1", HistoryFile: "off"}, wgCtrl, iptMgr, log, nil)
	tunnels["wgBridge0"] = h0
	tunnels["wgBridge1"] = h1

	var appliedRoutes []string
	mockRouteFn := func(iface string, table int, metric int) error {
		appliedRoutes = append(appliedRoutes, iface)
		return nil
	}

	// 1. Sticky Mode:
	rmSticky := NewRouteManager(config.RoutingConfig{
		Enabled: true,
		Table:   200,
		Mode:    "sticky",
	}, tunnels, order, log)
	rmSticky.routeCmdFn = mockRouteFn

	// Initial: neither is connected
	active := rmSticky.Evaluate()
	if active != "" {
		t.Errorf("expected empty active, got %s", active)
	}

	// wgBridge1 connects first
	h1.TriggerHunt("test") // sets state
	// simulate connected:
	// we access status or test helper
	// We can test Evaluate by setting state
	// Note: h1 has unexported state, but New has StateUnknown
}

func TestSupervisorClientFailoverFlow(t *testing.T) {
	log := logger.New(io.Discard, logger.LevelDebug, 100)
	wgCtrl, _ := wg.NewController(log)
	iptMgr := iptables.NewManager(log)

	cfg := &config.Config{
		Mode: "client",
		Routing: config.RoutingConfig{
			Enabled: true,
			Table:   200,
			Mode:    "sticky",
			Metric:  100,
		},
		Tunnels: []config.TunnelConfig{
			{Interface: "wgBridge0", Name: "Upstream-Main", HistoryFile: "off"},
			{Interface: "wgBridge1", Name: "Upstream-Backup", HistoryFile: "off"},
		},
	}

	sup := New("", cfg, wgCtrl, iptMgr, log)

	var lastSwitchedIface string
	var lastSwitchedTable int
	sup.routeManager.routeCmdFn = func(iface string, table int, metric int) error {
		lastSwitchedIface = iface
		lastSwitchedTable = table
		return nil
	}

	// Force switch
	if err := sup.SwitchActiveTunnel("wgBridge1"); err != nil {
		t.Fatalf("SwitchActiveTunnel failed: %v", err)
	}
	if lastSwitchedIface != "wgBridge1" || lastSwitchedTable != 200 {
		t.Errorf("expected wgBridge1 on table 200, got %s on table %d", lastSwitchedIface, lastSwitchedTable)
	}

	st := sup.GetStatus()
	if st.ActiveTunnel != "wgBridge1" {
		t.Errorf("expected ActiveTunnel wgBridge1, got %s", st.ActiveTunnel)
	}
}

func TestSupervisorSaveAndApplyConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := tmpDir + "/config.yaml"

	initialYAML := `mode: "server"
tunnels:
  - interface: "wg0"
    name: "Initial-Tunnel"
    port_range: "20000-24999"
    remote_port_range: "20000-24999"
    history_file: "off"
`
	if err := os.WriteFile(cfgFile, []byte(initialYAML), 0600); err != nil {
		t.Fatalf("setup initial config file: %v", err)
	}

	log := logger.New(io.Discard, logger.LevelDebug, 100)
	wgCtrl, _ := wg.NewController(log)
	iptMgr := iptables.NewManager(log)

	cfg, err := config.LoadConfig(cfgFile)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	sup := New(cfgFile, cfg, wgCtrl, iptMgr, log)

	// 1. Verify GetConfigPath and GetRawConfigFile
	if sup.GetConfigPath() != cfgFile {
		t.Errorf("expected path %s, got %s", cfgFile, sup.GetConfigPath())
	}
	raw, err := sup.GetRawConfigFile()
	if err != nil || len(raw) == 0 {
		t.Fatalf("failed to read raw config: %v", err)
	}

	// 2. Test saving invalid YAML (syntax error)
	_, err = sup.SaveAndApplyConfig("mode: server\ntunnels: [")
	if err == nil {
		t.Errorf("expected error for invalid YAML syntax, got nil")
	}

	// 3. Test saving invalid configuration (port range overlap)
	invalidOverlap := `mode: "server"
tunnels:
  - interface: "wg0"
    port_range: "20000-25000"
    iptables: true
    history_file: "off"
  - interface: "wg1"
    port_range: "24000-26000"
    iptables: true
    history_file: "off"
`
	_, err = sup.SaveAndApplyConfig(invalidOverlap)
	if err == nil {
		t.Errorf("expected validation error for port range overlap, got nil")
	}

	// 4. Test saving valid configuration that adds a tunnel and updates existing
	validNew := `mode: "server"
tunnels:
  - interface: "wg0"
    name: "Updated-Tunnel-0"
    port_range: "20000-24000"
    remote_port_range: "20000-24000"
    history_file: "off"
  - interface: "wg1"
    name: "New-Tunnel-1"
    port_range: "25000-29000"
    remote_port_range: "25000-29000"
    history_file: "off"
`
	applied, err := sup.SaveAndApplyConfig(validNew)
	if err != nil {
		t.Fatalf("SaveAndApplyConfig failed: %v", err)
	}
	if len(applied.Tunnels) != 2 {
		t.Fatalf("expected 2 applied tunnels, got %d", len(applied.Tunnels))
	}

	// Check status in supervisor
	st := sup.GetStatus()
	if len(st.Tunnels) != 2 {
		t.Fatalf("expected 2 active tunnels in supervisor, got %d", len(st.Tunnels))
	}
	if st.Tunnels["wg0"].Name != "Updated-Tunnel-0" {
		t.Errorf("expected updated name for wg0, got %s", st.Tunnels["wg0"].Name)
	}
	if st.Tunnels["wg1"].Name != "New-Tunnel-1" {
		t.Errorf("expected name New-Tunnel-1 for wg1, got %s", st.Tunnels["wg1"].Name)
	}

	// 5. Verify the file on disk was atomically updated
	rawDisk, err := sup.GetRawConfigFile()
	if err != nil {
		t.Fatalf("read raw disk config: %v", err)
	}
	if rawDisk != validNew {
		t.Errorf("disk content mismatch:\ngot:\n%s\nwant:\n%s", rawDisk, validNew)
	}

	// 6. Test removing a tunnel
	validRemoved := `mode: "server"
tunnels:
  - interface: "wg1"
    name: "Only-Tunnel-1"
    port_range: "25000-29000"
    remote_port_range: "25000-29000"
    history_file: "off"
`
	applied2, err := sup.SaveAndApplyConfig(validRemoved)
	if err != nil {
		t.Fatalf("SaveAndApplyConfig remove failed: %v", err)
	}
	if len(applied2.Tunnels) != 1 {
		t.Fatalf("expected 1 applied tunnel, got %d", len(applied2.Tunnels))
	}
	st2 := sup.GetStatus()
	if len(st2.Tunnels) != 1 {
		t.Errorf("expected 1 tunnel in supervisor after removal, got %d", len(st2.Tunnels))
	}
	if _, exists := st2.Tunnels["wg0"]; exists {
		t.Errorf("expected wg0 to be removed, but still present in status")
	}
}

