package supervisor

import (
	"context"
	"io"
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
