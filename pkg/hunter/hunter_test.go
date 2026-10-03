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
}
