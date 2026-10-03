package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParsePortRange(t *testing.T) {
	tests := []struct {
		input     string
		wantStart int
		wantEnd   int
		wantErr   bool
	}{
		{"20000-30000", 20000, 30000, false},
		{"20000:30000", 20000, 30000, false},
		{" 1000 - 2000 ", 1000, 2000, false},
		{"50000-40000", 0, 0, true},
		{"invalid", 0, 0, true},
		{"0-100", 0, 0, true},
		{"100-70000", 0, 0, true},
	}

	for _, tt := range tests {
		s, e, err := ParsePortRange(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParsePortRange(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && (s != tt.wantStart || e != tt.wantEnd) {
			t.Errorf("ParsePortRange(%q) = (%d, %d), expected (%d, %d)", tt.input, s, e, tt.wantStart, tt.wantEnd)
		}
	}
}

func TestPickRandomPort(t *testing.T) {
	for i := 0; i < 50; i++ {
		port, err := PickRandomPort("20000-20010")
		if err != nil {
			t.Fatalf("PickRandomPort failed: %v", err)
		}
		if port < 20000 || port > 20010 {
			t.Errorf("PickRandomPort out of bounds: %d", port)
		}
	}
}

func TestLoadAndSaveConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	initialYAML := `
wireguard:
  interface: "wg1"
iptables:
  enabled: true
  port_range: "25000-35000"
hunter:
  remote_port_range: "25000-35000"
  handshake_timeout: 20s
web:
  listen_addr: "127.0.0.1:9090"
`
	if err := os.WriteFile(configPath, []byte(initialYAML), 0644); err != nil {
		t.Fatalf("Write test config: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.WireGuard.Interface != "wg1" {
		t.Errorf("Expected interface wg1, got %s", cfg.WireGuard.Interface)
	}
	if cfg.Hunter.HandshakeTimeout != 20*time.Second {
		t.Errorf("Expected handshake_timeout 20s, got %v", cfg.Hunter.HandshakeTimeout)
	}
	// Check defaults
	if cfg.WireGuard.Mode != "wgctrl" {
		t.Errorf("Expected default mode wgctrl, got %s", cfg.WireGuard.Mode)
	}

	// Test modifying and saving
	cfg.Hunter.HandshakeTimeout = 30 * time.Second
	if err := SaveConfig(configPath, cfg); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	reloaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Reload config failed: %v", err)
	}
	if reloaded.Hunter.HandshakeTimeout != 30*time.Second {
		t.Errorf("Expected reloaded handshake_timeout 30s, got %v", reloaded.Hunter.HandshakeTimeout)
	}
}
