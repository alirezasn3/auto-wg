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

func TestLoadAndSaveConfigMultiTunnel(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	initialYAML := `
mode: "server"
post_up:
  - "echo postup global"
pre_down:
  - "echo predown global"
tunnels:
  - interface: "wg0"
    name: "Client-A"
    port_range: "20000-24999"
    remote_port_range: "20000-24999"
    handshake_timeout: 20s
    iptables: true
  - interface: "wg1"
    name: "Client-B"
    port_range: "25000-29999"
    remote_port_range: "25000-29999"
    iptables: true
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

	if cfg.Mode != "server" {
		t.Errorf("Expected mode server, got %s", cfg.Mode)
	}
	if len(cfg.Tunnels) != 2 {
		t.Fatalf("Expected 2 tunnels, got %d", len(cfg.Tunnels))
	}
	if cfg.Tunnels[0].Interface != "wg0" || cfg.Tunnels[1].Interface != "wg1" {
		t.Errorf("Unexpected tunnel interfaces: %+v", cfg.Tunnels)
	}
	if cfg.Tunnels[0].HandshakeTimeout != 20*time.Second {
		t.Errorf("Expected handshake_timeout 20s, got %v", cfg.Tunnels[0].HandshakeTimeout)
	}
	if len(cfg.PostUp) != 1 || cfg.PostUp[0] != "echo postup global" {
		t.Errorf("Unexpected PostUp: %+v", cfg.PostUp)
	}

	// Test modifying and saving
	cfg.Tunnels[0].HandshakeTimeout = 35 * time.Second
	if err := SaveConfig(configPath, cfg); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	reloaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Reload config failed: %v", err)
	}
	if reloaded.Tunnels[0].HandshakeTimeout != 35*time.Second {
		t.Errorf("Expected reloaded handshake_timeout 35s, got %v", reloaded.Tunnels[0].HandshakeTimeout)
	}
}

func TestValidatePortOverlap(t *testing.T) {
	cfg := &Config{
		Mode: "server",
		Tunnels: []TunnelConfig{
			{Interface: "wg0", PortRange: "20000-25000", Iptables: true},
			{Interface: "wg1", PortRange: "24000-28000", Iptables: true}, // overlaps 24000-25000!
		},
	}
	err := Validate(cfg)
	if err == nil {
		t.Fatalf("expected validation error for overlapping port ranges, got nil")
	}
}

func TestValidateDuplicateInterface(t *testing.T) {
	cfg := &Config{
		Mode: "server",
		Tunnels: []TunnelConfig{
			{Interface: "wg0", PortRange: "20000-24999", Iptables: true},
			{Interface: "wg0", PortRange: "25000-29999", Iptables: true}, // duplicate wg0
		},
	}
	err := Validate(cfg)
	if err == nil {
		t.Fatalf("expected validation error for duplicate interface, got nil")
	}
}
