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

func TestResolveTargetIPs(t *testing.T) {
	entries := []string{
		" 198.51.100.1 ",
		"[2001:db8::1]",
		"198.51.100.1",        // duplicate
		"2001:0db8::0001",     // duplicate canonical IPv6
		"",                    // empty
		"   ",                 // whitespace
		"localhost",           // hostname
	}

	resolved := ResolveTargetIPs(entries)
	if len(resolved) < 2 {
		t.Fatalf("expected at least 2 resolved IPs, got %d: %v", len(resolved), resolved)
	}

	if resolved[0] != "198.51.100.1" {
		t.Errorf("expected first IP 198.51.100.1, got %s", resolved[0])
	}
	if resolved[1] != "2001:db8::1" {
		t.Errorf("expected second IP 2001:db8::1, got %s", resolved[1])
	}

	// Verify deduplication
	seen := make(map[string]bool)
	for _, ip := range resolved {
		if seen[ip] {
			t.Errorf("duplicate IP found in resolved output: %s", ip)
		}
		seen[ip] = true
	}
}

func TestTargetIPsConfigDefaults(t *testing.T) {
	// Case 1: Only TargetIP provided
	cfg1 := &Config{
		Mode: "client",
		Tunnels: []TunnelConfig{
			{Interface: "wg0", TargetIP: "198.51.100.1"},
		},
	}
	SetDefaults(cfg1)
	if len(cfg1.Tunnels[0].TargetIPs) != 1 || cfg1.Tunnels[0].TargetIPs[0] != "198.51.100.1" {
		t.Errorf("expected TargetIPs to contain TargetIP, got %v", cfg1.Tunnels[0].TargetIPs)
	}

	// Case 2: Only TargetIPs provided
	cfg2 := &Config{
		Mode: "client",
		Tunnels: []TunnelConfig{
			{Interface: "wg0", TargetIPs: []string{"2001:db8::1", "198.51.100.1"}},
		},
	}
	SetDefaults(cfg2)
	if cfg2.Tunnels[0].TargetIP != "2001:db8::1" {
		t.Errorf("expected TargetIP to default to first TargetIPs entry, got %s", cfg2.Tunnels[0].TargetIP)
	}
}

