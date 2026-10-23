package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
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

func TestPassiveTunnelConfigDefaults(t *testing.T) {
	cfg := &Config{
		Mode: "server",
		Tunnels: []TunnelConfig{
			{Interface: "wg-mikrotik", Passive: true},
			{Interface: "wg0"},
		},
	}
	SetDefaults(cfg)
	if cfg.Tunnels[0].Hunting == nil || *cfg.Tunnels[0].Hunting != false {
		t.Errorf("expected tunnel 0 hunting to be false, got %v", cfg.Tunnels[0].Hunting)
	}
	if cfg.Tunnels[1].Hunting == nil || *cfg.Tunnels[1].Hunting != true {
		t.Errorf("expected tunnel 1 hunting to be true, got %v", cfg.Tunnels[1].Hunting)
	}
}

func TestHasHostnames(t *testing.T) {
	if HasHostnames([]string{"198.51.100.1", "2001:db8::1"}) {
		t.Errorf("expected false for static IP list")
	}
	if !HasHostnames([]string{"198.51.100.1", "vpn.example.com"}) {
		t.Errorf("expected true when list contains domain name")
	}
	if !HasHostnames([]string{"localhost"}) {
		t.Errorf("expected true for localhost")
	}
	if HasHostnames([]string{"[2001:db8::1]"}) {
		t.Errorf("expected false for bracketed IPv6")
	}
}




func TestBackendDefaultsAndValidation(t *testing.T) {
	cfg := &Config{Mode: "server", Tunnels: []TunnelConfig{
		{Interface: "wg0"},
		{Interface: "wg1", Backend: "AWG"},
		{Interface: "wg2", Backend: "AmneziaWG"},
	}}
	SetDefaults(cfg)
	want := []string{BackendWireGuard, BackendAmneziaWG, BackendAmneziaWG}
	for i, w := range want {
		if got := cfg.Tunnels[i].Backend; got != w {
			t.Errorf("tunnel %d: backend = %q, want %q", i, got, w)
		}
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("valid backends rejected: %v", err)
	}

	bad := &Config{Mode: "server", Tunnels: []TunnelConfig{{Interface: "wg0", Backend: "openvpn"}}}
	SetDefaults(bad)
	if err := Validate(bad); err == nil {
		t.Error("unknown backend must be rejected")
	}
}

func TestTLSDefaultsAndValidation(t *testing.T) {
	good := func() *Config {
		c := &Config{Mode: "server", Tunnels: []TunnelConfig{{
			Interface: "wg0", PortRange: "20000-24999", RemotePortRange: "25000-29999", Iptables: true,
			TLS: TLSConfig{Enabled: true, Secret: "0123456789abcdef"},
		}}}
		SetDefaults(c)
		return c
	}

	c := good()
	tl := c.Tunnels[0].TLS
	if tl.PortRange != "20000-24999" || tl.RemotePortRange != "25000-29999" || tl.FallbackAfter != 15*time.Second || tl.DialInterval != time.Second {
		t.Fatalf("unexpected defaults: %+v", tl)
	}
	if tl.HealthInterval != 3*time.Second || tl.HealthTimeout != 2*time.Second || tl.HealthFailures != 3 {
		t.Fatalf("unexpected health defaults: %+v", tl)
	}
	if err := Validate(c); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}

	bad := map[string]func(*Config){
		"short secret":   func(c *Config) { c.Tunnels[0].TLS.Secret = "short" },
		"passive":        func(c *Config) { f := false; c.Tunnels[0].Hunting = &f },
		"bad range":      func(c *Config) { c.Tunnels[0].TLS.PortRange = "nonsense" },
		"fast fallback":  func(c *Config) { c.Tunnels[0].TLS.FallbackAfter = time.Second },
		"fast dial":      func(c *Config) { c.Tunnels[0].TLS.DialInterval = time.Millisecond },
		"fast probes":    func(c *Config) { c.Tunnels[0].TLS.HealthInterval = 500 * time.Millisecond },
		"tiny timeout":   func(c *Config) { c.Tunnels[0].TLS.HealthTimeout = 100 * time.Millisecond },
		"huge timeout":   func(c *Config) { c.Tunnels[0].TLS.HealthTimeout = time.Minute },
		"no failures":    func(c *Config) { c.Tunnels[0].TLS.HealthFailures = -1 },
		"many failures":  func(c *Config) { c.Tunnels[0].TLS.HealthFailures = 50 },
		"relay in range": func(c *Config) { c.Tunnels[0].TLS.RelayPort = 21000 },
		"low relay":      func(c *Config) { c.Tunnels[0].TLS.RelayPort = 80 },
		"bad sni":        func(c *Config) { c.Tunnels[0].TLS.SNI = "not a host" },
		"empty alpn":     func(c *Config) { c.Tunnels[0].TLS.ALPN = []string{"h2", " "} },
	}
	for name, mutate := range bad {
		c := good()
		mutate(c)
		if err := Validate(c); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}

	// A disabled block is never validated and gets no defaults.
	off := &Config{Mode: "server", Tunnels: []TunnelConfig{{Interface: "wg0", TLS: TLSConfig{Secret: "x"}}}}
	SetDefaults(off)
	if err := Validate(off); err != nil || off.Tunnels[0].TLS.PortRange != "" {
		t.Errorf("disabled tls must be left alone: %v %+v", err, off.Tunnels[0].TLS)
	}

	// TCP ranges of two iptables-managed tunnels must not overlap.
	two := &Config{Mode: "server", Tunnels: []TunnelConfig{
		{Interface: "wg0", PortRange: "20000-21000", Iptables: true, TLS: TLSConfig{Enabled: true, Secret: "0123456789abcdef", PortRange: "30000-31000"}},
		{Interface: "wg1", PortRange: "22000-23000", Iptables: true, TLS: TLSConfig{Enabled: true, Secret: "0123456789abcdef", PortRange: "30500-31500"}},
	}}
	SetDefaults(two)
	if err := Validate(two); err == nil {
		t.Error("overlapping tls port ranges must be rejected")
	}
}

const secretsYAML = `# my config
mode: "client"   # keep this comment
tunnels:
  - interface: "wg0"
    tls:
      enabled: true
      secret: "super-secret-value-123"   # shared with the peer
  - interface: wg1
    tls:
      enabled: true
      secret: 'plain-secret-value-456'
  - interface: wg2
    tls:
      enabled: true
      secret: unquoted-secret-value-789
web:
  enabled: true
  password: "hunter2"
`

func TestMaskAndRestoreYAMLRoundTrip(t *testing.T) {
	var cfg Config
	if err := yaml.Unmarshal([]byte(secretsYAML), &cfg); err != nil {
		t.Fatal(err)
	}

	masked := MaskYAML(secretsYAML)
	for _, secret := range []string{"super-secret-value-123", "plain-secret-value-456", "unquoted-secret-value-789", "hunter2"} {
		if strings.Contains(masked, secret) {
			t.Fatalf("secret %q leaked into the masked YAML:\n%s", secret, masked)
		}
	}
	if strings.Count(masked, MaskedSecret) != 4 {
		t.Fatalf("expected four masked values:\n%s", masked)
	}
	if !strings.Contains(masked, "# keep this comment") || !strings.Contains(masked, "# shared with the peer") {
		t.Fatalf("masking must leave comments and formatting alone:\n%s", masked)
	}

	restored, err := RestoreMaskedSecrets(masked, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	var back Config
	if err := yaml.Unmarshal([]byte(restored), &back); err != nil {
		t.Fatalf("restored YAML must parse: %v\n%s", err, restored)
	}
	if back.Tunnels[0].TLS.Secret != "super-secret-value-123" || back.Tunnels[1].TLS.Secret != "plain-secret-value-456" ||
		back.Tunnels[2].TLS.Secret != "unquoted-secret-value-789" || back.Web.Password != "hunter2" {
		t.Fatalf("secrets not restored: %+v", back)
	}
	if !strings.Contains(restored, "# keep this comment") {
		t.Fatal("restoring must leave comments alone")
	}
}

func TestRestoreKeepsNewlyTypedSecretsAndRejectsUnknownInterfaces(t *testing.T) {
	var old Config
	_ = yaml.Unmarshal([]byte(secretsYAML), &old)

	// A secret the user typed is not touched.
	edited := strings.Replace(MaskYAML(secretsYAML), `secret: "********"   # shared`, `secret: "a-brand-new-secret-1"   # shared`, 1)
	got, err := RestoreMaskedSecrets(edited, &old)
	if err != nil || !strings.Contains(got, "a-brand-new-secret-1") {
		t.Fatalf("typed secret must survive: err=%v\n%s", err, got)
	}

	// A masked secret on an interface that has no stored secret cannot be restored.
	renamed := strings.Replace(MaskYAML(secretsYAML), `interface: "wg0"`, `interface: "renamed"`, 1)
	if _, err := RestoreMaskedSecrets(renamed, &old); err == nil {
		t.Fatal("expected an error for a masked secret without a stored value")
	}

	// Text without secrets is returned as is, and unparsable text does not panic.
	if out := MaskYAML("mode: server\n"); out != "mode: server\n" {
		t.Fatalf("got %q", out)
	}
	if out := MaskYAML(":\n  - ["); out != ":\n  - [" {
		t.Fatalf("unparsable YAML must be returned unchanged, got %q", out)
	}
}

func TestMaskSecretsConfig(t *testing.T) {
	cfg := Config{
		Web: WebConfig{Password: "pw"},
		Tunnels: []TunnelConfig{
			{Interface: "wg0", TLS: TLSConfig{Secret: "s0"}},
			{Interface: "wg1"},
		},
	}
	masked := MaskSecrets(cfg)
	if masked.Web.Password != MaskedSecret || masked.Tunnels[0].TLS.Secret != MaskedSecret || masked.Tunnels[1].TLS.Secret != "" {
		t.Fatalf("unexpected masking: %+v", masked)
	}
	if cfg.Tunnels[0].TLS.Secret != "s0" || cfg.Web.Password != "pw" {
		t.Fatal("masking must not modify the live configuration")
	}

	back := masked
	back.Tunnels = append([]TunnelConfig(nil), masked.Tunnels...)
	if err := RestoreMaskedSecretsConfig(&back, &cfg); err != nil {
		t.Fatal(err)
	}
	if back.Web.Password != "pw" || back.Tunnels[0].TLS.Secret != "s0" {
		t.Fatalf("restore failed: %+v", back)
	}
	gone := Config{Tunnels: []TunnelConfig{{Interface: "other", TLS: TLSConfig{Secret: MaskedSecret}}}}
	if err := RestoreMaskedSecretsConfig(&gone, &cfg); err == nil {
		t.Fatal("expected an error when there is nothing stored for the interface")
	}
}
