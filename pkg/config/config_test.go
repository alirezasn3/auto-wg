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

func linkOf(secret string) LinkConfig { return LinkConfig{Secret: secret} }

func TestTransportDefaults(t *testing.T) {
	cfg := &Config{Mode: "server", Tunnels: []TunnelConfig{
		{Interface: "wg0"},
		{Interface: "wg1", Transport: "TLS", TLS: TLSConfig{LinkConfig: linkOf("0123456789abcdef")}},
		{Interface: "wg2", Transport: "openssh", SSH: SSHConfig{LinkConfig: linkOf("0123456789abcdef")}},
	}}
	SetDefaults(cfg)

	if cfg.Tunnels[0].Transport != TransportDirect || cfg.Tunnels[1].Transport != TransportTLS || cfg.Tunnels[2].Transport != TransportSSH {
		t.Fatalf("transports not normalised: %q %q %q", cfg.Tunnels[0].Transport, cfg.Tunnels[1].Transport, cfg.Tunnels[2].Transport)
	}
	l := cfg.Tunnels[1].TLS.LinkConfig
	if l.DialInterval != time.Second || l.HealthInterval != 3*time.Second || l.HealthTimeout != 2*time.Second || l.HealthFailures != 3 || l.ReconnectAfter != 10*time.Second {
		t.Fatalf("link defaults: %+v", l)
	}
	ssh := cfg.Tunnels[2].SSH
	if ssh.User != "autowg" || ssh.SSHPath != "ssh" || ssh.SshdPort != 22 || ssh.LinkPort != 40022 || ssh.HealthFailures != 3 {
		t.Fatalf("ssh defaults: %+v", ssh)
	}
	// Only the block of the active transport gets defaults.
	if cfg.Tunnels[0].TLS.HealthInterval != 0 || cfg.Tunnels[0].SSH.LinkPort != 0 {
		t.Fatal("a direct tunnel must not get transport defaults")
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
}

func TestLegacyTLSBlockBecomesATLSTransport(t *testing.T) {
	cfg := &Config{Mode: "server", Tunnels: []TunnelConfig{{
		Interface: "wg0", PortRange: "20000-24999", RemotePortRange: "25000-29999",
		TLS: TLSConfig{LinkConfig: linkOf("0123456789abcdef"), Enabled: true, FallbackAfter: 15 * time.Second, PortRange: "443-8443", RemotePortRange: "9000-9100"},
	}}}
	SetDefaults(cfg)
	tn := cfg.Tunnels[0]
	if tn.Transport != TransportTLS {
		t.Fatalf("legacy tls.enabled must select transport tls, got %q", tn.Transport)
	}
	if tn.PortRange != "443-8443" || tn.RemotePortRange != "9000-9100" {
		t.Fatalf("legacy tls ranges must become the tunnel ranges, got %s / %s", tn.PortRange, tn.RemotePortRange)
	}
	if tn.TLS.Enabled || tn.TLS.FallbackAfter != 0 || tn.TLS.PortRange != "" || tn.TLS.RemotePortRange != "" {
		t.Fatalf("legacy fields must be cleared: %+v", tn.TLS)
	}
	if err := Validate(cfg); err != nil {
		t.Fatal(err)
	}

	// An explicit transport wins; the legacy block is ignored.
	explicit := &Config{Mode: "server", Tunnels: []TunnelConfig{{Interface: "wg0", Transport: "direct", TLS: TLSConfig{Enabled: true}}}}
	SetDefaults(explicit)
	if explicit.Tunnels[0].Transport != TransportDirect {
		t.Fatal("an explicit transport must not be overridden")
	}
}

func TestTransportValidation(t *testing.T) {
	tls := func() *Config {
		c := &Config{Mode: "server", Tunnels: []TunnelConfig{{
			Interface: "wg0", Transport: "tls", PortRange: "20000-24999", RemotePortRange: "25000-29999", Iptables: true,
			TLS: TLSConfig{LinkConfig: linkOf("0123456789abcdef")},
		}}}
		SetDefaults(c)
		return c
	}
	ssh := func() *Config {
		c := &Config{Mode: "server", Tunnels: []TunnelConfig{{
			Interface: "wg0", Transport: "ssh", PortRange: "20000-24999", RemotePortRange: "25000-29999", Iptables: true,
			SSH: SSHConfig{LinkConfig: linkOf("0123456789abcdef"), IdentityFile: "/etc/autowg/id_ed25519", HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"},
		}}}
		SetDefaults(c)
		return c
	}
	if err := Validate(tls()); err != nil {
		t.Fatalf("valid tls config rejected: %v", err)
	}
	if err := Validate(ssh()); err != nil {
		t.Fatalf("valid ssh config rejected: %v", err)
	}

	bad := map[string]func() *Config{}
	add := func(name string, base func() *Config, mutate func(*TunnelConfig)) {
		bad[name] = func() *Config { c := base(); mutate(&c.Tunnels[0]); return c }
	}
	add("unknown transport", tls, func(t *TunnelConfig) { t.Transport = "carrier-pigeon" })
	add("short secret", tls, func(t *TunnelConfig) { t.TLS.Secret = "short" })
	add("passive", tls, func(t *TunnelConfig) { f := false; t.Hunting = &f })
	add("bad range", tls, func(t *TunnelConfig) { t.PortRange = "nonsense" })
	add("fast dial", tls, func(t *TunnelConfig) { t.TLS.DialInterval = time.Millisecond })
	add("fast probes", tls, func(t *TunnelConfig) { t.TLS.HealthInterval = 500 * time.Millisecond })
	add("tiny timeout", tls, func(t *TunnelConfig) { t.TLS.HealthTimeout = 100 * time.Millisecond })
	add("huge timeout", tls, func(t *TunnelConfig) { t.TLS.HealthTimeout = time.Minute })
	add("no failures", tls, func(t *TunnelConfig) { t.TLS.HealthFailures = -1 })
	add("many failures", tls, func(t *TunnelConfig) { t.TLS.HealthFailures = 50 })
	add("fast reconnect", tls, func(t *TunnelConfig) { t.TLS.ReconnectAfter = time.Second })
	add("low relay", tls, func(t *TunnelConfig) { t.TLS.RelayPort = 80 })
	add("bad padding", tls, func(t *TunnelConfig) { t.TLS.Padding = "lots" })
	add("bad sni", tls, func(t *TunnelConfig) { t.TLS.SNI = "not a host" })
	add("empty alpn", tls, func(t *TunnelConfig) { t.TLS.ALPN = []string{"h2", " "} })
	add("ssh short secret", ssh, func(t *TunnelConfig) { t.SSH.Secret = "x" })
	add("ssh no host key", ssh, func(t *TunnelConfig) { t.SSH.HostKey = "" })
	add("ssh junk host key", ssh, func(t *TunnelConfig) { t.SSH.HostKey = "hello" })
	add("ssh no user", ssh, func(t *TunnelConfig) { t.SSH.User = "" })
	add("ssh odd user", ssh, func(t *TunnelConfig) { t.SSH.User = "a b@c" })
	add("ssh bad sshd port", ssh, func(t *TunnelConfig) { t.SSH.SshdPort = 70000 })
	add("ssh low link port", ssh, func(t *TunnelConfig) { t.SSH.LinkPort = 22 })
	for name, mk := range bad {
		if err := Validate(mk()); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}

	// An accept-only ssh peer needs neither an identity nor the peer's host key.
	accept := ssh()
	accept.Tunnels[0].SSH.IdentityFile, accept.Tunnels[0].SSH.HostKey = "", ""
	if err := Validate(accept); err != nil {
		t.Fatalf("an ssh peer without an identity only accepts and must validate: %v", err)
	}

	// A block of a transport that is not in use is never validated.
	direct := &Config{Mode: "server", Tunnels: []TunnelConfig{{Interface: "wg0", TLS: TLSConfig{LinkConfig: linkOf("x")}, SSH: SSHConfig{LinkConfig: linkOf("y")}}}}
	SetDefaults(direct)
	if err := Validate(direct); err != nil {
		t.Fatalf("unused transport blocks must be ignored: %v", err)
	}
}

func TestPortRangeOverlapIsPerProtocol(t *testing.T) {
	mk := func(a, b string, ta, tb string) *Config {
		c := &Config{Mode: "server", Tunnels: []TunnelConfig{
			{Interface: "wg0", Transport: ta, PortRange: a, Iptables: true, TLS: TLSConfig{LinkConfig: linkOf("0123456789abcdef")}, SSH: SSHConfig{LinkConfig: linkOf("0123456789abcdef")}},
			{Interface: "wg1", Transport: tb, PortRange: b, Iptables: true, TLS: TLSConfig{LinkConfig: linkOf("0123456789abcdef")}, SSH: SSHConfig{LinkConfig: linkOf("0123456789abcdef")}},
		}}
		SetDefaults(c)
		return c
	}
	// The same numbers on a UDP tunnel and a TCP tunnel are fine: they are different port spaces.
	if err := Validate(mk("20000-21000", "20000-21000", "direct", "tls")); err != nil {
		t.Fatalf("a UDP and a TCP range may overlap: %v", err)
	}
	if err := Validate(mk("20000-21000", "20500-21500", "direct", "direct")); err == nil {
		t.Fatal("two UDP ranges must not overlap")
	}
	if err := Validate(mk("20000-21000", "20500-21500", "tls", "ssh")); err == nil {
		t.Fatal("a tls and an ssh range are both TCP and must not overlap")
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
			{Interface: "wg0", TLS: TLSConfig{LinkConfig: linkOf("s0")}, SSH: SSHConfig{LinkConfig: linkOf("s1")}},
			{Interface: "wg1"},
		},
	}
	masked := MaskSecrets(cfg)
	if masked.Web.Password != MaskedSecret || masked.Tunnels[0].TLS.Secret != MaskedSecret || masked.Tunnels[0].SSH.Secret != MaskedSecret || masked.Tunnels[1].TLS.Secret != "" {
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
	if back.Web.Password != "pw" || back.Tunnels[0].TLS.Secret != "s0" || back.Tunnels[0].SSH.Secret != "s1" {
		t.Fatalf("restore failed: %+v", back)
	}
	gone := Config{Tunnels: []TunnelConfig{{Interface: "other", TLS: TLSConfig{LinkConfig: linkOf(MaskedSecret)}}}}
	if err := RestoreMaskedSecretsConfig(&gone, &cfg); err == nil {
		t.Fatal("expected an error when there is nothing stored for the interface")
	}
}

func TestPickRandomPortExcluding(t *testing.T) {
	for i := 0; i < 500; i++ {
		got, err := PickRandomPortExcluding("20000-20002", 20001)
		if err != nil || got == 20001 || got < 20000 || got > 20002 {
			t.Fatalf("got %d, err %v", got, err)
		}
	}
	// Excluded ports outside the range are irrelevant; a one-port range cannot avoid its only port.
	if got, _ := PickRandomPortExcluding("30000-30000", 30000); got != 30000 {
		t.Fatalf("single-port range must still return its port, got %d", got)
	}
	if got, _ := PickRandomPortExcluding("30000-30001", 5, 30000, 99999); got != 30001 {
		t.Fatalf("expected the only free port, got %d", got)
	}
	if _, err := PickRandomPortExcluding("nonsense"); err == nil {
		t.Fatal("bad range must fail")
	}
}

func TestMaskAndRestoreYAMLCoversSSHSecrets(t *testing.T) {
	const doc = `tunnels:
  - interface: wgTls
    transport: tls
    tls:
      secret: "tls-secret-value-0123"
  - interface: wgSsh
    transport: ssh
    ssh:
      secret: "ssh-secret-value-4567"
      user: autowg
`
	var cfg Config
	if err := yaml.Unmarshal([]byte(doc), &cfg); err != nil {
		t.Fatal(err)
	}
	masked := MaskYAML(doc)
	if strings.Contains(masked, "tls-secret-value-0123") || strings.Contains(masked, "ssh-secret-value-4567") {
		t.Fatalf("a secret leaked:\n%s", masked)
	}
	if strings.Count(masked, MaskedSecret) != 2 || !strings.Contains(masked, "user: autowg") {
		t.Fatalf("expected exactly the two secrets masked:\n%s", masked)
	}
	restored, err := RestoreMaskedSecrets(masked, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if restored != doc {
		t.Fatalf("restore must reproduce the original text byte for byte:\n%s", restored)
	}
}
