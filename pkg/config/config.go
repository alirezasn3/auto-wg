package config

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Mode       string           `yaml:"mode" json:"mode"` // "server" or "client" (default: "server")
	PostUp     []string         `yaml:"post_up" json:"post_up"`
	PreDown    []string         `yaml:"pre_down" json:"pre_down"`
	Routing    RoutingConfig    `yaml:"routing" json:"routing"`
	Tunnels    []TunnelConfig   `yaml:"tunnels" json:"tunnels"`
	Web        WebConfig        `yaml:"web" json:"web"`
	StatusPage StatusPageConfig `yaml:"status_page" json:"status_page"`
}

type RoutingConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"` // Enable automatic default route switching (in client mode)
	Table   int    `yaml:"table" json:"table"`     // Linux routing table to manage (e.g. 200, or 0 for main table)
	Mode    string `yaml:"mode" json:"mode"`       // "sticky" (avoid flapping) or "priority" (prefer first tunnel)
	Metric  int    `yaml:"metric" json:"metric"`   // Default route metric (default: 100)
}

// WireGuard implementations a tunnel interface can run on.
const (
	BackendWireGuard = "wireguard" // stock WireGuard, controlled through wgctrl (default)
	BackendAmneziaWG = "amneziawg" // AmneziaWG (kernel module or amneziawg-go), controlled through the awg command
)

type TunnelConfig struct {
	Interface        string           `yaml:"interface" json:"interface"` // Interface name, e.g. "wg0", "wgBridge"
	Backend          string           `yaml:"backend,omitempty" json:"backend,omitempty"` // "wireguard" (default) or "amneziawg"
	Name             string           `yaml:"name" json:"name"`           // Descriptive name (e.g. "Client-A", "Frankfurt-Main")
	TargetIP         string           `yaml:"target_ip,omitempty" json:"target_ip,omitempty"` // Optional remote endpoint IP / fallback
	TargetIPs        []string         `yaml:"target_ips,omitempty" json:"target_ips,omitempty"` // Multiple candidate destination IPs / hostnames (IPv4 & IPv6)
	PeerPublicKey    string           `yaml:"peer_public_key,omitempty" json:"peer_public_key,omitempty"` // Optional peer public key
	PortRange        string           `yaml:"port_range" json:"port_range"` // Local forwarded port range (UDP for transport direct, TCP for tls and ssh)
	RemotePortRange  string           `yaml:"remote_port_range" json:"remote_port_range"` // Remote peer's port range (UDP for transport direct, TCP for tls and ssh)
	Hunting          *bool            `yaml:"hunting,omitempty" json:"hunting,omitempty"` // Enable autonomous port hunting (default: true). Set false for passive/MikroTik peers!
	Passive          bool             `yaml:"passive,omitempty" json:"passive,omitempty"` // Alias for hunting: false (monitor & ping only, no port rotation)
	CheckInterval    time.Duration    `yaml:"check_interval" json:"check_interval"`       // Check frequency (default: 3s)
	HandshakeTimeout time.Duration    `yaml:"handshake_timeout" json:"handshake_timeout"` // Stale handshake threshold (default: 60s)
	CycleTimeout     time.Duration    `yaml:"cycle_timeout" json:"cycle_timeout"`         // Staggered turn duration (default: 8s)
	TunnelPing       TunnelPingConfig `yaml:"tunnel_ping" json:"tunnel_ping"`
	Transport        string           `yaml:"transport,omitempty" json:"transport,omitempty"` // How packets travel: "direct" (default), "tls" or "ssh"
	TLS              TLSConfig        `yaml:"tls,omitempty" json:"tls"`                       // Settings of transport "tls"
	SSH              SSHConfig        `yaml:"ssh,omitempty" json:"ssh"`                       // Settings of transport "ssh"
	HistoryFile      string           `yaml:"history_file" json:"history_file"` // Persistent history file path
	Iptables         bool             `yaml:"iptables" json:"iptables"`         // Manage the iptables REDIRECT rules (default: false when the key is missing; the web editor and the generated first-run config set true)
	PostUp           []string         `yaml:"post_up" json:"post_up"`           // Per-tunnel post_up shell commands
	PreDown          []string         `yaml:"pre_down" json:"pre_down"`         // Per-tunnel pre_down shell commands
}

type TunnelPingConfig struct {
	Enabled          bool          `yaml:"enabled" json:"enabled"`                     // Active in-tunnel ICMP ping
	TargetIP         string        `yaml:"target_ip" json:"target_ip"`                 // In-tunnel IP of the remote peer to ping
	Interval         time.Duration `yaml:"interval" json:"interval"`                   // Ping interval (default: 2s)
	Timeout          time.Duration `yaml:"timeout" json:"timeout"`                     // Single ping timeout (default: 2s)
	FailureThreshold int           `yaml:"failure_threshold" json:"failure_threshold"` // Consecutive failed pings before hunt (default: 3)
}

// How a tunnel's WireGuard packets travel between the two peers. The interface keeps running as usual; only
// the wire changes. Run one interface per transport and switch between them yourself.
const (
	TransportDirect = "direct" // plain UDP (default)
	TransportTLS    = "tls"    // UDP packets inside a TLS connection; needs Auto-WG on both peers
	TransportSSH    = "ssh"    // UDP packets inside a real OpenSSH session; needs ssh and sshd
)

// LinkConfig is what the TLS and SSH transports share: both keep one authenticated connection between the
// peers, check its health and carry WireGuard's UDP packets in it through a loopback relay.
type LinkConfig struct {
	Secret         string        `yaml:"secret" json:"secret"`                                   // Shared secret both peers authenticate with
	RelayPort      int           `yaml:"relay_port,omitempty" json:"relay_port"`                 // Loopback UDP port WireGuard talks to (0 = automatic)
	DialInterval   time.Duration `yaml:"dial_interval,omitempty" json:"dial_interval"`           // Pause between dial attempts while no link is up (default: 1s)
	HealthInterval time.Duration `yaml:"health_interval,omitempty" json:"health_interval"`       // Pause between health probes on a live link (default: 3s)
	HealthTimeout  time.Duration `yaml:"health_timeout,omitempty" json:"health_timeout"`         // How long a probe may stay unanswered (default: 2s)
	HealthFailures int           `yaml:"health_failures,omitempty" json:"health_failures"`       // Consecutive unanswered probes that drop the connection (default: 3)
	ReconnectAfter time.Duration `yaml:"reconnect_after,omitempty" json:"reconnect_after"`       // WireGuard dead this long on a link that passes its probes: build a new connection (default: 10s)
	Padding        string        `yaml:"padding,omitempty" json:"padding"`                       // Hide packet sizes: "off" (default), "bucket" (round writes up to 128/256/512/1024/1500 bytes) or "random" (append 0-256 random bytes)
}

// TLSConfig holds the settings of transport "tls". Both peers listen on the TCP port range and dial the other
// peer's range.
type TLSConfig struct {
	LinkConfig `yaml:",inline"`
	SNI        string   `yaml:"sni,omitempty" json:"sni"`   // Optional server name sent in the ClientHello (and used as certificate name)
	ALPN       []string `yaml:"alpn,omitempty" json:"alpn"` // Optional ALPN protocols, e.g. ["h2", "http/1.1"]

	// Deprecated: the old in-tunnel fallback block. A tunnel with `tls.enabled: true` and no transport is
	// treated as transport "tls"; the other three are folded into the tunnel settings and cleared.
	Enabled         bool          `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	FallbackAfter   time.Duration `yaml:"fallback_after,omitempty" json:"fallback_after,omitempty"`
	PortRange       string        `yaml:"port_range,omitempty" json:"port_range,omitempty"`
	RemotePortRange string        `yaml:"remote_port_range,omitempty" json:"remote_port_range,omitempty"`
}

// SSHConfig holds the settings of transport "ssh". Auto-WG opens the TCP connection itself (random source
// port of port_range, random destination port of remote_port_range) and runs the real OpenSSH client over it
// to the other peer's sshd, which the peer's iptables redirects the range to. A peer that has an
// identity_file dials; a peer without one only accepts. Give both an identity to let either side dial.
type SSHConfig struct {
	LinkConfig   `yaml:",inline"`
	User         string `yaml:"user,omitempty" json:"user"`                   // Account on the peer's sshd (default: autowg)
	IdentityFile string `yaml:"identity_file,omitempty" json:"identity_file"` // Private key used to log in; setting it makes this peer dial
	HostKey      string `yaml:"host_key,omitempty" json:"host_key"`           // The peer sshd's public key ("ssh-ed25519 AAAA..."), required to dial
	SSHPath      string `yaml:"ssh_path,omitempty" json:"ssh_path"`           // OpenSSH client binary (default: ssh)
	SshdPort     int    `yaml:"sshd_port,omitempty" json:"sshd_port"`         // Port this host's sshd listens on; the TCP range is redirected there (default: 22)
	LinkPort     int    `yaml:"link_port,omitempty" json:"link_port"`         // Loopback TCP port the peer's ssh forwards to; the same on both peers (default: 40022)
}

// MaskedSecret replaces secrets in configuration returned to the web UI.
const MaskedSecret = "********"

type WebConfig struct {
	Enabled    bool     `yaml:"enabled" json:"enabled"`         // Enable web dashboard (default: true)
	ListenAddr string   `yaml:"listen_addr" json:"listen_addr"` // e.g. "0.0.0.0:8080"
	Username   string   `yaml:"username" json:"username"`       // Optional HTTP Basic Auth
	Password   string   `yaml:"password" json:"password"`
	AllowedIPs []string `yaml:"allowed_ips" json:"allowed_ips"` // Whitelist of client IPs or CIDRs
	HTTPS      bool     `yaml:"https" json:"https"`             // Enable HTTPS/TLS (default: false)
	CertFile   string   `yaml:"cert_file" json:"cert_file"`     // Path to SSL certificate (PEM)
	KeyFile    string   `yaml:"key_file" json:"key_file"`       // Path to SSL private key (PEM)
}

type StatusPageConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`         // Enable isolated public status page (default: false)
	ListenAddr string `yaml:"listen_addr" json:"listen_addr"` // e.g. "0.0.0.0:8081" (default: 8081, or 8443 if HTTPS)
	Title      string `yaml:"title" json:"title"`             // Title displayed on status page (default: "Service Status")
	HTTPS      bool   `yaml:"https" json:"https"`             // Enable HTTPS/TLS (default: false)
	CertFile   string `yaml:"cert_file" json:"cert_file"`     // Path to SSL certificate (PEM)
	KeyFile    string `yaml:"key_file" json:"key_file"`       // Path to SSL private key (PEM)
}

// LoadConfig reads and parses a YAML configuration file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file %s: %w", path, err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config yaml: %w", err)
	}

	SetDefaults(cfg)
	if err := Validate(cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

// SaveConfig serializes the configuration to disk.
func SaveConfig(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config yaml: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config file %s: %w", path, err)
	}

	return nil
}

// SetDefaults assigns sensible defaults to unset configuration fields.
func SetDefaults(cfg *Config) {
	if cfg.Mode == "" {
		cfg.Mode = "server"
	}
	cfg.Mode = strings.ToLower(cfg.Mode)
	if cfg.Mode != "client" {
		cfg.Mode = "server"
	}

	if cfg.Mode == "client" {
		if cfg.Routing.Mode == "" {
			cfg.Routing.Mode = "sticky"
		}
		if cfg.Routing.Metric <= 0 {
			cfg.Routing.Metric = 100
		}
	}

	for i := range cfg.Tunnels {
		t := &cfg.Tunnels[i]
		migrateLegacyTLS(t)
		if t.PortRange == "" {
			t.PortRange = "20000-30000"
		}
		if t.RemotePortRange == "" {
			t.RemotePortRange = "20000-30000"
		}
		if t.CheckInterval <= 0 {
			t.CheckInterval = 3 * time.Second
		}
		if t.HandshakeTimeout <= 0 {
			t.HandshakeTimeout = 60 * time.Second
		}
		if t.CycleTimeout <= 0 {
			t.CycleTimeout = 8 * time.Second
		}
		if t.TunnelPing.Enabled {
			if t.TunnelPing.Interval <= 0 {
				t.TunnelPing.Interval = 2 * time.Second
			}
			if t.TunnelPing.Timeout <= 0 {
				t.TunnelPing.Timeout = 2 * time.Second
			}
			if t.TunnelPing.FailureThreshold <= 0 {
				t.TunnelPing.FailureThreshold = 3
			}
		}
		if t.Name == "" {
			t.Name = t.Interface
		}
		t.Backend = NormalizeBackend(t.Backend)
		t.Transport = NormalizeTransport(t.Transport)
		switch t.Transport {
		case TransportTLS:
			setLinkDefaults(&t.TLS.LinkConfig)
		case TransportSSH:
			setLinkDefaults(&t.SSH.LinkConfig)
			if t.SSH.User == "" {
				t.SSH.User = "autowg"
			}
			if t.SSH.SSHPath == "" {
				t.SSH.SSHPath = "ssh"
			}
			if t.SSH.SshdPort == 0 {
				t.SSH.SshdPort = 22
			}
			if t.SSH.LinkPort == 0 {
				t.SSH.LinkPort = 40022
			}
		}
		if t.Hunting == nil {
			defaultHunting := !t.Passive
			t.Hunting = &defaultHunting
		}
		if len(t.TargetIPs) == 0 && t.TargetIP != "" {
			t.TargetIPs = []string{t.TargetIP}
		}
		if t.TargetIP == "" && len(t.TargetIPs) > 0 {
			t.TargetIP = t.TargetIPs[0]
		}
	}

	if cfg.Web.ListenAddr == "" {
		if cfg.Web.HTTPS {
			cfg.Web.ListenAddr = "0.0.0.0:8443"
		} else {
			cfg.Web.ListenAddr = "0.0.0.0:8080"
		}
	}

	if cfg.StatusPage.ListenAddr == "" {
		if cfg.StatusPage.HTTPS {
			cfg.StatusPage.ListenAddr = "0.0.0.0:8443"
		} else {
			cfg.StatusPage.ListenAddr = "0.0.0.0:8081"
		}
	}
	if cfg.StatusPage.Title == "" {
		cfg.StatusPage.Title = "Service Status"
	}
}

// NormalizeTransport maps the accepted spellings to a transport constant; unknown values are kept so that
// Validate can report them.
func NormalizeTransport(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "direct", "udp", "wireguard":
		return TransportDirect
	case "tls":
		return TransportTLS
	case "ssh", "openssh":
		return TransportSSH
	}
	return strings.TrimSpace(v)
}

// migrateLegacyTLS turns the old in-tunnel `tls: {enabled: true}` fallback into a tunnel that runs over TLS.
func migrateLegacyTLS(t *TunnelConfig) {
	if strings.TrimSpace(t.Transport) == "" && t.TLS.Enabled {
		t.Transport = TransportTLS
		if t.TLS.PortRange != "" {
			t.PortRange = t.TLS.PortRange
		}
		if t.TLS.RemotePortRange != "" {
			t.RemotePortRange = t.TLS.RemotePortRange
		}
	}
	t.TLS.Enabled, t.TLS.FallbackAfter, t.TLS.PortRange, t.TLS.RemotePortRange = false, 0, "", ""
}

func setLinkDefaults(c *LinkConfig) {
	if c.DialInterval <= 0 {
		c.DialInterval = time.Second
	}
	if c.HealthInterval <= 0 {
		c.HealthInterval = 3 * time.Second
	}
	if c.HealthTimeout <= 0 {
		c.HealthTimeout = 2 * time.Second
	}
	if c.HealthFailures <= 0 {
		c.HealthFailures = 3
	}
	if c.ReconnectAfter <= 0 {
		c.ReconnectAfter = 10 * time.Second
	}
	c.Padding = strings.ToLower(strings.TrimSpace(c.Padding))
}

// NormalizeBackend maps the accepted spellings to a backend constant; unknown values are kept so that
// Validate can report them.
func NormalizeBackend(b string) string {
	switch strings.ToLower(strings.TrimSpace(b)) {
	case "", "wireguard", "wg":
		return BackendWireGuard
	case "amneziawg", "amnezia", "awg":
		return BackendAmneziaWG
	}
	return strings.TrimSpace(b)
}

// validateLink checks the settings the TLS and SSH transports share.
func validateLink(t TunnelConfig, name string, c LinkConfig) error {
	if len(c.Secret) < 16 {
		return fmt.Errorf("%s.secret must be at least 16 characters (it must match on both peers)", name)
	}
	if t.Passive || (t.Hunting != nil && !*t.Hunting) {
		return fmt.Errorf("transport %q needs port hunting; it cannot be used on a passive tunnel because the peer must run Auto-WG too", name)
	}
	if _, _, err := ParsePortRange(t.PortRange); err != nil {
		return fmt.Errorf("port_range: %w", err)
	}
	if _, _, err := ParsePortRange(t.RemotePortRange); err != nil {
		return fmt.Errorf("remote_port_range: %w", err)
	}
	if c.DialInterval < 200*time.Millisecond {
		return fmt.Errorf("%s.dial_interval must be at least 200ms", name)
	}
	if c.HealthInterval < time.Second {
		return fmt.Errorf("%s.health_interval must be at least 1s", name)
	}
	if c.HealthTimeout < 500*time.Millisecond || c.HealthTimeout > 30*time.Second {
		return fmt.Errorf("%s.health_timeout must be between 500ms and 30s", name)
	}
	if c.HealthFailures < 1 || c.HealthFailures > 20 {
		return fmt.Errorf("%s.health_failures must be between 1 and 20", name)
	}
	if c.ReconnectAfter < 3*time.Second {
		return fmt.Errorf("%s.reconnect_after must be at least 3s", name)
	}
	if c.RelayPort != 0 && (c.RelayPort < 1024 || c.RelayPort > 65535) {
		return fmt.Errorf("%s.relay_port must be 0 (automatic) or between 1024 and 65535", name)
	}
	switch c.Padding {
	case "", "off", "bucket", "random":
	default:
		return fmt.Errorf("%s.padding must be off, bucket or random", name)
	}
	return nil
}

// validateTransport checks the settings of the transport a tunnel runs on.
func validateTransport(t TunnelConfig) error {
	switch t.Transport {
	case TransportDirect:
		return nil
	case TransportTLS:
		c := t.TLS
		if err := validateLink(t, "tls", c.LinkConfig); err != nil {
			return err
		}
		if strings.ContainsAny(c.SNI, " \t/") {
			return fmt.Errorf("tls.sni must be a host name")
		}
		for _, p := range c.ALPN {
			if strings.TrimSpace(p) == "" {
				return fmt.Errorf("tls.alpn must not contain empty entries")
			}
		}
		return nil
	case TransportSSH:
		c := t.SSH
		if err := validateLink(t, "ssh", c.LinkConfig); err != nil {
			return err
		}
		if c.SshdPort < 1 || c.SshdPort > 65535 {
			return fmt.Errorf("ssh.sshd_port must be between 1 and 65535")
		}
		if c.LinkPort < 1024 || c.LinkPort > 65535 {
			return fmt.Errorf("ssh.link_port must be between 1024 and 65535")
		}
		if strings.ContainsAny(c.User, " \t@:/") {
			return fmt.Errorf("ssh.user must be a plain account name")
		}
		if c.IdentityFile != "" {
			if c.User == "" {
				return fmt.Errorf("ssh.user is required when ssh.identity_file is set")
			}
			if fields := strings.Fields(c.HostKey); len(fields) < 2 || !strings.HasPrefix(fields[0], "ssh-") && !strings.HasPrefix(fields[0], "ecdsa-") && !strings.HasPrefix(fields[0], "sk-") {
				return fmt.Errorf("ssh.host_key must be the peer sshd's public key (e.g. \"ssh-ed25519 AAAA...\"), it is required to dial")
			}
		}
		return nil
	}
	return fmt.Errorf("unknown transport %q (use %q, %q or %q)", t.Transport, TransportDirect, TransportTLS, TransportSSH)
}

// Validate checks for configuration sanity, non-empty interfaces, unique names,
// and ensures local port ranges do not overlap when iptables is active.
func Validate(cfg *Config) error {
	if len(cfg.Tunnels) == 0 {
		return fmt.Errorf("at least one tunnel must be configured under 'tunnels:'")
	}

	seenIfaces := make(map[string]bool)
	type portSpan struct {
		iface string
		start int
		end   int
	}
	var spans, tcpSpans []portSpan

	for i, t := range cfg.Tunnels {
		iface := strings.TrimSpace(t.Interface)
		if iface == "" {
			return fmt.Errorf("tunnel #%d missing 'interface'", i+1)
		}
		t.Transport = NormalizeTransport(t.Transport)
		if seenIfaces[iface] {
			return fmt.Errorf("duplicate interface %q configured", iface)
		}
		seenIfaces[iface] = true

		if b := NormalizeBackend(t.Backend); b != BackendWireGuard && b != BackendAmneziaWG {
			return fmt.Errorf("tunnel %q has unknown backend %q (use %q or %q)", iface, t.Backend, BackendWireGuard, BackendAmneziaWG)
		}

		if err := validateTransport(t); err != nil {
			return fmt.Errorf("tunnel %q: %w", iface, err)
		}

		if t.Iptables && t.PortRange != "" {
			start, end, err := ParsePortRange(t.PortRange)
			if err != nil {
				return fmt.Errorf("tunnel %q port_range error: %w", iface, err)
			}
			// UDP ranges (direct) and TCP ranges (tls, ssh) live in separate port spaces
			set, proto := &spans, "udp"
			if t.Transport != TransportDirect {
				set, proto = &tcpSpans, "tcp"
			}
			for _, prev := range *set {
				if start <= prev.end && prev.start <= end {
					return fmt.Errorf("port_range conflict: tunnel %q (%s %d-%d) overlaps with tunnel %q (%s %d-%d)",
						iface, proto, start, end, prev.iface, proto, prev.start, prev.end)
				}
			}
			*set = append(*set, portSpan{iface: iface, start: start, end: end})
		}
	}

	return nil
}

// ParsePortRange parses a range string like "20000-30000" into start and end integers.
func ParsePortRange(spec string) (int, int, error) {
	spec = strings.TrimSpace(spec)
	spec = strings.ReplaceAll(spec, ":", "-")
	parts := strings.Split(spec, "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid port range %q: expected format 'start-end' (e.g. 20000-30000)", spec)
	}

	start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid start port %q: %w", parts[0], err)
	}

	end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid end port %q: %w", parts[1], err)
	}

	if start < 1 || end > 65535 || start > end {
		return 0, 0, fmt.Errorf("invalid port range %d-%d: ports must be 1-65535 and start <= end", start, end)
	}

	return start, end, nil
}

// PickRandomPort selects a random uniform port within the given range string.
func PickRandomPort(rangeSpec string) (int, error) {
	start, end, err := ParsePortRange(rangeSpec)
	if err != nil {
		return 0, err
	}

	count := big.NewInt(int64(end - start + 1))
	n, err := rand.Int(rand.Reader, count)
	if err != nil {
		return 0, fmt.Errorf("crypto rand failure: %w", err)
	}

	return start + int(n.Int64()), nil
}

// PickRandomPortExcluding picks a random port of the range that differs from every excluded port. A range with
// a single usable port cannot do that and returns it anyway, so the caller is never left without a port.
func PickRandomPortExcluding(rangeSpec string, exclude ...int) (int, error) {
	start, end, err := ParsePortRange(rangeSpec)
	if err != nil {
		return 0, err
	}
	free := end - start + 1
	for _, e := range exclude {
		if e >= start && e <= end {
			free--
		}
	}
	if free <= 0 {
		return PickRandomPort(rangeSpec)
	}
	for i := 0; i < 64; i++ {
		port, err := PickRandomPort(rangeSpec)
		if err != nil {
			return 0, err
		}
		taken := false
		for _, e := range exclude {
			if port == e {
				taken = true
				break
			}
		}
		if !taken {
			return port, nil
		}
	}
	return PickRandomPort(rangeSpec)
}

// HasHostnames checks if any entry in the target list is a non-IP domain name or hostname.
func HasHostnames(entries []string) bool {
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		clean := strings.TrimPrefix(strings.TrimSuffix(entry, "]"), "[")
		if net.ParseIP(clean) == nil {
			return true
		}
	}
	return false
}

// ResolveTargetIPs resolves a list of target IPs and/or hostnames into deduplicated,
// canonical IP address strings (both IPv4 and IPv6).
func ResolveTargetIPs(entries []string) []string {
	return ResolveTargetIPsContext(context.Background(), entries)
}

// ResolveTargetIPsContext resolves target IPs/hostnames with a context for DNS queries.
func ResolveTargetIPsContext(ctx context.Context, entries []string) []string {
	var results []string
	seen := make(map[string]bool)

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// Strip square brackets if formatted as [2001:db8::1]
		clean := strings.TrimPrefix(strings.TrimSuffix(entry, "]"), "[")
		if ip := net.ParseIP(clean); ip != nil {
			var canon string
			if ip4 := ip.To4(); ip4 != nil {
				canon = ip4.String()
			} else {
				canon = ip.String()
			}
			if !seen[canon] {
				seen[canon] = true
				results = append(results, canon)
			}
			continue
		}

		// Not an IP address, attempt DNS lookup for both A (IPv4) and AAAA (IPv6) records
		lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		ips, err := net.DefaultResolver.LookupIP(lookupCtx, "ip", clean)
		cancel()

		if err == nil && len(ips) > 0 {
			for _, ip := range ips {
				var canon string
				if ip4 := ip.To4(); ip4 != nil {
					canon = ip4.String()
				} else {
					canon = ip.String()
				}
				if !seen[canon] {
					seen[canon] = true
					results = append(results, canon)
				}
			}
		} else {
			// If DNS resolution fails, preserve the original entry so caller can retry or use as fallback
			if !seen[clean] {
				seen[clean] = true
				results = append(results, clean)
			}
		}
	}

	return results
}
