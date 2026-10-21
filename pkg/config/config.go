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

type TunnelConfig struct {
	Interface        string            `yaml:"interface" json:"interface"`                                 // Interface name, e.g. "wg0", "wgBridge"
	Name             string            `yaml:"name" json:"name"`                                           // Descriptive name (e.g. "Client-A", "Frankfurt-Main")
	TargetIP         string            `yaml:"target_ip,omitempty" json:"target_ip,omitempty"`             // Optional remote endpoint IP / fallback
	TargetIPs        []string          `yaml:"target_ips,omitempty" json:"target_ips,omitempty"`           // Multiple candidate destination IPs / hostnames (IPv4 & IPv6)
	PeerPublicKey    string            `yaml:"peer_public_key,omitempty" json:"peer_public_key,omitempty"` // Optional peer public key
	PortRange        string            `yaml:"port_range" json:"port_range"`                               // Local forwarded port range
	RemotePortRange  string            `yaml:"remote_port_range" json:"remote_port_range"`                 // Remote peer's port range
	Hunting          *bool             `yaml:"hunting,omitempty" json:"hunting,omitempty"`                 // Enable autonomous port hunting (default: true). Set false for passive/MikroTik peers!
	Passive          bool              `yaml:"passive,omitempty" json:"passive,omitempty"`                 // Alias for hunting: false (monitor & ping only, no port rotation)
	CheckInterval    time.Duration     `yaml:"check_interval" json:"check_interval"`                       // Check frequency (default: 3s)
	HandshakeTimeout time.Duration     `yaml:"handshake_timeout" json:"handshake_timeout"`                 // Stale handshake threshold (default: 60s)
	CycleTimeout     time.Duration     `yaml:"cycle_timeout" json:"cycle_timeout"`                         // Staggered turn duration (default: 8s)
	TunnelPing       TunnelPingConfig  `yaml:"tunnel_ping" json:"tunnel_ping"`
	Obfuscation      ObfuscationConfig `yaml:"obfuscation,omitempty" json:"obfuscation"` // DPI evasion for outgoing handshake packets (Linux, needs NFQUEUE)
	HistoryFile      string            `yaml:"history_file" json:"history_file"`         // Persistent history file path
	Iptables         bool              `yaml:"iptables" json:"iptables"`                 // Manage iptables REDIRECT rule (default: true)
	PostUp           []string          `yaml:"post_up" json:"post_up"`                   // Per-tunnel post_up shell commands
	PreDown          []string          `yaml:"pre_down" json:"pre_down"`                 // Per-tunnel pre_down shell commands
}

type TunnelPingConfig struct {
	Enabled          bool          `yaml:"enabled" json:"enabled"`                     // Active in-tunnel ICMP ping
	TargetIP         string        `yaml:"target_ip" json:"target_ip"`                 // In-tunnel IP of the remote peer to ping
	Interval         time.Duration `yaml:"interval" json:"interval"`                   // Ping interval (default: 2s)
	Timeout          time.Duration `yaml:"timeout" json:"timeout"`                     // Single ping timeout (default: 2s)
	FailureThreshold int           `yaml:"failure_threshold" json:"failure_threshold"` // Consecutive failed pings before hunt (default: 3)
}

// ObfuscationConfig hides WireGuard handshake packets (148-byte initiation, 92-byte response)
// from DPI. Outgoing handshakes are intercepted via NFQUEUE and surrounded by decoy packets and/or
// split into IP fragments. Only the sender needs it; the peer can run stock WireGuard.
type ObfuscationConfig struct {
	Enabled          bool `yaml:"enabled" json:"enabled"`
	Decoys           int  `yaml:"decoys" json:"decoys"`                 // Junk UDP packets sent before every handshake packet (default: 3)
	DecoyMinSize     int  `yaml:"decoy_min_size" json:"decoy_min_size"` // Decoy payload size range in bytes (default: 40-120)
	DecoyMaxSize     int  `yaml:"decoy_max_size" json:"decoy_max_size"`
	DecoyTTL         int  `yaml:"decoy_ttl" json:"decoy_ttl"`                     // 0 = same TTL as the real packet; a low value (e.g. 4) makes decoys expire before the server
	DecoyBadChecksum bool `yaml:"decoy_bad_checksum" json:"decoy_bad_checksum"`   // Corrupt the UDP checksum so the server's stack drops decoys but DPI still sees them
	DelayMs          int  `yaml:"delay_ms" json:"delay_ms"`                       // Pause between the decoys and the real packet
	Fragment         bool `yaml:"fragment" json:"fragment"`                       // Send the real handshake as two IPv4 fragments (IPv6 is left untouched)
	FragmentSplit    int  `yaml:"fragment_split" json:"fragment_split"`           // Bytes of the UDP datagram in the first fragment, multiple of 8 (default: 8 = header only)
	QueueNum         int  `yaml:"queue_num,omitempty" json:"queue_num,omitempty"` // NFQUEUE number, 0 = assigned automatically
}

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
		setObfuscationDefaults(&t.Obfuscation)
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

func setObfuscationDefaults(o *ObfuscationConfig) {
	if o.Decoys == 0 && !o.Fragment {
		o.Decoys = 3
	}
	if o.DecoyMinSize <= 0 {
		o.DecoyMinSize = 40
	}
	if o.DecoyMaxSize <= 0 {
		o.DecoyMaxSize = 120
	}
	if o.DecoyMaxSize < o.DecoyMinSize {
		o.DecoyMaxSize = o.DecoyMinSize
	}
	if o.FragmentSplit <= 0 {
		o.FragmentSplit = 8
	}
}

// ValidateObfuscation checks the bounds of the obfuscation settings.
func ValidateObfuscation(o ObfuscationConfig) error {
	switch {
	case o.Decoys < 0 || o.Decoys > 20:
		return fmt.Errorf("decoys must be between 0 and 20")
	case o.DecoyMinSize < 1 || o.DecoyMaxSize > 1200:
		return fmt.Errorf("decoy sizes must be between 1 and 1200 bytes")
	case o.DecoyMinSize > o.DecoyMaxSize:
		return fmt.Errorf("decoy_min_size must not exceed decoy_max_size")
	case o.DecoyTTL < 0 || o.DecoyTTL > 255:
		return fmt.Errorf("decoy_ttl must be between 0 and 255")
	case o.DelayMs < 0 || o.DelayMs > 1000:
		return fmt.Errorf("delay_ms must be between 0 and 1000")
	case o.FragmentSplit < 8 || o.FragmentSplit > 152 || o.FragmentSplit%8 != 0:
		return fmt.Errorf("fragment_split must be a multiple of 8 between 8 and 152")
	case o.QueueNum < 0 || o.QueueNum > 65535:
		return fmt.Errorf("queue_num must be between 0 and 65535")
	}
	return nil
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
	var spans []portSpan

	for i, t := range cfg.Tunnels {
		iface := strings.TrimSpace(t.Interface)
		if iface == "" {
			return fmt.Errorf("tunnel #%d missing 'interface'", i+1)
		}
		if seenIfaces[iface] {
			return fmt.Errorf("duplicate interface %q configured", iface)
		}
		seenIfaces[iface] = true

		if t.Obfuscation.Enabled {
			if err := ValidateObfuscation(t.Obfuscation); err != nil {
				return fmt.Errorf("tunnel %q obfuscation: %w", iface, err)
			}
		}

		if t.Iptables && t.PortRange != "" {
			start, end, err := ParsePortRange(t.PortRange)
			if err != nil {
				return fmt.Errorf("tunnel %q port_range error: %w", iface, err)
			}
			for _, prev := range spans {
				if start <= prev.end && prev.start <= end {
					return fmt.Errorf("port_range conflict: tunnel %q (%d-%d) overlaps with tunnel %q (%d-%d)",
						iface, start, end, prev.iface, prev.start, prev.end)
				}
			}
			spans = append(spans, portSpan{iface: iface, start: start, end: end})
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
