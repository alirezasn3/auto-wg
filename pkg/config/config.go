package config

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	WireGuard  WireGuardConfig  `yaml:"wireguard"`
	Iptables   IptablesConfig   `yaml:"iptables"`
	Hunter     HunterConfig     `yaml:"hunter"`
	Web        WebConfig        `yaml:"web"`
	StatusPage StatusPageConfig `yaml:"status_page"`
}

type WireGuardConfig struct {
	Interface string `yaml:"interface"` // Interface name (default: "wg0")
	Mode      string `yaml:"mode"`      // "wgctrl" (default) or "cli"
	Command   string `yaml:"command"`   // "wg" (default) or "awg" (AmneziaWG)
}

type IptablesConfig struct {
	Enabled   bool   `yaml:"enabled"`    // Automatically manage iptables redirect rule (default: true)
	PortRange string `yaml:"port_range"` // Local forwarded range, e.g. "20000-30000"
}

type HunterConfig struct {
	RemotePortRange  string           `yaml:"remote_port_range"` // Remote peer's forwarded port range
	CheckInterval    time.Duration    `yaml:"check_interval"`    // Check frequency (default: 3s)
	HandshakeTimeout time.Duration    `yaml:"handshake_timeout"` // Stale threshold to trigger hunt (default: 15s)
	CycleTimeout     time.Duration    `yaml:"cycle_timeout"`     // Staggered turn duration (default: 8s)
	TunnelPing       TunnelPingConfig `yaml:"tunnel_ping"`
}

type TunnelPingConfig struct {
	Enabled          bool          `yaml:"enabled"`           // Active in-tunnel ICMP ping
	TargetIP         string        `yaml:"target_ip"`         // In-tunnel IP of the remote peer to ping (e.g. "10.0.0.1")
	Interval         time.Duration `yaml:"interval"`          // Ping interval (default: 2s)
	Timeout          time.Duration `yaml:"timeout"`           // Single ping timeout (default: 2s)
	FailureThreshold int           `yaml:"failure_threshold"` // Consecutive failed pings before hunt (default: 3)
}

type WebConfig struct {
	Enabled    bool     `yaml:"enabled"`     // Enable web dashboard (default: true)
	ListenAddr string   `yaml:"listen_addr"` // e.g. "0.0.0.0:8080"
	Username   string   `yaml:"username"`    // Optional HTTP Basic Auth
	Password   string   `yaml:"password"`
	AllowedIPs []string `yaml:"allowed_ips"` // Whitelist of client IPs or CIDRs (e.g. ["127.0.0.1", "192.168.1.0/24"]). If empty, all IPs allowed.
	HTTPS      bool     `yaml:"https"`       // Enable HTTPS/TLS (default: false)
	CertFile   string   `yaml:"cert_file"`   // Path to SSL certificate (PEM)
	KeyFile    string   `yaml:"key_file"`    // Path to SSL private key (PEM)
}

type StatusPageConfig struct {
	Enabled    bool   `yaml:"enabled"`     // Enable public status page (default: false)
	ListenAddr string `yaml:"listen_addr"` // e.g. "0.0.0.0:8081" (or "0.0.0.0:8443" for HTTPS)
	Title      string `yaml:"title"`       // Optional custom title (default: "Service Status")
	HTTPS      bool   `yaml:"https"`       // Enable HTTPS/TLS (default: false)
	CertFile   string `yaml:"cert_file"`   // Path to SSL certificate (PEM)
	KeyFile    string `yaml:"key_file"`    // Path to SSL private key (PEM)
}

// LoadConfig reads and parses configuration from a YAML file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	cfg := &Config{}
	// Default TunnelPing to enabled before unmarshaling so it's on by default
	cfg.Hunter.TunnelPing.Enabled = true

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config yaml: %w", err)
	}

	SetDefaults(cfg)
	return cfg, nil
}

// SaveConfig serializes the configuration back to a YAML file.
func SaveConfig(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config yaml: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	return nil
}

// SetDefaults applies sensible defaults to empty configuration fields.
func SetDefaults(cfg *Config) {
	if cfg.WireGuard.Interface == "" {
		cfg.WireGuard.Interface = "wg0"
	}
	if cfg.WireGuard.Mode == "" {
		cfg.WireGuard.Mode = "wgctrl"
	}
	if cfg.WireGuard.Command == "" {
		cfg.WireGuard.Command = "wg"
	}

	if cfg.Iptables.PortRange == "" {
		cfg.Iptables.PortRange = "20000-30000"
	}

	if cfg.Hunter.RemotePortRange == "" {
		cfg.Hunter.RemotePortRange = "20000-30000"
	}
	if cfg.Hunter.CheckInterval == 0 {
		cfg.Hunter.CheckInterval = 3 * time.Second
	}
	if cfg.Hunter.HandshakeTimeout == 0 {
		cfg.Hunter.HandshakeTimeout = 60 * time.Second
	}
	if cfg.Hunter.CycleTimeout == 0 {
		cfg.Hunter.CycleTimeout = 8 * time.Second
	}
	if cfg.Hunter.TunnelPing.Interval == 0 {
		cfg.Hunter.TunnelPing.Interval = 2 * time.Second
	}
	if cfg.Hunter.TunnelPing.Timeout == 0 {
		cfg.Hunter.TunnelPing.Timeout = 2 * time.Second
	}
	if cfg.Hunter.TunnelPing.FailureThreshold == 0 {
		cfg.Hunter.TunnelPing.FailureThreshold = 3
	}

	if cfg.Web.ListenAddr == "" {
		cfg.Web.ListenAddr = "0.0.0.0:8080"
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

// ParsePortRange splits a port range string like "20000-30000" or "20000:30000" into start and end integers.
func ParsePortRange(rangeStr string) (int, int, error) {
	rangeStr = strings.TrimSpace(rangeStr)
	rangeStr = strings.ReplaceAll(rangeStr, ":", "-")
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid port range %q (expected format: start-end)", rangeStr)
	}

	start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid start port in %q: %w", rangeStr, err)
	}
	end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid end port in %q: %w", rangeStr, err)
	}

	if start < 1 || end > 65535 || start > end {
		return 0, 0, fmt.Errorf("out-of-bounds port range %d-%d (must be 1-65535 and start <= end)", start, end)
	}

	return start, end, nil
}

// PickRandomPort picks a random integer within a port range.
func PickRandomPort(rangeStr string) (int, error) {
	start, end, err := ParsePortRange(rangeStr)
	if err != nil {
		return 0, err
	}

	delta := int64(end - start + 1)
	n, err := rand.Int(rand.Reader, big.NewInt(delta))
	if err != nil {
		return start, err
	}

	return start + int(n.Int64()), nil
}
