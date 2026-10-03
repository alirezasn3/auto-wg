package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	PeerID       string            `yaml:"peer_id"`
	RemotePeerID string            `yaml:"remote_peer_id"`
	WireGuard    WireGuardConfig   `yaml:"wireguard"`
	Signaling    SignalingConfig   `yaml:"signaling"`
	Monitor      MonitorConfig     `yaml:"monitor"`
	Negotiation  NegotiationConfig `yaml:"negotiation"`
	Web          WebConfig         `yaml:"web"`
}

type WireGuardConfig struct {
	Interface     string `yaml:"interface"`       // e.g. "wg0"
	PeerPublicKey string `yaml:"peer_public_key"` // Base64 public key of remote peer
	RemoteHost    string `yaml:"remote_host"`     // Domain or IP of remote peer (without port)
	Mode          string `yaml:"mode"`            // "wgctrl" (default) or "cli" / "awg"
	Command       string `yaml:"command"`         // "wg" (default) or "awg" (AmneziaWG)
}

type SignalingConfig struct {
	SecretToken string           `yaml:"secret_token"` // Pre-shared HMAC key
	Timeout     time.Duration    `yaml:"timeout"`      // Request timeout (default: 5s)
	Cloudflare  CloudflareConfig `yaml:"cloudflare"`
	VPSRelay    VPSRelayConfig   `yaml:"vps_relay"`
	Direct      DirectConfig     `yaml:"direct"`
}

type CloudflareConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"` // e.g. "https://auto-wg.workers.dev"
}

type VPSRelayConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"` // e.g. "https://relay.mydomain.com:8443"
}

type DirectConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"` // e.g. ":9443"
	RemoteAddr string `yaml:"remote_addr"` // e.g. "peer-b.example.com:9443"
}

type MonitorConfig struct {
	CheckInterval    time.Duration    `yaml:"check_interval"`    // e.g. 3s
	HandshakeTimeout time.Duration    `yaml:"handshake_timeout"` // e.g. 150s
	TunnelPing       TunnelPingConfig `yaml:"tunnel_ping"`
}

type TunnelPingConfig struct {
	Enabled          bool          `yaml:"enabled"`           // Active in-tunnel ping
	TargetIP         string        `yaml:"target_ip"`         // e.g. "10.0.0.2"
	TargetPort       int           `yaml:"target_port"`       // e.g. 51820 or dedicated echo port
	Interval         time.Duration `yaml:"interval"`          // e.g. 2s
	FailureThreshold int           `yaml:"failure_threshold"` // consecutive failures to trigger (e.g. 4)
}

type NegotiationConfig struct {
	PortSpecs          []string      `yaml:"candidate_ports"` // e.g. ["53", "80", "123", "443", "853", "20000-20050"]
	QuickRebindFirst   bool          `yaml:"quick_rebind_first"`
	QuickRebindTimeout time.Duration `yaml:"quick_rebind_timeout"`
	ProbeTimeout       time.Duration `yaml:"probe_timeout"`
	CandidatePorts     []int         `yaml:"-"` // Parsed integer list
}

type WebConfig struct {
	Enabled    bool   `yaml:"enabled"`     // default true
	ListenAddr string `yaml:"listen_addr"` // e.g. "0.0.0.0:8080"
	Username   string `yaml:"username"`
	Password   string `yaml:"password"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config yaml: %w", err)
	}

	setDefaults(cfg)

	ports, err := ParsePortSpecs(cfg.Negotiation.PortSpecs)
	if err != nil {
		return nil, fmt.Errorf("parse candidate ports: %w", err)
	}
	cfg.Negotiation.CandidatePorts = ports

	return cfg, nil
}

func setDefaults(cfg *Config) {
	if cfg.WireGuard.Mode == "" {
		cfg.WireGuard.Mode = "wgctrl"
	}
	if cfg.WireGuard.Command == "" {
		cfg.WireGuard.Command = "wg"
	}
	if cfg.Signaling.Timeout == 0 {
		cfg.Signaling.Timeout = 5 * time.Second
	}
	if cfg.Monitor.CheckInterval == 0 {
		cfg.Monitor.CheckInterval = 3 * time.Second
	}
	if cfg.Monitor.HandshakeTimeout == 0 {
		cfg.Monitor.HandshakeTimeout = 150 * time.Second
	}
	if cfg.Monitor.TunnelPing.Interval == 0 {
		cfg.Monitor.TunnelPing.Interval = 2 * time.Second
	}
	if cfg.Monitor.TunnelPing.FailureThreshold == 0 {
		cfg.Monitor.TunnelPing.FailureThreshold = 4
	}
	if cfg.Negotiation.QuickRebindTimeout == 0 {
		cfg.Negotiation.QuickRebindTimeout = 8 * time.Second
	}
	if cfg.Negotiation.ProbeTimeout == 0 {
		cfg.Negotiation.ProbeTimeout = 12 * time.Second
	}
	if len(cfg.Negotiation.PortSpecs) == 0 {
		cfg.Negotiation.PortSpecs = []string{"53", "80", "123", "443", "853", "500", "4500", "51820", "20000-20050"}
	}
	if cfg.Web.ListenAddr == "" {
		cfg.Web.ListenAddr = "0.0.0.0:8080"
	}
}

// ParsePortSpecs expands port specifications like ["53", "80", "20000-20010"] into a slice of unique ports.
func ParsePortSpecs(specs []string) ([]int, error) {
	portMap := make(map[int]bool)
	var result []int

	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}

		if strings.Contains(spec, "-") {
			parts := strings.Split(spec, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", spec)
			}
			start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port in range %s: %w", spec, err)
			}
			end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port in range %s: %w", spec, err)
			}
			if start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("out-of-bounds port range: %s", spec)
			}
			for p := start; p <= end; p++ {
				if !portMap[p] {
					portMap[p] = true
					result = append(result, p)
				}
			}
		} else {
			p, err := strconv.Atoi(spec)
			if err != nil {
				return nil, fmt.Errorf("invalid port %s: %w", spec, err)
			}
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("port %d out of bounds (1-65535)", p)
			}
			if !portMap[p] {
				portMap[p] = true
				result = append(result, p)
			}
		}
	}

	return result, nil
}
