package iptables

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"auto-wg/pkg/logger"

	goiptables "github.com/coreos/go-iptables/iptables"
)

type Manager struct {
	ipt4       *goiptables.IPTables
	ipt6       *goiptables.IPTables
	log        *logger.Logger
	mu         sync.Mutex
	activeRule []string
	isLinux    bool
}

// NewManager initializes the iptables and ip6tables managers.
func NewManager(log *logger.Logger) *Manager {
	ipt4, err4 := goiptables.NewWithProtocol(goiptables.ProtocolIPv4)
	ipt6, err6 := goiptables.NewWithProtocol(goiptables.ProtocolIPv6)

	if err4 != nil && err6 != nil {
		log.Warn("IPTABLES", "iptables/ip6tables is not available on this system (%v). Port forwarding rules must be set manually if running outside Linux.", err4)
		return &Manager{
			log:     log,
			isLinux: false,
		}
	}

	return &Manager{
		ipt4:    ipt4,
		ipt6:    ipt6,
		log:     log,
		isLinux: true,
	}
}

// FormatIptablesPortRange converts "20000-30000" or "20000:30000" to "20000:30000".
func FormatIptablesPortRange(spec string) (string, error) {
	spec = strings.TrimSpace(spec)
	spec = strings.ReplaceAll(spec, "-", ":")
	parts := strings.Split(spec, ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid port range format %q, expected start:end or start-end", spec)
	}

	start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return "", fmt.Errorf("invalid start port in %q: %w", spec, err)
	}
	end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return "", fmt.Errorf("invalid end port in %q: %w", spec, err)
	}

	if start < 1 || end > 65535 || start > end {
		return "", fmt.Errorf("out-of-bounds port range %d:%d (must be 1-65535 and start <= end)", start, end)
	}

	return fmt.Sprintf("%d:%d", start, end), nil
}

// ApplyForwardingRule installs the NAT PREROUTING REDIRECT rule for IPv4 and IPv6:
// iptables/ip6tables -t nat -A PREROUTING -p udp --dport <start>:<end> -j REDIRECT --to-ports <targetPort>
func (m *Manager) ApplyForwardingRule(portRangeSpec string, targetPort int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isLinux {
		m.log.Warn("IPTABLES", "Skipping iptables configuration (non-Linux or iptables binary missing)")
		return nil
	}

	dport, err := FormatIptablesPortRange(portRangeSpec)
	if err != nil {
		return fmt.Errorf("format port range: %w", err)
	}

	ruleSpec := []string{
		"-p", "udp",
		"--dport", dport,
		"-j", "REDIRECT",
		"--to-ports", strconv.Itoa(targetPort),
	}

	// 1. IPv4 (iptables)
	if m.ipt4 != nil {
		if len(m.activeRule) > 0 && !sliceEqual(m.activeRule, ruleSpec) {
			_ = m.ipt4.DeleteIfExists("nat", "PREROUTING", m.activeRule...)
		}
		exists, err := m.ipt4.Exists("nat", "PREROUTING", ruleSpec...)
		if err == nil && !exists {
			if err := m.ipt4.AppendUnique("nat", "PREROUTING", ruleSpec...); err != nil {
				m.log.Warn("IPTABLES", "Failed to append IPv4 rule: %v", err)
			} else {
				m.log.Info("IPTABLES", "Applied IPv4 NAT REDIRECT: UDP dport %s -> WireGuard port %d", dport, targetPort)
			}
		} else if exists {
			m.log.Info("IPTABLES", "IPv4 forwarding rule already active: UDP %s -> WireGuard port %d", dport, targetPort)
		}
	}

	// 2. IPv6 (ip6tables)
	if m.ipt6 != nil {
		if len(m.activeRule) > 0 && !sliceEqual(m.activeRule, ruleSpec) {
			_ = m.ipt6.DeleteIfExists("nat", "PREROUTING", m.activeRule...)
		}
		exists, err := m.ipt6.Exists("nat", "PREROUTING", ruleSpec...)
		if err == nil && !exists {
			if err := m.ipt6.AppendUnique("nat", "PREROUTING", ruleSpec...); err != nil {
				m.log.Warn("IPTABLES", "Failed to append IPv6 rule (ip6tables nat might not be supported in kernel): %v", err)
			} else {
				m.log.Info("IPTABLES", "Applied IPv6 NAT REDIRECT: UDP dport %s -> WireGuard port %d", dport, targetPort)
			}
		} else if exists {
			m.log.Info("IPTABLES", "IPv6 forwarding rule already active: UDP %s -> WireGuard port %d", dport, targetPort)
		}
	}

	m.activeRule = ruleSpec
	return nil
}

// RemoveRule deletes the active forwarding rule from both IPv4 and IPv6.
func (m *Manager) RemoveRule() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isLinux || len(m.activeRule) == 0 {
		return nil
	}

	m.log.Info("IPTABLES", "Removing active NAT forwarding rules: %v", m.activeRule)
	if m.ipt4 != nil {
		_ = m.ipt4.DeleteIfExists("nat", "PREROUTING", m.activeRule...)
	}
	if m.ipt6 != nil {
		_ = m.ipt6.DeleteIfExists("nat", "PREROUTING", m.activeRule...)
	}
	m.activeRule = nil
	return nil
}

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
