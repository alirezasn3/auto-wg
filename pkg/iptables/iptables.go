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
	ipt        *goiptables.IPTables
	log        *logger.Logger
	mu         sync.Mutex
	activeRule []string
	isLinux    bool
}

// NewManager initializes the iptables manager.
func NewManager(log *logger.Logger) *Manager {
	ipt, err := goiptables.NewWithProtocol(goiptables.ProtocolIPv4)
	if err != nil {
		log.Warn("IPTABLES", "iptables is not available on this system (%v). Port forwarding rules must be set manually if running outside Linux.", err)
		return &Manager{
			log:     log,
			isLinux: false,
		}
	}

	return &Manager{
		ipt:     ipt,
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

// ApplyForwardingRule installs the NAT PREROUTING REDIRECT rule:
// iptables -t nat -A PREROUTING -p udp --dport <start>:<end> -j REDIRECT --to-ports <targetPort>
func (m *Manager) ApplyForwardingRule(portRangeSpec string, targetPort int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isLinux || m.ipt == nil {
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

	// Remove any previous rule if changed
	if len(m.activeRule) > 0 && !sliceEqual(m.activeRule, ruleSpec) {
		_ = m.ipt.DeleteIfExists("nat", "PREROUTING", m.activeRule...)
	}

	exists, err := m.ipt.Exists("nat", "PREROUTING", ruleSpec...)
	if err != nil {
		return fmt.Errorf("check iptables rule exists: %w", err)
	}

	if exists {
		m.log.Info("IPTABLES", "Forwarding rule already active: UDP %s -> WireGuard port %d", dport, targetPort)
		m.activeRule = ruleSpec
		return nil
	}

	if err := m.ipt.AppendUnique("nat", "PREROUTING", ruleSpec...); err != nil {
		return fmt.Errorf("append iptables rule: %w", err)
	}

	m.activeRule = ruleSpec
	m.log.Info("IPTABLES", "Applied NAT REDIRECT rule: UDP dport %s -> WireGuard port %d", dport, targetPort)
	return nil
}

// RemoveRule deletes the active forwarding rule.
func (m *Manager) RemoveRule() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isLinux || m.ipt == nil || len(m.activeRule) == 0 {
		return nil
	}

	m.log.Info("IPTABLES", "Removing active NAT forwarding rule: %v", m.activeRule)
	err := m.ipt.DeleteIfExists("nat", "PREROUTING", m.activeRule...)
	m.activeRule = nil
	return err
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
