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
	ipt4        *goiptables.IPTables
	ipt6        *goiptables.IPTables
	log         *logger.Logger
	mu          sync.Mutex
	activeRules map[string][]string // iface -> ruleSpec
	isLinux     bool
}

// NewManager initializes the iptables and ip6tables managers.
func NewManager(log *logger.Logger) *Manager {
	ipt4, err4 := goiptables.NewWithProtocol(goiptables.ProtocolIPv4)
	ipt6, err6 := goiptables.NewWithProtocol(goiptables.ProtocolIPv6)

	if err4 != nil && err6 != nil {
		log.Warn("IPTABLES", "iptables/ip6tables is not available on this system (%v). Port forwarding rules must be set manually if running outside Linux.", err4)
		return &Manager{
			log:         log,
			activeRules: make(map[string][]string),
			isLinux:     false,
		}
	}

	return &Manager{
		ipt4:        ipt4,
		ipt6:        ipt6,
		log:         log,
		activeRules: make(map[string][]string),
		isLinux:     true,
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

// ApplyForwardingRule installs the UDP NAT PREROUTING REDIRECT rule of a WireGuard interface.
func (m *Manager) ApplyForwardingRule(iface string, portRangeSpec string, targetPort int) error {
	return m.ApplyRedirect(iface, "udp", portRangeSpec, targetPort)
}

// ApplyRedirect installs the NAT PREROUTING REDIRECT rule for IPv4 and IPv6 under a key (an interface
// name, or "<iface>-tls" for the TCP rule of the TLS path):
// iptables/ip6tables -t nat -A PREROUTING -p <proto> --dport <start>:<end> -m comment --comment "autowg-<key>" -j REDIRECT --to-ports <targetPort>
func (m *Manager) ApplyRedirect(key, proto, portRangeSpec string, targetPort int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	iface := key

	if !m.isLinux {
		m.log.Warn("IPTABLES", "Skipping iptables configuration for %s (non-Linux or iptables binary missing)", iface)
		return nil
	}

	dport, err := FormatIptablesPortRange(portRangeSpec)
	if err != nil {
		return fmt.Errorf("format port range: %w", err)
	}

	comment := CommentPrefix + iface
	ruleSpec := []string{
		"-p", proto,
		"--dport", dport,
		"-m", "comment",
		"--comment", comment,
		"-j", "REDIRECT",
		"--to-ports", strconv.Itoa(targetPort),
	}

	// Remove previous rule for this interface if port range or targetPort changed
	if oldRule, ok := m.activeRules[iface]; ok && !sliceEqual(oldRule, ruleSpec) {
		if m.ipt4 != nil {
			_ = m.ipt4.DeleteIfExists("nat", "PREROUTING", oldRule...)
		}
		if m.ipt6 != nil {
			_ = m.ipt6.DeleteIfExists("nat", "PREROUTING", oldRule...)
		}
	}

	// 1. IPv4 (iptables)
	if m.ipt4 != nil {
		exists, err := m.ipt4.Exists("nat", "PREROUTING", ruleSpec...)
		if err == nil && !exists {
			if err := m.ipt4.AppendUnique("nat", "PREROUTING", ruleSpec...); err != nil {
				m.log.Warn("IPTABLES", "[%s] Failed to append IPv4 rule: %v", iface, err)
			} else {
				m.log.Info("IPTABLES", "[%s] Applied IPv4 NAT REDIRECT: %s dport %s -> local port %d", iface, proto, dport, targetPort)
			}
		} else if exists {
			m.log.Info("IPTABLES", "[%s] IPv4 forwarding rule already active: %s %s -> local port %d", iface, proto, dport, targetPort)
		}
	}

	// 2. IPv6 (ip6tables)
	if m.ipt6 != nil {
		exists, err := m.ipt6.Exists("nat", "PREROUTING", ruleSpec...)
		if err == nil && !exists {
			if err := m.ipt6.AppendUnique("nat", "PREROUTING", ruleSpec...); err != nil {
				m.log.Warn("IPTABLES", "[%s] Failed to append IPv6 rule (ip6tables nat might not be supported in kernel): %v", iface, err)
			} else {
				m.log.Info("IPTABLES", "[%s] Applied IPv6 NAT REDIRECT: %s dport %s -> local port %d", iface, proto, dport, targetPort)
			}
		} else if exists {
			m.log.Info("IPTABLES", "[%s] IPv6 forwarding rule already active: %s %s -> local port %d", iface, proto, dport, targetPort)
		}
	}

	m.activeRules[iface] = ruleSpec
	return nil
}

// RemoveRule deletes the active forwarding rule for a specific interface.
func (m *Manager) RemoveRule(iface string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isLinux {
		return nil
	}

	ruleSpec, ok := m.activeRules[iface]
	if !ok || len(ruleSpec) == 0 {
		return nil
	}

	m.log.Info("IPTABLES", "[%s] Removing active NAT forwarding rule: %v", iface, ruleSpec)
	if m.ipt4 != nil {
		_ = m.ipt4.DeleteIfExists("nat", "PREROUTING", ruleSpec...)
	}
	if m.ipt6 != nil {
		_ = m.ipt6.DeleteIfExists("nat", "PREROUTING", ruleSpec...)
	}
	delete(m.activeRules, iface)
	return nil
}

// RemoveAllRules deletes all active forwarding rules managed by this manager.
func (m *Manager) RemoveAllRules() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isLinux || len(m.activeRules) == 0 {
		return nil
	}

	for iface, ruleSpec := range m.activeRules {
		m.log.Info("IPTABLES", "[%s] Removing active NAT forwarding rule: %v", iface, ruleSpec)
		if m.ipt4 != nil {
			_ = m.ipt4.DeleteIfExists("nat", "PREROUTING", ruleSpec...)
		}
		if m.ipt6 != nil {
			_ = m.ipt6.DeleteIfExists("nat", "PREROUTING", ruleSpec...)
		}
	}
	m.activeRules = make(map[string][]string)
	return nil
}

// CommentPrefix tags every rule this package installs, so leftovers can be recognised.
const CommentPrefix = "autowg-"

// staleRuleSpec turns a listed rule (`-A PREROUTING ... --comment autowg-wg0 ...`) into arguments for a
// delete, if it carries an autowg- comment. The comment token is unquoted, because the arguments are passed to
// iptables directly and not through a shell.
func staleRuleSpec(line string) (spec []string, key string, ok bool) {
	f := strings.Fields(line)
	if len(f) < 3 || f[0] != "-A" || f[1] != "PREROUTING" {
		return nil, "", false
	}
	spec = append([]string(nil), f[2:]...)
	for i := 0; i+1 < len(spec); i++ {
		if spec[i] != "--comment" {
			continue
		}
		val := strings.Trim(spec[i+1], `"'`)
		if !strings.HasPrefix(val, CommentPrefix) {
			return nil, "", false
		}
		spec[i+1] = val
		return spec, strings.TrimPrefix(val, CommentPrefix), true
	}
	return nil, "", false
}

// RemoveStaleRules deletes NAT PREROUTING rules tagged autowg-* that this process does not manage: the ones a
// previous run left behind after a crash or kill -9, and the ones of tunnels that are no longer configured. They
// would otherwise stay in front of the fresh rules and keep redirecting to a port nothing listens on. Call it
// before applying rules. It returns how many rules it removed.
func (m *Manager) RemoveStaleRules() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isLinux {
		return 0
	}
	removed := 0
	for _, fam := range []struct {
		name string
		ipt  *goiptables.IPTables
	}{{"IPv4", m.ipt4}, {"IPv6", m.ipt6}} {
		if fam.ipt == nil {
			continue
		}
		lines, err := fam.ipt.List("nat", "PREROUTING")
		if err != nil {
			continue
		}
		for _, line := range lines {
			spec, key, ok := staleRuleSpec(line)
			if !ok {
				continue
			}
			if _, managed := m.activeRules[key]; managed {
				continue
			}
			if err := fam.ipt.Delete("nat", "PREROUTING", spec...); err != nil {
				m.log.Warn("IPTABLES", "Could not remove stale %s rule %q: %v", fam.name, line, err)
				continue
			}
			removed++
			m.log.Info("IPTABLES", "Removed stale %s NAT rule left by a previous run: %s", fam.name, strings.TrimPrefix(line, "-A PREROUTING "))
		}
	}
	return removed
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
