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
	queueRules  map[string][]queueRule
	isLinux     bool
}

// queueRule is one mangle/OUTPUT NFQUEUE rule installed for handshake obfuscation.
type queueRule struct {
	v6   bool
	spec []string
}

// Total IP packet lengths of a WireGuard handshake initiation (148 byte payload) and response (92 byte
// payload) including IP and UDP headers. Data packets are 32+16n bytes and can never collide with these.
var (
	handshakeLengthsV4 = []int{176, 120}
	handshakeLengthsV6 = []int{196, 140}
)

// NewManager initializes the iptables and ip6tables managers.
func NewManager(log *logger.Logger) *Manager {
	ipt4, err4 := goiptables.NewWithProtocol(goiptables.ProtocolIPv4)
	ipt6, err6 := goiptables.NewWithProtocol(goiptables.ProtocolIPv6)

	if err4 != nil && err6 != nil {
		log.Warn("IPTABLES", "iptables/ip6tables is not available on this system (%v). Port forwarding rules must be set manually if running outside Linux.", err4)
		return &Manager{
			log:         log,
			activeRules: make(map[string][]string),
			queueRules:  make(map[string][]queueRule),
			isLinux:     false,
		}
	}

	return &Manager{
		ipt4:        ipt4,
		ipt6:        ipt6,
		log:         log,
		activeRules: make(map[string][]string),
		queueRules:  make(map[string][]queueRule),
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

// ApplyForwardingRule installs the NAT PREROUTING REDIRECT rule for IPv4 and IPv6 for a given interface:
// iptables/ip6tables -t nat -A PREROUTING -p udp --dport <start>:<end> -m comment --comment "autowg-<iface>" -j REDIRECT --to-ports <targetPort>
func (m *Manager) ApplyForwardingRule(iface string, portRangeSpec string, targetPort int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isLinux {
		m.log.Warn("IPTABLES", "Skipping iptables configuration for %s (non-Linux or iptables binary missing)", iface)
		return nil
	}

	dport, err := FormatIptablesPortRange(portRangeSpec)
	if err != nil {
		return fmt.Errorf("format port range: %w", err)
	}

	comment := fmt.Sprintf("autowg-%s", iface)
	ruleSpec := []string{
		"-p", "udp",
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
				m.log.Info("IPTABLES", "[%s] Applied IPv4 NAT REDIRECT: UDP dport %s -> WireGuard port %d", iface, dport, targetPort)
			}
		} else if exists {
			m.log.Info("IPTABLES", "[%s] IPv4 forwarding rule already active: UDP %s -> WireGuard port %d", iface, dport, targetPort)
		}
	}

	// 2. IPv6 (ip6tables)
	if m.ipt6 != nil {
		exists, err := m.ipt6.Exists("nat", "PREROUTING", ruleSpec...)
		if err == nil && !exists {
			if err := m.ipt6.AppendUnique("nat", "PREROUTING", ruleSpec...); err != nil {
				m.log.Warn("IPTABLES", "[%s] Failed to append IPv6 rule (ip6tables nat might not be supported in kernel): %v", iface, err)
			} else {
				m.log.Info("IPTABLES", "[%s] Applied IPv6 NAT REDIRECT: UDP dport %s -> WireGuard port %d", iface, dport, targetPort)
			}
		} else if exists {
			m.log.Info("IPTABLES", "[%s] IPv6 forwarding rule already active: UDP %s -> WireGuard port %d", iface, dport, targetPort)
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

	for iface := range m.queueRules {
		m.removeQueueRulesLocked(iface)
	}

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

func (m *Manager) tableFor(v6 bool) *goiptables.IPTables {
	if v6 {
		return m.ipt6
	}
	return m.ipt4
}

// ApplyQueueRules sends outgoing WireGuard handshake packets from the tunnel's port range to an NFQUEUE:
// iptables -t mangle -I OUTPUT -p udp --sport <range> -m length --length <n> -j NFQUEUE --queue-num <q> --queue-bypass
// --queue-bypass makes the kernel accept the packet untouched if nothing is listening on the queue.
func (m *Manager) ApplyQueueRules(iface, portRangeSpec string, queue int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isLinux {
		return fmt.Errorf("iptables is not available on this system")
	}
	sport, err := FormatIptablesPortRange(portRangeSpec)
	if err != nil {
		return fmt.Errorf("format port range: %w", err)
	}

	var want []queueRule
	for _, v6 := range []bool{false, true} {
		lengths := handshakeLengthsV4
		if v6 {
			lengths = handshakeLengthsV6
		}
		for _, n := range lengths {
			want = append(want, queueRule{v6: v6, spec: []string{
				"-p", "udp", "--sport", sport,
				"-m", "length", "--length", strconv.Itoa(n),
				"-m", "comment", "--comment", "autowg-obfs-" + iface,
				"-j", "NFQUEUE", "--queue-num", strconv.Itoa(queue), "--queue-bypass",
			}})
		}
	}

	m.removeQueueRulesLocked(iface)
	var firstErr error
	for _, r := range want {
		ipt := m.tableFor(r.v6)
		if ipt == nil {
			continue
		}
		exists, err := ipt.Exists("mangle", "OUTPUT", r.spec...)
		if err == nil && exists {
			m.queueRules[iface] = append(m.queueRules[iface], r)
			continue
		}
		if err := ipt.Insert("mangle", "OUTPUT", 1, r.spec...); err != nil {
			m.log.Warn("IPTABLES", "[%s] Failed to insert NFQUEUE rule (ipv6=%v): %v", iface, r.v6, err)
			if !r.v6 && firstErr == nil {
				firstErr = err
			}
			continue
		}
		m.queueRules[iface] = append(m.queueRules[iface], r)
	}
	if firstErr != nil {
		m.removeQueueRulesLocked(iface)
		return fmt.Errorf("insert NFQUEUE rules: %w", firstErr)
	}
	m.log.Info("IPTABLES", "[%s] Handshake NFQUEUE rules active: UDP sport %s -> queue %d", iface, sport, queue)
	return nil
}

// RemoveQueueRules deletes the NFQUEUE rules of a tunnel.
func (m *Manager) RemoveQueueRules(iface string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeQueueRulesLocked(iface)
}

func (m *Manager) removeQueueRulesLocked(iface string) {
	for _, r := range m.queueRules[iface] {
		if ipt := m.tableFor(r.v6); ipt != nil {
			_ = ipt.DeleteIfExists("mangle", "OUTPUT", r.spec...)
		}
	}
	delete(m.queueRules, iface)
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
