package obfs

import (
	"sync"

	"auto-wg/pkg/config"
	"auto-wg/pkg/iptables"
	"auto-wg/pkg/logger"
)

const baseQueue = 4200

type managed struct {
	engine    *Engine
	portRange string
	queue     int
}

// Manager runs one Engine per tunnel that has obfuscation enabled and keeps the NFQUEUE rules in sync.
type Manager struct {
	ipt *iptables.Manager
	log *logger.Logger

	mu      sync.Mutex
	engines map[string]*managed
}

func NewManager(ipt *iptables.Manager, log *logger.Logger) *Manager {
	return &Manager{ipt: ipt, log: log, engines: make(map[string]*managed)}
}

// Apply starts, updates or stops obfuscation for a tunnel to match its configuration.
func (m *Manager) Apply(t config.TunnelConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cur := m.engines[t.Interface]
	if !t.Obfuscation.Enabled || m.ipt == nil {
		m.removeLocked(t.Interface)
		return
	}

	queue := t.Obfuscation.QueueNum
	if queue == 0 {
		queue = m.queueForLocked(t.Interface)
	}

	if cur != nil && cur.queue == queue && cur.portRange == t.PortRange {
		cur.engine.Update(t.Obfuscation)
		return
	}
	m.removeLocked(t.Interface)

	engine, err := NewEngine(t.Interface, queue, t.Obfuscation, m.log)
	if err != nil {
		m.log.Warn("OBFS", "[%s] Handshake obfuscation unavailable: %v", t.Interface, err)
		return
	}
	if err := m.ipt.ApplyQueueRules(t.Interface, t.PortRange, queue); err != nil {
		m.log.Warn("OBFS", "[%s] Handshake obfuscation unavailable: %v", t.Interface, err)
		engine.Close()
		return
	}
	m.engines[t.Interface] = &managed{engine: engine, portRange: t.PortRange, queue: queue}
	o := t.Obfuscation
	m.log.Info("OBFS", "[%s] Handshake obfuscation on (queue %d): %d decoys of %d-%d bytes, ttl=%d, bad_checksum=%v, fragment=%v",
		t.Interface, queue, o.Decoys, o.DecoyMinSize, o.DecoyMaxSize, o.DecoyTTL, o.DecoyBadChecksum, o.Fragment)
}

// Remove stops obfuscation for a tunnel.
func (m *Manager) Remove(iface string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeLocked(iface)
}

// Close stops every engine and removes all NFQUEUE rules.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for iface := range m.engines {
		m.removeLocked(iface)
	}
}

// Status returns the counters of every running engine, keyed by interface.
func (m *Manager) Status() map[string]Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]Status, len(m.engines))
	for iface, e := range m.engines {
		out[iface] = e.engine.Status()
	}
	return out
}

func (m *Manager) removeLocked(iface string) {
	e, ok := m.engines[iface]
	if !ok {
		return
	}
	m.ipt.RemoveQueueRules(iface)
	e.engine.Close()
	delete(m.engines, iface)
	m.log.Info("OBFS", "[%s] Handshake obfuscation stopped", iface)
}

// queueForLocked keeps an interface on the same automatic queue across reconfigurations.
func (m *Manager) queueForLocked(iface string) int {
	if e, ok := m.engines[iface]; ok {
		return e.queue
	}
	used := make(map[int]bool, len(m.engines))
	for _, e := range m.engines {
		used[e.queue] = true
	}
	q := baseQueue
	for used[q] {
		q++
	}
	return q
}
