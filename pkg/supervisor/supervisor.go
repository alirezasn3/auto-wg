package supervisor

import (
	"context"
	"fmt"
	"sync"

	"auto-wg/pkg/cmdexec"
	"auto-wg/pkg/config"
	"auto-wg/pkg/hunter"
	"auto-wg/pkg/iptables"
	"auto-wg/pkg/logger"
	"auto-wg/pkg/wg"
)

type SupervisorStatus struct {
	hunter.StatusReport `json:",inline"`

	Mode         string                         `json:"mode"`
	ActiveTunnel string                         `json:"active_tunnel,omitempty"`
	Routing      config.RoutingConfig           `json:"routing"`
	Tunnels      map[string]hunter.StatusReport `json:"tunnels"`
	TunnelOrder  []string                       `json:"tunnel_order"`
}

type Supervisor struct {
	cfgPath      string
	cfg          *config.Config
	wgCtrl       *wg.Controller
	iptMgr       *iptables.Manager
	log          *logger.Logger
	mu           sync.RWMutex
	hunters      map[string]*hunter.Hunter
	tunnelOrder  []string
	routeManager *RouteManager
}

// New creates a new Supervisor to manage multiple WireGuard tunnels.
func New(cfgPath string, cfg *config.Config, wgCtrl *wg.Controller, iptMgr *iptables.Manager, log *logger.Logger) *Supervisor {
	config.SetDefaults(cfg)

	s := &Supervisor{
		cfgPath:     cfgPath,
		cfg:         cfg,
		wgCtrl:      wgCtrl,
		iptMgr:      iptMgr,
		log:         log,
		hunters:     make(map[string]*hunter.Hunter),
		tunnelOrder: make([]string, 0, len(cfg.Tunnels)),
	}

	for _, t := range cfg.Tunnels {
		s.tunnelOrder = append(s.tunnelOrder, t.Interface)
		h := hunter.New(t, wgCtrl, iptMgr, log, s.handleStateChange)
		s.hunters[t.Interface] = h
	}

	if cfg.Mode == "client" && cfg.Routing.Enabled {
		s.routeManager = NewRouteManager(cfg.Routing, s.hunters, s.tunnelOrder, log)
	}

	return s
}

func (s *Supervisor) handleStateChange(h *hunter.Hunter, oldState, newState string) {
	if s.routeManager != nil {
		s.routeManager.Evaluate()
	}
}

// Start launches all tunnels, executes PostUp commands, and monitors connections.
func (s *Supervisor) Start(ctx context.Context) {
	s.log.Info("SUPERVISOR", "=================================================================")
	s.log.Info("SUPERVISOR", " Starting Auto-WG Supervisor (Mode: %s, %d managed tunnels)", s.cfg.Mode, len(s.hunters))
	s.log.Info("SUPERVISOR", "=================================================================")

	// 1. Run Global PostUp shell commands
	if len(s.cfg.PostUp) > 0 {
		s.log.Info("SUPERVISOR", "Executing global PostUp commands (%d commands)...", len(s.cfg.PostUp))
		if err := cmdexec.RunCommands(ctx, s.cfg.PostUp, "POSTUP", s.log); err != nil {
			s.log.Warn("SUPERVISOR", "Global PostUp error: %v", err)
		}
	}

	// 2. Start each tunnel hunter and run per-tunnel PostUp
	var wgGroup sync.WaitGroup
	for _, iface := range s.tunnelOrder {
		h := s.hunters[iface]
		if h == nil {
			continue
		}

		// Per-tunnel PostUp
		tCfg := s.getTunnelConfig(iface)
		if len(tCfg.PostUp) > 0 {
			s.log.Info("SUPERVISOR", "[%s] Executing tunnel PostUp commands (%d commands)...", iface, len(tCfg.PostUp))
			if err := cmdexec.RunCommands(ctx, tCfg.PostUp, fmt.Sprintf("POSTUP-%s", iface), s.log); err != nil {
				s.log.Warn("SUPERVISOR", "[%s] Tunnel PostUp error: %v", iface, err)
			}
		}

		wgGroup.Add(1)
		go func(hunterInstance *hunter.Hunter) {
			defer wgGroup.Done()
			hunterInstance.Start(ctx)
		}(h)
	}

	// 3. Initial route evaluation if in client mode
	if s.routeManager != nil {
		s.routeManager.Evaluate()
	}

	// Wait for shutdown signal
	<-ctx.Done()
	s.log.Info("SUPERVISOR", "Shutdown signal received. Tearing down tunnels...")

	// 4. Save persistent history for all tunnels
	_ = s.SaveAllHistory()

	// 5. Run per-tunnel PreDown commands
	for _, iface := range s.tunnelOrder {
		tCfg := s.getTunnelConfig(iface)
		if len(tCfg.PreDown) > 0 {
			s.log.Info("SUPERVISOR", "[%s] Executing tunnel PreDown commands (%d commands)...", iface, len(tCfg.PreDown))
			_ = cmdexec.RunCommands(context.Background(), tCfg.PreDown, fmt.Sprintf("PREDOWN-%s", iface), s.log)
		}
	}

	// 6. Remove all iptables forwarding rules
	if s.iptMgr != nil {
		_ = s.iptMgr.RemoveAllRules()
	}

	// 7. Run Global PreDown shell commands
	if len(s.cfg.PreDown) > 0 {
		s.log.Info("SUPERVISOR", "Executing global PreDown commands (%d commands)...", len(s.cfg.PreDown))
		_ = cmdexec.RunCommands(context.Background(), s.cfg.PreDown, "PREDOWN", s.log)
	}

	wgGroup.Wait()
	s.log.Info("SUPERVISOR", "Supervisor stopped cleanly.")
}

func (s *Supervisor) getTunnelConfig(iface string) config.TunnelConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.cfg.Tunnels {
		if t.Interface == iface {
			return t
		}
	}
	return config.TunnelConfig{}
}

// GetStatus compiles the status report for all managed tunnels.
func (s *Supervisor) GetStatus() SupervisorStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	active := ""
	if s.routeManager != nil {
		active = s.routeManager.GetActiveTunnel()
	}

	reports := make(map[string]hunter.StatusReport, len(s.hunters))
	for iface, h := range s.hunters {
		reports[iface] = h.GetStatus()
	}

	orderCopy := make([]string, len(s.tunnelOrder))
	copy(orderCopy, s.tunnelOrder)

	var primaryReport hunter.StatusReport
	if active != "" {
		if r, ok := reports[active]; ok {
			primaryReport = r
		}
	}
	if primaryReport.Interface == "" && len(orderCopy) > 0 {
		if r, ok := reports[orderCopy[0]]; ok {
			primaryReport = r
		}
	}

	return SupervisorStatus{
		StatusReport: primaryReport,
		Mode:         s.cfg.Mode,
		ActiveTunnel: active,
		Routing:      s.cfg.Routing,
		Tunnels:      reports,
		TunnelOrder:  orderCopy,
	}
}

// GetHunter returns the Hunter instance for a specific interface.
func (s *Supervisor) GetHunter(iface string) (*hunter.Hunter, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.hunters[iface]
	return h, ok
}

// GetAllHunters returns a slice of all active Hunter instances.
func (s *Supervisor) GetAllHunters() []*hunter.Hunter {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]*hunter.Hunter, 0, len(s.tunnelOrder))
	for _, iface := range s.tunnelOrder {
		if h, ok := s.hunters[iface]; ok {
			list = append(list, h)
		}
	}
	return list
}

// TriggerHunt triggers an immediate hunt cycle for a specific interface (or all if iface is "").
func (s *Supervisor) TriggerHunt(iface, reason string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if iface == "" || iface == "all" {
		for _, h := range s.hunters {
			h.TriggerHunt(reason)
		}
		return nil
	}

	h, ok := s.hunters[iface]
	if !ok {
		return fmt.Errorf("tunnel %q not found", iface)
	}
	h.TriggerHunt(reason)
	return nil
}

// TriggerRebind rotates the local port for a specific interface.
func (s *Supervisor) TriggerRebind(iface string) error {
	s.mu.RLock()
	h, ok := s.hunters[iface]
	s.mu.RUnlock()

	if !ok {
		return fmt.Errorf("tunnel %q not found", iface)
	}
	return h.TriggerRebind()
}

// SwitchActiveTunnel manually overrides the active upstream route in client mode.
func (s *Supervisor) SwitchActiveTunnel(iface string) error {
	s.mu.RLock()
	rm := s.routeManager
	s.mu.RUnlock()

	if rm == nil {
		return fmt.Errorf("route failover manager is not active (mode must be client with routing.enabled=true)")
	}
	return rm.ForceSwitch(iface)
}

// SaveAllHistory flushes history to disk for all tunnels.
func (s *Supervisor) SaveAllHistory() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var firstErr error
	for _, h := range s.hunters {
		if err := h.SaveHistory(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// GetConfig returns current supervisor configuration.
func (s *Supervisor) GetConfig() config.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return *s.cfg
}

// UpdateConfig updates the in-memory supervisor configuration.
func (s *Supervisor) UpdateConfig(newCfg *config.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	config.SetDefaults(newCfg)
	s.cfg = newCfg
	return nil
}
