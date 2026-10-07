package supervisor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

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
	cfgPath       string
	cfg           *config.Config
	wgCtrl        *wg.Controller
	iptMgr        *iptables.Manager
	log           *logger.Logger
	mu            sync.RWMutex
	hunters       map[string]*hunter.Hunter
	tunnelOrder   []string
	hunterCancels map[string]context.CancelFunc
	routeManager  *RouteManager
	ctx           context.Context
}

// New creates a new Supervisor to manage multiple WireGuard tunnels.
func New(cfgPath string, cfg *config.Config, wgCtrl *wg.Controller, iptMgr *iptables.Manager, log *logger.Logger) *Supervisor {
	config.SetDefaults(cfg)

	absPath, err := filepath.Abs(cfgPath)
	if err == nil {
		cfgPath = absPath
	}

	s := &Supervisor{
		cfgPath:       cfgPath,
		cfg:           cfg,
		wgCtrl:        wgCtrl,
		iptMgr:        iptMgr,
		log:           log,
		hunters:       make(map[string]*hunter.Hunter),
		tunnelOrder:   make([]string, 0, len(cfg.Tunnels)),
		hunterCancels: make(map[string]context.CancelFunc),
	}

	cfgDir := filepath.Dir(cfgPath)

	for _, t := range cfg.Tunnels {
		if t.HistoryFile != "off" && t.HistoryFile != "none" {
			if t.HistoryFile == "" {
				t.HistoryFile = filepath.Join(cfgDir, fmt.Sprintf("history-%s.json", t.Interface))
			} else if !filepath.IsAbs(t.HistoryFile) {
				t.HistoryFile = filepath.Join(cfgDir, t.HistoryFile)
			}
		}
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
	s.mu.Lock()
	s.ctx = ctx
	s.mu.Unlock()

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
	s.mu.Lock()
	for _, iface := range s.tunnelOrder {
		h := s.hunters[iface]
		if h == nil {
			continue
		}

		// Per-tunnel PostUp
		tCfg := s.getTunnelConfigLocked(iface)
		if len(tCfg.PostUp) > 0 {
			s.log.Info("SUPERVISOR", "[%s] Executing tunnel PostUp commands (%d commands)...", iface, len(tCfg.PostUp))
			if err := cmdexec.RunCommands(ctx, tCfg.PostUp, fmt.Sprintf("POSTUP-%s", iface), s.log); err != nil {
				s.log.Warn("SUPERVISOR", "[%s] Tunnel PostUp error: %v", iface, err)
			}
		}

		wgGroup.Add(1)
		hCtx, hCancel := context.WithCancel(ctx)
		s.hunterCancels[iface] = hCancel
		go func(hunterInstance *hunter.Hunter, c context.Context) {
			defer wgGroup.Done()
			hunterInstance.Start(c)
		}(h, hCtx)
	}
	s.mu.Unlock()

	// 3. Initial route evaluation if in client mode
	s.mu.RLock()
	rm := s.routeManager
	s.mu.RUnlock()
	if rm != nil {
		rm.Evaluate()
	}

	// Wait for shutdown signal
	<-ctx.Done()
	s.log.Info("SUPERVISOR", "Shutdown signal received. Tearing down tunnels...")

	s.mu.Lock()
	for _, cancel := range s.hunterCancels {
		cancel()
	}
	s.mu.Unlock()

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

func (s *Supervisor) getTunnelConfigLocked(iface string) config.TunnelConfig {
	for _, t := range s.cfg.Tunnels {
		if t.Interface == iface {
			return t
		}
	}
	return config.TunnelConfig{}
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

// GetConfigPath returns the absolute path of the startup configuration file.
func (s *Supervisor) GetConfigPath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfgPath
}

// GetRawConfigFile reads the raw content of the startup configuration file on disk.
func (s *Supervisor) GetRawConfigFile() (string, error) {
	s.mu.RLock()
	filePath := s.cfgPath
	s.mu.RUnlock()

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			s.mu.RLock()
			defer s.mu.RUnlock()
			yml, mErr := yaml.Marshal(s.cfg)
			if mErr != nil {
				return "", fmt.Errorf("read config file: %w", err)
			}
			return string(yml), nil
		}
		return "", fmt.Errorf("read config file %s: %w", filePath, err)
	}

	return string(data), nil
}

// SaveAndApplyConfig validates the YAML, atomically writes it to the startup file on disk,
// and dynamically applies the changes live in-memory to running tunnels and routing.
func (s *Supervisor) SaveAndApplyConfig(yamlStr string) (*config.Config, error) {
	var newCfg config.Config
	if err := yaml.Unmarshal([]byte(yamlStr), &newCfg); err != nil {
		return nil, fmt.Errorf("invalid YAML syntax: %w", err)
	}

	config.SetDefaults(&newCfg)
	if err := config.Validate(&newCfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if newCfg.Web.Password == "********" || newCfg.Web.Password == "" {
		newCfg.Web.Password = s.cfg.Web.Password
	}
	if strings.Contains(yamlStr, `"********"`) && s.cfg.Web.Password != "" {
		yamlStr = strings.ReplaceAll(yamlStr, `"********"`, fmt.Sprintf("%q", s.cfg.Web.Password))
	}

	// 1. Write atomically to startup config file
	cfgDir := filepath.Dir(s.cfgPath)
	if cfgDir != "" && cfgDir != "." {
		if err := os.MkdirAll(cfgDir, 0755); err != nil {
			return nil, fmt.Errorf("create config directory %s: %w", cfgDir, err)
		}
	}

	tmpFile := s.cfgPath + ".tmp"
	if err := os.WriteFile(tmpFile, []byte(yamlStr), 0600); err != nil {
		return nil, fmt.Errorf("write temp config file: %w", err)
	}
	if err := os.Rename(tmpFile, s.cfgPath); err != nil {
		_ = os.Remove(s.cfgPath)
		if rErr := os.Rename(tmpFile, s.cfgPath); rErr != nil {
			return nil, fmt.Errorf("replace config file %s: %w", s.cfgPath, rErr)
		}
	}

	// 2. Set history file paths for tunnels
	for i := range newCfg.Tunnels {
		t := &newCfg.Tunnels[i]
		if t.HistoryFile != "off" && t.HistoryFile != "none" {
			if t.HistoryFile == "" {
				t.HistoryFile = filepath.Join(cfgDir, fmt.Sprintf("history-%s.json", t.Interface))
			} else if !filepath.IsAbs(t.HistoryFile) {
				t.HistoryFile = filepath.Join(cfgDir, t.HistoryFile)
			}
		}
	}

	// 3. Map new tunnels by interface
	newTunnelMap := make(map[string]config.TunnelConfig, len(newCfg.Tunnels))
	var newOrder []string
	for _, t := range newCfg.Tunnels {
		newTunnelMap[t.Interface] = t
		newOrder = append(newOrder, t.Interface)
	}

	// 4. Clean up removed tunnels
	for iface, h := range s.hunters {
		if _, exists := newTunnelMap[iface]; !exists {
			s.log.Info("SUPERVISOR", "Removing tunnel %s (omitted from new configuration)", iface)
			if cancel, ok := s.hunterCancels[iface]; ok {
				cancel()
				delete(s.hunterCancels, iface)
			}
			_ = h.SaveHistory()
			if s.iptMgr != nil {
				_ = s.iptMgr.RemoveRule(iface)
			}
			delete(s.hunters, iface)
		}
	}

	// 5. Update existing tunnels or start newly added ones
	for _, t := range newCfg.Tunnels {
		if h, exists := s.hunters[t.Interface]; exists {
			h.UpdateConfig(t)
		} else {
			s.log.Info("SUPERVISOR", "Adding new tunnel %s (%s)", t.Interface, t.Name)
			h := hunter.New(t, s.wgCtrl, s.iptMgr, s.log, s.handleStateChange)
			s.hunters[t.Interface] = h
			if s.ctx != nil {
				hCtx, hCancel := context.WithCancel(s.ctx)
				s.hunterCancels[t.Interface] = hCancel
				go h.Start(hCtx)
			}
		}
	}

	s.tunnelOrder = newOrder
	s.cfg = &newCfg

	// 6. Update RouteManager
	if newCfg.Mode == "client" && newCfg.Routing.Enabled {
		if s.routeManager == nil {
			s.routeManager = NewRouteManager(newCfg.Routing, s.hunters, s.tunnelOrder, s.log)
		} else {
			s.routeManager.UpdateRoutingConfig(newCfg.Routing, s.hunters, s.tunnelOrder)
		}
		s.routeManager.Evaluate()
	} else if s.routeManager != nil {
		s.routeManager.UpdateRoutingConfig(newCfg.Routing, s.hunters, s.tunnelOrder)
	}

	s.log.Info("SUPERVISOR", "Configuration successfully saved to %s and applied live (%d active tunnels)",
		s.cfgPath, len(s.hunters))

	return &newCfg, nil
}

// UpdateConfig updates the in-memory supervisor configuration.
func (s *Supervisor) UpdateConfig(newCfg *config.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	config.SetDefaults(newCfg)
	s.cfg = newCfg
	return nil
}

