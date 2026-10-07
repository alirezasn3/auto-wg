package supervisor

import (
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"auto-wg/pkg/config"
	"auto-wg/pkg/hunter"
	"auto-wg/pkg/logger"
)

type RouteManager struct {
	cfg          config.RoutingConfig
	tunnels      map[string]*hunter.Hunter
	tunnelOrder  []string
	activeTunnel string
	log          *logger.Logger
	mu           sync.Mutex
	isLinux      bool
	routeCmdFn   func(iface string, table int, metric int) error // for mocking in tests
}

func NewRouteManager(cfg config.RoutingConfig, tunnels map[string]*hunter.Hunter, tunnelOrder []string, log *logger.Logger) *RouteManager {
	return &RouteManager{
		cfg:         cfg,
		tunnels:     tunnels,
		tunnelOrder: tunnelOrder,
		log:         log,
		isLinux:     runtime.GOOS == "linux",
	}
}

// Evaluate checks the status of all tunnels and applies route failover if needed.
func (rm *RouteManager) Evaluate() string {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if !rm.cfg.Enabled || len(rm.tunnelOrder) == 0 {
		return ""
	}

	currentActive := rm.activeTunnel
	currentHunter, currentExists := rm.tunnels[currentActive]
	currentHealthy := currentExists && currentHunter != nil && currentHunter.GetState() == hunter.StateConnected

	// 1. If in sticky mode and current active tunnel is healthy: stay on it!
	if rm.cfg.Mode == "sticky" && currentHealthy {
		return currentActive
	}

	// 2. In priority mode, check if any higher-priority tunnel is connected
	if rm.cfg.Mode == "priority" {
		for _, iface := range rm.tunnelOrder {
			h := rm.tunnels[iface]
			if h != nil && h.GetState() == hunter.StateConnected {
				if iface != currentActive {
					rm.applyRouteLocked(iface)
				}
				return iface
			}
			if iface == currentActive && currentHealthy {
				// Current active is the highest available priority
				return currentActive
			}
		}
	}

	// 3. Current active is not healthy (or not set), find first available connected tunnel
	for _, iface := range rm.tunnelOrder {
		h := rm.tunnels[iface]
		if h != nil && h.GetState() == hunter.StateConnected {
			rm.applyRouteLocked(iface)
			return iface
		}
	}

	// 4. No connected tunnels available!
	if rm.activeTunnel != "" {
		rm.log.Warn("ROUTER", "All upstream tunnels are currently down or hunting. Active route suspended.")
		rm.activeTunnel = ""
	}
	return ""
}

// ForceSwitch manually forces the active tunnel in client mode.
func (rm *RouteManager) ForceSwitch(iface string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	h, ok := rm.tunnels[iface]
	if !ok {
		return fmt.Errorf("tunnel %q not found", iface)
	}

	rm.applyRouteLocked(iface)
	rm.log.Info("ROUTER", "Manually forced active route to %s (tunnel state: %s)", iface, h.GetState())
	return nil
}

func (rm *RouteManager) applyRouteLocked(iface string) {
	oldIface := rm.activeTunnel
	rm.activeTunnel = iface

	if rm.routeCmdFn != nil {
		if err := rm.routeCmdFn(iface, rm.cfg.Table, rm.cfg.Metric); err != nil {
			rm.log.Error("ROUTER", "Mock route replacement to %s failed: %v", iface, err)
		}
		return
	}

	if !rm.isLinux {
		rm.log.Info("ROUTER", "[Non-Linux] Simulated route switch: %s -> %s (Table: %d, Metric: %d)",
			oldIface, iface, rm.cfg.Table, rm.cfg.Metric)
		return
	}

	// Execute: ip route replace default dev <iface> [table <table>] [metric <metric>]
	args := []string{"route", "replace", "default", "dev", iface}
	if rm.cfg.Table > 0 {
		args = append(args, "table", strconv.Itoa(rm.cfg.Table))
	} else if rm.cfg.Metric > 0 {
		args = append(args, "metric", strconv.Itoa(rm.cfg.Metric))
	}

	cmd := exec.Command("ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		rm.log.Error("ROUTER", "Failed to switch route: ip %s (error: %v, output: %s)",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		return
	}

	rm.log.Info("ROUTER", "===============================================================")
	rm.log.Info("ROUTER", " ACTIVE UPSTREAM SWITCHED: %s -> %s (Table: %d)", oldIface, iface, rm.cfg.Table)
	rm.log.Info("ROUTER", "===============================================================")
}

func (rm *RouteManager) GetActiveTunnel() string {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	return rm.activeTunnel
}

// UpdateRoutingConfig updates routing settings and active tunnels in memory.
func (rm *RouteManager) UpdateRoutingConfig(cfg config.RoutingConfig, tunnels map[string]*hunter.Hunter, tunnelOrder []string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.cfg = cfg
	rm.tunnels = tunnels
	rm.tunnelOrder = tunnelOrder
	rm.log.Info("ROUTER", "Routing configuration updated (enabled: %v, mode: %s, table: %d, metric: %d)",
		cfg.Enabled, cfg.Mode, cfg.Table, cfg.Metric)
}

