package hunter

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"auto-wg/pkg/config"
	"auto-wg/pkg/iptables"
	"auto-wg/pkg/logger"
	"auto-wg/pkg/ping"
	"auto-wg/pkg/wg"
)

const (
	StateConnected    = "CONNECTED"
	StateDisconnected = "DISCONNECTED"
	StateStalled      = "STALLED"
	StateHunting      = "HUNTING"
	StateUnknown      = "UNKNOWN"
)

type ConnectionEvent struct {
	ID          int64     `json:"id"`
	Type        string    `json:"type"`        // "CONNECTED" or "DISCONNECTED"
	Timestamp   time.Time `json:"timestamp"`
	Direction   string    `json:"direction"`   // "Local → Remote" or "Remote → Local"
	Initiator   string    `json:"initiator"`   // "Local Host" or "Remote Peer"
	LocalRole   string    `json:"local_role"`  // "Primary" or "Secondary"
	LocalPort   int       `json:"local_port"`
	RemotePort  int       `json:"remote_port"`
	TargetIP    string    `json:"target_ip"`
	Reason      string    `json:"reason"`
	DurationSec float64   `json:"duration_sec"`// Duration of state that just ended
}

type StatusReport struct {
	Interface          string            `json:"interface"`
	Name               string            `json:"name"`
	State              string            `json:"state"`
	LocalPublicKey     string            `json:"local_public_key"`
	PeerPublicKey      string            `json:"peer_public_key"`
	TargetIP           string            `json:"target_ip"`
	TargetIPs          []string          `json:"target_ips,omitempty"`
	InTunnelPingTarget string            `json:"in_tunnel_ping_target"`
	LocalPort          int               `json:"local_port"`
	RemotePort         int               `json:"remote_port"`
	LastHandshake      time.Time         `json:"last_handshake"`
	HandshakeAge       time.Duration     `json:"handshake_age"`
	HandshakeAgeSec    float64           `json:"handshake_age_seconds"`
	LastConnectedAt    time.Time         `json:"last_connected_at"`
	LastDisconnectedAt time.Time         `json:"last_disconnected_at"`
	LastDirection      string            `json:"last_direction"`
	Events             []ConnectionEvent `json:"events"`
	TransmitBytes      int64             `json:"transmit_bytes"`
	ReceiveBytes       int64             `json:"receive_bytes"`
	TotalHunts         int64             `json:"total_hunts"`
	SuccessfulHunts    int64             `json:"successful_hunts"`
	CurrentAttempt     int               `json:"current_attempt"`
	FailedPings        int               `json:"failed_pings"`
	LastHuntTime       time.Time         `json:"last_hunt_time"`
	LastHuntReason     string            `json:"last_hunt_reason"`
	IptablesActive     bool              `json:"iptables_active"`
	LocalPortRange     string            `json:"local_port_range"`
	RemotePortRange    string            `json:"remote_port_range"`
	IsPrimary          bool              `json:"is_primary"`
}

type HistoryState struct {
	LastState          string            `json:"last_state,omitempty"`
	LastConnectedAt    time.Time         `json:"last_connected_at,omitempty"`
	LastDisconnectedAt time.Time         `json:"last_disconnected_at,omitempty"`
	LastDirection      string            `json:"last_direction,omitempty"`
	TotalHunts         int64             `json:"total_hunts"`
	SuccessfulHunts    int64             `json:"successful_hunts"`
	NextEventID        int64             `json:"next_event_id"`
	Events             []ConnectionEvent `json:"events,omitempty"`
	SavedAt            time.Time         `json:"saved_at,omitempty"`
}

type StateChangeHandler func(h *Hunter, oldState, newState string)

type Hunter struct {
	cfg           config.TunnelConfig
	historyFile   string
	wgCtrl        *wg.Controller
	iptMgr        *iptables.Manager
	log           *logger.Logger
	onStateChange StateChangeHandler
	mu            sync.RWMutex

	// Live state
	state                string
	localPubKey          string
	peerPubKey           string
	targetIP             string
	targetIPs            []string
	targetIPIndex        int
	configuredTargets    []string
	pingTarget           string
	localPort            int
	remotePort           int
	lastHandshake        time.Time
	handshakeAge         time.Duration
	lastConnectedAt      time.Time
	lastDisconnectedAt   time.Time
	lastDialedRemotePort int
	lastDialedAt         time.Time
	lastDirection        string
	events               []ConnectionEvent
	nextEventID          int64
	txBytes              int64
	rxBytes              int64
	lastRxBytes          int64
	failedPings          int
	totalHunts           int64
	successfulHunts      int64
	currentAttempt       int
	lastHuntTime         time.Time
	lastHuntReason       string
	iptablesActive       bool
	manualTrigger        chan string
}

func New(tunnelCfg config.TunnelConfig, wgCtrl *wg.Controller, iptMgr *iptables.Manager, log *logger.Logger, onStateChange StateChangeHandler) *Hunter {
	if tunnelCfg.CheckInterval <= 0 {
		tunnelCfg.CheckInterval = 3 * time.Second
	}
	if tunnelCfg.HandshakeTimeout <= 0 {
		tunnelCfg.HandshakeTimeout = 60 * time.Second
	}
	if tunnelCfg.CycleTimeout <= 0 {
		tunnelCfg.CycleTimeout = 8 * time.Second
	}

	histFile := tunnelCfg.HistoryFile
	if histFile == "" {
		histFile = fmt.Sprintf("history-%s.json", tunnelCfg.Interface)
	}
	if histFile == "off" || histFile == "none" {
		histFile = ""
	}

	var rawTargets []string
	for _, ip := range tunnelCfg.TargetIPs {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			rawTargets = append(rawTargets, ip)
		}
	}
	if tunnelCfg.TargetIP != "" {
		ip := strings.TrimSpace(tunnelCfg.TargetIP)
		if ip != "" {
			rawTargets = append(rawTargets, ip)
		}
	}
	resolved := config.ResolveTargetIPs(rawTargets)
	var initialTarget string
	if len(resolved) > 0 {
		initialTarget = resolved[0]
	} else if tunnelCfg.TargetIP != "" {
		initialTarget = strings.Trim(tunnelCfg.TargetIP, "[]")
	}

	h := &Hunter{
		cfg:               tunnelCfg,
		historyFile:       histFile,
		wgCtrl:            wgCtrl,
		iptMgr:            iptMgr,
		log:               log,
		onStateChange:     onStateChange,
		state:             StateUnknown,
		targetIP:          initialTarget,
		targetIPs:         resolved,
		targetIPIndex:     0,
		configuredTargets: rawTargets,
		lastDirection:     "Local ⇄ Remote",
		events:            make([]ConnectionEvent, 0, 50),
		manualTrigger:     make(chan string, 10),
	}
	h.loadHistory()
	return h
}

func (h *Hunter) setState(newState string) {
	oldState := h.state
	if oldState == newState {
		return
	}
	h.state = newState
	h.log.Info("HUNTER", "[%s] State changed: %s -> %s", h.cfg.Interface, oldState, newState)
	if h.onStateChange != nil {
		go h.onStateChange(h, oldState, newState)
	}
}

func (h *Hunter) loadHistory() {
	if h.historyFile == "" {
		return
	}

	data, err := os.ReadFile(h.historyFile)
	if err != nil {
		if !os.IsNotExist(err) {
			h.log.Warn("HUNTER", "[%s] Could not read history file %s: %v", h.cfg.Interface, h.historyFile, err)
		}
		return
	}

	var state HistoryState
	if err := json.Unmarshal(data, &state); err != nil {
		h.log.Warn("HUNTER", "[%s] Could not parse history file %s: %v", h.cfg.Interface, h.historyFile, err)
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.lastConnectedAt = state.LastConnectedAt
	h.lastDisconnectedAt = state.LastDisconnectedAt
	if state.LastDirection != "" {
		h.lastDirection = state.LastDirection
	}
	h.totalHunts = state.TotalHunts
	h.successfulHunts = state.SuccessfulHunts
	h.nextEventID = state.NextEventID
	if len(state.Events) > 0 {
		h.events = state.Events
		for _, e := range h.events {
			if e.ID > h.nextEventID {
				h.nextEventID = e.ID
			}
		}
	}

	h.log.Info("HUNTER", "[%s] Loaded persistent history from %s (%d events, %d total hunts, %d successful)",
		h.cfg.Interface, h.historyFile, len(h.events), h.totalHunts, h.successfulHunts)
}

func (h *Hunter) saveHistoryLocked() error {
	if h.historyFile == "" {
		return nil
	}

	eventsCopy := make([]ConnectionEvent, len(h.events))
	copy(eventsCopy, h.events)

	state := HistoryState{
		LastState:          h.state,
		LastConnectedAt:    h.lastConnectedAt,
		LastDisconnectedAt: h.lastDisconnectedAt,
		LastDirection:      h.lastDirection,
		TotalHunts:         h.totalHunts,
		SuccessfulHunts:    h.successfulHunts,
		NextEventID:        h.nextEventID,
		Events:             eventsCopy,
		SavedAt:            time.Now(),
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(h.historyFile)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	tmpFile := h.historyFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return err
	}

	if err := os.Rename(tmpFile, h.historyFile); err != nil {
		_ = os.Remove(h.historyFile)
		return os.Rename(tmpFile, h.historyFile)
	}
	h.log.Info("HUNTER", "[%s] Saved persistent history to %s", h.cfg.Interface, h.historyFile)
	return nil
}

// SaveHistory writes the current history and stats to disk.
func (h *Hunter) SaveHistory() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.saveHistoryLocked()
}

// SetHistoryFile updates the persistent history file path.
func (h *Hunter) SetHistoryFile(path string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.historyFile = path
}

func (h *Hunter) addEvent(eventType string, direction string, initiator string, reason string, durationSec float64) {
	h.nextEventID++
	localRole := "Secondary"
	if h.localPubKey != "" && h.peerPubKey != "" && h.localPubKey < h.peerPubKey {
		localRole = "Primary"
	}

	evt := ConnectionEvent{
		ID:          h.nextEventID,
		Type:        eventType,
		Timestamp:   time.Now(),
		Direction:   direction,
		Initiator:   initiator,
		LocalRole:   localRole,
		LocalPort:   h.localPort,
		RemotePort:  h.remotePort,
		TargetIP:    h.targetIP,
		Reason:      reason,
		DurationSec: durationSec,
	}

	h.events = append([]ConnectionEvent{evt}, h.events...)
	if len(h.events) > 50 {
		h.events = h.events[:50]
	}
	_ = h.saveHistoryLocked()
}

// Start runs the autonomous monitoring and hunting loop.
func (h *Hunter) Start(ctx context.Context) {
	h.log.Info("HUNTER", "[%s] Starting Autonomous WireGuard Hunter (Zero-Negotiator Mode)", h.cfg.Interface)
	defer func() {
		_ = h.SaveHistory()
	}()

	// Apply iptables rule if enabled
	h.applyIptablesRule()

	// Save initial history state so the file exists on disk immediately
	_ = h.SaveHistory()

	ticker := time.NewTicker(h.cfg.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			h.log.Info("HUNTER", "[%s] Stopping hunter loop...", h.cfg.Interface)
			return

		case reason := <-h.manualTrigger:
			h.log.Info("HUNTER", "[%s] Manual trigger received: %s", h.cfg.Interface, reason)
			h.executeHunt(reason)

		case <-ticker.C:
			h.tick(ctx)
		}
	}
}

func (h *Hunter) applyIptablesRule() {
	h.mu.Lock()
	enabled := h.cfg.Iptables
	portRange := h.cfg.PortRange
	iface := h.cfg.Interface
	h.mu.Unlock()

	if !enabled {
		h.log.Info("HUNTER", "[%s] Iptables management is disabled in config", iface)
		return
	}

	// Read current WireGuard listen port
	dev, err := h.wgCtrl.GetDeviceInfo(iface, "")
	targetPort := 51820
	if err == nil && dev.ListenPort > 0 {
		targetPort = dev.ListenPort
	}

	if err := h.iptMgr.ApplyForwardingRule(iface, portRange, targetPort); err != nil {
		h.log.Warn("HUNTER", "[%s] Failed to apply iptables forwarding rule: %v", iface, err)
		h.mu.Lock()
		h.iptablesActive = false
		h.mu.Unlock()
	} else {
		h.mu.Lock()
		h.iptablesActive = true
		h.mu.Unlock()
	}
}

func (h *Hunter) tick(ctx context.Context) {
	h.mu.RLock()
	iface := h.cfg.Interface
	timeout := h.cfg.HandshakeTimeout
	cycleTimeout := h.cfg.CycleTimeout
	pingEnabled := h.cfg.TunnelPing.Enabled
	threshold := h.cfg.TunnelPing.FailureThreshold
	if threshold <= 0 {
		threshold = 3
	}
	pingTimeout := h.cfg.TunnelPing.Timeout
	if pingTimeout <= 0 {
		pingTimeout = 2 * time.Second
	}
	h.mu.RUnlock()

	dev, err := h.wgCtrl.GetDeviceInfo(iface, "")
	if err != nil {
		h.mu.Lock()
		h.setState(StateUnknown)
		h.mu.Unlock()
		h.log.Warn("HUNTER", "[%s] Cannot query WireGuard interface %s: %v", iface, iface, err)
		return
	}

	h.mu.Lock()
	if dev.PublicKey != "" {
		h.localPubKey = dev.PublicKey
	}
	if dev.PeerPublicKey != "" {
		h.peerPubKey = dev.PeerPublicKey
	} else if h.peerPubKey == "" && h.cfg.PeerPublicKey != "" {
		h.peerPubKey = h.cfg.PeerPublicKey
	}

	if dev.PeerEndpointIP != "" {
		cleanDevIP := strings.Trim(dev.PeerEndpointIP, "[]")
		h.targetIP = cleanDevIP
		// Find cleanDevIP in targetIPs and update targetIPIndex
		found := false
		for idx, tip := range h.targetIPs {
			if tip == cleanDevIP {
				found = true
				h.targetIPIndex = idx
				break
			}
		}
		if !found && cleanDevIP != "" {
			h.targetIPs = append(h.targetIPs, cleanDevIP)
			h.targetIPIndex = len(h.targetIPs) - 1
		}
	} else if h.targetIP == "" && len(h.targetIPs) > 0 {
		h.targetIP = h.targetIPs[0]
	} else if h.targetIP == "" && h.cfg.TargetIP != "" {
		h.targetIP = strings.Trim(h.cfg.TargetIP, "[]")
	}
	h.localPort = dev.ListenPort
	h.remotePort = dev.PeerPort
	h.lastHandshake = dev.LastHandshake
	h.handshakeAge = dev.HandshakeAge
	h.txBytes = dev.TransmitBytes
	h.rxBytes = dev.ReceiveBytes

	// 1. Check if traffic is actively arriving
	rxProgress := dev.ReceiveBytes > h.lastRxBytes && h.lastRxBytes > 0
	h.lastRxBytes = dev.ReceiveBytes

	// Determine in-tunnel ping target:
	pingTarget := strings.TrimSpace(h.cfg.TunnelPing.TargetIP)
	if pingTarget == "" && len(dev.PeerAllowedIPs) > 0 {
		pingTarget = dev.PeerAllowedIPs[0]
	}
	h.pingTarget = pingTarget

	if h.peerPubKey == "" {
		h.setState(StateUnknown)
		h.mu.Unlock()
		h.log.Warn("HUNTER", "[%s] No peer found on interface %s. Waiting for peer configuration...", iface, iface)
		return
	}

	isPrimary := dev.PublicKey < dev.PeerPublicKey

	// 2. Check if tunnel is healthy:
	isHandshakeFresh := !dev.LastHandshake.IsZero() && dev.HandshakeAge <= timeout

	if isHandshakeFresh || rxProgress {
		if h.state == StateHunting || h.state == StateStalled {
			remoteEndpointStr := net.JoinHostPort(h.targetIP, strconv.Itoa(h.remotePort))
			h.log.Info("HUNTER", "===============================================================")
			h.log.Info("HUNTER", " [%s] WIREGUARD CONNECTED! Working 5-tuple: :%d -> %s (Handshake: %v ago)",
				iface, h.localPort, remoteEndpointStr, dev.HandshakeAge.Round(time.Millisecond))
			h.log.Info("HUNTER", "===============================================================")
			h.successfulHunts++
			h.currentAttempt = 0

			dir, init := h.determineDirection(dev.PeerPort)
			h.lastDirection = dir
			var downtimeSec float64
			if !h.lastDisconnectedAt.IsZero() {
				downtimeSec = time.Since(h.lastDisconnectedAt).Seconds()
			}
			h.lastConnectedAt = time.Now()
			h.addEvent(StateConnected, dir, init, fmt.Sprintf("5-tuple: :%d -> %s", h.localPort, remoteEndpointStr), downtimeSec)
		} else if h.lastConnectedAt.IsZero() {
			if !dev.LastHandshake.IsZero() {
				h.lastConnectedAt = dev.LastHandshake
			} else {
				h.lastConnectedAt = time.Now()
			}
			dir := "Local ⇄ Remote"
			h.lastDirection = dir
			remoteEndpointStr := net.JoinHostPort(h.targetIP, strconv.Itoa(h.remotePort))
			h.log.Info("HUNTER", "[%s] Tunnel healthy & active: :%d -> %s (Handshake: %v ago)",
				iface, h.localPort, remoteEndpointStr, dev.HandshakeAge.Round(time.Millisecond))
			h.addEvent(StateConnected, dir, "Initial Handshake", fmt.Sprintf("Link active: :%d -> %s", h.localPort, remoteEndpointStr), 0)
		}
		h.setState(StateConnected)
		h.failedPings = 0
		h.mu.Unlock()
		return
	}

	// 3. Handshake is stale or zero, and no incoming RX packets.
	if pingEnabled && pingTarget != "" {
		h.mu.Unlock()
		pingOK := ping.Ping(ctx, pingTarget, pingTimeout)
		h.mu.Lock()

		if pingOK {
			h.log.Debug("HUNTER", "[%s] Handshake stale (%v) but in-tunnel ping to %s succeeded; link is alive",
				iface, dev.HandshakeAge.Round(time.Second), pingTarget)
			h.failedPings = 0
			if h.state == StateHunting || h.state == StateStalled {
				remoteEndpointStr := net.JoinHostPort(h.targetIP, strconv.Itoa(h.remotePort))
				h.log.Info("HUNTER", "===============================================================")
				h.log.Info("HUNTER", " [%s] WIREGUARD CONNECTED! In-tunnel ping to %s verified (5-tuple: :%d -> %s)",
					iface, pingTarget, h.localPort, remoteEndpointStr)
				h.log.Info("HUNTER", "===============================================================")
				h.successfulHunts++
				h.currentAttempt = 0

				dir, init := h.determineDirection(dev.PeerPort)
				h.lastDirection = dir
				var downtimeSec float64
				if !h.lastDisconnectedAt.IsZero() {
					downtimeSec = time.Since(h.lastDisconnectedAt).Seconds()
				}
				h.lastConnectedAt = time.Now()
				h.addEvent(StateConnected, dir, init, fmt.Sprintf("Ping verified: :%d -> %s", h.localPort, remoteEndpointStr), downtimeSec)
			} else if h.lastConnectedAt.IsZero() {
				h.lastConnectedAt = time.Now()
				dir := "Local ⇄ Remote"
				h.lastDirection = dir
				remoteEndpointStr := net.JoinHostPort(h.targetIP, strconv.Itoa(h.remotePort))
				h.addEvent(StateConnected, dir, "Initial Ping", fmt.Sprintf("Ping verified: :%d -> %s", h.localPort, remoteEndpointStr), 0)
			}
			h.setState(StateConnected)
			h.mu.Unlock()
			return
		}

		// In-tunnel ping failed
		h.failedPings++
		h.log.Warn("HUNTER", "[%s] Tunnel unresponsive: handshake age %v, in-tunnel ping #%d/%d to %s failed",
			iface, dev.HandshakeAge.Round(time.Second), h.failedPings, threshold, pingTarget)

		if h.failedPings < threshold {
			// In grace verification period, do not hunt yet!
			if h.state == StateConnected || (h.state == StateUnknown && !h.lastConnectedAt.IsZero() && (h.lastDisconnectedAt.IsZero() || h.lastConnectedAt.After(h.lastDisconnectedAt))) {
				h.lastDisconnectedAt = time.Now()
				var uptimeSec float64
				if !h.lastConnectedAt.IsZero() {
					uptimeSec = time.Since(h.lastConnectedAt).Seconds()
				}
				h.addEvent(StateDisconnected, h.lastDirection, "", fmt.Sprintf("in-tunnel ping #%d/%d failed", h.failedPings, threshold), uptimeSec)
			}
			h.setState(StateStalled)
			h.lastHuntReason = fmt.Sprintf("verifying_stalled_ping_%d/%d", h.failedPings, threshold)
			h.mu.Unlock()
			return
		}
	}

	// 4. Link is confirmed dead!
	stallReason := "handshake_expired"
	if dev.LastHandshake.IsZero() {
		stallReason = "no_handshake_ever"
	} else if h.failedPings >= threshold {
		stallReason = fmt.Sprintf("pings_failed_%d_times", h.failedPings)
	}

	if h.state == StateConnected || (h.state == StateUnknown && !h.lastConnectedAt.IsZero() && (h.lastDisconnectedAt.IsZero() || h.lastConnectedAt.After(h.lastDisconnectedAt))) {
		h.lastDisconnectedAt = time.Now()
		var uptimeSec float64
		if !h.lastConnectedAt.IsZero() {
			uptimeSec = time.Since(h.lastConnectedAt).Seconds()
		}
		h.addEvent(StateDisconnected, h.lastDirection, "", stallReason, uptimeSec)
	}
	h.setState(StateHunting)
	attempt := h.currentAttempt
	h.mu.Unlock()

	// Role-staggered turn coordination
	nowUnix := time.Now().Unix()
	cycleSec := int64(cycleTimeout.Seconds())
	if cycleSec <= 0 {
		cycleSec = 8
	}
	cycle := (nowUnix / cycleSec) % 2
	isMyTurn := false

	if attempt >= 4 {
		isMyTurn = (rand.Intn(2) == 0)
	} else if isPrimary && cycle == 0 {
		isMyTurn = true
	} else if !isPrimary && cycle == 1 {
		isMyTurn = true
	}

	if isMyTurn {
		h.executeHunt(stallReason)
	} else {
		roleName := "Secondary"
		if isPrimary {
			roleName = "Primary"
		}
		h.log.Debug("HUNTER", "[%s] Waiting for peer's staggered hunt window (My role: %s, Attempt: #%d)", iface, roleName, attempt)
	}
}

func (h *Hunter) determineDirection(currentRemotePort int) (string, string) {
	localInitiated := false
	if !h.lastDialedAt.IsZero() && time.Since(h.lastDialedAt) < 2*time.Minute {
		if currentRemotePort == h.lastDialedRemotePort && h.lastDialedRemotePort > 0 {
			localInitiated = true
		}
	}

	if localInitiated {
		return "Local → Remote", "Local Host"
	}
	return "Remote → Local", "Remote Peer"
}

func (h *Hunter) executeHunt(reason string) {
	h.mu.Lock()
	iface := h.cfg.Interface
	localRange := h.cfg.PortRange
	remoteRange := h.cfg.RemotePortRange
	peerKey := h.peerPubKey
	h.totalHunts++
	h.currentAttempt++
	h.lastHuntTime = time.Now()
	h.lastHuntReason = reason
	attempt := h.currentAttempt

	// Re-resolve candidate targets if empty
	if len(h.targetIPs) == 0 && len(h.configuredTargets) > 0 {
		h.targetIPs = config.ResolveTargetIPs(h.configuredTargets)
	}

	// Rotate candidate target IP if multiple candidate destinations are configured
	if len(h.targetIPs) > 1 {
		h.targetIPIndex = (h.targetIPIndex + 1) % len(h.targetIPs)
		h.targetIP = h.targetIPs[h.targetIPIndex]
	} else if len(h.targetIPs) == 1 {
		h.targetIP = h.targetIPs[0]
	}
	targetIP := h.targetIP
	_ = h.saveHistoryLocked()
	h.mu.Unlock()

	if targetIP == "" {
		h.log.Warn("HUNTER", "[%s] Cannot hunt: remote IP is not yet known. Ensure WireGuard has an initial endpoint set.", iface)
		return
	}

	newLocalPort, err := config.PickRandomPort(localRange)
	if err != nil {
		h.log.Error("HUNTER", "[%s] Failed to pick random local port from %s: %v", iface, localRange, err)
		return
	}

	newRemotePort, err := config.PickRandomPort(remoteRange)
	if err != nil {
		h.log.Error("HUNTER", "[%s] Failed to pick random remote port from %s: %v", iface, remoteRange, err)
		return
	}

	newEndpoint := net.JoinHostPort(targetIP, strconv.Itoa(newRemotePort))
	h.log.Info("HUNTER", "[%s] [Hunt #%d] Rotating 5-tuple: local :%d -> remote %s (Reason: %s)",
		iface, attempt, newLocalPort, newEndpoint, reason)

	// 1. Update local WireGuard ListenPort
	if err := h.wgCtrl.UpdateListenPort(iface, newLocalPort); err != nil {
		h.log.Error("HUNTER", "[%s] UpdateListenPort to %d failed: %v", iface, newLocalPort, err)
	} else {
		h.mu.Lock()
		h.localPort = newLocalPort
		h.mu.Unlock()
	}

	// 2. Sync iptables REDIRECT rule to match new listen port
	if h.cfg.Iptables {
		if err := h.iptMgr.ApplyForwardingRule(iface, localRange, newLocalPort); err != nil {
			h.log.Warn("HUNTER", "[%s] Failed to sync iptables rule to port %d: %v", iface, newLocalPort, err)
			h.mu.Lock()
			h.iptablesActive = false
			h.mu.Unlock()
		} else {
			h.mu.Lock()
			h.iptablesActive = true
			h.mu.Unlock()
		}
	}

	// 3. Update remote peer endpoint to newly selected remote port
	if err := h.wgCtrl.UpdatePeerEndpoint(iface, peerKey, newEndpoint); err != nil {
		h.log.Error("HUNTER", "[%s] UpdatePeerEndpoint failed: %v", iface, err)
	} else {
		h.mu.Lock()
		h.remotePort = newRemotePort
		h.lastDialedRemotePort = newRemotePort
		h.lastDialedAt = time.Now()
		h.mu.Unlock()
	}

	// 4. Send probe UDP packet
	go h.sendProbePacket(newLocalPort, targetIP, newRemotePort)
}

func (h *Hunter) sendProbePacket(localPort int, targetIP string, remotePort int) {
	cleanIP := strings.Trim(targetIP, "[]")
	parsedIP := net.ParseIP(cleanIP)
	isIPv6 := parsedIP != nil && parsedIP.To4() == nil

	remoteEndpoint := net.JoinHostPort(cleanIP, strconv.Itoa(remotePort))
	network := "udp4"
	localBind := fmt.Sprintf("0.0.0.0:%d", localPort)
	if isIPv6 {
		network = "udp6"
		localBind = fmt.Sprintf("[::]:%d", localPort)
	}

	remoteAddr, err := net.ResolveUDPAddr(network, remoteEndpoint)
	if err != nil {
		return
	}

	localAddr, _ := net.ResolveUDPAddr(network, localBind)

	conn, err := net.DialUDP(network, localAddr, remoteAddr)
	if err != nil {
		// Fallback to dialing without binding local address if local port is unavailable or family mismatch
		conn, err = net.DialUDP(network, nil, remoteAddr)
		if err != nil {
			return
		}
	}
	defer conn.Close()

	probe := []byte{0x01, 0x00, 0x00, 0x00}
	_, _ = conn.Write(probe)
}

// TriggerHunt initiates an immediate hunt cycle out-of-band.
func (h *Hunter) TriggerHunt(reason string) {
	select {
	case h.manualTrigger <- reason:
	default:
	}
}

// TriggerRebind rotates the local listen port and updates iptables forwarding.
func (h *Hunter) TriggerRebind() error {
	h.mu.Lock()
	iface := h.cfg.Interface
	localRange := h.cfg.PortRange
	h.mu.Unlock()

	newPort, err := config.PickRandomPort(localRange)
	if err != nil {
		return fmt.Errorf("pick random port: %w", err)
	}

	if h.wgCtrl != nil {
		if err := h.wgCtrl.UpdateListenPort(iface, newPort); err != nil {
			h.log.Warn("HUNTER", "[%s] UpdateListenPort failed: %v", iface, err)
		}
	}

	if h.cfg.Iptables && h.iptMgr != nil {
		_ = h.iptMgr.ApplyForwardingRule(iface, localRange, newPort)
	}

	h.mu.Lock()
	h.localPort = newPort
	h.mu.Unlock()
	return nil
}

// GetStatus returns the current status report for this tunnel.
func (h *Hunter) GetStatus() StatusReport {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var hsAgeSec float64
	if !h.lastHandshake.IsZero() {
		hsAgeSec = time.Since(h.lastHandshake).Seconds()
	}

	isPrimary := false
	if h.localPubKey != "" && h.peerPubKey != "" {
		isPrimary = h.localPubKey < h.peerPubKey
	}

	eventsCopy := make([]ConnectionEvent, len(h.events))
	copy(eventsCopy, h.events)

	targetIPsCopy := make([]string, len(h.targetIPs))
	copy(targetIPsCopy, h.targetIPs)

	lastDir := h.lastDirection
	if lastDir == "" {
		lastDir = "Local ⇄ Remote"
	}

	return StatusReport{
		Interface:          h.cfg.Interface,
		Name:               h.cfg.Name,
		State:              h.state,
		LocalPublicKey:     h.localPubKey,
		PeerPublicKey:      h.peerPubKey,
		TargetIP:           h.targetIP,
		TargetIPs:          targetIPsCopy,
		InTunnelPingTarget: h.pingTarget,
		LocalPort:          h.localPort,
		RemotePort:         h.remotePort,
		LastHandshake:      h.lastHandshake,
		HandshakeAge:       h.handshakeAge,
		HandshakeAgeSec:    hsAgeSec,
		LastConnectedAt:    h.lastConnectedAt,
		LastDisconnectedAt: h.lastDisconnectedAt,
		LastDirection:      lastDir,
		Events:             eventsCopy,
		TransmitBytes:      h.txBytes,
		ReceiveBytes:       h.rxBytes,
		TotalHunts:         h.totalHunts,
		SuccessfulHunts:    h.successfulHunts,
		CurrentAttempt:     h.currentAttempt,
		FailedPings:        h.failedPings,
		LastHuntTime:       h.lastHuntTime,
		LastHuntReason:     h.lastHuntReason,
		IptablesActive:     h.iptablesActive,
		LocalPortRange:     h.cfg.PortRange,
		RemotePortRange:    h.cfg.RemotePortRange,
		IsPrimary:          isPrimary,
	}
}

// GetInterface returns the WireGuard interface name.
func (h *Hunter) GetInterface() string {
	return h.cfg.Interface
}

// GetState returns the current state.
func (h *Hunter) GetState() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.state
}
