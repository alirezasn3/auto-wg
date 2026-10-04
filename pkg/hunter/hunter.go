package hunter

import (
	"context"
	"fmt"
	"math/rand"
	"net"
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
	StateConnected = "CONNECTED"
	StateStalled   = "STALLED"
	StateHunting   = "HUNTING"
	StateUnknown   = "UNKNOWN"
)

type StatusReport struct {
	State              string        `json:"state"`
	Interface          string        `json:"interface"`
	LocalPublicKey     string        `json:"local_public_key"`
	PeerPublicKey      string        `json:"peer_public_key"`
	TargetIP           string        `json:"target_ip"`
	InTunnelPingTarget string        `json:"in_tunnel_ping_target"`
	LocalPort          int           `json:"local_port"`
	RemotePort         int           `json:"remote_port"`
	LastHandshake      time.Time     `json:"last_handshake"`
	HandshakeAge       time.Duration `json:"handshake_age"`
	HandshakeAgeSec    float64       `json:"handshake_age_seconds"`
	LastConnectedAt    time.Time     `json:"last_connected_at"`
	LastDisconnectedAt time.Time     `json:"last_disconnected_at"`
	TransmitBytes      int64         `json:"transmit_bytes"`
	ReceiveBytes       int64         `json:"receive_bytes"`
	TotalHunts         int64         `json:"total_hunts"`
	SuccessfulHunts    int64         `json:"successful_hunts"`
	CurrentAttempt     int           `json:"current_attempt"`
	FailedPings        int           `json:"failed_pings"`
	LastHuntTime       time.Time     `json:"last_hunt_time"`
	LastHuntReason     string        `json:"last_hunt_reason"`
	IptablesActive     bool          `json:"iptables_active"`
	LocalPortRange     string        `json:"local_port_range"`
	RemotePortRange    string        `json:"remote_port_range"`
	IsPrimary          bool          `json:"is_primary"`
}

type Hunter struct {
	cfgPath    string
	cfg        *config.Config
	wgCtrl     *wg.Controller
	iptMgr     *iptables.Manager
	log        *logger.Logger
	mu         sync.RWMutex

	// Live state
	state              string
	localPubKey        string
	peerPubKey         string
	targetIP           string
	pingTarget         string
	localPort          int
	remotePort         int
	lastHandshake      time.Time
	handshakeAge       time.Duration
	lastConnectedAt    time.Time
	lastDisconnectedAt time.Time
	txBytes            int64
	rxBytes            int64
	lastRxBytes        int64
	failedPings        int
	totalHunts         int64
	successfulHunts    int64
	currentAttempt     int
	lastHuntTime       time.Time
	lastHuntReason     string
	iptablesActive     bool
	manualTrigger      chan string
}

func New(cfgPath string, cfg *config.Config, wgCtrl *wg.Controller, iptMgr *iptables.Manager, log *logger.Logger) *Hunter {
	return &Hunter{
		cfgPath:       cfgPath,
		cfg:           cfg,
		wgCtrl:        wgCtrl,
		iptMgr:        iptMgr,
		log:           log,
		state:         StateUnknown,
		manualTrigger: make(chan string, 10),
	}
}

// Start runs the autonomous monitoring and hunting loop.
func (h *Hunter) Start(ctx context.Context) {
	h.log.Info("HUNTER", "Starting Autonomous WireGuard Hunter (Zero-Negotiator Mode)")

	// Apply iptables rule if enabled
	h.applyIptablesRule()

	ticker := time.NewTicker(h.cfg.Hunter.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			h.log.Info("HUNTER", "Stopping hunter loop...")
			return

		case reason := <-h.manualTrigger:
			h.log.Info("HUNTER", "Manual trigger received: %s", reason)
			h.executeHunt(reason)

		case <-ticker.C:
			h.tick(ctx)
		}
	}
}

func (h *Hunter) applyIptablesRule() {
	h.mu.Lock()
	enabled := h.cfg.Iptables.Enabled
	portRange := h.cfg.Iptables.PortRange
	iface := h.cfg.WireGuard.Interface
	h.mu.Unlock()

	if !enabled {
		h.log.Info("HUNTER", "Iptables management is disabled in config")
		return
	}

	// Read current WireGuard listen port
	dev, err := h.wgCtrl.GetDeviceInfo(iface, "")
	targetPort := 51820
	if err == nil && dev.ListenPort > 0 {
		targetPort = dev.ListenPort
	}

	if err := h.iptMgr.ApplyForwardingRule(portRange, targetPort); err != nil {
		h.log.Warn("HUNTER", "Failed to apply iptables forwarding rule: %v", err)
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
	iface := h.cfg.WireGuard.Interface
	timeout := h.cfg.Hunter.HandshakeTimeout
	cycleTimeout := h.cfg.Hunter.CycleTimeout
	pingEnabled := h.cfg.Hunter.TunnelPing.Enabled
	threshold := h.cfg.Hunter.TunnelPing.FailureThreshold
	if threshold <= 0 {
		threshold = 3
	}
	pingTimeout := h.cfg.Hunter.TunnelPing.Timeout
	if pingTimeout <= 0 {
		pingTimeout = 2 * time.Second
	}
	h.mu.RUnlock()

	dev, err := h.wgCtrl.GetDeviceInfo(iface, "")
	if err != nil {
		h.mu.Lock()
		h.state = StateUnknown
		h.mu.Unlock()
		h.log.Warn("HUNTER", "Cannot query WireGuard interface %s: %v", iface, err)
		return
	}

	h.mu.Lock()
	h.localPubKey = dev.PublicKey
	h.peerPubKey = dev.PeerPublicKey
	if dev.PeerEndpointIP != "" {
		h.targetIP = strings.Trim(dev.PeerEndpointIP, "[]")
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

	// Determine in-tunnel ping target strictly from peer's AllowedIPs
	var pingTarget string
	if len(dev.PeerAllowedIPs) > 0 {
		pingTarget = dev.PeerAllowedIPs[0]
	}
	h.pingTarget = pingTarget

	if h.peerPubKey == "" {
		h.state = StateUnknown
		h.mu.Unlock()
		h.log.Warn("HUNTER", "No peer found on interface %s. Waiting for peer configuration...", iface)
		return
	}

	isPrimary := dev.PublicKey < dev.PeerPublicKey

	// 2. Check if tunnel is healthy:
	// - Handshake was negotiated recently (HandshakeAge <= timeout) AND NOT zero, OR
	// - Incoming traffic is actively flowing (rxProgress is true)
	isHandshakeFresh := !dev.LastHandshake.IsZero() && dev.HandshakeAge <= timeout

	if isHandshakeFresh || rxProgress {
		if h.state == StateHunting || h.state == StateStalled {
			remoteEndpointStr := net.JoinHostPort(h.targetIP, strconv.Itoa(h.remotePort))
			h.log.Info("HUNTER", "===============================================================")
			h.log.Info("HUNTER", " WIREGUARD CONNECTED! Working 5-tuple: :%d -> %s (Handshake: %v ago)",
				h.localPort, remoteEndpointStr, dev.HandshakeAge.Round(time.Millisecond))
			h.log.Info("HUNTER", "===============================================================")
			h.successfulHunts++
			h.currentAttempt = 0
			h.lastConnectedAt = time.Now()
		} else if h.lastConnectedAt.IsZero() {
			if !dev.LastHandshake.IsZero() {
				h.lastConnectedAt = dev.LastHandshake
			} else {
				h.lastConnectedAt = time.Now()
			}
		}
		h.state = StateConnected
		h.failedPings = 0
		h.mu.Unlock()
		return
	}

	// 3. Handshake is stale or zero, and no incoming RX packets.
	// Before deciding to hunt: verify if the peer responds to in-tunnel ping!
	if pingEnabled && pingTarget != "" {
		h.mu.Unlock()
		pingOK := ping.Ping(ctx, pingTarget, pingTimeout)
		h.mu.Lock()

		if pingOK {
			h.log.Debug("HUNTER", "Handshake stale (%v) but in-tunnel ping to %s succeeded; link is alive",
				dev.HandshakeAge.Round(time.Second), pingTarget)
			h.failedPings = 0
			if h.state == StateHunting || h.state == StateStalled {
				remoteEndpointStr := net.JoinHostPort(h.targetIP, strconv.Itoa(h.remotePort))
				h.log.Info("HUNTER", "===============================================================")
				h.log.Info("HUNTER", " WIREGUARD CONNECTED! In-tunnel ping to %s verified (5-tuple: :%d -> %s)",
					pingTarget, h.localPort, remoteEndpointStr)
				h.log.Info("HUNTER", "===============================================================")
				h.successfulHunts++
				h.currentAttempt = 0
				h.lastConnectedAt = time.Now()
			} else if h.lastConnectedAt.IsZero() {
				h.lastConnectedAt = time.Now()
			}
			h.state = StateConnected
			h.mu.Unlock()
			return
		}

		// In-tunnel ping failed
		h.failedPings++
		h.log.Warn("HUNTER", "Tunnel unresponsive: handshake age %v, in-tunnel ping #%d/%d to %s failed",
			dev.HandshakeAge.Round(time.Second), h.failedPings, threshold, pingTarget)

		if h.failedPings < threshold {
			// In grace verification period, do not hunt yet!
			if h.state == StateConnected {
				h.lastDisconnectedAt = time.Now()
			}
			h.state = StateStalled
			h.lastHuntReason = fmt.Sprintf("verifying_stalled_ping_%d/%d", h.failedPings, threshold)
			h.mu.Unlock()
			return
		}
	}

	// 4. Link is confirmed dead (failed pings reached threshold, or ping disabled)!
	if h.state == StateConnected {
		h.lastDisconnectedAt = time.Now()
	}
	h.state = StateHunting
	attempt := h.currentAttempt
	stallReason := "handshake_expired"
	if dev.LastHandshake.IsZero() {
		stallReason = "no_handshake_ever"
	} else if h.failedPings >= threshold {
		stallReason = fmt.Sprintf("pings_failed_%d_times", h.failedPings)
	}
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
		// Both try with random backoff
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
		h.log.Debug("HUNTER", "Waiting for peer's staggered hunt window (My role: %s, Attempt: #%d)", roleName, attempt)
	}
}

func (h *Hunter) executeHunt(reason string) {
	h.mu.Lock()
	iface := h.cfg.WireGuard.Interface
	localRange := h.cfg.Iptables.PortRange
	remoteRange := h.cfg.Hunter.RemotePortRange
	targetIP := h.targetIP
	peerKey := h.peerPubKey
	h.totalHunts++
	h.currentAttempt++
	h.lastHuntTime = time.Now()
	h.lastHuntReason = reason
	attempt := h.currentAttempt
	h.mu.Unlock()

	if targetIP == "" {
		h.log.Warn("HUNTER", "Cannot hunt: remote IP is not yet known. Ensure WireGuard has an initial endpoint set.")
		return
	}

	newLocalPort, err := config.PickRandomPort(localRange)
	if err != nil {
		h.log.Error("HUNTER", "Failed to pick random local port from %s: %v", localRange, err)
		return
	}

	newRemotePort, err := config.PickRandomPort(remoteRange)
	if err != nil {
		h.log.Error("HUNTER", "Failed to pick random remote port from %s: %v", remoteRange, err)
		return
	}

	newEndpoint := net.JoinHostPort(targetIP, strconv.Itoa(newRemotePort))
	h.log.Info("HUNTER", "[Hunt #%d] Rotating 5-tuple: local :%d -> remote %s (Reason: %s)",
		attempt, newLocalPort, newEndpoint, reason)

	// 1. Update local WireGuard ListenPort (busting client source-port DPI filter)
	if err := h.wgCtrl.UpdateListenPort(iface, newLocalPort); err != nil {
		h.log.Warn("HUNTER", "Failed to update local listen port: %v", err)
	}

	// 2. Synchronize iptables/ip6tables REDIRECT to the new ListenPort
	h.mu.RLock()
	iptEnabled := h.cfg.Iptables.Enabled
	h.mu.RUnlock()
	if iptEnabled {
		if err := h.iptMgr.ApplyForwardingRule(localRange, newLocalPort); err != nil {
			h.log.Warn("HUNTER", "Failed to sync iptables rule to port %d: %v", newLocalPort, err)
		}
	}

	// 3. Update remote peer Endpoint (destination port in peer's forwarded range)
	if err := h.wgCtrl.UpdatePeerEndpoint(iface, peerKey, newEndpoint); err != nil {
		h.log.Warn("HUNTER", "Failed to update peer endpoint to %s: %v", newEndpoint, err)
	}

	// 3. Trigger handshake packet burst
	h.triggerPacketBurst(targetIP, newRemotePort)
}

func (h *Hunter) triggerPacketBurst(targetIP string, remotePort int) {
	h.mu.RLock()
	pingEnabled := h.cfg.Hunter.TunnelPing.Enabled
	pingTarget := h.pingTarget
	h.mu.RUnlock()

	if pingEnabled && pingTarget != "" {
		// Send small UDP ping through the tunnel to force immediate packet queuing
		go func() {
			pingAddr := net.JoinHostPort(strings.Trim(pingTarget, "[]"), "51820")
			conn, err := net.DialTimeout("udp", pingAddr, 500*time.Millisecond)
			if err == nil {
				_, _ = conn.Write([]byte("wg-ping"))
				_ = conn.Close()
			}
		}()
	}
}

// TriggerHunt manually triggers an immediate hunt cycle.
func (h *Hunter) TriggerHunt(reason string) {
	select {
	case h.manualTrigger <- reason:
	default:
	}
}

// TriggerRebind manually rotates only the local listen port.
func (h *Hunter) TriggerRebind() {
	h.mu.Lock()
	iface := h.cfg.WireGuard.Interface
	localRange := h.cfg.Iptables.PortRange
	h.mu.Unlock()

	newPort, err := config.PickRandomPort(localRange)
	if err != nil {
		h.log.Error("HUNTER", "Pick random port failed: %v", err)
		return
	}

	h.log.Info("HUNTER", "Manual rebind: setting local ListenPort to %d", newPort)
	if err := h.wgCtrl.UpdateListenPort(iface, newPort); err != nil {
		h.log.Error("HUNTER", "UpdateListenPort failed: %v", err)
	}

	h.mu.RLock()
	iptEnabled := h.cfg.Iptables.Enabled
	h.mu.RUnlock()
	if iptEnabled {
		if err := h.iptMgr.ApplyForwardingRule(localRange, newPort); err != nil {
			h.log.Warn("HUNTER", "Failed to sync iptables rule to port %d: %v", newPort, err)
		}
	}
}

// UpdateConfig updates the in-memory config and saves it to disk.
func (h *Hunter) UpdateConfig(newCfg *config.Config) error {
	config.SetDefaults(newCfg)

	if err := config.SaveConfig(h.cfgPath, newCfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	h.mu.Lock()
	oldIptablesRange := h.cfg.Iptables.PortRange
	oldIptablesEnabled := h.cfg.Iptables.Enabled
	h.cfg = newCfg
	h.mu.Unlock()

	h.log.Info("HUNTER", "Configuration updated and saved to %s", h.cfgPath)

	// Reapply iptables if port range or enabled status changed
	if newCfg.Iptables.Enabled != oldIptablesEnabled || newCfg.Iptables.PortRange != oldIptablesRange {
		if !newCfg.Iptables.Enabled {
			_ = h.iptMgr.RemoveRule()
			h.mu.Lock()
			h.iptablesActive = false
			h.mu.Unlock()
		} else {
			h.applyIptablesRule()
		}
	}

	return nil
}

// GetConfig returns a copy of current configuration.
func (h *Hunter) GetConfig() config.Config {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return *h.cfg
}

// GetStatus returns the current status report for the web panel API.
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

	return StatusReport{
		State:              h.state,
		Interface:          h.cfg.WireGuard.Interface,
		LocalPublicKey:     h.localPubKey,
		PeerPublicKey:      h.peerPubKey,
		TargetIP:           h.targetIP,
		InTunnelPingTarget: h.pingTarget,
		LocalPort:          h.localPort,
		RemotePort:         h.remotePort,
		LastHandshake:      h.lastHandshake,
		HandshakeAge:       h.handshakeAge,
		HandshakeAgeSec:    hsAgeSec,
		LastConnectedAt:    h.lastConnectedAt,
		LastDisconnectedAt: h.lastDisconnectedAt,
		TransmitBytes:      h.txBytes,
		ReceiveBytes:       h.rxBytes,
		TotalHunts:         h.totalHunts,
		SuccessfulHunts:    h.successfulHunts,
		CurrentAttempt:     h.currentAttempt,
		FailedPings:        h.failedPings,
		LastHuntTime:       h.lastHuntTime,
		LastHuntReason:     h.lastHuntReason,
		IptablesActive:     h.iptablesActive,
		LocalPortRange:     h.cfg.Iptables.PortRange,
		RemotePortRange:    h.cfg.Hunter.RemotePortRange,
		IsPrimary:          isPrimary,
	}
}
