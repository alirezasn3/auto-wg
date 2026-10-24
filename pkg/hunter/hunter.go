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
	"sync/atomic"
	"time"

	"auto-wg/pkg/config"
	"auto-wg/pkg/iptables"
	"auto-wg/pkg/logger"
	"auto-wg/pkg/ping"
	"auto-wg/pkg/transport"
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
	Backend            string            `json:"backend,omitempty"`
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
	PingVerified       bool              `json:"ping_verified"`
	PingEnabled        bool              `json:"ping_enabled"`
	LastHuntTime       time.Time         `json:"last_hunt_time"`
	LastHuntReason     string            `json:"last_hunt_reason"`
	IptablesActive     bool              `json:"iptables_active"`
	LocalPortRange     string            `json:"local_port_range"`
	RemotePortRange    string            `json:"remote_port_range"`
	Hunting            bool              `json:"hunting"`
	IsPrimary          bool              `json:"is_primary"`

	// Transport is "direct", "tls" or "ssh"; the Link fields describe the TLS/SSH connection.
	Transport       string    `json:"transport"`
	LinkConnected   bool      `json:"link_connected"`
	LinkDirection   string    `json:"link_direction,omitempty"` // "dialed" or "accepted"
	LinkRemote      string    `json:"link_remote,omitempty"`
	LinkListenPort  int       `json:"link_listen_port,omitempty"`
	LinkRelayPort   int       `json:"link_relay_port,omitempty"`
	LinkBytesRx     uint64    `json:"link_bytes_rx"`
	LinkBytesTx     uint64    `json:"link_bytes_tx"`
	LinkLastError   string    `json:"link_last_error,omitempty"`
	LinkVerifying   bool      `json:"link_verifying,omitempty"`
	LinkRTTMs       float64   `json:"link_rtt_ms"`
	LinkProbeFails  uint64    `json:"link_probe_failures"`
	LinkVerifyFails uint64    `json:"link_verify_failures"`
	LinkResets      uint64    `json:"link_resets"`
	LinkSince       time.Time `json:"link_since"`
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
	wgCtrl        wg.Backend
	iptMgr        *iptables.Manager
	log           *logger.Logger
	onStateChange StateChangeHandler
	mu            sync.RWMutex

	// Live state
	state                string
	huntingEnabled       bool
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
	pingVerified         bool
	totalHunts           int64
	successfulHunts      int64
	currentAttempt       int
	lastHuntTime         time.Time
	lastHuntReason       string
	iptablesActive       bool
	manualTrigger        chan string

	// TLS/SSH transport (link.go)
	ctx           context.Context
	tun           linkTunnel
	newTunnel     func(transport.Options, transport.Deps) linkTunnel
	deadSince     time.Time // when the current dead period began
	lastLinkReset time.Time // when the link was last rebuilt in this dead period
	wgListenPort  atomic.Int32
	now           func() time.Time
}

func New(tunnelCfg config.TunnelConfig, wgCtrl wg.Backend, iptMgr *iptables.Manager, log *logger.Logger, onStateChange StateChangeHandler) *Hunter {
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

	// A nil *Controller wrapped in the interface must still read as "no backend".
	switch c := wgCtrl.(type) {
	case *wg.Controller:
		if c == nil {
			wgCtrl = nil
		}
	case *wg.AWGController:
		if c == nil {
			wgCtrl = nil
		}
	}

	huntingEnabled := true
	if tunnelCfg.Hunting != nil {
		huntingEnabled = *tunnelCfg.Hunting
	} else if tunnelCfg.Passive {
		huntingEnabled = false
	}

	h := &Hunter{
		cfg:               tunnelCfg,
		historyFile:       histFile,
		wgCtrl:            wgCtrl,
		iptMgr:            iptMgr,
		log:               log,
		onStateChange:     onStateChange,
		state:             StateUnknown,
		huntingEnabled:    huntingEnabled,
		targetIP:          initialTarget,
		targetIPs:         resolved,
		targetIPIndex:     0,
		configuredTargets: rawTargets,
		pingTarget:        strings.TrimSpace(tunnelCfg.TunnelPing.TargetIP),
		lastDirection:     "Local ⇄ Remote",
		events:            make([]ConnectionEvent, 0, 50),
		manualTrigger:     make(chan string, 10),
		newTunnel:         newLinkTunnel,
		now:               time.Now,
	}
	h.loadHistory()
	return h
}

// setLocalPort records WireGuard's listen port. The copy in wgListenPort lets the link's relay read it
// without taking the hunter lock on every packet.
func (h *Hunter) setLocalPort(p int) {
	h.localPort = p
	h.wgListenPort.Store(int32(p))
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
	h.mu.Lock()
	h.ctx = ctx
	h.mu.Unlock()
	defer func() {
		h.stopLink()
		_ = h.SaveHistory()
	}()

	// 1. Initialize WireGuard listen port and peer endpoint from config if unset in interface config
	h.initializeInterface()

	// 2. Apply iptables rule if enabled
	h.applyIptablesRule()

	// 2b. Start the TLS/SSH transport (listener, dial loop, relay) if configured
	h.startLink()

	// 3. Save initial history state so the file exists on disk immediately
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

func (h *Hunter) initializeInterface() {
	h.mu.RLock()
	iface := h.cfg.Interface
	localRange := h.cfg.PortRange
	remoteRange := h.cfg.RemotePortRange
	peerKey := h.cfg.PeerPublicKey
	targetIP := h.targetIP
	h.mu.RUnlock()

	if h.wgCtrl == nil {
		return
	}

	dev, err := h.wgCtrl.GetDeviceInfo(iface, peerKey)
	if err != nil {
		h.log.Debug("HUNTER", "[%s] Cannot query interface on startup initialize: %v", iface, err)
		return
	}

	h.mu.Lock()
	if dev.PublicKey != "" {
		h.localPubKey = dev.PublicKey
	}
	if dev.PeerPublicKey != "" {
		h.peerPubKey = dev.PeerPublicKey
		peerKey = dev.PeerPublicKey
	}
	h.mu.Unlock()

	// A TLS/SSH transport keeps WireGuard on its configured port: the port ranges are TCP and belong to the link.
	if linked(h.cfg) {
		if dev.ListenPort > 0 {
			h.mu.Lock()
			h.setLocalPort(dev.ListenPort)
			h.mu.Unlock()
		}
		return
	}

	// 1. Ensure local listen port is within configured port_range
	start, end, errRange := config.ParsePortRange(localRange)
	needsNewListenPort := false
	if errRange == nil {
		if dev.ListenPort < start || dev.ListenPort > end {
			needsNewListenPort = true
		}
	}
	if needsNewListenPort && localRange != "" {
		newPort, err := config.PickRandomPort(localRange)
		if err == nil {
			if err := h.wgCtrl.UpdateListenPort(iface, newPort); err == nil {
				h.mu.Lock()
				h.setLocalPort(newPort)
				h.mu.Unlock()
				h.log.Info("HUNTER", "[%s] Auto-assigned WireGuard listen port to :%d (from port_range %s)", iface, newPort, localRange)
			} else {
				h.log.Warn("HUNTER", "[%s] Failed to set initial listen port :%d: %v", iface, newPort, err)
			}
		}
	} else if dev.ListenPort > 0 {
		h.mu.Lock()
		h.setLocalPort(dev.ListenPort)
		h.mu.Unlock()
	}

	// 2. If WireGuard peer has no endpoint configured (or has an unconfigured stale endpoint with no active handshake), auto-assign initial endpoint!
	endpointNeedsInit := dev.PeerEndpoint == ""
	if !endpointNeedsInit && len(h.targetIPs) > 0 && dev.PeerEndpointIP != "" {
		cleanDevIP := strings.Trim(dev.PeerEndpointIP, "[]")
		match := false
		for _, tip := range h.targetIPs {
			if tip == cleanDevIP {
				match = true
				break
			}
		}
		if !match && (dev.LastHandshake.IsZero() || dev.HandshakeAge > h.cfg.HandshakeTimeout) {
			endpointNeedsInit = true
		}
	}
	if endpointNeedsInit && peerKey != "" && targetIP != "" && remoteRange != "" {
		initialRemotePort, err := config.PickRandomPort(remoteRange)
		if err == nil {
			initialEndpoint := net.JoinHostPort(targetIP, strconv.Itoa(initialRemotePort))
			if err := h.wgCtrl.UpdatePeerEndpoint(iface, peerKey, initialEndpoint); err == nil {
				h.mu.Lock()
				h.remotePort = initialRemotePort
				h.lastDialedRemotePort = initialRemotePort
				h.lastDialedAt = time.Now()
				h.mu.Unlock()
				h.log.Info("HUNTER", "[%s] Auto-assigned peer endpoint to %s (from target_ips and remote_port_range %s)",
					iface, initialEndpoint, remoteRange)
			} else {
				h.log.Warn("HUNTER", "[%s] Failed to set initial peer endpoint %s: %v", iface, initialEndpoint, err)
			}
		}
	} else if dev.PeerPort > 0 {
		h.mu.Lock()
		h.remotePort = dev.PeerPort
		h.mu.Unlock()
	}
}

func (h *Hunter) applyIptablesRule() {
	h.mu.Lock()
	enabled := h.cfg.Iptables
	portRange := h.cfg.PortRange
	iface := h.cfg.Interface
	localPort := h.localPort
	h.mu.Unlock()

	if !enabled {
		h.log.Info("HUNTER", "[%s] Iptables management is disabled in config", iface)
		return
	}
	if linked(h.cfg) {
		return // the link installs its own TCP redirect
	}

	// Read current WireGuard listen port
	targetPort := 51820
	if localPort > 0 {
		targetPort = localPort
	}
	if h.wgCtrl != nil {
		dev, err := h.wgCtrl.GetDeviceInfo(iface, "")
		if err == nil && dev.ListenPort > 0 {
			targetPort = dev.ListenPort
		}
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

	// On a TLS/SSH transport WireGuard's endpoint is the loopback relay, which is not a peer address: it
	// must neither become the target IP nor the remote port.
	onRelay := linked(h.cfg)
	if onRelay {
		h.ensureRelayEndpointLocked(dev.PeerEndpointIP, dev.PeerPort)
	}
	isLoopbackEndpoint := onRelay
	if ip := net.ParseIP(strings.Trim(dev.PeerEndpointIP, "[]")); ip != nil && ip.IsLoopback() {
		isLoopbackEndpoint = true
	}

	if isLoopbackEndpoint {
		// keep the last direct target
	} else if dev.PeerEndpointIP != "" {
		cleanDevIP := strings.Trim(dev.PeerEndpointIP, "[]")
		found := false
		for idx, tip := range h.targetIPs {
			if tip == cleanDevIP {
				found = true
				h.targetIPIndex = idx
				h.targetIP = cleanDevIP
				break
			}
		}
		if !found && cleanDevIP != "" {
			if len(h.configuredTargets) == 0 {
				h.targetIP = cleanDevIP
				h.targetIPs = []string{cleanDevIP}
				h.targetIPIndex = 0
			} else if !dev.LastHandshake.IsZero() && dev.HandshakeAge <= timeout {
				// Handshake is active and healthy: WireGuard roamed to peer's actual NAT/egress IP
				h.targetIP = cleanDevIP
			}
		}
	} else if h.targetIP == "" && len(h.targetIPs) > 0 {
		h.targetIP = h.targetIPs[0]
	} else if h.targetIP == "" && h.cfg.TargetIP != "" {
		h.targetIP = strings.Trim(h.cfg.TargetIP, "[]")
	}
	h.setLocalPort(dev.ListenPort)
	if !isLoopbackEndpoint {
		h.remotePort = dev.PeerPort
	}
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
		for _, aip := range dev.PeerAllowedIPs {
			clean := strings.TrimSpace(aip)
			if clean != "" && clean != "0.0.0.0" && clean != "::" && !strings.HasSuffix(clean, ".0") {
				pingTarget = clean
				break
			}
		}
	}
	h.pingTarget = pingTarget

	if h.peerPubKey == "" {
		h.setState(StateUnknown)
		h.pingVerified = false
		h.mu.Unlock()
		h.log.Warn("HUNTER", "[%s] No peer found on interface %s. Waiting for peer configuration...", iface, iface)
		return
	}

	isPrimary := dev.PublicKey < dev.PeerPublicKey
	if h.tun != nil {
		h.tun.SetPrimary(isPrimary)
		h.tun.SetTargets(h.linkTargetsLocked())
	}

	hasHandshakeEver := !dev.LastHandshake.IsZero()
	isHandshakeFresh := hasHandshakeEver && dev.HandshakeAge <= timeout

	// 2. Active In-Tunnel Ping Verification (if enabled)
	if pingEnabled && pingTarget != "" {
		if hasHandshakeEver || rxProgress {
			h.mu.Unlock()
			pingOK := ping.Ping(ctx, pingTarget, pingTimeout)
			h.mu.Lock()

			if pingOK {
				h.pingVerified = true
				h.failedPings = 0
				if h.state == StateHunting || h.state == StateStalled {
					remoteEndpointStr := h.remoteDescLocked()
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
					remoteEndpointStr := h.remoteDescLocked()
					h.addEvent(StateConnected, dir, "Initial Ping", fmt.Sprintf("Ping verified: :%d -> %s", h.localPort, remoteEndpointStr), 0)
				}
				h.deadSince, h.lastLinkReset = time.Time{}, time.Time{}
				h.setState(StateConnected)
				h.mu.Unlock()
				return
			}

			// In-tunnel ping failed
			h.pingVerified = false
			h.failedPings++
			h.log.Warn("HUNTER", "[%s] In-tunnel ping #%d/%d to %s failed (handshake age: %v)",
				iface, h.failedPings, threshold, pingTarget, dev.HandshakeAge.Round(time.Second))

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
		} else {
			h.pingVerified = false
		}
	} else {
		// Ping is disabled or no target: rely on passive WireGuard handshake & rxProgress
		h.pingVerified = false
		if isHandshakeFresh || (hasHandshakeEver && rxProgress) {
			if h.state == StateHunting || h.state == StateStalled {
				remoteEndpointStr := h.remoteDescLocked()
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
				remoteEndpointStr := h.remoteDescLocked()
				h.log.Info("HUNTER", "[%s] Tunnel healthy & active: :%d -> %s (Handshake: %v ago)",
					iface, h.localPort, remoteEndpointStr, dev.HandshakeAge.Round(time.Millisecond))
				h.addEvent(StateConnected, dir, "Initial Handshake", fmt.Sprintf("Link active: :%d -> %s", h.localPort, remoteEndpointStr), 0)
			}
			h.deadSince, h.lastLinkReset = time.Time{}, time.Time{}
			h.setState(StateConnected)
			h.failedPings = 0
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

	if !h.huntingEnabled {
		h.setState(StateDisconnected)
		h.lastHuntReason = "passive_mode_no_hunt"
		h.mu.Unlock()
		return
	}

	h.setState(StateHunting)
	attempt := h.currentAttempt
	if h.deadSince.IsZero() {
		h.deadSince = h.now()
	}
	if linked(h.cfg) {
		act := h.planLinkLocked()
		h.mu.Unlock()
		// UDP ports are not hunted here; the link is rebuilt instead.
		if act != linkStay {
			h.recoverLink(act, stallReason)
		}
		return
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
	if linked(h.cfg) && h.tun != nil {
		if st := h.tun.Status(); st.Direction == "dialed" {
			return "Local → Remote", "Local Host"
		}
		return "Remote → Local", "Remote Peer"
	}
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
	if h.reconnectLink() {
		return
	}
	h.mu.RLock()
	configuredTargets := make([]string, len(h.configuredTargets))
	copy(configuredTargets, h.configuredTargets)
	h.mu.RUnlock()

	// If domain names/hostnames are configured, re-resolve them on every hunt attempt!
	if config.HasHostnames(configuredTargets) {
		freshIPs := config.ResolveTargetIPs(configuredTargets)
		if len(freshIPs) > 0 {
			h.mu.Lock()
			h.targetIPs = freshIPs
			h.mu.Unlock()
		}
	}

	h.mu.Lock()
	iface := h.cfg.Interface
	localRange := h.cfg.PortRange
	remoteRange := h.cfg.RemotePortRange
	peerKey := h.peerPubKey
	curLocal, curRemote := h.localPort, h.remotePort
	h.totalHunts++
	h.currentAttempt++
	h.lastHuntTime = time.Now()
	h.lastHuntReason = reason
	h.pingVerified = false
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

	// Both ends of the 5-tuple change on every hunt, and never to the value currently in use.
	newLocalPort, err := config.PickRandomPortExcluding(localRange, curLocal)
	if err != nil {
		h.log.Error("HUNTER", "[%s] Failed to pick random local port from %s: %v", iface, localRange, err)
		return
	}

	newRemotePort, err := config.PickRandomPortExcluding(remoteRange, curRemote)
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
		h.setLocalPort(newLocalPort)
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
}

// TriggerHunt initiates an immediate hunt cycle out-of-band.
func (h *Hunter) TriggerHunt(reason string) {
	if !h.huntingEnabled {
		h.log.Warn("HUNTER", "[%s] Cannot trigger hunt: tunnel is in passive/monitoring mode (hunting disabled)", h.cfg.Interface)
		return
	}
	select {
	case h.manualTrigger <- reason:
	default:
	}
}

// TriggerRebind rotates the local listen port and updates iptables forwarding.
func (h *Hunter) TriggerRebind() error {
	if !h.huntingEnabled {
		return fmt.Errorf("rebind is disabled on passive tunnel %s", h.cfg.Interface)
	}

	if h.reconnectLink() {
		return nil
	}

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
	h.setLocalPort(newPort)
	h.pingVerified = false
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

	report := StatusReport{
		Interface:          h.cfg.Interface,
		Backend:            h.cfg.Backend,
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
		PingVerified:       h.pingVerified,
		PingEnabled:        h.cfg.TunnelPing.Enabled,
		LastHuntTime:       h.lastHuntTime,
		LastHuntReason:     h.lastHuntReason,
		IptablesActive:     h.iptablesActive,
		LocalPortRange:     h.cfg.PortRange,
		RemotePortRange:    h.cfg.RemotePortRange,
		Hunting:            h.huntingEnabled,
		IsPrimary:          isPrimary,
		Transport:          config.NormalizeTransport(h.cfg.Transport),
	}
	if ts, ok := h.linkStatusLocked(); ok {
		report.LinkConnected = ts.Connected
		report.LinkDirection = ts.Direction
		report.LinkRemote = ts.Remote
		report.LinkListenPort = ts.ListenPort
		report.LinkRelayPort = ts.RelayPort
		report.LinkBytesRx = ts.BytesRx
		report.LinkBytesTx = ts.BytesTx
		report.LinkLastError = ts.LastError
		report.LinkVerifying = ts.Verifying
		report.LinkRTTMs = ts.RTTMs
		report.LinkProbeFails = ts.ProbeFails
		report.LinkVerifyFails = ts.VerifyFails
		report.LinkResets = ts.Resets
		report.LinkSince = ts.Since
	}
	return report
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

// UpdateConfig dynamically updates the tunnel configuration in memory without tearing down active handshakes.
func (h *Hunter) UpdateConfig(newCfg config.TunnelConfig) {
	h.mu.Lock()
	defer h.mu.Unlock()
	oldCfg := h.cfg

	h.cfg.Name = newCfg.Name
	if newCfg.CheckInterval > 0 {
		h.cfg.CheckInterval = newCfg.CheckInterval
	}
	if newCfg.HandshakeTimeout > 0 {
		h.cfg.HandshakeTimeout = newCfg.HandshakeTimeout
	}
	if newCfg.CycleTimeout > 0 {
		h.cfg.CycleTimeout = newCfg.CycleTimeout
	}
	if newCfg.PortRange != "" {
		h.cfg.PortRange = newCfg.PortRange
	}
	if newCfg.RemotePortRange != "" {
		h.cfg.RemotePortRange = newCfg.RemotePortRange
	}
	if newCfg.PeerPublicKey != "" {
		h.cfg.PeerPublicKey = newCfg.PeerPublicKey
		h.peerPubKey = newCfg.PeerPublicKey
	}

	if newCfg.Hunting != nil {
		h.huntingEnabled = *newCfg.Hunting
		h.cfg.Hunting = newCfg.Hunting
	} else if newCfg.Passive {
		h.huntingEnabled = false
		h.cfg.Passive = true
	} else {
		h.huntingEnabled = true
	}

	h.cfg.TunnelPing = newCfg.TunnelPing
	h.pingTarget = strings.TrimSpace(newCfg.TunnelPing.TargetIP)
	h.cfg.Iptables = newCfg.Iptables

	// Update target IPs / hostnames
	var rawTargets []string
	for _, ip := range newCfg.TargetIPs {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			rawTargets = append(rawTargets, ip)
		}
	}
	if newCfg.TargetIP != "" {
		ip := strings.TrimSpace(newCfg.TargetIP)
		if ip != "" {
			rawTargets = append(rawTargets, ip)
		}
	}
	h.configuredTargets = rawTargets
	resolved := config.ResolveTargetIPs(rawTargets)
	if len(resolved) > 0 {
		h.targetIPs = resolved
		targetChanged := false
		found := false
		for idx, tip := range resolved {
			if tip == h.targetIP {
				found = true
				h.targetIPIndex = idx
				break
			}
		}
		if !found {
			h.targetIP = resolved[0]
			h.targetIPIndex = 0
			targetChanged = true
		}

		if targetChanged && h.peerPubKey != "" && h.targetIP != "" {
			port := h.remotePort
			if port <= 0 && h.cfg.RemotePortRange != "" {
				port, _ = config.PickRandomPort(h.cfg.RemotePortRange)
			}
			if port > 0 {
				h.remotePort = port
				newEndpoint := net.JoinHostPort(h.targetIP, strconv.Itoa(port))
				if err := h.wgCtrl.UpdatePeerEndpoint(h.cfg.Interface, h.peerPubKey, newEndpoint); err == nil {
					h.log.Info("HUNTER", "[%s] Updated WireGuard peer endpoint to %s on config update", h.cfg.Interface, newEndpoint)
				}
			}
		}
	}

	h.cfg.Transport = newCfg.Transport
	h.cfg.TLS, h.cfg.SSH = newCfg.TLS, newCfg.SSH

	// Update iptables rules if needed
	if linked(h.cfg) {
		if h.iptMgr != nil {
			_ = h.iptMgr.RemoveRule(h.cfg.Interface)
		}
		h.iptablesActive = false
	} else if h.cfg.Iptables && h.iptMgr != nil && h.localPort > 0 {
		_ = h.iptMgr.ApplyForwardingRule(h.cfg.Interface, h.cfg.PortRange, h.localPort)
		h.iptablesActive = true
	} else if !h.cfg.Iptables && h.iptMgr != nil {
		_ = h.iptMgr.RemoveRule(h.cfg.Interface)
		h.iptablesActive = false
	}

	// Rebuild the link when its settings (or the ranges and iptables flag it depends on) changed
	if linkConfigChanged(oldCfg, h.cfg) {
		h.stopLinkLocked()
		if linked(oldCfg) && !linked(h.cfg) {
			h.restoreDirectLocked()
		}
		h.startLinkLocked()
	}

	h.log.Info("HUNTER", "[%s] Config updated live: hunting=%v, port_range=%s, targets=%v",
		h.cfg.Interface, h.huntingEnabled, h.cfg.PortRange, h.targetIPs)
}

