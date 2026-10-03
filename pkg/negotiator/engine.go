package negotiator

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"time"

	"auto-wg/pkg/config"
	"auto-wg/pkg/logger"
	"auto-wg/pkg/monitor"
	"auto-wg/pkg/prober"
	"auto-wg/pkg/signaling"
	"auto-wg/pkg/wg"
)

type Engine struct {
	cfg        *config.Config
	wgCtrl     *wg.Controller
	signaler   *signaling.CompositeSignaler
	monitor    *monitor.Monitor
	log        *logger.Logger
	epoch      int64
	mu         sync.Mutex
	isBusy     bool
	lastAction time.Time
}

func NewEngine(cfg *config.Config, wgCtrl *wg.Controller, signaler *signaling.CompositeSignaler, mon *monitor.Monitor, log *logger.Logger) *Engine {
	e := &Engine{
		cfg:        cfg,
		wgCtrl:     wgCtrl,
		signaler:   signaler,
		monitor:    mon,
		log:        log,
		epoch:      time.Now().Unix(),
		lastAction: time.Now(),
	}
	return e
}

// TriggerFailure handles a detected tunnel drop.
func (e *Engine) TriggerFailure(reason string) {
	e.mu.Lock()
	if e.isBusy {
		e.mu.Unlock()
		return
	}
	e.isBusy = true
	e.mu.Unlock()

	defer func() {
		e.mu.Lock()
		e.isBusy = false
		e.mu.Unlock()
	}()

	e.log.Warn("ENGINE", "Initiating tunnel recovery. Trigger reason: %s", reason)
	e.monitor.SetState(monitor.StateNegotiating)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Stage 1: Quick Local Rebind (bypasses 5-tuple DPI blocks on client source port)
	if e.cfg.Negotiation.QuickRebindFirst {
		if e.tryQuickRebind(ctx) {
			e.log.Info("ENGINE", "Quick local port rebind successfully restored the tunnel!")
			e.monitor.SetState(monitor.StateHealthy)
			return
		}
		e.log.Warn("ENGINE", "Quick rebind did not restore connection. Proceeding to full coordinated negotiation...")
	}

	// Stage 2: Coordinated Full Port Negotiation
	if err := e.PerformNegotiation(ctx); err != nil {
		e.log.Error("ENGINE", "Full negotiation failed: %v", err)
		e.monitor.SetState(monitor.StateStalled)
	} else {
		e.log.Info("ENGINE", "Port negotiation succeeded! WireGuard tunnel re-established.")
		e.monitor.SetState(monitor.StateHealthy)
	}
}

// tryQuickRebind changes local ListenPort to reset DPI 5-tuple tracking.
func (e *Engine) tryQuickRebind(ctx context.Context) bool {
	e.log.Info("ENGINE", "Attempting Stage 1: Quick local ListenPort rotation...")

	info, err := e.wgCtrl.GetDeviceInfo(e.cfg.WireGuard.Interface, e.cfg.WireGuard.PeerPublicKey)
	if err != nil {
		e.log.Warn("ENGINE", "Failed to get device info for quick rebind: %v", err)
		return false
	}

	// Pick a new random port from candidate ports different from current
	candidates := e.cfg.Negotiation.CandidatePorts
	if len(candidates) == 0 {
		return false
	}

	newPort := candidates[rand.Intn(len(candidates))]
	if newPort == info.ListenPort && len(candidates) > 1 {
		newPort = candidates[(rand.Intn(len(candidates)-1)+1)%len(candidates)]
	}

	e.log.Info("ENGINE", "Rotating local ListenPort from %d to %d (resetting DPI flow state)", info.ListenPort, newPort)
	if err := e.wgCtrl.UpdateListenPort(e.cfg.WireGuard.Interface, newPort); err != nil {
		e.log.Warn("ENGINE", "Failed to update listen port: %v", err)
		return false
	}

	// Wait up to QuickRebindTimeout for handshake
	timeout := e.cfg.Negotiation.QuickRebindTimeout
	deadline := time.Now().Add(timeout)
	lastHs := info.LastHandshake

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(1500 * time.Millisecond):
		}

		curInfo, err := e.wgCtrl.GetDeviceInfo(e.cfg.WireGuard.Interface, e.cfg.WireGuard.PeerPublicKey)
		if err == nil && !curInfo.LastHandshake.IsZero() && curInfo.LastHandshake.After(lastHs) {
			e.log.Info("ENGINE", "New handshake observed at %v (age: %v) after quick rebind!",
				curInfo.LastHandshake.Format("15:04:05"), curInfo.HandshakeAge.Round(time.Millisecond))
			return true
		}
	}

	return false
}

// PerformNegotiation coordinates candidate port discovery with the remote peer via signaling backends.
func (e *Engine) PerformNegotiation(ctx context.Context) error {
	e.epoch++
	epoch := e.epoch
	e.log.Info("ENGINE", "Starting negotiation Epoch #%d with peer %s", epoch, e.cfg.RemotePeerID)

	candidates := e.cfg.Negotiation.CandidatePorts
	if len(candidates) == 0 {
		return fmt.Errorf("no candidate ports configured")
	}

	// 1. Announce Hunting State
	myState := &signaling.PeerState{
		PeerID: e.cfg.PeerID,
		Role:   signaling.RoleHunting,
		Epoch:  epoch,
	}
	if err := e.signaler.PublishState(ctx, myState); err != nil {
		e.log.Warn("ENGINE", "Failed to publish hunting state: %v", err)
	}

	// 2. Start UDP Prober Listener on candidate ports
	listener := prober.NewListener(e.cfg.RemotePeerID, e.cfg.Signaling.SecretToken, candidates, e.log)
	if err := listener.Start(ctx); err != nil {
		e.log.Warn("ENGINE", "Listener start warnings: %v", err)
	}
	defer listener.Stop()

	// 3. Send UDP Probes to remote host
	remoteHost := e.cfg.WireGuard.RemoteHost
	if remoteHost == "" {
		// Try parsing from initial endpoint
		remoteHost = extractHost(e.cfg.WireGuard.Interface)
	}

	if remoteHost != "" {
		p := prober.NewProber(e.cfg.PeerID, e.cfg.Signaling.SecretToken, remoteHost, candidates, e.log)
		go func() {
			time.Sleep(500 * time.Millisecond) // Let remote listener start
			_ = p.SendProbes(ctx, 3)
		}()
	}

	// 4. Wait for probes to be exchanged
	probeWait := e.cfg.Negotiation.ProbeTimeout
	e.log.Info("ENGINE", "Probing active. Waiting %v for probes to traverse network...", probeWait)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(probeWait):
	}

	// 5. Collect local received ports & publish RoleProbeResult
	receivedPorts := listener.GetReceivedPorts()
	e.log.Info("ENGINE", "Probe phase completed. Locally received verified probes on %d ports: %v",
		len(receivedPorts), receivedPorts)

	myResultState := &signaling.PeerState{
		PeerID:       e.cfg.PeerID,
		Role:         signaling.RoleProbeResult,
		Epoch:        epoch,
		WorkingPorts: receivedPorts,
	}
	if err := e.signaler.PublishState(ctx, myResultState); err != nil {
		e.log.Warn("ENGINE", "Failed to publish probe results: %v", err)
	}

	// 6. Fetch remote peer's probe results from signaling plane
	remoteResults, err := e.pollRemoteResults(ctx, epoch, 20*time.Second)
	if err != nil {
		return fmt.Errorf("poll remote peer results: %w", err)
	}

	e.log.Info("ENGINE", "Received remote peer %s probe results: %v (they can receive from us on these ports)",
		e.cfg.RemotePeerID, remoteResults.WorkingPorts)

	// 7. Select Ports:
	// - Remote peer can receive on `remoteResults.WorkingPorts` -> We use one of these as our Endpoint port!
	// - We can receive on `receivedPorts` -> We use one of these as our local ListenPort!
	var selectedRemotePort int
	if len(remoteResults.WorkingPorts) > 0 {
		selectedRemotePort = remoteResults.WorkingPorts[0]
	} else if len(candidates) > 0 {
		// Fallback if asymmetric blocking: try next candidate
		selectedRemotePort = candidates[rand.Intn(len(candidates))]
		e.log.Warn("ENGINE", "No confirmed remote ports received; falling back to candidate port %d", selectedRemotePort)
	}

	var selectedLocalPort int
	if len(receivedPorts) > 0 {
		selectedLocalPort = receivedPorts[0]
	} else if len(candidates) > 0 {
		selectedLocalPort = candidates[rand.Intn(len(candidates))]
		e.log.Warn("ENGINE", "No confirmed local ports received; falling back to candidate port %d", selectedLocalPort)
	}

	e.log.Info("ENGINE", "Applying negotiated configuration: Local ListenPort=%d, Remote EndpointPort=%d",
		selectedLocalPort, selectedRemotePort)

	// Stop listener before binding WireGuard to the selected port
	listener.Stop()

	// 8. Update WireGuard
	if selectedLocalPort > 0 {
		if err := e.wgCtrl.UpdateListenPort(e.cfg.WireGuard.Interface, selectedLocalPort); err != nil {
			e.log.Error("ENGINE", "Failed to apply negotiated local listen port: %v", err)
		}
	}

	if selectedRemotePort > 0 && remoteHost != "" {
		endpoint := net.JoinHostPort(remoteHost, strconv.Itoa(selectedRemotePort))
		if err := e.wgCtrl.UpdatePeerEndpoint(e.cfg.WireGuard.Interface, e.cfg.WireGuard.PeerPublicKey, endpoint); err != nil {
			e.log.Error("ENGINE", "Failed to apply negotiated remote endpoint: %v", err)
		}
	}

	// 9. Publish Agreed state
	agreedState := &signaling.PeerState{
		PeerID:      e.cfg.PeerID,
		Role:        signaling.RoleAgreed,
		Epoch:       epoch,
		CurrentPort: selectedRemotePort,
		LocalListen: selectedLocalPort,
	}
	_ = e.signaler.PublishState(ctx, agreedState)

	// 10. Verify Handshake
	e.log.Info("ENGINE", "Awaiting handshake verification on new ports...")
	return e.verifyHandshake(ctx, 15*time.Second)
}

func (e *Engine) pollRemoteResults(ctx context.Context, epoch int64, timeout time.Duration) (*signaling.PeerState, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(1 * time.Second):
		}

		st, err := e.signaler.FetchPeerState(ctx, e.cfg.RemotePeerID)
		if err != nil {
			e.log.Debug("ENGINE", "Polling peer state: %v", err)
			continue
		}

		if st != nil && st.Epoch == epoch && (st.Role == signaling.RoleProbeResult || st.Role == signaling.RoleAgreed) {
			return st, nil
		}
	}
	return nil, fmt.Errorf("timeout waiting for peer %s probe results", e.cfg.RemotePeerID)
}

func (e *Engine) verifyHandshake(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}

		info, err := e.wgCtrl.GetDeviceInfo(e.cfg.WireGuard.Interface, e.cfg.WireGuard.PeerPublicKey)
		if err == nil && !info.LastHandshake.IsZero() && info.HandshakeAge < 20*time.Second {
			e.log.Info("ENGINE", "Handshake confirmed! Tunnel is healthy (age: %v, rx: %d B, tx: %d B)",
				info.HandshakeAge.Round(time.Millisecond), info.ReceiveBytes, info.TransmitBytes)
			return nil
		}
	}
	return fmt.Errorf("handshake verification timed out after %v", timeout)
}

func extractHost(endpoint string) string {
	host, _, err := net.SplitHostPort(endpoint)
	if err == nil {
		return host
	}
	return endpoint
}
