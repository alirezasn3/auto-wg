package monitor

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"auto-wg/pkg/config"
	"auto-wg/pkg/logger"
	"auto-wg/pkg/wg"
)

type TunnelHealthState string

const (
	StateHealthy     TunnelHealthState = "HEALTHY"
	StateStalled     TunnelHealthState = "STALLED"
	StateAsymmetric  TunnelHealthState = "ASYMMETRIC"
	StateNegotiating TunnelHealthState = "NEGOTIATING"
	StateUnknown     TunnelHealthState = "UNKNOWN"
)

type StatusReport struct {
	State          TunnelHealthState `json:"state"`
	Interface      string            `json:"interface"`
	LocalPort      int               `json:"local_port"`
	PeerEndpoint   string            `json:"peer_endpoint"`
	LastHandshake  time.Time         `json:"last_handshake"`
	HandshakeAge   time.Duration     `json:"handshake_age"`
	HandshakeSecs  int64             `json:"handshake_secs"`
	TxBytes        int64             `json:"tx_bytes"`
	RxBytes        int64             `json:"rx_bytes"`
	PingFailures   int               `json:"ping_failures"`
	LastCheckTime  time.Time         `json:"last_check_time"`
	StateReason    string            `json:"state_reason"`
}

type Monitor struct {
	cfg        *config.Config
	wgCtrl     *wg.Controller
	log        *logger.Logger
	mu         sync.RWMutex
	lastReport StatusReport
	consecFail int
	lastTx     int64
	lastRx     int64
	onFailure  func(reason string)
}

func New(cfg *config.Config, wgCtrl *wg.Controller, log *logger.Logger, onFailure func(reason string)) *Monitor {
	return &Monitor{
		cfg:       cfg,
		wgCtrl:    wgCtrl,
		log:       log,
		onFailure: onFailure,
		lastReport: StatusReport{
			State: StateUnknown,
		},
	}
}

func (m *Monitor) Start(ctx context.Context) {
	ticker := time.NewTicker(m.cfg.Monitor.CheckInterval)
	defer ticker.Stop()

	m.log.Info("MONITOR", "WireGuard tunnel health monitor started (interval: %v, handshake timeout: %v)",
		m.cfg.Monitor.CheckInterval, m.cfg.Monitor.HandshakeTimeout)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkHealth()
		}
	}
}

func (m *Monitor) checkHealth() {
	m.mu.Lock()
	if m.lastReport.State == StateNegotiating {
		m.mu.Unlock()
		return // Currently in negotiation, skip checks
	}
	m.mu.Unlock()

	info, err := m.wgCtrl.GetDeviceInfo(m.cfg.WireGuard.Interface, m.cfg.WireGuard.PeerPublicKey)
	if err != nil {
		m.log.Warn("MONITOR", "Failed to query WireGuard device: %v", err)
		return
	}

	report := StatusReport{
		Interface:     info.Name,
		LocalPort:     info.ListenPort,
		PeerEndpoint:  info.PeerEndpoint,
		LastHandshake: info.LastHandshake,
		HandshakeAge:  info.HandshakeAge,
		HandshakeSecs: int64(info.HandshakeAge.Seconds()),
		TxBytes:       info.TransmitBytes,
		RxBytes:       info.ReceiveBytes,
		LastCheckTime: time.Now(),
	}

	var state TunnelHealthState = StateHealthy
	var failureReason string

	// 1. Passive Handshake Age Check
	if !info.LastHandshake.IsZero() && info.HandshakeAge > m.cfg.Monitor.HandshakeTimeout {
		state = StateStalled
		failureReason = fmt.Sprintf("Handshake age (%v) exceeds timeout (%v)", info.HandshakeAge.Round(time.Second), m.cfg.Monitor.HandshakeTimeout)
	}

	// 2. Asymmetric Flow Check: Tx increasing but Rx zero or stagnant
	if info.TransmitBytes > m.lastTx+2000 && info.ReceiveBytes == m.lastRx && !info.LastHandshake.IsZero() && info.HandshakeAge > 30*time.Second {
		// Only trigger if data was attempted to be sent but nothing arrived back
		state = StateAsymmetric
		failureReason = fmt.Sprintf("Asymmetric traffic drop detected (Tx increased by %d B, Rx stagnant)", info.TransmitBytes-m.lastTx)
	}

	// 3. Active In-Tunnel Ping Check
	if m.cfg.Monitor.TunnelPing.Enabled && m.cfg.Monitor.TunnelPing.TargetIP != "" {
		pingOK := m.pingTunnelTarget()
		if !pingOK {
			m.consecFail++
			report.PingFailures = m.consecFail
			if m.consecFail >= m.cfg.Monitor.TunnelPing.FailureThreshold {
				state = StateStalled
				failureReason = fmt.Sprintf("Active in-tunnel probe failed %d consecutive times", m.consecFail)
			}
		} else {
			m.consecFail = 0
		}
	}

	m.lastTx = info.TransmitBytes
	m.lastRx = info.ReceiveBytes

	report.State = state
	report.StateReason = failureReason

	m.mu.Lock()
	prevReport := m.lastReport
	m.lastReport = report
	m.mu.Unlock()

	if state != StateHealthy && prevReport.State == StateHealthy {
		m.log.Warn("MONITOR", "Tunnel failure detected: %s", failureReason)
		if m.onFailure != nil {
			go m.onFailure(failureReason)
		}
	}
}

func (m *Monitor) pingTunnelTarget() bool {
	target := fmt.Sprintf("%s:%d", m.cfg.Monitor.TunnelPing.TargetIP, m.cfg.Monitor.TunnelPing.TargetPort)
	if m.cfg.Monitor.TunnelPing.TargetPort == 0 {
		target = fmt.Sprintf("%s:51820", m.cfg.Monitor.TunnelPing.TargetIP)
	}

	conn, err := net.DialTimeout("udp", target, 800*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Send 16-byte dummy probe
	_, err = conn.Write([]byte("WG_HEALTH_PING"))
	return err == nil
}

func (m *Monitor) SetState(state TunnelHealthState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastReport.State = state
}

func (m *Monitor) GetStatus() StatusReport {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastReport
}
