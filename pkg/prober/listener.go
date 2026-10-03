package prober

import (
	"context"
	"fmt"
	"net"
	"sync"

	"auto-wg/pkg/logger"
)

type Listener struct {
	secretToken     string
	expectedPeerID  string
	candidatePorts  []int
	log             *logger.Logger
	conns           map[int]*net.UDPConn
	receivedPorts   map[int]bool
	mu              sync.RWMutex
	cancel          context.CancelFunc
}

func NewListener(expectedPeerID, secretToken string, candidatePorts []int, log *logger.Logger) *Listener {
	return &Listener{
		secretToken:    secretToken,
		expectedPeerID: expectedPeerID,
		candidatePorts: candidatePorts,
		log:            log,
		conns:          make(map[int]*net.UDPConn),
		receivedPorts:  make(map[int]bool),
	}
}

// Start opens UDP sockets on candidate ports and starts listening.
func (l *Listener) Start(ctx context.Context) error {
	l.mu.Lock()
	l.receivedPorts = make(map[int]bool)
	l.conns = make(map[int]*net.UDPConn)
	ctx, l.cancel = context.WithCancel(ctx)
	l.mu.Unlock()

	boundCount := 0
	for _, port := range l.candidatePorts {
		addr := &net.UDPAddr{Port: port}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			// Some ports (e.g. <1024 or in use by WireGuard) might fail without root; continue with other ports
			l.log.Debug("PROBER", "Could not bind listener on port %d: %v", port, err)
			continue
		}

		l.mu.Lock()
		l.conns[port] = conn
		l.mu.Unlock()
		boundCount++

		go l.listenOnPort(ctx, port, conn)
	}

	l.log.Info("PROBER", "Listening for probes on %d candidate ports", boundCount)
	if boundCount == 0 {
		return fmt.Errorf("failed to bind any candidate ports (permission issue or already in use)")
	}

	return nil
}

func (l *Listener) listenOnPort(ctx context.Context, port int, conn *net.UDPConn) {
	defer conn.Close()
	buf := make([]byte, 512)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, remoteAddr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}

		peerID, err := ParseAndVerifyProbePacket(buf[:n], l.secretToken)
		if err != nil {
			l.log.Debug("PROBER", "Ignored invalid packet on port %d from %v: %v", port, remoteAddr, err)
			continue
		}

		if l.expectedPeerID != "" && peerID != l.expectedPeerID {
			l.log.Warn("PROBER", "Probe from unexpected peer %q on port %d", peerID, port)
			continue
		}

		l.mu.Lock()
		if !l.receivedPorts[port] {
			l.receivedPorts[port] = true
			l.log.Info("PROBER", "Verified probe received on port %d from %s (peer %s)", port, remoteAddr, peerID)
		}
		l.mu.Unlock()
	}
}

// Stop closes all listening sockets.
func (l *Listener) Stop() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.cancel != nil {
		l.cancel()
	}

	for port, conn := range l.conns {
		_ = conn.Close()
		delete(l.conns, port)
	}
}

// GetReceivedPorts returns the list of candidate ports that successfully received a probe.
func (l *Listener) GetReceivedPorts() []int {
	l.mu.RLock()
	defer l.mu.RUnlock()

	ports := make([]int, 0, len(l.receivedPorts))
	for p := range l.receivedPorts {
		ports = append(ports, p)
	}
	return ports
}
