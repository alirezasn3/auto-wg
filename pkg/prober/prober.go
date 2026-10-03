package prober

import (
	"context"
	"fmt"
	"net"
	"time"

	"auto-wg/pkg/logger"
)

type Prober struct {
	peerID         string
	secretToken    string
	targetHost     string
	candidatePorts []int
	log            *logger.Logger
}

func NewProber(peerID, secretToken, targetHost string, candidatePorts []int, log *logger.Logger) *Prober {
	return &Prober{
		peerID:         peerID,
		secretToken:    secretToken,
		targetHost:     targetHost,
		candidatePorts: candidatePorts,
		log:            log,
	}
}

// SendProbes sends probe packets to all candidate ports on the target host.
func (p *Prober) SendProbes(ctx context.Context, burstCount int) error {
	p.log.Info("PROBER", "Sending probe bursts (%d probes/port) across %d candidate ports to %s",
		burstCount, len(p.candidatePorts), p.targetHost)

	packetData, err := BuildProbePacket(p.peerID, p.secretToken)
	if err != nil {
		return fmt.Errorf("build probe packet: %w", err)
	}

	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return fmt.Errorf("open probe socket: %w", err)
	}
	defer conn.Close()

	for _, port := range p.candidatePorts {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		addrStr := fmt.Sprintf("%s:%d", p.targetHost, port)
		dstAddr, err := net.ResolveUDPAddr("udp", addrStr)
		if err != nil {
			p.log.Debug("PROBER", "Failed to resolve %s: %v", addrStr, err)
			continue
		}

		for b := 0; b < burstCount; b++ {
			if _, err := conn.WriteTo(packetData, dstAddr); err != nil {
				p.log.Debug("PROBER", "Send to %s failed: %v", addrStr, err)
			}
			time.Sleep(2 * time.Millisecond)
		}

		// Small interval between ports
		time.Sleep(10 * time.Millisecond)
	}

	p.log.Info("PROBER", "Finished sending probe bursts to %s", p.targetHost)
	return nil
}
