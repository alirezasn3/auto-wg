package transport

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync/atomic"

	"auto-wg/pkg/config"
)

// relay is the loopback UDP socket WireGuard talks to while the TLS path is active: WireGuard's peer
// endpoint is set to 127.0.0.1:port. Packets from WireGuard go into the TLS link; packets from the link
// are written back to WireGuard from the same socket, so WireGuard sees them coming from the endpoint.
type relay struct {
	pc     *net.UDPConn
	port   int
	wgAddr atomic.Pointer[netip.AddrPort]
	wgPort func() int // current WireGuard listen port
	send   func([]byte) bool

	rxPkts, txPkts atomic.Uint64
}

func inRanges(port int, ranges []string) bool {
	for _, spec := range ranges {
		if start, end, err := config.ParsePortRange(spec); err == nil && port >= start && port <= end {
			return true
		}
	}
	return false
}

// newRelay binds 127.0.0.1:port, or a random port in 40000-49999 outside avoid when port is 0.
func newRelay(port int, avoid []string, wgPort func() int, send func([]byte) bool) (*relay, error) {
	loopback := net.IPv4(127, 0, 0, 1)
	var (
		pc  *net.UDPConn
		err error
	)
	if port != 0 {
		pc, err = net.ListenUDP("udp4", &net.UDPAddr{IP: loopback, Port: port})
	} else {
		for i := 0; i < 50; i++ {
			p := 40000 + rand.IntN(10000)
			if inRanges(p, avoid) {
				continue
			}
			if pc, err = net.ListenUDP("udp4", &net.UDPAddr{IP: loopback, Port: p}); err == nil {
				break
			}
		}
	}
	if pc == nil {
		return nil, fmt.Errorf("bind TLS relay socket: %v", err)
	}
	r := &relay{pc: pc, port: pc.LocalAddr().(*net.UDPAddr).Port, wgPort: wgPort, send: send}
	return r, nil
}

// run forwards WireGuard's packets into the link until the socket is closed.
func (r *relay) run() {
	buf := make([]byte, 65535)
	for {
		n, src, err := r.pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if isClosed(err) {
				return
			}
			continue
		}
		a := src
		r.wgAddr.Store(&a)
		if n > maxFrame {
			continue
		}
		r.rxPkts.Add(1)
		r.send(buf[:n])
	}
}

// deliver writes a packet that arrived over the link to WireGuard. The current listen port is preferred
// to the address learned from earlier packets, which goes stale when the listen port is rotated.
func (r *relay) deliver(p []byte) {
	var dst netip.AddrPort
	if port := r.wgPort(); port > 0 {
		dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(port))
	} else if a := r.wgAddr.Load(); a != nil {
		dst = *a
	} else {
		return
	}
	if _, err := r.pc.WriteToUDPAddrPort(p, dst); err == nil {
		r.txPkts.Add(1)
	}
}

func (r *relay) close() { _ = r.pc.Close() }

func isClosed(err error) bool { return errors.Is(err, net.ErrClosed) }
