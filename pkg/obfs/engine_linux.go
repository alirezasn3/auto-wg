//go:build linux

package obfs

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/florianl/go-nfqueue/v2"
	"golang.org/x/sys/unix"

	"auto-wg/pkg/config"
	"auto-wg/pkg/logger"
)

// Engine owns one NFQUEUE and the raw sockets used to inject packets.
type Engine struct {
	iface    string
	queue    int
	log      *logger.Logger
	nf       *nfqueue.Nfqueue
	cancel   context.CancelFunc
	settings atomic.Pointer[config.ObfuscationConfig]
	stats    counters

	mu    sync.Mutex
	socks map[sockKey]int
}

type sockKey struct {
	v6   bool
	mark uint32
}

// NewEngine binds the queue and starts handling packets.
func NewEngine(iface string, queue int, cfg config.ObfuscationConfig, log *logger.Logger) (*Engine, error) {
	nf, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      uint16(queue),
		MaxPacketLen: 0xffff,
		MaxQueueLen:  1024,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		return nil, fmt.Errorf("open nfqueue %d: %w", queue, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{iface: iface, queue: queue, log: log, nf: nf, cancel: cancel, socks: make(map[sockKey]int)}
	e.settings.Store(&cfg)

	err = nf.RegisterWithErrorFunc(ctx, e.hook, func(err error) int {
		if ctx.Err() == nil {
			log.Warn("OBFS", "[%s] nfqueue receive error: %v", iface, err)
		}
		return 0
	})
	if err != nil {
		cancel()
		_ = nf.Close()
		return nil, fmt.Errorf("register nfqueue %d: %w", queue, err)
	}
	return e, nil
}

// Update swaps the active settings without touching the queue.
func (e *Engine) Update(cfg config.ObfuscationConfig) { e.settings.Store(&cfg) }

// Status returns the engine counters.
func (e *Engine) Status() Status { return e.stats.status(e.queue) }

// Close unbinds the queue and closes the raw sockets.
func (e *Engine) Close() {
	e.cancel()
	_ = e.nf.Close()
	e.mu.Lock()
	for _, fd := range e.socks {
		_ = unix.Close(fd)
	}
	e.socks = make(map[sockKey]int)
	e.mu.Unlock()
}

func (e *Engine) hook(a nfqueue.Attribute) int {
	if a.PacketID == nil {
		return 0
	}
	id := *a.PacketID
	if a.Payload == nil {
		_ = e.nf.SetVerdict(id, nfqueue.NfAccept)
		return 0
	}
	raw := append([]byte(nil), (*a.Payload)...)
	var mark uint32
	if a.Mark != nil {
		mark = *a.Mark
	}
	// Handled off the receive loop so a configured delay never stalls other packets.
	go e.handle(id, raw, mark)
	return 0
}

func (e *Engine) handle(id uint32, raw []byte, mark uint32) {
	verdict := nfqueue.NfAccept
	defer func() {
		if err := e.nf.SetVerdict(id, verdict); err != nil {
			e.stats.errors.Add(1)
			e.log.Warn("OBFS", "[%s] set verdict failed: %v", e.iface, err)
		}
	}()

	cfg := *e.settings.Load()
	if !cfg.Enabled {
		return
	}
	p, err := ParsePacket(raw)
	if err != nil || !p.IsHandshake() {
		return
	}
	e.stats.handshakes.Add(1)

	sent := 0
	for i := 0; i < cfg.Decoys; i++ {
		if err := e.send(p.V6, mark, p.Dst, BuildDecoy(p, cfg)); err != nil {
			e.stats.errors.Add(1)
			e.log.Warn("OBFS", "[%s] decoy send failed: %v", e.iface, err)
			break
		}
		sent++
	}
	e.stats.decoys.Add(uint64(sent))

	if cfg.DelayMs > 0 {
		time.Sleep(time.Duration(cfg.DelayMs) * time.Millisecond)
	}

	fragmented := false
	if cfg.Fragment && !p.V6 {
		fragmented = e.sendFragments(p, mark, cfg.FragmentSplit)
		if fragmented {
			verdict = nfqueue.NfDrop
			e.stats.fragmented.Add(1)
		}
	}
	e.log.Debug("OBFS", "[%s] handshake %s:%d -> %s:%d (%d bytes): %d decoys, fragmented=%v",
		e.iface, p.Src, p.SrcPort, p.Dst, p.DstPort, len(p.Payload), sent, fragmented)
}

func (e *Engine) sendFragments(p *Packet, mark uint32, split int) bool {
	sport, ok := e.wireSourcePort(p)
	if !ok {
		return false
	}
	frags, err := BuildFragments(p, sport, split)
	if err != nil {
		e.log.Warn("OBFS", "[%s] cannot fragment: %v", e.iface, err)
		return false
	}
	for i, f := range frags {
		if err := e.send(false, mark, p.Dst, f); err != nil {
			e.stats.errors.Add(1)
			e.log.Warn("OBFS", "[%s] fragment %d send failed: %v", e.iface, i+1, err)
			return false
		}
	}
	return true
}

// wireSourcePort works out which source port the peer will see. Fragments skip connection tracking
// and therefore NAT, so a reply that a REDIRECT rule would have translated must be sent with the
// translated port explicitly. When that cannot be determined for a response, fragmenting is skipped.
func (e *Engine) wireSourcePort(p *Packet) (uint16, bool) {
	f, err := os.Open("/proc/net/nf_conntrack")
	if err != nil {
		// No connection tracking, so no NAT.
		return p.SrcPort, true
	}
	defer f.Close()
	if port, ok := ReplyOriginalDstPort(f, p.SrcPort, p.Dst, p.DstPort); ok {
		return port, true
	}
	if p.IsResponse() {
		return 0, false
	}
	return p.SrcPort, true
}

func (e *Engine) send(v6 bool, mark uint32, dst netip.Addr, pkt []byte) error {
	fd, err := e.socket(v6, mark)
	if err != nil {
		return err
	}
	if v6 {
		return unix.Sendto(fd, pkt, 0, &unix.SockaddrInet6{Addr: dst.As16()})
	}
	return unix.Sendto(fd, pkt, 0, &unix.SockaddrInet4{Addr: dst.As4()})
}

// socket returns a raw socket that carries the original packet's fwmark, so policy routing sends
// injected packets the same way as the real ones (wg-quick relies on this to avoid routing loops).
func (e *Engine) socket(v6 bool, mark uint32) (int, error) {
	key := sockKey{v6, mark}
	e.mu.Lock()
	defer e.mu.Unlock()
	if fd, ok := e.socks[key]; ok {
		return fd, nil
	}
	family := unix.AF_INET
	if v6 {
		family = unix.AF_INET6
	}
	fd, err := unix.Socket(family, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		return 0, fmt.Errorf("raw socket: %w", err)
	}
	if mark != 0 {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(mark)); err != nil {
			_ = unix.Close(fd)
			return 0, fmt.Errorf("set SO_MARK: %w", err)
		}
	}
	if !v6 {
		// Without this, conntrack would reassemble our fragments again before they leave.
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_NODEFRAG, 1); err != nil {
			_ = unix.Close(fd)
			return 0, fmt.Errorf("set IP_NODEFRAG: %w", err)
		}
	}
	e.socks[key] = fd
	return fd, nil
}
