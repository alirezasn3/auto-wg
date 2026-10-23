package tlstun

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"auto-wg/pkg/config"
	"auto-wg/pkg/logger"
)

const (
	keepaliveEvery = 5 * time.Second
	readTimeout    = 20 * time.Second
	writeTimeout   = 10 * time.Second
	authTimeout    = 5 * time.Second
	dialTimeout    = 3 * time.Second
	sendQueueLen   = 256
	maxPreAuth     = 16
	resolveEvery   = 30 * time.Second
	authLogEvery   = 10 * time.Second
)

// conn is one authenticated TLS connection.
type conn struct {
	tc     *tls.Conn
	dialed bool // we dialed it (as opposed to accepting it)
	remote string
	since  time.Time
	sendQ  chan []byte
	done   chan struct{}
	once   sync.Once
}

func newConn(tc *tls.Conn, dialed bool) *conn {
	return &conn{
		tc:     tc,
		dialed: dialed,
		remote: tc.RemoteAddr().String(),
		since:  time.Now(),
		sendQ:  make(chan []byte, sendQueueLen),
		done:   make(chan struct{}),
	}
}

func (c *conn) close() {
	c.once.Do(func() {
		close(c.done)
		_ = c.tc.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		_ = c.tc.Close()
	})
}

func (c *conn) direction() string {
	if c.dialed {
		return "dialed"
	}
	return "accepted"
}

// preferNew decides which connection survives when two are up at once (both peers dial each other):
// the one the primary peer dialed. Both sides apply the same rule, so they keep the same connection.
// Until the roles are known the existing connection is kept.
func preferNew(cur, nw *conn, primary, known bool) bool {
	if !known {
		return false
	}
	dialedByPrimary := func(c *conn) bool { return c.dialed == primary }
	return dialedByPrimary(nw) && !dialedByPrimary(cur)
}

type linkStats struct {
	rxBytes, txBytes, rxPkts, txPkts, dropped, dials, authFails atomic.Uint64
}

// Link owns the TCP listener and the dial loop and keeps at most one live connection.
type Link struct {
	cfg      config.TLSConfig
	iface    string
	log      *logger.Logger
	onPacket func([]byte) // called from the reader goroutine; the slice is only valid during the call
	redirect func(portRange string, port int) error

	srv *tls.Config
	cli *tls.Config

	active atomic.Pointer[conn]

	mu           sync.Mutex
	primary      bool
	primaryKnown bool
	targets      []string
	resolved     []string
	resolvedAt   time.Time
	targetIdx    int
	ln           net.Listener
	listenPort   int
	lastAuthLog  time.Time
	lastErr      string
	downSince    time.Time

	preauth chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	st      linkStats
}

func newLink(cfg config.TLSConfig, iface string, log *logger.Logger, onPacket func([]byte), redirect func(string, int) error) *Link {
	return &Link{
		cfg:      cfg,
		iface:    iface,
		log:      log,
		onPacket: onPacket,
		redirect: redirect,
		preauth:  make(chan struct{}, maxPreAuth),
	}
}

// Start binds the listener and starts dialing.
func (l *Link) Start(ctx context.Context) error {
	cert, err := newCert(l.cfg.SNI)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}
	l.srv = serverTLS(cert, l.cfg.ALPN)
	l.cli = clientTLS(l.cfg.SNI, l.cfg.ALPN)
	l.ctx, l.cancel = context.WithCancel(ctx)
	l.downSince = time.Now()

	if err := l.listen(); err != nil {
		l.cancel()
		return err
	}
	l.wg.Add(1)
	go l.dialLoop()
	return nil
}

// Stop closes everything and waits for the goroutines.
func (l *Link) Stop() {
	if l.cancel == nil {
		return
	}
	l.cancel()
	l.mu.Lock()
	ln := l.ln
	l.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	if c := l.active.Load(); c != nil {
		c.close()
	}
	l.wg.Wait()
}

func (l *Link) listen() error {
	var (
		ln   net.Listener
		port int
		err  error
	)
	for i := 0; i < 30; i++ {
		if port, err = config.PickRandomPort(l.cfg.PortRange); err != nil {
			return err
		}
		ln, err = net.Listen("tcp", net.JoinHostPort("::", strconv.Itoa(port)))
		if err != nil {
			ln, err = net.Listen("tcp", net.JoinHostPort("0.0.0.0", strconv.Itoa(port)))
		}
		if err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("listen on a TCP port from %s: %w", l.cfg.PortRange, err)
	}

	l.mu.Lock()
	old := l.ln
	l.ln, l.listenPort = ln, port
	l.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}

	if l.redirect != nil {
		if err := l.redirect(l.cfg.PortRange, port); err != nil {
			l.log.Warn("TLS", "[%s] Failed to redirect TCP range %s to :%d: %v", l.iface, l.cfg.PortRange, port, err)
		}
	}
	l.log.Info("TLS", "[%s] Listening for TLS peers on TCP :%d (range %s)", l.iface, port, l.cfg.PortRange)

	l.wg.Add(1)
	go l.acceptLoop(ln)
	return nil
}

func (l *Link) listener() net.Listener {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ln
}

func (l *Link) acceptLoop(ln net.Listener) {
	defer l.wg.Done()
	for {
		raw, err := ln.Accept()
		if err != nil {
			if l.ctx.Err() != nil || l.listener() != ln || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			l.handleIncoming(raw)
		}()
	}
}

func (l *Link) handleIncoming(raw net.Conn) {
	select {
	case l.preauth <- struct{}{}:
		defer func() { <-l.preauth }()
	default:
		_ = raw.Close()
		return
	}

	// A shutdown must not wait for a peer that is still in its handshake.
	defer context.AfterFunc(l.ctx, func() { _ = raw.Close() })()
	setKeepAlive(raw)
	_ = raw.SetDeadline(time.Now().Add(authTimeout))
	tc := tls.Server(raw, l.srv)
	if err := tc.Handshake(); err != nil {
		_ = raw.Close()
		l.log.Debug("TLS", "[%s] TLS handshake from %s failed: %v", l.iface, raw.RemoteAddr(), err)
		return
	}
	if err := authenticate(tc, l.cfg.Secret, false); err != nil {
		_ = raw.Close()
		l.noteAuthFailure(raw.RemoteAddr().String(), err)
		return
	}
	_ = raw.SetDeadline(time.Time{})
	l.install(newConn(tc, false))
}

func (l *Link) noteAuthFailure(remote string, err error) {
	if !errors.Is(err, ErrAuth) {
		l.log.Debug("TLS", "[%s] Peer %s failed to authenticate: %v", l.iface, remote, err)
		return
	}
	l.st.authFails.Add(1)
	l.mu.Lock()
	quiet := time.Since(l.lastAuthLog) < authLogEvery
	if !quiet {
		l.lastAuthLog = time.Now()
	}
	l.lastErr = "peer authentication failed (is tls.secret identical on both peers?)"
	l.mu.Unlock()
	if !quiet {
		l.log.Warn("TLS", "[%s] Peer %s failed authentication: is tls.secret identical on both peers?", l.iface, remote)
	}
}

func (l *Link) setErr(err error) {
	l.mu.Lock()
	l.lastErr = err.Error()
	l.mu.Unlock()
}

func (l *Link) dialLoop() {
	defer l.wg.Done()
	for {
		if l.active.Load() == nil {
			l.dialOnce()
		}
		d := l.cfg.DialInterval + time.Duration(rand.Int64N(int64(l.cfg.DialInterval)/4+1))
		select {
		case <-l.ctx.Done():
			return
		case <-time.After(d):
		}
	}
}

func (l *Link) dialOnce() {
	ip, ok := l.nextTarget()
	if !ok {
		return
	}
	port, err := config.PickRandomPort(l.cfg.RemotePortRange)
	if err != nil {
		l.setErr(err)
		return
	}
	l.dialTo(net.JoinHostPort(ip, strconv.Itoa(port)))
}

// dialTo makes one connection attempt to addr and installs the connection when it authenticates.
func (l *Link) dialTo(addr string) {
	l.st.dials.Add(1)

	raw, err := l.dial(addr)
	if err != nil {
		l.setErr(err)
		return
	}
	defer context.AfterFunc(l.ctx, func() { _ = raw.Close() })()
	setKeepAlive(raw)
	_ = raw.SetDeadline(time.Now().Add(authTimeout))
	tc := tls.Client(raw, l.cli)
	if err := tc.Handshake(); err != nil {
		_ = raw.Close()
		l.setErr(err)
		return
	}
	if err := authenticate(tc, l.cfg.Secret, true); err != nil {
		_ = raw.Close()
		l.noteAuthFailure(addr, err)
		return
	}
	_ = raw.SetDeadline(time.Time{})
	l.install(newConn(tc, true))
}

// dial connects from a random source port of the local range (like the UDP path binds its listen port
// inside the range), falling back to an ephemeral port when the chosen ones are taken.
func (l *Link) dial(addr string) (net.Conn, error) {
	// SO_REUSEADDR lets a source port that still has TIME_WAIT sockets (every failed attempt leaves one)
	// be bound again; the 4-tuple stays unique because the remote port is random too.
	d := net.Dialer{Timeout: dialTimeout, Control: func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		})
	}}
	for i := 0; i < 5; i++ {
		lp, err := config.PickRandomPort(l.cfg.PortRange)
		if err != nil {
			break
		}
		d.LocalAddr = &net.TCPAddr{Port: lp}
		c, err := d.DialContext(l.ctx, "tcp", addr)
		if err == nil {
			return c, nil
		}
		if !errors.Is(err, syscall.EADDRINUSE) {
			return nil, err
		}
	}
	d.LocalAddr = nil
	return d.DialContext(l.ctx, "tcp", addr)
}

func setKeepAlive(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: 10 * time.Second, Interval: 10 * time.Second, Count: 3})
		_ = tcp.SetNoDelay(true)
	}
}

// nextTarget returns the next destination IP, rotating through the targets so an address family the
// DPI blocks does not stall the link. Hostnames are re-resolved every resolveEvery.
func (l *Link) nextTarget() (string, bool) {
	l.mu.Lock()
	raw := append([]string(nil), l.targets...)
	stale := len(l.resolved) == 0 || time.Since(l.resolvedAt) > resolveEvery
	l.mu.Unlock()
	if len(raw) == 0 {
		return "", false
	}

	var fresh []string
	if stale {
		fresh = config.ResolveTargetIPs(raw)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if stale && len(fresh) > 0 {
		l.resolved, l.resolvedAt = fresh, time.Now()
	}
	if len(l.resolved) == 0 {
		return "", false
	}
	l.targetIdx = (l.targetIdx + 1) % len(l.resolved)
	return l.resolved[l.targetIdx], true
}

// install makes c the active connection unless the tie-break prefers the one we already have.
func (l *Link) install(c *conn) {
	l.mu.Lock()
	cur := l.active.Load()
	if cur != nil && !preferNew(cur, c, l.primary, l.primaryKnown) {
		l.mu.Unlock()
		c.close()
		l.log.Debug("TLS", "[%s] Dropped duplicate TLS connection (%s %s)", l.iface, c.direction(), c.remote)
		return
	}
	l.active.Store(c)
	l.downSince = time.Time{}
	l.lastErr = ""
	l.mu.Unlock()

	if cur != nil {
		cur.close()
		l.log.Info("TLS", "[%s] Replaced duplicate TLS connection with the one dialed by the primary peer", l.iface)
	}
	l.log.Info("TLS", "[%s] TLS link up: %s %s", l.iface, c.direction(), c.remote)

	l.wg.Add(2)
	go l.reader(c)
	go l.writer(c)
}

func (l *Link) dropped(c *conn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active.CompareAndSwap(c, nil) {
		l.downSince = time.Now()
		l.log.Info("TLS", "[%s] TLS link down (%s %s)", l.iface, c.direction(), c.remote)
	}
}

func (l *Link) reader(c *conn) {
	defer l.wg.Done()
	defer func() {
		c.close()
		l.dropped(c)
	}()
	buf := make([]byte, maxFrame)
	for {
		_ = c.tc.SetReadDeadline(time.Now().Add(readTimeout))
		p, err := readFrame(c.tc, buf)
		if err != nil {
			return
		}
		if len(p) == 0 {
			continue
		}
		l.st.rxBytes.Add(uint64(len(p)))
		l.st.rxPkts.Add(1)
		if l.onPacket != nil {
			l.onPacket(p)
		}
	}
}

func (l *Link) writer(c *conn) {
	defer l.wg.Done()
	defer func() {
		c.close()
		l.dropped(c)
	}()
	tick := time.NewTicker(keepaliveEvery)
	defer tick.Stop()
	for {
		var p []byte // nil is a keepalive frame
		select {
		case p = <-c.sendQ:
		case <-tick.C:
		case <-c.done:
			return
		}
		_ = c.tc.SetWriteDeadline(time.Now().Add(writeTimeout))
		if err := writeFrame(c.tc, p); err != nil {
			return
		}
		if len(p) > 0 {
			l.st.txBytes.Add(uint64(len(p)))
			l.st.txPkts.Add(1)
		}
	}
}

// Send queues a packet for the active connection and reports whether it was accepted. Packets are
// dropped, never buffered without bound, when no link is up or the connection cannot keep up.
func (l *Link) Send(p []byte) bool {
	c := l.active.Load()
	if c == nil {
		return false
	}
	cp := append([]byte(nil), p...)
	select {
	case c.sendQ <- cp:
		return true
	default:
		l.st.dropped.Add(1)
		return false
	}
}

// Connected reports whether an authenticated connection is up.
func (l *Link) Connected() bool { return l.active.Load() != nil }

// DownFor is how long no connection has been up (zero while connected).
func (l *Link) DownFor() time.Duration {
	if l.active.Load() != nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.downSince.IsZero() {
		return 0
	}
	return time.Since(l.downSince)
}

// SetPrimary tells the link which peer is primary, used to break ties between duplicate connections.
func (l *Link) SetPrimary(primary bool) {
	l.mu.Lock()
	l.primary, l.primaryKnown = primary, true
	l.mu.Unlock()
}

// SetTargets sets the destinations to dial: IPs or hostnames.
func (l *Link) SetTargets(raw []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(raw) == len(l.targets) {
		same := true
		for i := range raw {
			if raw[i] != l.targets[i] {
				same = false
				break
			}
		}
		if same {
			return
		}
	}
	l.targets = append([]string(nil), raw...)
	l.resolved = nil
}

// Reconnect drops the live connection and moves the listener to a new port of the local range.
func (l *Link) Reconnect() {
	if c := l.active.Load(); c != nil {
		c.close()
	}
	if l.ctx != nil && l.ctx.Err() == nil {
		if err := l.listen(); err != nil {
			l.log.Warn("TLS", "[%s] Could not rotate the TLS listener: %v", l.iface, err)
		}
	}
}
