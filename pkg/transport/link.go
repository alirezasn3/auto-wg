package transport

import (
	"context"
	"errors"
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
	ctrlQueueLen   = 64

	// Defaults for hand-built configurations (tests); the real config always sets these.
	defaultHealthInterval = 3 * time.Second
	defaultHealthTimeout  = 2 * time.Second
	defaultHealthFailures = 3
)

// verifyProbeSizes are the payload sizes of the probes every new connection must answer before it is
// used. They match the sizes of WireGuard's fixed-size messages (148 initiation, 92 response, 32
// keepalive) plus a near-full-size packet, so each probe makes a TLS record as large as the real packet
// it stands for. A path that lets the first frames of a flow through and then stalls it, or one that
// reacts to those record sizes, fails this right away instead of after the first real handshake.
var verifyProbeSizes = []int{148, 92, 32, 1200}

// conn is one authenticated connection of a carrier (TLS, or an OpenSSH session).
type conn struct {
	tc     net.Conn
	dialed bool // we dialed it (as opposed to accepting it)
	remote string
	since  time.Time
	sendQ  chan []byte // WireGuard packets
	ctrlQ  chan []byte // health probes and their echoes, sent ahead of data
	pongs  chan uint64 // nonces of echoes received, for the prober
	done   chan struct{}
	once   sync.Once

	verified atomic.Bool  // passed the verification probes; only then is the link used
	rtt      atomic.Int64 // last probe round trip, nanoseconds
	failures atomic.Int32 // consecutive unanswered probes
}

func newConn(tc net.Conn, dialed bool) *conn {
	return &conn{
		tc:     tc,
		dialed: dialed,
		remote: tc.RemoteAddr().String(),
		since:  time.Now(),
		sendQ:  make(chan []byte, sendQueueLen),
		ctrlQ:  make(chan []byte, ctrlQueueLen),
		pongs:  make(chan uint64, 16),
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
	probes, probeFails, verifyFails, resets                     atomic.Uint64
}

// Options select and configure a carrier. Kind is "tls" or "ssh"; the ranges are the tunnel's TCP ranges.
type Options struct {
	Kind            string
	PortRange       string // local TCP range, redirected to the carrier's listener
	RemotePortRange string // the peer's TCP range to dial
	Link            config.LinkConfig
	TLS             config.TLSConfig
	SSH             config.SSHConfig
}

// OptionsFor builds the options of a tunnel that runs over TLS or SSH.
func OptionsFor(t config.TunnelConfig) Options {
	o := Options{Kind: t.Transport, PortRange: t.PortRange, RemotePortRange: t.RemotePortRange, TLS: t.TLS, SSH: t.SSH}
	if t.Transport == config.TransportSSH {
		o.Link = t.SSH.LinkConfig
	} else {
		o.Link = t.TLS.LinkConfig
	}
	return o
}

// carrier is what differs between the transports: how connections are accepted and how they are dialed. Both
// hand the link authenticated net.Conns that speak the frame protocol.
type carrier interface {
	name() string                                        // "TLS" or "SSH", used in logs and the dashboard
	start(l *Link) error                                 // bind listeners and install the iptables redirect
	stop()                                               // close the listeners
	rotate(l *Link)                                      // move the listener to a new port, if the carrier has a movable one
	listenPort() int                                     // the port to show on the dashboard (0 if none)
	dial(l *Link, ip string, port int) (net.Conn, error) // one authenticated outgoing connection; errNoDial if this peer does not dial
}

// errNoDial means this peer is accept-only on this carrier.
var errNoDial = errors.New("this peer does not dial")

// Link keeps at most one live, verified connection to the peer: it accepts and dials through its carrier,
// probes the connection's health and moves WireGuard's packets in and out.
type Link struct {
	opts     Options
	cfg      config.LinkConfig
	car      carrier
	tag      string // log component: "TLS" or "SSH"
	iface    string
	log      *logger.Logger
	onPacket func([]byte) // called from the reader goroutine; the slice is only valid during the call
	redirect func(portRange string, port int) error

	active atomic.Pointer[conn]

	mu           sync.Mutex
	primary      bool
	primaryKnown bool
	targets      []string
	resolved     []string
	resolvedAt   time.Time
	targetIdx    int
	lastAuthLog  time.Time
	lastDialLog  time.Time
	lastErr      string
	downSince    time.Time

	// onInstalled is a test hook, called when a connection becomes the active one (before verification).
	onInstalled atomic.Pointer[func(*conn)]

	preauth chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	st      linkStats
}

func newLink(opts Options, iface string, log *logger.Logger, onPacket func([]byte), redirect func(string, int) error) *Link {
	cfg := opts.Link
	if cfg.HealthInterval <= 0 {
		cfg.HealthInterval = defaultHealthInterval
	}
	if cfg.HealthTimeout <= 0 {
		cfg.HealthTimeout = defaultHealthTimeout
	}
	if cfg.HealthFailures <= 0 {
		cfg.HealthFailures = defaultHealthFailures
	}
	if cfg.DialInterval <= 0 {
		cfg.DialInterval = time.Second
	}
	l := &Link{
		opts:     opts,
		cfg:      cfg,
		iface:    iface,
		log:      log,
		onPacket: onPacket,
		redirect: redirect,
		preauth:  make(chan struct{}, maxPreAuth),
	}
	if opts.Kind == config.TransportSSH {
		l.car, l.tag = &sshCarrier{}, "SSH"
	} else {
		l.car, l.tag = &tlsCarrier{}, "TLS"
	}
	return l
}

// Start binds the carrier's listeners and starts dialing.
func (l *Link) Start(ctx context.Context) error {
	l.ctx, l.cancel = context.WithCancel(ctx)
	l.downSince = time.Now()
	if err := l.car.start(l); err != nil {
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
	l.car.stop()
	if c := l.active.Load(); c != nil {
		c.close()
	}
	l.wg.Wait()
}

// gate admits a connection to the pre-authentication stage unless too many are already there, so a peer that
// connects and says nothing cannot occupy the listener. The returned function releases the slot.
func (l *Link) gate() (release func(), ok bool) {
	select {
	case l.preauth <- struct{}{}:
		return func() { <-l.preauth }, true
	default:
		return nil, false
	}
}

func (l *Link) noteAuthFailure(remote string, err error) {
	if !errors.Is(err, ErrAuth) {
		l.log.Debug(l.tag, "[%s] Peer %s failed to authenticate: %v", l.iface, remote, err)
		return
	}
	l.st.authFails.Add(1)
	l.mu.Lock()
	quiet := time.Since(l.lastAuthLog) < authLogEvery
	if !quiet {
		l.lastAuthLog = time.Now()
	}
	l.lastErr = "peer authentication failed (is the secret identical on both peers?)"
	l.mu.Unlock()
	if !quiet {
		l.log.Warn(l.tag, "[%s] Peer %s failed authentication: is the secret identical on both peers?", l.iface, remote)
	}
}

// warnDial logs a dial failure the operator has to act on, at most once per authLogEvery.
func (l *Link) warnDial(err error) {
	l.mu.Lock()
	quiet := time.Since(l.lastDialLog) < authLogEvery
	if !quiet {
		l.lastDialLog = time.Now()
	}
	l.mu.Unlock()
	if !quiet {
		l.log.Warn(l.tag, "[%s] %v", l.iface, err)
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
	port, err := config.PickRandomPort(l.opts.RemotePortRange)
	if err != nil {
		l.setErr(err)
		return
	}
	l.dialTo(ip, port)
}

// dialTo makes one connection attempt and installs the connection when it authenticates.
func (l *Link) dialTo(ip string, port int) {
	c, err := l.car.dial(l, ip, port)
	if errors.Is(err, errNoDial) {
		return
	}
	l.st.dials.Add(1)
	if err != nil {
		var le *loggedError
		switch {
		case errors.Is(err, ErrAuth):
			l.noteAuthFailure(net.JoinHostPort(ip, strconv.Itoa(port)), err)
		case errors.As(err, &le):
			l.setErr(err)
			l.warnDial(err)
		default:
			l.setErr(err)
		}
		return
	}
	l.install(newConn(c, true))
}

// dialTCP connects from a random source port of the local range (like the UDP side binds its listen port
// inside the range), falling back to an ephemeral port when the chosen ones are taken.
func (l *Link) dialTCP(addr string) (net.Conn, error) {
	// SO_REUSEADDR lets a source port that still has TIME_WAIT sockets (every failed attempt leaves one)
	// be bound again; the 4-tuple stays unique because the remote port is random too.
	d := net.Dialer{Timeout: dialTimeout, Control: func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		})
	}}
	for i := 0; i < 5; i++ {
		lp, err := config.PickRandomPort(l.opts.PortRange)
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

// install makes c the active connection unless the tie-break prefers the one we already have. The
// connection is not used for traffic until the prober has verified it.
func (l *Link) install(c *conn) {
	l.mu.Lock()
	cur := l.active.Load()
	if cur != nil && !preferNew(cur, c, l.primary, l.primaryKnown) {
		l.mu.Unlock()
		c.close()
		l.log.Debug(l.tag, "[%s] Dropped duplicate %s connection (%s %s)", l.iface, l.car.name(), c.direction(), c.remote)
		return
	}
	l.active.Store(c)
	l.mu.Unlock()

	if cur != nil {
		cur.close()
		l.log.Info(l.tag, "[%s] Replaced duplicate %s connection with the one dialed by the primary peer", l.iface, l.car.name())
	}
	l.log.Debug(l.tag, "[%s] %s connection established (%s %s), verifying", l.iface, l.car.name(), c.direction(), c.remote)
	if f := l.onInstalled.Load(); f != nil {
		(*f)(c)
	}

	l.wg.Add(3)
	go l.reader(c)
	go l.writer(c)
	go l.prober(c)
}

// markVerified turns an authenticated connection into the working link.
func (l *Link) markVerified(c *conn) {
	c.verified.Store(true)
	l.mu.Lock()
	if l.active.Load() == c {
		l.downSince = time.Time{}
		l.lastErr = ""
	}
	l.mu.Unlock()
	l.log.Info(l.tag, "[%s] %s link up: %s %s (round trip %v)", l.iface, l.car.name(), c.direction(), c.remote, fmtRTT(time.Duration(c.rtt.Load())))
}

// fmtRTT keeps sub-millisecond round trips (loopback, LAN) readable instead of rounding them to 0s.
func fmtRTT(d time.Duration) time.Duration {
	if d < time.Millisecond {
		return d.Round(10 * time.Microsecond)
	}
	return d.Round(100 * time.Microsecond)
}

func (l *Link) dropped(c *conn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active.CompareAndSwap(c, nil) {
		if l.downSince.IsZero() {
			l.downSince = time.Now()
		}
		if c.verified.Load() {
			l.log.Info(l.tag, "[%s] %s link down (%s %s)", l.iface, l.car.name(), c.direction(), c.remote)
		}
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
		p, control, err := readFrame(c.tc, buf)
		if err != nil {
			return
		}
		if control {
			l.handleControl(c, p)
			continue
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

// handleControl answers a ping with an identical pong and hands pongs to the prober.
func (l *Link) handleControl(c *conn, p []byte) {
	if len(p) < probeHeader {
		return
	}
	switch p[0] {
	case ctrlPing:
		pong := append([]byte(nil), p...)
		pong[0] = ctrlPong
		select {
		case c.ctrlQ <- pong:
		default: // a congested link must not answer, that is what the peer's probe is for
		}
	case ctrlPong:
		if nonce, ok := probeNonce(p); ok {
			select {
			case c.pongs <- nonce:
			default:
			}
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
		var (
			p    []byte // nil is a keepalive frame
			ctrl bool
		)
		// Probes go first: they measure the network, not our own queue.
		select {
		case p = <-c.ctrlQ:
			ctrl = true
		default:
			select {
			case p = <-c.ctrlQ:
				ctrl = true
			case p = <-c.sendQ:
			case <-tick.C:
			case <-c.done:
				return
			}
		}
		_ = c.tc.SetWriteDeadline(time.Now().Add(writeTimeout))
		var err error
		if ctrl {
			err = writeControl(c.tc, p, l.cfg.Padding)
		} else {
			err = writeFrame(c.tc, p, l.cfg.Padding)
		}
		if err != nil {
			return
		}
		if !ctrl && len(p) > 0 {
			l.st.txBytes.Add(uint64(len(p)))
			l.st.txPkts.Add(1)
		}
	}
}

// probeSet sends one ping per size back to back and reports whether every one was echoed within the
// timeout, and the slowest round trip. Pongs of earlier, timed-out probes are ignored.
func (l *Link) probeSet(c *conn, sizes []int) (bool, time.Duration) {
	pending := make(map[uint64]time.Time, len(sizes))
	for _, size := range sizes {
		nonce := rand.Uint64()
		select {
		case c.ctrlQ <- newProbe(nonce, size):
			pending[nonce] = time.Now()
		default:
			return false, 0
		}
	}
	l.st.probes.Add(uint64(len(sizes)))

	timer := time.NewTimer(l.cfg.HealthTimeout)
	defer timer.Stop()
	var worst time.Duration
	for len(pending) > 0 {
		select {
		case got := <-c.pongs:
			if sent, ok := pending[got]; ok {
				if d := time.Since(sent); d > worst {
					worst = d
				}
				delete(pending, got)
			}
		case <-timer.C:
			return false, worst
		case <-c.done:
			return false, worst
		case <-l.ctx.Done():
			return false, worst
		}
	}
	c.rtt.Store(int64(worst))
	return true, worst
}

// steadySize picks the size of one steady-state probe. It is random so the probes do not form a fixed
// pattern on the wire.
func steadySize() int { return 24 + rand.IntN(577) }

// prober verifies a new connection and then keeps probing it. A connection that cannot echo probes, now or
// later, is closed so the dial loop builds a fresh one. Without this a flow that a middlebox lets start and
// then stalls stays "up" until the read deadline, and the tunnel would switch onto it in the meantime.
func (l *Link) prober(c *conn) {
	defer l.wg.Done()
	if ok, _ := l.probeSet(c, verifyProbeSizes); !ok {
		select {
		case <-c.done:
			return // closed meanwhile (a duplicate that lost the tie-break, or a shutdown): not a verification failure
		case <-l.ctx.Done():
			return
		default:
		}
		l.st.verifyFails.Add(1)
		l.setErrText("new connection did not pass the health probes")
		l.log.Warn(l.tag, "[%s] New %s connection to %s failed verification (no probe echoed within %v); reconnecting", l.iface, l.car.name(), c.remote, l.cfg.HealthTimeout)
		c.close()
		return
	}
	l.markVerified(c)

	retry := false
	for {
		// Jitter and random sizes keep the probes from forming a fixed pattern. After a miss the next
		// probe goes out at once: a stalled stream needs no extra waiting between attempts.
		if !retry {
			wait := time.Duration(float64(l.cfg.HealthInterval) * (0.75 + rand.Float64()/2))
			select {
			case <-time.After(wait):
			case <-c.done:
				return
			case <-l.ctx.Done():
				return
			}
		}
		retry = false

		if ok, _ := l.probeSet(c, []int{steadySize()}); ok {
			c.failures.Store(0)
			continue
		}
		select {
		case <-c.done:
			return
		default:
		}
		l.st.probeFails.Add(1)
		n := int(c.failures.Add(1))
		l.log.Debug(l.tag, "[%s] Health probe unanswered (%d/%d)", l.iface, n, l.cfg.HealthFailures)
		if n >= l.cfg.HealthFailures {
			l.setErrText("link stopped answering health probes")
			l.log.Warn(l.tag, "[%s] %s link to %s failed its health check (%d probes unanswered); reconnecting", l.iface, l.car.name(), c.remote, n)
			c.close()
			return
		}
		retry = true
	}
}

func (l *Link) setErrText(s string) {
	l.mu.Lock()
	l.lastErr = s
	l.mu.Unlock()
}

// Send queues a packet for the active connection and reports whether it was accepted. Packets are
// dropped, never buffered without bound, when no link is up or the connection cannot keep up.
func (l *Link) Send(p []byte) bool {
	c := l.active.Load()
	if c == nil || !c.verified.Load() {
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

// Connected reports whether a verified connection is up: one that has echoed health probes of realistic
// sizes. An authenticated connection that has not passed (yet) is not used.
func (l *Link) Connected() bool {
	c := l.active.Load()
	return c != nil && c.verified.Load()
}

// DownFor is how long no working connection has been up (zero while connected).
func (l *Link) DownFor() time.Duration {
	if l.Connected() {
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

// ResetConn drops the live connection so the dial loop (or the peer) builds a new one, keeping the
// listener where it is. It is the remedy for a link whose probes pass while the traffic on it does not.
func (l *Link) ResetConn() bool {
	c := l.active.Load()
	if c == nil {
		return false
	}
	l.st.resets.Add(1)
	l.log.Info(l.tag, "[%s] Dropping the %s connection to %s so a new one is built", l.iface, l.car.name(), c.remote)
	c.close()
	return true
}

// Reconnect drops the live connection and, for carriers that have a movable listener, moves it to a new port
// of the local range.
func (l *Link) Reconnect() {
	if c := l.active.Load(); c != nil {
		c.close()
	}
	if l.ctx != nil && l.ctx.Err() == nil {
		l.car.rotate(l)
	}
}
