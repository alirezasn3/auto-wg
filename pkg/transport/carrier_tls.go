package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"auto-wg/pkg/config"
)

// tlsCarrier runs the link over TLS 1.3 sessions: a listener on a random port of the local TCP range
// (the range is redirected to it) and dials from the local range to a random port of the remote range.
type tlsCarrier struct {
	srv *tls.Config
	cli *tls.Config

	mu   sync.Mutex
	ln   net.Listener
	port int
}

func (t *tlsCarrier) name() string { return "TLS" }

func (t *tlsCarrier) start(l *Link) error {
	cert, err := newCert(l.opts.TLS.SNI)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}
	t.srv = serverTLS(cert, l.opts.TLS.ALPN)
	t.cli = clientTLS(l.opts.TLS.SNI, l.opts.TLS.ALPN)
	return t.listen(l)
}

func (t *tlsCarrier) stop() {
	t.mu.Lock()
	ln := t.ln
	t.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
}

func (t *tlsCarrier) listenPort() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.port
}

func (t *tlsCarrier) listener() net.Listener {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ln
}

func (t *tlsCarrier) rotate(l *Link) {
	if err := t.listen(l); err != nil {
		l.log.Warn(l.tag, "[%s] Could not rotate the TLS listener: %v", l.iface, err)
	}
}

// listen binds a random port of the local range, moves the redirect to it and retires the old listener.
func (t *tlsCarrier) listen(l *Link) error {
	var (
		ln   net.Listener
		port int
		err  error
	)
	for i := 0; i < 30; i++ {
		if port, err = config.PickRandomPort(l.opts.PortRange); err != nil {
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
		return fmt.Errorf("listen on a TCP port from %s: %w", l.opts.PortRange, err)
	}

	t.mu.Lock()
	old := t.ln
	t.ln, t.port = ln, port
	t.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}

	if l.redirect != nil {
		if err := l.redirect(l.opts.PortRange, port); err != nil {
			l.log.Warn(l.tag, "[%s] Failed to redirect TCP range %s to :%d: %v", l.iface, l.opts.PortRange, port, err)
		}
	}
	l.log.Info(l.tag, "[%s] Listening for TLS peers on TCP :%d (range %s)", l.iface, port, l.opts.PortRange)

	l.wg.Add(1)
	go t.acceptLoop(l, ln)
	return nil
}

func (t *tlsCarrier) acceptLoop(l *Link, ln net.Listener) {
	defer l.wg.Done()
	for {
		raw, err := ln.Accept()
		if err != nil {
			if l.ctx.Err() != nil || t.listener() != ln || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			t.handleIncoming(l, raw)
		}()
	}
}

func (t *tlsCarrier) handleIncoming(l *Link, raw net.Conn) {
	release, ok := l.gate()
	if !ok {
		_ = raw.Close()
		return
	}
	defer release()

	// A shutdown must not wait for a peer that is still in its handshake.
	defer context.AfterFunc(l.ctx, func() { _ = raw.Close() })()
	setKeepAlive(raw)
	_ = raw.SetDeadline(time.Now().Add(authTimeout))
	tc := tls.Server(raw, t.srv)
	if err := tc.Handshake(); err != nil {
		_ = raw.Close()
		l.log.Debug(l.tag, "[%s] TLS handshake from %s failed: %v", l.iface, raw.RemoteAddr(), err)
		return
	}
	if err := authTLS(tc, l.cfg.Secret, false); err != nil {
		_ = raw.Close()
		l.noteAuthFailure(raw.RemoteAddr().String(), err)
		return
	}
	_ = raw.SetDeadline(time.Time{})
	l.install(newConn(tc, false))
}

func authTLS(tc *tls.Conn, secret string, dialer bool) error {
	binding, err := tlsBinding(tc)
	if err != nil {
		return err
	}
	return authenticate(tc, secret, binding, dialer)
}

func (t *tlsCarrier) dial(l *Link, ip string, port int) (net.Conn, error) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	raw, err := l.dialTCP(addr)
	if err != nil {
		return nil, err
	}
	setKeepAlive(raw)
	_ = raw.SetDeadline(time.Now().Add(authTimeout))
	tc := tls.Client(raw, t.cli)
	if err := tc.Handshake(); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("TLS handshake with %s: %w", addr, err)
	}
	if err := authTLS(tc, l.cfg.Secret, true); err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	return tc, nil
}
