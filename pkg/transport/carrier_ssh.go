package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// loggedError marks a dial failure that tells the operator something (ssh's own message, such as a rejected
// key), as opposed to the routine ones of a peer that is simply unreachable.
type loggedError struct{ error }

func (e *loggedError) Unwrap() error { return e.error }

// sshHandshakeTimeout bounds key exchange, login and the forward's opening: more round trips than TLS.
const sshHandshakeTimeout = 15 * time.Second

// sshCarrier runs the link inside genuine OpenSSH sessions, so on the wire it is whatever the installed
// ssh client and the peer's sshd really produce.
//
// The dialing side opens the TCP socket itself (source port from the local range, destination port from
// the peer's range) and hands it to the real `ssh` client through a one-shot loopback proxy; the client
// logs in and runs `-W 127.0.0.1:link_port`, which makes the peer's sshd connect to the link listener of
// that peer. Its stdin/stdout are the frame stream. The accepting side needs no code for SSH itself: its
// range is redirected to sshd, and sshd's forward lands on the loopback link listener.
type sshCarrier struct {
	sshPath        string
	identity       string
	user           string
	alias          string // HostKeyAlias
	linkPort       int    // loopback listener the peer's ssh forwards to
	remoteLinkPort int    // the port the peer's sshd must connect to (same as linkPort unless a test says otherwise)
	sshdPort       int
	extraArgs      []string // additional -o options, for tests

	dir        string // holds known_hosts
	knownHosts string

	mu sync.Mutex
	ln net.Listener
}

func (s *sshCarrier) name() string { return "SSH" }

func (s *sshCarrier) listenPort() int { return 0 }

func (s *sshCarrier) rotate(l *Link) {}

func (s *sshCarrier) start(l *Link) error {
	o := l.opts.SSH
	s.sshPath, s.identity, s.user = o.SSHPath, o.IdentityFile, o.User
	s.linkPort, s.sshdPort = o.LinkPort, o.SshdPort
	if s.remoteLinkPort == 0 {
		s.remoteLinkPort = o.LinkPort
	}
	s.alias = "autowg-" + l.iface

	if s.identity != "" {
		path, err := exec.LookPath(s.sshPath)
		if err != nil {
			return fmt.Errorf("ssh transport needs the OpenSSH client (ssh_path %q): %w", s.sshPath, err)
		}
		s.sshPath = path
		if _, err := os.Stat(s.identity); err != nil {
			return fmt.Errorf("ssh identity_file: %w", err)
		}
		dir, err := os.MkdirTemp("", "autowg-ssh-")
		if err != nil {
			return err
		}
		s.dir = dir
		line, err := knownHostsLine(s.alias, o.HostKey)
		if err != nil {
			s.cleanup()
			return err
		}
		s.knownHosts = filepath.Join(dir, "known_hosts")
		if err := os.WriteFile(s.knownHosts, []byte(line), 0o600); err != nil {
			s.cleanup()
			return err
		}
	}

	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(s.linkPort)))
	if err != nil {
		s.cleanup()
		return fmt.Errorf("listen for the sshd forward on 127.0.0.1:%d: %w", s.linkPort, err)
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()

	if l.redirect != nil {
		if err := l.redirect(l.opts.PortRange, s.sshdPort); err != nil {
			l.log.Warn(l.tag, "[%s] Failed to redirect TCP range %s to sshd on :%d: %v", l.iface, l.opts.PortRange, s.sshdPort, err)
		}
	}
	if s.identity != "" {
		l.log.Info(l.tag, "[%s] SSH transport: dialing %s as %s with %s; range %s goes to sshd :%d, forward lands on 127.0.0.1:%d", l.iface, l.opts.RemotePortRange, s.user, s.sshPath, l.opts.PortRange, s.sshdPort, s.linkPort)
	} else {
		l.log.Info(l.tag, "[%s] SSH transport (accept only, no identity_file): range %s goes to sshd :%d, forward lands on 127.0.0.1:%d", l.iface, l.opts.PortRange, s.sshdPort, s.linkPort)
	}

	l.wg.Add(1)
	go s.acceptLoop(l, ln)
	return nil
}

func (s *sshCarrier) stop() {
	s.mu.Lock()
	ln := s.ln
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	s.cleanup()
}

func (s *sshCarrier) cleanup() {
	if s.dir != "" {
		_ = os.RemoveAll(s.dir)
		s.dir = ""
	}
}

// knownHostsLine turns the configured host key ("ssh-ed25519 AAAA..." with an optional comment, or a whole
// known_hosts line) into a known_hosts entry for the alias.
func knownHostsLine(alias, hostKey string) (string, error) {
	f := strings.Fields(hostKey)
	for i := 0; i+1 < len(f); i++ {
		if strings.HasPrefix(f[i], "ssh-") || strings.HasPrefix(f[i], "ecdsa-") || strings.HasPrefix(f[i], "sk-") {
			return fmt.Sprintf("%s %s %s\n", alias, f[i], f[i+1]), nil
		}
	}
	return "", errors.New("ssh host_key is not a public key like \"ssh-ed25519 AAAA...\"")
}

func (s *sshCarrier) acceptLoop(l *Link, ln net.Listener) {
	defer l.wg.Done()
	for {
		raw, err := ln.Accept()
		if err != nil {
			if l.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			s.handleIncoming(l, raw)
		}()
	}
}

func (s *sshCarrier) handleIncoming(l *Link, raw net.Conn) {
	release, ok := l.gate()
	if !ok {
		_ = raw.Close()
		return
	}
	defer release()

	defer context.AfterFunc(l.ctx, func() { _ = raw.Close() })()
	_ = raw.SetDeadline(time.Now().Add(authTimeout))
	if err := authenticateNonce(raw, l.cfg.Secret, false); err != nil {
		_ = raw.Close()
		l.noteAuthFailure(raw.RemoteAddr().String(), err)
		return
	}
	_ = raw.SetDeadline(time.Time{})
	l.install(newConn(raw, false))
}

func (s *sshCarrier) args(proxyPort int) []string {
	a := []string{
		"-F", "/dev/null",
		"-W", net.JoinHostPort("127.0.0.1", strconv.Itoa(s.remoteLinkPort)),
		"-p", strconv.Itoa(proxyPort),
		"-l", s.user,
		"-i", s.identity,
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityAgent=none",
		"-o", "BatchMode=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + s.knownHosts,
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "HostKeyAlias=" + s.alias,
		"-o", "CheckHostIP=no",
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
		"-o", "ExitOnForwardFailure=yes",
		"-o", "ConnectTimeout=" + strconv.Itoa(int(sshHandshakeTimeout/time.Second)),
		"-o", "LogLevel=ERROR",
	}
	for _, o := range s.extraArgs {
		a = append(a, "-o", o)
	}
	return append(a, "127.0.0.1")
}

func (s *sshCarrier) dial(l *Link, ip string, port int) (net.Conn, error) {
	if s.identity == "" {
		return nil, errNoDial
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	raw, err := l.dialTCP(addr)
	if err != nil {
		return nil, err
	}
	setKeepAlive(raw)
	sc, err := s.spawn(l, raw)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = sc.SetDeadline(time.Now().Add(sshHandshakeTimeout))
	if err := authenticateNonce(sc, l.cfg.Secret, true); err != nil {
		reason := sc.failure()
		sc.Close()
		if errors.Is(err, ErrAuth) {
			return nil, err
		}
		if reason != "" {
			return nil, &loggedError{fmt.Errorf("ssh to %s: %s", addr, reason)}
		}
		return nil, fmt.Errorf("ssh to %s: %w", addr, err)
	}
	_ = sc.SetDeadline(time.Time{})
	return sc, nil
}

// spawn starts the ssh client against a one-shot loopback proxy that relays to the already connected tcp.
func (s *sshCarrier) spawn(l *Link, tcp net.Conn) (*sshConn, error) {
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		_ = pl.Close()
		return nil, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		_ = pl.Close()
		_ = inR.Close()
		_ = inW.Close()
		return nil, err
	}

	sc := &sshConn{tcp: tcp, in: inW, out: outR, exited: make(chan struct{})}
	cmd := exec.CommandContext(l.ctx, s.sshPath, s.args(pl.Addr().(*net.TCPAddr).Port)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inR, outW, &sc.stderr
	sc.cmd = cmd
	err = cmd.Start()
	_ = inR.Close()
	_ = outW.Close()
	if err != nil {
		_ = pl.Close()
		_ = inW.Close()
		_ = outR.Close()
		return nil, fmt.Errorf("start %s: %w", s.sshPath, err)
	}

	go func() {
		defer pl.Close()
		_ = pl.(*net.TCPListener).SetDeadline(time.Now().Add(sshHandshakeTimeout))
		c, err := pl.Accept()
		if err != nil {
			sc.Close()
			return
		}
		go func() { _, _ = io.Copy(tcp, c); sc.Close(); _ = c.Close() }()
		_, _ = io.Copy(c, tcp)
		_ = c.Close()
		sc.Close()
	}()
	go func() {
		_ = cmd.Wait()
		close(sc.exited)
		sc.Close()
	}()
	return sc, nil
}

// sshConn is the stdio of one ssh process presented as a net.Conn; closing it ends the process and
// the TCP connection it was riding on.
type sshConn struct {
	cmd    *exec.Cmd
	in     *os.File // ssh's stdin (we write)
	out    *os.File // ssh's stdout (we read)
	tcp    net.Conn // the real connection to the peer's sshd
	exited chan struct{}
	stderr lockedBuf
	once   sync.Once
}

type lockedBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buf.Len() < 4096 {
		b.buf.Write(p)
	}
	return len(p), nil
}

func (b *lockedBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (c *sshConn) Read(p []byte) (int, error)  { return c.out.Read(p) }
func (c *sshConn) Write(p []byte) (int, error) { return c.in.Write(p) }

func (c *sshConn) Close() error {
	c.once.Do(func() {
		if c.cmd.Process != nil {
			_ = c.cmd.Process.Kill()
		}
		_ = c.in.Close()
		_ = c.out.Close()
		_ = c.tcp.Close()
	})
	return nil
}

func (c *sshConn) LocalAddr() net.Addr  { return c.tcp.LocalAddr() }
func (c *sshConn) RemoteAddr() net.Addr { return c.tcp.RemoteAddr() }

func (c *sshConn) SetDeadline(t time.Time) error {
	_ = c.in.SetWriteDeadline(t)
	return c.out.SetReadDeadline(t)
}
func (c *sshConn) SetReadDeadline(t time.Time) error  { return c.out.SetReadDeadline(t) }
func (c *sshConn) SetWriteDeadline(t time.Time) error { return c.in.SetWriteDeadline(t) }

// failure is ssh's own explanation of why it exited ("Permission denied (publickey).", "Host key
// verification failed."), or "" when it has none.
func (c *sshConn) failure() string {
	select {
	case <-c.exited:
	case <-time.After(time.Second):
	}
	lines := strings.Split(strings.TrimSpace(c.stderr.String()), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
