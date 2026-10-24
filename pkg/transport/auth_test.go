package transport

import (
	"crypto/hmac"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"
)

// handshakePair performs a real TLS 1.3 handshake over loopback and returns both ends.
func handshakePair(t *testing.T) (dialer, acceptor *tls.Conn) {
	t.Helper()
	cert, err := newCert("")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type res struct {
		c   *tls.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			ch <- res{nil, err}
			return
		}
		c := tls.Server(raw, serverTLS(cert, nil))
		ch <- res{c, c.Handshake()}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	d := tls.Client(raw, clientTLS("", nil))
	if err := d.Handshake(); err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	t.Cleanup(func() { d.Close(); r.c.Close() })
	_ = d.SetDeadline(time.Now().Add(5 * time.Second))
	_ = r.c.SetDeadline(time.Now().Add(5 * time.Second))
	return d, r.c
}

func runAuth(t *testing.T, dialerSecret, acceptorSecret string) (dErr, aErr error) {
	t.Helper()
	d, a := handshakePair(t)
	done := make(chan error, 1)
	go func() {
		err := authTLS(a, acceptorSecret, false)
		if err != nil {
			a.Close() // like the link: an unauthenticated peer just gets closed
		}
		done <- err
	}()
	dErr = authTLS(d, dialerSecret, true)
	return dErr, <-done
}

func TestAuthSameSecret(t *testing.T) {
	dErr, aErr := runAuth(t, "a-long-shared-secret", "a-long-shared-secret")
	if dErr != nil || aErr != nil {
		t.Fatalf("matching secrets must authenticate: dialer=%v acceptor=%v", dErr, aErr)
	}
}

func TestAuthWrongSecret(t *testing.T) {
	dErr, aErr := runAuth(t, "a-long-shared-secret", "another-secret-value")
	if !errors.Is(aErr, ErrAuth) {
		t.Fatalf("acceptor must reject the proof with ErrAuth, got %v", aErr)
	}
	if dErr == nil {
		t.Fatal("dialer must not be told it authenticated: the acceptor answers only after verifying")
	}
}

func TestProofIsBoundToSessionAndRole(t *testing.T) {
	const secret = "a-long-shared-secret"
	d1, _ := handshakePair(t)
	d2, _ := handshakePair(t)

	b1, err := tlsBinding(d1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := tlsBinding(d2)
	if err != nil {
		t.Fatal(err)
	}
	p1 := proof(secret, b1, roleDialer)
	p2 := proof(secret, b2, roleDialer)
	if hmac.Equal(p1, p2) {
		t.Fatal("a proof from one session must not verify on another (replay)")
	}

	pa := proof(secret, b1, roleAcceptor)
	if hmac.Equal(p1, pa) {
		t.Fatal("dialer and acceptor proofs must differ so one cannot be reflected as the other")
	}
}

func TestCertCamouflage(t *testing.T) {
	c, err := newCert("www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Certificate) != 1 {
		t.Fatal("expected one certificate")
	}
	// The SNI and ALPN settings must be accepted by a real handshake.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		raw, _ := ln.Accept()
		s := tls.Server(raw, serverTLS(c, []string{"h2", "http/1.1"}))
		if s.Handshake() == nil {
			got <- s.ConnectionState().ServerName + "|" + s.ConnectionState().NegotiatedProtocol
		} else {
			got <- "handshake failed"
		}
		s.Close()
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cl := tls.Client(raw, clientTLS("www.example.com", []string{"h2", "http/1.1"}))
	if err := cl.Handshake(); err != nil {
		t.Fatal(err)
	}
	cl.Close()
	if g := <-got; g != "www.example.com|h2" {
		t.Fatalf("server saw %q, want SNI www.example.com and ALPN h2", g)
	}
}

func runNonceAuth(t *testing.T, dialerSecret, acceptorSecret string) (dErr, aErr error) {
	t.Helper()
	d, a := net.Pipe()
	defer d.Close()
	defer a.Close()
	_ = d.SetDeadline(time.Now().Add(5 * time.Second))
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan error, 1)
	go func() {
		err := authenticateNonce(a, acceptorSecret, false)
		if err != nil {
			a.Close()
		}
		done <- err
	}()
	dErr = authenticateNonce(d, dialerSecret, true)
	return dErr, <-done
}

func TestNonceAuthSameSecret(t *testing.T) {
	if dErr, aErr := runNonceAuth(t, "a-long-shared-secret", "a-long-shared-secret"); dErr != nil || aErr != nil {
		t.Fatalf("same secret must authenticate: dialer=%v acceptor=%v", dErr, aErr)
	}
}

func TestNonceAuthWrongSecret(t *testing.T) {
	dErr, aErr := runNonceAuth(t, "a-long-shared-secret", "another-secret-value")
	if !errors.Is(aErr, ErrAuth) {
		t.Fatalf("acceptor must answer a wrong proof with ErrAuth, got %v", aErr)
	}
	if dErr == nil {
		t.Fatal("dialer must not authenticate against an acceptor that rejected it")
	}
}
