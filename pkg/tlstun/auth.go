package tlstun

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const exporterLabel = "auto-wg tls tunnel"

// ErrAuth means the peer failed the shared-secret proof (wrong secret, or not an Auto-WG peer).
var ErrAuth = errors.New("tlstun: peer authentication failed")

type role byte

const (
	roleDialer   role = 'D'
	roleAcceptor role = 'A'
)

// proof is HMAC-SHA256(secret, exporter keying material || role). The exporter value is unique to this
// TLS session, so a proof cannot be replayed on another connection, and the secret never crosses the
// wire. The role byte stops a peer from reflecting the other side's proof back at it.
func proof(secret string, cs tls.ConnectionState, r role) ([]byte, error) {
	km, err := cs.ExportKeyingMaterial(exporterLabel, nil, 32)
	if err != nil {
		return nil, fmt.Errorf("export keying material: %w", err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(km)
	mac.Write([]byte{byte(r)})
	return mac.Sum(nil), nil
}

// authenticate runs the proof exchange on an established TLS connection. The dialer proves first; the
// acceptor answers only after verifying, so an unauthenticated dialer learns nothing.
func authenticate(c *tls.Conn, secret string, dialer bool) error {
	cs := c.ConnectionState()
	buf := make([]byte, maxFrame)

	if dialer {
		mine, err := proof(secret, cs, roleDialer)
		if err != nil {
			return err
		}
		if err := writeFrame(c, mine); err != nil {
			return err
		}
		got, ctrl, err := readFrame(c, buf)
		if err != nil {
			return err
		}
		if ctrl {
			return ErrAuth
		}
		want, err := proof(secret, cs, roleAcceptor)
		if err != nil {
			return err
		}
		if !hmac.Equal(got, want) {
			return ErrAuth
		}
		return nil
	}

	got, ctrl, err := readFrame(c, buf)
	if err != nil {
		return err
	}
	if ctrl {
		return ErrAuth
	}
	want, err := proof(secret, cs, roleDialer)
	if err != nil {
		return err
	}
	if !hmac.Equal(got, want) {
		return ErrAuth
	}
	mine, err := proof(secret, cs, roleAcceptor)
	if err != nil {
		return err
	}
	return writeFrame(c, mine)
}

// newCert makes an ephemeral self-signed certificate. When name is set it is used as the common name
// and DNS name so the certificate matches the camouflage SNI; otherwise the name is random.
func newCert(name string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if name = strings.TrimSpace(name); name != "" {
		tmpl.Subject = pkix.Name{CommonName: name}
		tmpl.DNSNames = []string{name}
	} else {
		rnd := make([]byte, 8)
		_, _ = rand.Read(rnd)
		tmpl.Subject = pkix.Name{CommonName: hex.EncodeToString(rnd)}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// fillRandom fills b with cryptographically random bytes (probe padding must not be a recognisable pattern).
func fillRandom(b []byte) { _, _ = rand.Read(b) }

func serverTLS(cert tls.Certificate, alpn []string) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: alpn}
}

// clientTLS skips certificate verification on purpose: peers authenticate with the shared-secret proof
// after the handshake, and the certificate is ephemeral and self-signed.
func clientTLS(sni string, alpn []string) *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, ServerName: sni, NextProtos: alpn}
}
