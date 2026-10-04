package web

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"auto-wg/pkg/config"
	"auto-wg/pkg/hunter"
	"auto-wg/pkg/iptables"
	"auto-wg/pkg/logger"
	"auto-wg/pkg/wg"
)

func setupTestServer(t *testing.T) (*Server, *hunter.Hunter) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	cfg := &config.Config{
		WireGuard: config.WireGuardConfig{
			Interface: "wg0",
			Mode:      "cli",
			Command:   "wg",
		},
		Iptables: config.IptablesConfig{
			Enabled:   false,
			PortRange: "20000-30000",
		},
		Hunter: config.HunterConfig{
			RemotePortRange:  "20000-30000",
			CheckInterval:    3 * time.Second,
			HandshakeTimeout: 15 * time.Second,
			CycleTimeout:     8 * time.Second,
		},
		Web: config.WebConfig{
			Enabled:    true,
			ListenAddr: "127.0.0.1:0",
		},
	}
	if err := config.SaveConfig(cfgPath, cfg); err != nil {
		t.Fatalf("Save test config: %v", err)
	}

	log := logger.New(io.Discard, logger.LevelDebug, 100)
	wgCtrl, _ := wg.NewController("cli", "wg", log)
	iptMgr := iptables.NewManager(log)
	h := hunter.New(cfgPath, cfg, wgCtrl, iptMgr, log)

	s := NewServer(h, log)
	return s, h
}

func TestServerStatusAPI(t *testing.T) {
	s, _ := setupTestServer(t)

	req := httptest.NewRequest("GET", "/api/status", nil)
	w := httptest.NewRecorder()

	s.handleStatus(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	var status hunter.StatusReport
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("Failed to decode status JSON: %v", err)
	}

	if status.Interface != "wg0" {
		t.Errorf("Expected interface wg0, got %s", status.Interface)
	}
}

func TestServerConfigAPI(t *testing.T) {
	s, h := setupTestServer(t)

	// 1. GET /api/config
	getReq := httptest.NewRequest("GET", "/api/config", nil)
	getW := httptest.NewRecorder()
	s.handleConfig(getW, getReq)

	if getW.Code != http.StatusOK {
		t.Fatalf("GET /api/config code %d", getW.Code)
	}

	var currentCfg config.Config
	if err := json.NewDecoder(getW.Body).Decode(&currentCfg); err != nil {
		t.Fatalf("Decode config: %v", err)
	}
	if currentCfg.WireGuard.Interface != "wg0" {
		t.Errorf("Expected wg0, got %s", currentCfg.WireGuard.Interface)
	}

	// 2. POST /api/config to update
	currentCfg.WireGuard.Interface = "wg_custom"
	currentCfg.Hunter.HandshakeTimeout = 25 * time.Second

	body, _ := json.Marshal(currentCfg)
	postReq := httptest.NewRequest("POST", "/api/config", bytes.NewReader(body))
	postW := httptest.NewRecorder()
	s.handleConfig(postW, postReq)

	if postW.Code != http.StatusOK {
		t.Fatalf("POST /api/config failed: %s", postW.Body.String())
	}

	// Verify hunter received the update
	updated := h.GetConfig()
	if updated.WireGuard.Interface != "wg_custom" {
		t.Errorf("Expected interface wg_custom, got %s", updated.WireGuard.Interface)
	}
	if updated.Hunter.HandshakeTimeout != 25*time.Second {
		t.Errorf("Expected timeout 25s, got %v", updated.Hunter.HandshakeTimeout)
	}
}

func TestServerActionHunt(t *testing.T) {
	s, _ := setupTestServer(t)

	req := httptest.NewRequest("POST", "/api/actions/hunt", nil)
	w := httptest.NewRecorder()

	s.handleActionHunt(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Action hunt returned status %d", w.Code)
	}
}

func TestServerActionRebind(t *testing.T) {
	s, _ := setupTestServer(t)

	req := httptest.NewRequest("POST", "/api/actions/rebind", nil)
	w := httptest.NewRecorder()

	s.handleActionRebind(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Action rebind returned status %d", w.Code)
	}
}

func TestIsIPAllowed(t *testing.T) {
	allowedList := []string{
		"127.0.0.1",
		"::1",
		"192.168.1.0/24",
		"10.0.0.0/8",
		"2a10:ed40:6:3::/64",
	}

	tests := []struct {
		ip       string
		expected bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"192.168.1.50", true},
		{"192.168.2.50", false},
		{"10.254.1.1", true},
		{"11.0.0.1", false},
		{"2a10:ed40:6:3:20c:29ff:fe6b:7325", true},
		{"2a10:ed40:6:4::1", false},
		{"invalid-ip", false},
	}

	for _, tt := range tests {
		got := isIPAllowed(tt.ip, allowedList)
		if got != tt.expected {
			t.Errorf("isIPAllowed(%q) = %v; want %v", tt.ip, got, tt.expected)
		}
	}
}

func TestServerAllowedIPsMiddleware(t *testing.T) {
	s, h := setupTestServer(t)

	// Configure allowed IPs
	cfg := h.GetConfig()
	cfg.Web.AllowedIPs = []string{"192.168.1.100", "10.0.0.0/24"}
	_ = h.UpdateConfig(&cfg)

	handler := s.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	// 1. Authorized IP
	reqAllowed := httptest.NewRequest("GET", "/api/status", nil)
	reqAllowed.RemoteAddr = "192.168.1.100:54321"
	wAllowed := httptest.NewRecorder()
	handler.ServeHTTP(wAllowed, reqAllowed)
	if wAllowed.Code != http.StatusOK {
		t.Errorf("Expected 200 for allowed IP, got %d", wAllowed.Code)
	}

	// 2. Authorized CIDR IP
	reqCIDR := httptest.NewRequest("GET", "/api/status", nil)
	reqCIDR.RemoteAddr = "10.0.0.55:12345"
	wCIDR := httptest.NewRecorder()
	handler.ServeHTTP(wCIDR, reqCIDR)
	if wCIDR.Code != http.StatusOK {
		t.Errorf("Expected 200 for allowed CIDR IP, got %d", wCIDR.Code)
	}

	// 3. Unauthorized IP
	reqBlocked := httptest.NewRequest("GET", "/api/status", nil)
	reqBlocked.RemoteAddr = "192.168.1.101:54321"
	wBlocked := httptest.NewRecorder()
	handler.ServeHTTP(wBlocked, reqBlocked)
	if wBlocked.Code != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for unauthorized IP, got %d", wBlocked.Code)
	}
}

func TestStatusPageHTML(t *testing.T) {
	s, _ := setupTestServer(t)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	s.handleStatusPage(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	html := string(body)

	// Verify it contains uptime / downtime section and title
	if !strings.Contains(html, "Service Status") {
		t.Errorf("Expected HTML to contain 'Service Status'")
	}
	if !strings.Contains(html, "Continuous Uptime") && !strings.Contains(html, "Downtime") {
		t.Errorf("Expected HTML to mention uptime or downtime")
	}

	// Verify no sensitive keys or internal IP addresses are leaked in HTML
	if strings.Contains(html, "private_key") || strings.Contains(html, "public_key") {
		t.Errorf("Status page HTML must not contain WireGuard keys")
	}
}

func TestStatusPageJSON(t *testing.T) {
	s, _ := setupTestServer(t)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	s.handleStatusPage(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}

	var pub PublicStatus
	if err := json.NewDecoder(resp.Body).Decode(&pub); err != nil {
		t.Fatalf("Decode JSON: %v", err)
	}

	if pub.Title != "Service Status" {
		t.Errorf("Expected title 'Service Status', got %q", pub.Title)
	}
	if pub.UptimePercent < 0 || pub.UptimePercent > 100 {
		t.Errorf("Invalid UptimePercent: %v", pub.UptimePercent)
	}
}

func TestStatusPageHTTPSAndMissingCert(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	cfg := &config.Config{
		WireGuard: config.WireGuardConfig{Interface: "wg0"},
		Web:       config.WebConfig{Enabled: false},
		StatusPage: config.StatusPageConfig{
			Enabled:    true,
			ListenAddr: "127.0.0.1:0",
			HTTPS:      true,
			CertFile:   filepath.Join(tmpDir, "missing_cert.pem"),
			KeyFile:    filepath.Join(tmpDir, "missing_key.pem"),
		},
	}
	_ = config.SaveConfig(cfgPath, cfg)

	log := logger.New(io.Discard, logger.LevelDebug, 100)
	wgCtrl, _ := wg.NewController("cli", "wg", log)
	iptMgr := iptables.NewManager(log)
	h := hunter.New(cfgPath, cfg, wgCtrl, iptMgr, log)

	s := NewServer(h, log)

	// 1. Missing cert should fail to start
	err := s.Start()
	if err == nil {
		t.Fatalf("Expected error when cert_file does not exist, got nil")
	}
	_ = s.Stop(context.Background())

	// 2. Valid cert and key should succeed
	certPath, keyPath := generateSelfSignedCert(t, tmpDir)
	cfg.StatusPage.CertFile = certPath
	cfg.StatusPage.KeyFile = keyPath
	_ = h.UpdateConfig(cfg)

	s2 := NewServer(h, log)
	// Pick random free port
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := l.Addr().String()
	l.Close()

	cfg.StatusPage.ListenAddr = addr
	_ = h.UpdateConfig(cfg)

	if err := s2.Start(); err != nil {
		t.Fatalf("s2.Start with HTTPS failed: %v", err)
	}
	defer s2.Stop(context.Background())

	// Test HTTPS connection
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}

	var resp *http.Response
	for i := 0; i < 10; i++ {
		time.Sleep(50 * time.Millisecond)
		resp, err = client.Get(fmt.Sprintf("https://%s/", addr))
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("GET https://%s/ failed: %v", addr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK from HTTPS, got %d", resp.StatusCode)
	}
}

func generateSelfSignedCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Auto-WG Test"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	certPath := filepath.Join(dir, "cert.pem")
	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("Create cert.pem: %v", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPath := filepath.Join(dir, "key.pem")
	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("Create key.pem: %v", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	keyOut.Close()

	return certPath, keyPath
}
