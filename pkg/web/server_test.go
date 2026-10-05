package web

import (
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
	"auto-wg/pkg/iptables"
	"auto-wg/pkg/logger"
	"auto-wg/pkg/supervisor"
	"auto-wg/pkg/wg"
)

func setupTestServer(t *testing.T) (*Server, *supervisor.Supervisor) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	cfg := &config.Config{
		Mode: "server",
		Tunnels: []config.TunnelConfig{
			{
				Interface:        "wg0",
				Name:             "Client-1",
				PortRange:        "20000-30000",
				RemotePortRange:  "20000-30000",
				CheckInterval:    3 * time.Second,
				HandshakeTimeout: 15 * time.Second,
				CycleTimeout:     8 * time.Second,
				HistoryFile:      "off",
			},
		},
		Web: config.WebConfig{
			Enabled:    true,
			ListenAddr: "127.0.0.1:0",
		},
		StatusPage: config.StatusPageConfig{
			Enabled:    true,
			ListenAddr: "127.0.0.1:0",
			Title:      "Service Status",
		},
	}
	if err := config.SaveConfig(cfgPath, cfg); err != nil {
		t.Fatalf("Save test config: %v", err)
	}

	log := logger.New(io.Discard, logger.LevelDebug, 100)
	wgCtrl, _ := wg.NewController(log)
	iptMgr := iptables.NewManager(log)
	sup := supervisor.New(cfgPath, cfg, wgCtrl, iptMgr, log)

	s := NewServer(sup, log)
	return s, sup
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

	var status supervisor.SupervisorStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("Failed to decode status JSON: %v", err)
	}

	if status.Mode != "server" {
		t.Errorf("Expected mode server, got %s", status.Mode)
	}
	if status.Tunnels["wg0"].Interface != "wg0" {
		t.Errorf("Expected interface wg0, got %s", status.Tunnels["wg0"].Interface)
	}
}

func TestServerConfigAPI(t *testing.T) {
	s, sup := setupTestServer(t)

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
	if currentCfg.Tunnels[0].Interface != "wg0" {
		t.Errorf("Expected wg0, got %s", currentCfg.Tunnels[0].Interface)
	}

	if sup == nil {
		t.Fatalf("Expected supervisor instance")
	}
}

func TestServerActionHunt(t *testing.T) {
	s, _ := setupTestServer(t)

	req := httptest.NewRequest("POST", "/api/actions/hunt?tunnel=wg0", nil)
	w := httptest.NewRecorder()

	s.handleActionHunt(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Action hunt returned status %d", w.Code)
	}
}

func TestServerActionRebind(t *testing.T) {
	s, _ := setupTestServer(t)

	req := httptest.NewRequest("POST", "/api/actions/rebind?tunnel=wg0", nil)
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
	s, sup := setupTestServer(t)

	// Configure allowed IPs
	newCfg := sup.GetConfig()
	newCfg.Web.AllowedIPs = []string{"192.168.1.100", "10.0.0.0/24"}
	_ = sup.UpdateConfig(&newCfg)

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
		t.Fatalf("Read body: %v", err)
	}

	htmlStr := string(body)
	if !strings.Contains(htmlStr, "Service Status") {
		t.Errorf("HTML does not contain title 'Service Status'")
	}
	if !strings.Contains(htmlStr, "INITIAL_DATA") {
		t.Errorf("HTML does not contain embedded INITIAL_DATA")
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

	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Expected application/json, got %s", resp.Header.Get("Content-Type"))
	}

	var pub PublicStatus
	if err := json.NewDecoder(resp.Body).Decode(&pub); err != nil {
		t.Fatalf("Decode JSON: %v", err)
	}

	if pub.Title != "Service Status" {
		t.Errorf("Expected title 'Service Status', got %s", pub.Title)
	}
	if len(pub.Tunnels) != 1 {
		t.Errorf("Expected 1 tunnel status, got %d", len(pub.Tunnels))
	}
}

func generateSelfSignedCert(t *testing.T, certPath, keyPath string) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"AutoWG Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	defer certOut.Close()
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal ec key: %v", err)
	}
	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	defer keyOut.Close()
	_ = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
}

func TestStatusPageHTTPSAndMissingCert(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "status.crt")
	keyFile := filepath.Join(tmpDir, "status.key")

	log := logger.New(io.Discard, logger.LevelDebug, 100)
	wgCtrl, _ := wg.NewController(log)
	iptMgr := iptables.NewManager(log)

	// 1. Missing cert error test
	cfgMissing := &config.Config{
		Mode: "server",
		Tunnels: []config.TunnelConfig{
			{Interface: "wg0", HistoryFile: "off"},
		},
		StatusPage: config.StatusPageConfig{
			Enabled:    true,
			ListenAddr: "127.0.0.1:0",
			HTTPS:      true,
			CertFile:   "/non/existent/cert.crt",
			KeyFile:    "/non/existent/key.key",
		},
	}
	supMissing := supervisor.New("", cfgMissing, wgCtrl, iptMgr, log)
	srvMissing := NewServer(supMissing, log)
	if err := srvMissing.Start(); err == nil {
		t.Errorf("expected error for non-existent cert, got nil")
	}

	// 2. Working HTTPS test with generated self-signed certificate
	generateSelfSignedCert(t, certFile, keyFile)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	chosenAddr := l.Addr().String()
	_ = l.Close()

	cfgValid := &config.Config{
		Mode: "server",
		Tunnels: []config.TunnelConfig{
			{Interface: "wg0", HistoryFile: "off"},
		},
		StatusPage: config.StatusPageConfig{
			Enabled:    true,
			ListenAddr: chosenAddr,
			HTTPS:      true,
			CertFile:   certFile,
			KeyFile:    keyFile,
		},
	}

	supValid := supervisor.New("", cfgValid, wgCtrl, iptMgr, log)
	srvValid := NewServer(supValid, log)
	if err := srvValid.Start(); err != nil {
		t.Fatalf("Start() with valid HTTPS failed: %v", err)
	}
	defer func() {
		_ = srvValid.Stop(context.Background())
	}()

	time.Sleep(50 * time.Millisecond)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}

	resp, err := client.Get(fmt.Sprintf("https://%s/", chosenAddr))
	if err != nil {
		t.Fatalf("HTTPS GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected HTTPS 200, got %d", resp.StatusCode)
	}
}
