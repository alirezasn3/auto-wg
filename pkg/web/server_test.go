package web

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
