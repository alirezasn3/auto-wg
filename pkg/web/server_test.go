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
