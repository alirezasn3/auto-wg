package web

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"auto-wg/pkg/update"
)

// updateHeader must be sent on a POST /api/update. A custom header cannot be added by a cross-site form,
// and a cross-origin fetch with it is stopped by the browser's preflight, so a page on another site cannot
// trigger an update with the admin's cached credentials.
const updateHeader = "X-Autowg-Action"

// Updater lets the dashboard check for and install releases. Restart is called once the new binary is in
// place and the response has been sent.
type Updater struct {
	Version string // running version, as set at build time
	Exe     string // path of the binary to replace
	Restart func()
}

// checkCache keeps the last answer from GitHub for a few minutes: every dashboard load asks, and the API
// allows only 60 unauthenticated requests an hour per address.
type checkCache struct {
	mu   sync.Mutex
	info *update.Info
	at   time.Time
}

const checkCacheTTL = 10 * time.Minute

func (c *checkCache) get() *update.Info {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.info != nil && time.Since(c.at) < checkCacheTTL {
		cp := *c.info
		return &cp
	}
	return nil
}

func (c *checkCache) put(info *update.Info) {
	c.mu.Lock()
	c.info, c.at = info, time.Now()
	c.mu.Unlock()
}

// SetUpdater enables the update endpoints.
func (s *Server) SetUpdater(u *Updater) { s.updater = u }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	u := s.updater
	if u == nil {
		http.Error(w, "updates are not available in this build", http.StatusNotFound)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	switch r.Method {
	case http.MethodGet:
		if info := s.updateCache.get(); info != nil {
			writeJSON(w, http.StatusOK, info)
			return
		}
		cctx, ccancel := context.WithTimeout(ctx, 15*time.Second)
		defer ccancel()
		info, _, err := update.Check(cctx, u.Version)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"current": u.Version, "error": err.Error()})
			return
		}
		s.updateCache.put(info)
		writeJSON(w, http.StatusOK, info)

	case http.MethodPost:
		if r.Header.Get(updateHeader) != "update" {
			http.Error(w, "missing "+updateHeader+" header", http.StatusForbidden)
			return
		}
		info, rel, err := update.Check(ctx, u.Version)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
		if !info.Available {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "already on the latest version", "current": info.Current, "latest": info.Latest})
			return
		}
		if err := update.Install(ctx, rel, u.Exe); err != nil {
			s.log.Error("UPDATE", "Installing %s failed: %v", rel.Tag, err)
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		s.log.Info("UPDATE", "Installed %s over %s; restarting", rel.Tag, u.Version)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": rel.Tag, "restarting": u.Restart != nil})
		if u.Restart != nil {
			go func() {
				time.Sleep(500 * time.Millisecond) // let the response reach the browser
				u.Restart()
			}()
		}

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
