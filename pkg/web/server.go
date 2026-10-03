package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"time"

	"auto-wg/pkg/config"
	"auto-wg/pkg/hunter"
	"auto-wg/pkg/logger"
)

//go:embed static/*
var staticFS embed.FS

type Server struct {
	hunter *hunter.Hunter
	log    *logger.Logger
	server *http.Server
}

func NewServer(h *hunter.Hunter, log *logger.Logger) *Server {
	return &Server{
		hunter: h,
		log:    log,
	}
}

func (s *Server) Start() error {
	cfg := s.hunter.GetConfig()

	subFS, err := fs.Sub(staticFS, "static")
	if err != nil {
		return fmt.Errorf("sub static fs: %w", err)
	}

	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/logs", s.handleLogs)
	mux.HandleFunc("/api/logs/stream", s.handleLogStream)
	mux.HandleFunc("/api/actions/hunt", s.handleActionHunt)
	mux.HandleFunc("/api/actions/rebind", s.handleActionRebind)

	// Static UI assets
	fileServer := http.FileServer(http.FS(subFS))
	mux.Handle("/", fileServer)

	// Auth wrapper
	handler := s.authMiddleware(mux)

	s.server = &http.Server{
		Addr:         cfg.Web.ListenAddr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 0, // Keep open for SSE
	}

	s.log.Info("WEB", "Web Panel available at http://%s", cfg.Web.ListenAddr)
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.log.Error("WEB", "Web server failed: %v", err)
		}
	}()

	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := s.hunter.GetConfig()
		if cfg.Web.Username != "" && cfg.Web.Password != "" {
			u, p, ok := r.BasicAuth()
			if !ok || u != cfg.Web.Username || p != cfg.Web.Password {
				w.Header().Set("WWW-Authenticate", `Basic realm="Auto-WG Panel"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	report := s.hunter.GetStatus()
	_ = json.NewEncoder(w).Encode(report)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		cfg := s.hunter.GetConfig()
		_ = json.NewEncoder(w).Encode(cfg)
		return
	}

	if r.Method == http.MethodPost {
		var newCfg config.Config
		if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
			http.Error(w, fmt.Sprintf("invalid request payload: %v", err), http.StatusBadRequest)
			return
		}

		if err := s.hunter.UpdateConfig(&newCfg); err != nil {
			http.Error(w, fmt.Sprintf("failed to update config: %v", err), http.StatusInternalServerError)
			return
		}

		s.log.Info("WEB", "Configuration updated via web panel settings")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Settings saved and applied successfully"})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	entries := s.log.GetRecentEntries()
	_ = json.NewEncoder(w).Encode(entries)
}

func (s *Server) handleLogStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	logChan, unsubscribe := s.log.Subscribe()
	defer unsubscribe()

	// Initial ping
	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	notify := r.Context().Done()
	for {
		select {
		case <-notify:
			return
		case entry, ok := <-logChan:
			if !ok {
				return
			}
			data, err := json.Marshal(entry)
			if err == nil {
				fmt.Fprintf(w, "data: %s\n\n", string(data))
				flusher.Flush()
			}
		}
	}
}

func (s *Server) handleActionHunt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.log.Info("WEB", "Manual 5-tuple port hunt triggered via web panel")
	go s.hunter.TriggerHunt("manual_web_request")

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "hunt_triggered"})
}

func (s *Server) handleActionRebind(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.log.Info("WEB", "Manual local source port rebind triggered via web panel")
	go s.hunter.TriggerRebind()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "rebind_triggered"})
}
