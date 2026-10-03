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
	"auto-wg/pkg/logger"
	"auto-wg/pkg/monitor"
	"auto-wg/pkg/negotiator"
	"auto-wg/pkg/signaling"
	"auto-wg/pkg/wg"
)

//go:embed static/*
var staticFS embed.FS

type Server struct {
	cfg       *config.Config
	monitor   *monitor.Monitor
	engine    *negotiator.Engine
	signaler  *signaling.CompositeSignaler
	wgCtrl    *wg.Controller
	log       *logger.Logger
	server    *http.Server
}

func NewServer(
	cfg *config.Config,
	mon *monitor.Monitor,
	eng *negotiator.Engine,
	sig *signaling.CompositeSignaler,
	wgCtrl *wg.Controller,
	log *logger.Logger,
) *Server {
	return &Server{
		cfg:      cfg,
		monitor:  mon,
		engine:   eng,
		signaler: sig,
		wgCtrl:   wgCtrl,
		log:      log,
	}
}

func (s *Server) Start() error {
	subFS, err := fs.Sub(staticFS, "static")
	if err != nil {
		return fmt.Errorf("sub static fs: %w", err)
	}

	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/logs", s.handleLogs)
	mux.HandleFunc("/api/logs/stream", s.handleLogStream)
	mux.HandleFunc("/api/actions/renegotiate", s.handleActionRenegotiate)
	mux.HandleFunc("/api/actions/rebind", s.handleActionRebind)

	// Static UI assets
	fileServer := http.FileServer(http.FS(subFS))
	mux.Handle("/", fileServer)

	// Auth wrapper
	handler := s.authMiddleware(mux)

	s.server = &http.Server{
		Addr:         s.cfg.Web.ListenAddr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 0, // Keep open for SSE
	}

	s.log.Info("WEB", "Web Panel available at http://%s", s.cfg.Web.ListenAddr)
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
		if s.cfg.Web.Username != "" && s.cfg.Web.Password != "" {
			u, p, ok := r.BasicAuth()
			if !ok || u != s.cfg.Web.Username || p != s.cfg.Web.Password {
				w.Header().Set("WWW-Authenticate", `Basic realm="Auto-WG Panel"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

type FullStatusResponse struct {
	PeerID         string                    `json:"peer_id"`
	RemotePeerID   string                    `json:"remote_peer_id"`
	TunnelReport   monitor.StatusReport      `json:"tunnel_report"`
	Signaling      []signaling.BackendStatus `json:"signaling_backends"`
	CandidatePorts []int                     `json:"candidate_ports"`
	ServerTime     time.Time                 `json:"server_time"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	report := s.monitor.GetStatus()
	sigStatuses := s.signaler.GetStatuses()

	resp := FullStatusResponse{
		PeerID:         s.cfg.PeerID,
		RemotePeerID:   s.cfg.RemotePeerID,
		TunnelReport:   report,
		Signaling:      sigStatuses,
		CandidatePorts: s.cfg.Negotiation.CandidatePorts,
		ServerTime:     time.Now(),
	}

	_ = json.NewEncoder(w).Encode(resp)
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

func (s *Server) handleActionRenegotiate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.log.Info("WEB", "Manual full renegotiation requested via web panel")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := s.engine.PerformNegotiation(ctx); err != nil {
			s.log.Error("WEB", "Manual renegotiation failed: %v", err)
		} else {
			s.log.Info("WEB", "Manual renegotiation completed successfully!")
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "initiated"})
}

func (s *Server) handleActionRebind(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.log.Info("WEB", "Manual quick client rebind requested via web panel")
	go func() {
		s.engine.TriggerFailure("manual_web_rebind_request")
	}()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "initiated"})
}
