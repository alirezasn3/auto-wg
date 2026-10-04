package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"math"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"auto-wg/pkg/config"
	"auto-wg/pkg/hunter"
	"auto-wg/pkg/logger"
)

//go:embed static/*
var staticFS embed.FS

type Server struct {
	hunter       *hunter.Hunter
	log          *logger.Logger
	adminServer  *http.Server
	statusServer *http.Server
	statusTmpl   *template.Template
}

type PublicStatus struct {
	Title                 string        `json:"title"`
	Connected             bool          `json:"connected"`
	State                 string        `json:"state"`
	StatusMessage         string        `json:"status_message"`
	StatusDescription     string        `json:"status_description"`
	UptimeSeconds         float64       `json:"uptime_seconds"`
	UptimeFormatted       string        `json:"uptime_formatted"`
	LastConnectedAt       string        `json:"last_connected_at"`
	LastConnectedAgo      string        `json:"last_connected_ago"`
	LastDisconnectedAt    string        `json:"last_disconnected_at"`
	LastDowntimeSeconds   float64       `json:"last_downtime_seconds"`
	LastDowntimeFormatted string        `json:"last_downtime_formatted"`
	LastDowntimeAgo       string        `json:"last_downtime_ago"`
	UptimePercent         float64       `json:"uptime_percent"`
	Events                []PublicEvent `json:"events"`
	ServerTime            string        `json:"server_time"`
	InitialDataJSON       string        `json:"-"`
}

type PublicEvent struct {
	Type        string  `json:"type"` // "CONNECTED" or "DISCONNECTED"
	Timestamp   string  `json:"timestamp"`
	DurationSec float64 `json:"duration_sec"`
	Duration    string  `json:"duration"`
	Message     string  `json:"message"`
}

func NewServer(h *hunter.Hunter, log *logger.Logger) *Server {
	tmpl, err := template.ParseFS(staticFS, "static/status.html")
	if err != nil {
		log.Warn("WEB", "Failed to parse status.html template: %v", err)
	}

	return &Server{
		hunter:     h,
		log:        log,
		statusTmpl: tmpl,
	}
}

func (s *Server) Start() error {
	cfg := s.hunter.GetConfig()

	// 1. Admin Web Panel
	if cfg.Web.Enabled {
		subFS, err := fs.Sub(staticFS, "static")
		if err != nil {
			return fmt.Errorf("sub static fs: %w", err)
		}

		adminMux := http.NewServeMux()
		adminMux.HandleFunc("/api/status", s.handleStatus)
		adminMux.HandleFunc("/api/config", s.handleConfig)
		adminMux.HandleFunc("/api/logs", s.handleLogs)
		adminMux.HandleFunc("/api/logs/stream", s.handleLogStream)
		adminMux.HandleFunc("/api/actions/hunt", s.handleActionHunt)
		adminMux.HandleFunc("/api/actions/rebind", s.handleActionRebind)
		adminMux.Handle("/", http.FileServer(http.FS(subFS)))

		handler := s.authMiddleware(adminMux)

		s.adminServer = &http.Server{
			Addr:         cfg.Web.ListenAddr,
			Handler:      handler,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 0, // Keep open for SSE
		}

		if cfg.Web.HTTPS {
			if cfg.Web.CertFile == "" || cfg.Web.KeyFile == "" {
				return fmt.Errorf("web: https is enabled but cert_file or key_file is missing")
			}
			if _, err := os.Stat(cfg.Web.CertFile); err != nil {
				return fmt.Errorf("web cert_file: %w", err)
			}
			if _, err := os.Stat(cfg.Web.KeyFile); err != nil {
				return fmt.Errorf("web key_file: %w", err)
			}
			s.log.Info("WEB", "Web Admin Panel available at https://%s", cfg.Web.ListenAddr)
			go func() {
				if err := s.adminServer.ListenAndServeTLS(cfg.Web.CertFile, cfg.Web.KeyFile); err != nil && err != http.ErrServerClosed {
					s.log.Error("WEB", "Web admin server TLS failed: %v", err)
				}
			}()
		} else {
			s.log.Info("WEB", "Web Admin Panel available at http://%s", cfg.Web.ListenAddr)
			go func() {
				if err := s.adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					s.log.Error("WEB", "Web admin server failed: %v", err)
				}
			}()
		}
	}

	// 2. Public Status Page (Uptime & Downtime Only)
	if cfg.StatusPage.Enabled {
		statusMux := http.NewServeMux()
		statusMux.HandleFunc("/", s.handleStatusPage)

		s.statusServer = &http.Server{
			Addr:         cfg.StatusPage.ListenAddr,
			Handler:      statusMux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}

		if cfg.StatusPage.HTTPS {
			if cfg.StatusPage.CertFile == "" || cfg.StatusPage.KeyFile == "" {
				return fmt.Errorf("status_page: https is enabled but cert_file or key_file is missing")
			}
			if _, err := os.Stat(cfg.StatusPage.CertFile); err != nil {
				return fmt.Errorf("status_page cert_file: %w", err)
			}
			if _, err := os.Stat(cfg.StatusPage.KeyFile); err != nil {
				return fmt.Errorf("status_page key_file: %w", err)
			}
			s.log.Info("WEB", "Public Status Page available at https://%s", cfg.StatusPage.ListenAddr)
			go func() {
				if err := s.statusServer.ListenAndServeTLS(cfg.StatusPage.CertFile, cfg.StatusPage.KeyFile); err != nil && err != http.ErrServerClosed {
					s.log.Error("WEB", "Public status server TLS failed: %v", err)
				}
			}()
		} else {
			s.log.Info("WEB", "Public Status Page available at http://%s", cfg.StatusPage.ListenAddr)
			go func() {
				if err := s.statusServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					s.log.Error("WEB", "Public status server failed: %v", err)
				}
			}()
		}
	}

	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	var errs []string
	if s.adminServer != nil {
		if err := s.adminServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Sprintf("admin server: %v", err))
		}
	}
	if s.statusServer != nil {
		if err := s.statusServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Sprintf("status server: %v", err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %s", strings.Join(errs, ", "))
	}
	return nil
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := s.hunter.GetConfig()

		// 1. Client IP Whitelist check
		if len(cfg.Web.AllowedIPs) > 0 {
			clientIP := extractClientIP(r)
			if !isIPAllowed(clientIP, cfg.Web.AllowedIPs) {
				s.log.Warn("WEB", "Access denied: client IP %s is not in web.allowed_ips", clientIP)
				http.Error(w, "Forbidden: IP not authorized", http.StatusForbidden)
				return
			}
		}

		// 2. HTTP Basic Auth check
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

func extractClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return strings.TrimSpace(host)
}

func isIPAllowed(clientIPStr string, allowedList []string) bool {
	parsedIP := net.ParseIP(clientIPStr)
	if parsedIP == nil {
		return false
	}

	for _, entry := range allowedList {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if strings.Contains(entry, "/") {
			_, ipNet, err := net.ParseCIDR(entry)
			if err == nil && ipNet.Contains(parsedIP) {
				return true
			}
		} else {
			entryIP := net.ParseIP(entry)
			if entryIP != nil && entryIP.Equal(parsedIP) {
				return true
			}
		}
	}
	return false
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

func (s *Server) handleStatusPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	pubStatus := s.getPublicStatus()

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pubStatus)
		return
	}

	if s.statusTmpl == nil {
		http.Error(w, "Status page template not loaded", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.statusTmpl.Execute(w, pubStatus); err != nil {
		s.log.Error("WEB", "Failed to render status page: %v", err)
	}
}

func (s *Server) getPublicStatus() PublicStatus {
	st := s.hunter.GetStatus()
	cfg := s.hunter.GetConfig()

	title := cfg.StatusPage.Title
	if title == "" {
		title = "Service Status"
	}

	isConnected := st.State == hunter.StateConnected
	now := time.Now()

	var uptimeSec float64
	var lastConnAgo string
	if !st.LastConnectedAt.IsZero() {
		diff := now.Sub(st.LastConnectedAt).Seconds()
		if diff < 0 {
			diff = 0
		}
		if isConnected {
			uptimeSec = diff
		}
		lastConnAgo = formatDurationAgo(st.LastConnectedAt, now)
	} else {
		lastConnAgo = "Never"
	}

	var lastDowntimeSec float64
	var lastDiscAgo string
	if !st.LastDisconnectedAt.IsZero() {
		diff := now.Sub(st.LastDisconnectedAt).Seconds()
		if diff < 0 {
			diff = 0
		}
		lastDiscAgo = formatDurationAgo(st.LastDisconnectedAt, now)
	} else {
		lastDiscAgo = "Never"
	}

	// Calculate uptime ratio and extract sanitized events
	var totalUpSec, totalDownSec float64
	for _, evt := range st.Events {
		if evt.Type == hunter.StateConnected {
			// DurationSec on connected event is the downtime that just ended
			totalDownSec += evt.DurationSec
			if lastDowntimeSec == 0 && evt.DurationSec > 0 {
				lastDowntimeSec = evt.DurationSec
			}
		} else if evt.Type == hunter.StateDisconnected {
			// DurationSec on disconnected event is the uptime that just ended
			totalUpSec += evt.DurationSec
		}
	}
	if isConnected && uptimeSec > 0 {
		totalUpSec += uptimeSec
	}
	if !isConnected && !st.LastDisconnectedAt.IsZero() {
		currDown := now.Sub(st.LastDisconnectedAt).Seconds()
		if currDown > 0 {
			totalDownSec += currDown
			lastDowntimeSec = currDown
		}
	}

	uptimePercent := 100.0
	if totalUpSec+totalDownSec > 0 {
		uptimePercent = (totalUpSec / (totalUpSec + totalDownSec)) * 100.0
	}

	var lastDowntimeFormatted string
	if lastDowntimeSec > 0 {
		lastDowntimeFormatted = formatDurationHuman(lastDowntimeSec)
	}

	publicEvents := make([]PublicEvent, 0, len(st.Events))
	for _, evt := range st.Events {
		durStr := formatDurationHuman(evt.DurationSec)
		msg := "Operational"
		if evt.Type == hunter.StateConnected {
			if evt.DurationSec > 0 {
				msg = fmt.Sprintf("Connection restored (interruption was %s)", durStr)
			} else {
				msg = "Connection established"
			}
		} else if evt.Type == hunter.StateDisconnected {
			if evt.DurationSec > 0 {
				msg = fmt.Sprintf("Service interrupted (was up for %s)", durStr)
			} else {
				msg = "Service interrupted"
			}
		}

		publicEvents = append(publicEvents, PublicEvent{
			Type:        evt.Type,
			Timestamp:   evt.Timestamp.Format(time.RFC3339),
			DurationSec: evt.DurationSec,
			Duration:    durStr,
			Message:     msg,
		})
	}

	statusMsg := "All Systems Operational"
	statusDesc := "The tunnel is active and passing traffic."
	if !isConnected {
		statusMsg = "Service Interruption"
		statusDesc = "The tunnel is interrupted; automatic port recovery in progress."
	}

	var lastConnRFC, lastDiscRFC string
	if !st.LastConnectedAt.IsZero() {
		lastConnRFC = st.LastConnectedAt.Format(time.RFC3339)
	}
	if !st.LastDisconnectedAt.IsZero() {
		lastDiscRFC = st.LastDisconnectedAt.Format(time.RFC3339)
	}

	pub := PublicStatus{
		Title:                 title,
		Connected:             isConnected,
		State:                 st.State,
		StatusMessage:         statusMsg,
		StatusDescription:     statusDesc,
		UptimeSeconds:         uptimeSec,
		UptimeFormatted:       formatDurationHuman(uptimeSec),
		LastConnectedAt:       lastConnRFC,
		LastConnectedAgo:      lastConnAgo,
		LastDisconnectedAt:    lastDiscRFC,
		LastDowntimeSeconds:   lastDowntimeSec,
		LastDowntimeFormatted: lastDowntimeFormatted,
		LastDowntimeAgo:       lastDiscAgo,
		UptimePercent:         math.Round(uptimePercent*100) / 100,
		Events:                publicEvents,
		ServerTime:            now.Format(time.RFC3339),
	}

	jsonData, _ := json.Marshal(pub)
	pub.InitialDataJSON = string(jsonData)

	return pub
}

func formatDurationHuman(seconds float64) string {
	if seconds <= 0 {
		return "0s"
	}
	totalSec := int64(seconds)
	days := totalSec / 86400
	hours := (totalSec % 86400) / 3600
	minutes := (totalSec % 3600) / 60
	secs := totalSec % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, secs)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, secs)
	}
	return fmt.Sprintf("%ds", secs)
}

func formatDurationAgo(t time.Time, now time.Time) string {
	if t.IsZero() {
		return "Never"
	}
	diff := now.Sub(t)
	if diff < 0 {
		diff = 0
	}
	sec := int64(diff.Seconds())
	if sec < 60 {
		return fmt.Sprintf("%ds ago", sec)
	}
	mins := sec / 60
	if mins < 60 {
		return fmt.Sprintf("%dm ago", mins)
	}
	hours := mins / 60
	if hours < 24 {
		return fmt.Sprintf("%dh %dm ago", hours, mins%60)
	}
	days := hours / 24
	return fmt.Sprintf("%dd %dh ago", days, hours%24)
}
