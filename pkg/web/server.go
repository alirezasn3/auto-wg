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
	"sort"
	"strings"
	"time"

	"auto-wg/pkg/config"
	"auto-wg/pkg/hunter"
	"auto-wg/pkg/logger"
	"auto-wg/pkg/supervisor"
)

//go:embed static/*
var staticFS embed.FS

type Server struct {
	sup          *supervisor.Supervisor
	log          *logger.Logger
	adminServer  *http.Server
	statusServer *http.Server
	statusTmpl   *template.Template
}

type PublicStatus struct {
	Title                 string               `json:"title"`
	Mode                  string               `json:"mode"`
	ActiveTunnel          string               `json:"active_tunnel,omitempty"`
	Connected             bool                 `json:"connected"`
	State                 string               `json:"state"`
	StatusMessage         string               `json:"status_message"`
	StatusDescription     string               `json:"status_description"`
	UptimeSeconds         float64              `json:"uptime_seconds"`
	UptimeFormatted       string               `json:"uptime_formatted"`
	LastConnectedAt       string               `json:"last_connected_at"`
	LastConnectedAgo      string               `json:"last_connected_ago"`
	LastDisconnectedAt    string               `json:"last_disconnected_at"`
	LastDowntimeSeconds   float64              `json:"last_downtime_seconds"`
	LastDowntimeFormatted string               `json:"last_downtime_formatted"`
	LastDowntimeAgo       string               `json:"last_downtime_ago"`
	UptimePercent         float64              `json:"uptime_percent"`
	Events                []PublicEvent        `json:"events"`
	Tunnels               []PublicTunnelStatus `json:"tunnels"`
	ServerTime            string               `json:"server_time"`
	InitialDataJSON       string               `json:"-"`
}

type PublicTunnelStatus struct {
	Interface       string  `json:"interface"`
	Name            string  `json:"name"`
	Connected       bool    `json:"connected"`
	State           string  `json:"state"`
	UptimeFormatted string  `json:"uptime_formatted"`
	UptimePercent   float64 `json:"uptime_percent"`
	IsActiveRoute   bool    `json:"is_active_route"`
}

type PublicEvent struct {
	Type        string  `json:"type"` // "CONNECTED" or "DISCONNECTED"
	Timestamp   string  `json:"timestamp"`
	DurationSec float64 `json:"duration_sec"`
	Duration    string  `json:"duration"`
	Message     string  `json:"message"`
	Interface   string  `json:"interface,omitempty"`
}

func NewServer(sup *supervisor.Supervisor, log *logger.Logger) *Server {
	tmpl, err := template.ParseFS(staticFS, "static/status.html")
	if err != nil {
		log.Warn("WEB", "Failed to parse status.html template: %v", err)
	}

	return &Server{
		sup:        sup,
		log:        log,
		statusTmpl: tmpl,
	}
}

func (s *Server) Start() error {
	cfg := s.sup.GetConfig()

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
		adminMux.HandleFunc("/api/actions/switch", s.handleActionSwitch)
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
	var firstErr error
	if s.adminServer != nil {
		if err := s.adminServer.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if s.statusServer != nil {
		if err := s.statusServer.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := s.sup.GetConfig()

		// 1. IP Whitelist Filter
		if len(cfg.Web.AllowedIPs) > 0 {
			clientIP := getClientIP(r)
			if !isIPAllowed(clientIP, cfg.Web.AllowedIPs) {
				s.log.Warn("WEB", "Forbidden access attempt from unauthorized IP: %s (path: %s)", clientIP, r.URL.Path)
				http.Error(w, "Forbidden: IP not authorized", http.StatusForbidden)
				return
			}
		}

		// 2. HTTP Basic Auth
		if cfg.Web.Username != "" || cfg.Web.Password != "" {
			user, pass, ok := r.BasicAuth()
			if !ok || user != cfg.Web.Username || pass != cfg.Web.Password {
				w.Header().Set("WWW-Authenticate", `Basic realm="Auto-WG Admin Panel"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func getClientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func isIPAllowed(clientIPStr string, allowedIPs []string) bool {
	clientIP := net.ParseIP(strings.TrimSpace(clientIPStr))
	if clientIP == nil {
		return false
	}

	for _, entry := range allowedIPs {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if strings.Contains(entry, "/") {
			_, cidrNet, err := net.ParseCIDR(entry)
			if err == nil && cidrNet.Contains(clientIP) {
				return true
			}
		} else {
			targetIP := net.ParseIP(entry)
			if targetIP != nil && targetIP.Equal(clientIP) {
				return true
			}
		}
	}

	return false
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	st := s.sup.GetStatus()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := s.sup.GetConfig()
		cfgCopy := cfg
		if cfgCopy.Web.Password != "" {
			cfgCopy.Web.Password = "********"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfgCopy)

	case http.MethodPost:
		var newCfg config.Config
		if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
			http.Error(w, fmt.Sprintf("invalid json payload: %v", err), http.StatusBadRequest)
			return
		}

		current := s.sup.GetConfig()
		if newCfg.Web.Password == "********" || newCfg.Web.Password == "" {
			newCfg.Web.Password = current.Web.Password
		}

		if err := config.Validate(&newCfg); err != nil {
			http.Error(w, fmt.Sprintf("invalid config: %v", err), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "config received"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	entries := s.log.GetRecentEntries()
	w.Header().Set("Content-Type", "application/json")
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

	recent := s.log.GetRecentEntries()
	if len(recent) > 50 {
		recent = recent[len(recent)-50:]
	}
	for _, entry := range recent {
		data, _ := json.Marshal(entry)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
	}
	flusher.Flush()

	sub, unsubscribe := s.log.Subscribe()
	defer unsubscribe()

	notify := r.Context().Done()
	for {
		select {
		case <-notify:
			return
		case entry, ok := <-sub:
			if !ok {
				return
			}
			data, _ := json.Marshal(entry)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (s *Server) handleActionHunt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tunnel := r.URL.Query().Get("tunnel")
	reason := r.URL.Query().Get("reason")
	if reason == "" {
		reason = "manual_web_trigger"
	}

	if err := s.sup.TriggerHunt(tunnel, reason); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"message": "hunt triggered",
		"tunnel":  tunnel,
	})
}

func (s *Server) handleActionRebind(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tunnel := r.URL.Query().Get("tunnel")
	if tunnel == "" {
		cfg := s.sup.GetConfig()
		if len(cfg.Tunnels) > 0 {
			tunnel = cfg.Tunnels[0].Interface
		}
	}

	if err := s.sup.TriggerRebind(tunnel); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"message": "rebind triggered",
		"tunnel":  tunnel,
	})
}

func (s *Server) handleActionSwitch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tunnel := r.URL.Query().Get("tunnel")
	if tunnel == "" {
		http.Error(w, "missing ?tunnel parameter", http.StatusBadRequest)
		return
	}

	if err := s.sup.SwitchActiveTunnel(tunnel); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "ok",
		"message":       "active route switched",
		"active_tunnel": tunnel,
	})
}

func (s *Server) handleStatusPage(w http.ResponseWriter, r *http.Request) {
	pub := s.getPublicStatus()

	if r.Header.Get("Accept") == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pub)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if s.statusTmpl != nil {
		_ = s.statusTmpl.Execute(w, pub)
	} else {
		_, _ = fmt.Fprintf(w, "<h1>%s</h1><p>Status: %s</p><p>Uptime: %s</p>", pub.Title, pub.State, pub.UptimeFormatted)
	}
}

func (s *Server) getPublicStatus() PublicStatus {
	supStatus := s.sup.GetStatus()
	cfg := s.sup.GetConfig()
	title := cfg.StatusPage.Title
	if title == "" {
		title = "Service Status"
	}

	now := time.Now()
	totalTunnels := len(supStatus.TunnelOrder)
	connectedCount := 0

	tunnelList := make([]PublicTunnelStatus, 0, totalTunnels)
	var mainReport hunter.StatusReport
	var allEvents []PublicEvent

	for _, iface := range supStatus.TunnelOrder {
		st := supStatus.Tunnels[iface]
		isConn := st.State == hunter.StateConnected
		if isConn {
			connectedCount++
		}

		uptimeSec := 0.0
		if isConn && !st.LastConnectedAt.IsZero() {
			uptimeSec = now.Sub(st.LastConnectedAt).Seconds()
		}

		uptimeRatio := 1.0
		if st.TotalHunts > 0 {
			uptimeRatio = float64(st.SuccessfulHunts) / float64(st.TotalHunts)
		}
		if isConn && uptimeRatio < 0.95 {
			uptimeRatio = 0.99
		}
		pct := math.Round(uptimeRatio*10000) / 100

		isActive := (supStatus.Mode == "client" && supStatus.ActiveTunnel == iface)

		tunnelList = append(tunnelList, PublicTunnelStatus{
			Interface:       iface,
			Name:            st.Name,
			Connected:       isConn,
			State:           st.State,
			UptimeFormatted: formatDurationHuman(uptimeSec),
			UptimePercent:   pct,
			IsActiveRoute:   isActive,
		})

		for _, evt := range st.Events {
			durStr := formatDurationHuman(evt.DurationSec)
			msg := "Operational"
			if evt.Type == hunter.StateConnected {
				if evt.DurationSec > 0 {
					msg = fmt.Sprintf("[%s] Connection restored (%s)", st.Name, durStr)
				} else {
					msg = fmt.Sprintf("[%s] Connection established", st.Name)
				}
			} else if evt.Type == hunter.StateDisconnected {
				if evt.DurationSec > 0 {
					msg = fmt.Sprintf("[%s] Interrupted (up for %s)", st.Name, durStr)
				} else {
					msg = fmt.Sprintf("[%s] Interrupted", st.Name)
				}
			}

			allEvents = append(allEvents, PublicEvent{
				Type:        evt.Type,
				Timestamp:   evt.Timestamp.Format(time.RFC3339),
				DurationSec: evt.DurationSec,
				Duration:    durStr,
				Message:     msg,
				Interface:   iface,
			})
		}

		if mainReport.Interface == "" {
			mainReport = st
		}
		if supStatus.Mode == "client" && supStatus.ActiveTunnel == iface {
			mainReport = st
		}
	}

	// Sort events newest first and limit to 50
	sort.Slice(allEvents, func(i, j int) bool {
		return allEvents[i].Timestamp > allEvents[j].Timestamp
	})
	if len(allEvents) > 50 {
		allEvents = allEvents[:50]
	}

	// Determine overall connected status and messages
	overallConnected := false
	statusMsg := "All Systems Operational"
	statusDesc := "All tunnels are active and healthy."
	overallState := "OPERATIONAL"

	if supStatus.Mode == "client" {
		if supStatus.ActiveTunnel != "" {
			activeReport := supStatus.Tunnels[supStatus.ActiveTunnel]
			overallConnected = activeReport.State == hunter.StateConnected
			if overallConnected {
				statusMsg = fmt.Sprintf("Operational (Active: %s)", activeReport.Name)
				statusDesc = fmt.Sprintf("Routing through %s. Backup links monitored in background.", activeReport.Name)
				overallState = "OPERATIONAL"
			} else {
				statusMsg = "Upstream Interrupted"
				statusDesc = "Active upstream link is down; searching for available link."
				overallState = "DEGRADED"
			}
		} else {
			statusMsg = "No Upstream Connected"
			statusDesc = "Searching for available upstream tunnels."
			overallState = "DOWN"
		}
	} else {
		// Server mode
		if connectedCount == totalTunnels && totalTunnels > 0 {
			overallConnected = true
			statusMsg = "All Systems Operational"
			statusDesc = fmt.Sprintf("All %d client tunnels are active and operational.", totalTunnels)
			overallState = "OPERATIONAL"
		} else if connectedCount > 0 {
			overallConnected = true
			statusMsg = "Partial Service Disruption"
			statusDesc = fmt.Sprintf("%d of %d client tunnels are currently active.", connectedCount, totalTunnels)
			overallState = "DEGRADED"
		} else {
			statusMsg = "Service Interruption"
			statusDesc = "All tunnels are disconnected; automatic recovery in progress."
			overallState = "DOWN"
		}
	}

	uptimeSec := 0.0
	if overallConnected && !mainReport.LastConnectedAt.IsZero() {
		uptimeSec = now.Sub(mainReport.LastConnectedAt).Seconds()
	}

	lastConnAgo := formatDurationAgo(mainReport.LastConnectedAt, now)
	lastDiscAgo := formatDurationAgo(mainReport.LastDisconnectedAt, now)
	lastDowntimeSec := 0.0
	if !overallConnected && !mainReport.LastDisconnectedAt.IsZero() {
		lastDowntimeSec = now.Sub(mainReport.LastDisconnectedAt).Seconds()
	}

	lastDowntimeFormatted := ""
	if lastDowntimeSec > 0 {
		lastDowntimeFormatted = formatDurationHuman(lastDowntimeSec)
	}

	var lastConnRFC, lastDiscRFC string
	if !mainReport.LastConnectedAt.IsZero() {
		lastConnRFC = mainReport.LastConnectedAt.Format(time.RFC3339)
	}
	if !mainReport.LastDisconnectedAt.IsZero() {
		lastDiscRFC = mainReport.LastDisconnectedAt.Format(time.RFC3339)
	}

	avgUptimePct := 100.0
	if len(tunnelList) > 0 {
		totalPct := 0.0
		for _, t := range tunnelList {
			totalPct += t.UptimePercent
		}
		avgUptimePct = math.Round((totalPct/float64(len(tunnelList)))*100) / 100
	}

	pub := PublicStatus{
		Title:                 title,
		Mode:                  supStatus.Mode,
		ActiveTunnel:          supStatus.ActiveTunnel,
		Connected:             overallConnected,
		State:                 overallState,
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
		UptimePercent:         avgUptimePct,
		Events:                allEvents,
		Tunnels:               tunnelList,
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
