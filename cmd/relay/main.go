package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type CachedState struct {
	State   json.RawMessage
	Expires time.Time
}

type RelayServer struct {
	token   string
	mu      sync.RWMutex
	storage map[string]CachedState
}

func NewRelayServer(token string) *RelayServer {
	return &RelayServer{
		token:   token,
		storage: make(map[string]CachedState),
	}
}

func (s *RelayServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// CORS Headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.URL.Path == "/health" || r.URL.Path == "/" {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","timestamp":%d}`, time.Now().Unix())
		return
	}

	if strings.HasPrefix(r.URL.Path, "/state/") {
		peerID := strings.TrimPrefix(r.URL.Path, "/state/")
		if peerID == "" {
			http.Error(w, "Missing peer_id", http.StatusBadRequest)
			return
		}

		// Check Auth
		if s.token != "" {
			auth := r.Header.Get("Authorization")
			token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer"))
			if token != s.token {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		if r.Method == http.MethodPost {
			var body json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
				return
			}

			s.mu.Lock()
			s.storage[peerID] = CachedState{
				State:   body,
				Expires: time.Now().Add(5 * time.Minute),
			}
			s.mu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"status":"stored","peer_id":%q}`, peerID)
			return
		}

		if r.Method == http.MethodGet {
			s.mu.RLock()
			cached, exists := s.storage[peerID]
			s.mu.RUnlock()

			if !exists || time.Now().After(cached.Expires) {
				http.Error(w, "Peer state not found or expired", http.StatusNotFound)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(cached.State)
			return
		}

		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	http.NotFound(w, r)
}

func main() {
	addr := flag.String("addr", ":8443", "HTTP listen address")
	token := flag.String("token", "", "Pre-shared secret token (enforces Authorization: Bearer <token>)")
	certFile := flag.String("cert", "", "Path to TLS certificate file (optional)")
	keyFile := flag.String("key", "", "Path to TLS private key file (optional)")
	flag.Parse()

	server := NewRelayServer(*token)

	log.Printf("[RELAY] Auto-WG VPS Relay server listening on %s", *addr)
	if *certFile != "" && *keyFile != "" {
		log.Printf("[RELAY] Running with TLS (HTTPS)")
		if err := http.ListenAndServeTLS(*addr, *certFile, *keyFile, server); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	} else {
		log.Printf("[RELAY] Running with plain HTTP (recommended behind Nginx/Caddy/Cloudflare)")
		if err := http.ListenAndServe(*addr, server); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}
}
