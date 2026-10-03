package signaling

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

type DirectSignaler struct {
	listenAddr string
	remoteAddr string
	token      string
	httpClient *http.Client
	server     *http.Server
	mu         sync.RWMutex
	lastState  map[string]*PeerState
}

func NewDirectSignaler(listenAddr, remoteAddr, token string, timeout time.Duration) *DirectSignaler {
	d := &DirectSignaler{
		listenAddr: listenAddr,
		remoteAddr: remoteAddr,
		token:      token,
		httpClient: &http.Client{Timeout: timeout},
		lastState:  make(map[string]*PeerState),
	}
	if listenAddr != "" {
		d.startServer()
	}
	return d
}

func (d *DirectSignaler) startServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/direct-state", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+d.token {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPost {
			var state PeerState
			if err := json.NewDecoder(r.Body).Decode(&state); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !state.Verify(d.token, 60*time.Second) {
				http.Error(w, "Invalid signature", http.StatusForbidden)
				return
			}
			d.mu.Lock()
			d.lastState[state.PeerID] = &state
			d.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodGet {
			peerID := r.URL.Query().Get("peer_id")
			d.mu.RLock()
			st, exists := d.lastState[peerID]
			d.mu.RUnlock()
			if !exists {
				http.Error(w, "Not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(st)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	d.server = &http.Server{
		Addr:    d.listenAddr,
		Handler: mux,
	}

	go func() {
		_ = d.server.ListenAndServe()
	}()
}

func (d *DirectSignaler) Close() error {
	if d.server != nil {
		return d.server.Close()
	}
	return nil
}

func (d *DirectSignaler) Name() string {
	return "DirectP2P"
}

func (d *DirectSignaler) PublishState(ctx context.Context, state *PeerState) error {
	if d.remoteAddr == "" {
		return fmt.Errorf("direct signaling remote address not configured")
	}

	state.Sign(d.token)
	body, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	url := fmt.Sprintf("http://%s/direct-state", d.remoteAddr)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create direct request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+d.token)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("direct post to %s failed: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("direct peer returned error %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (d *DirectSignaler) FetchPeerState(ctx context.Context, peerID string) (*PeerState, error) {
	// First check local in-memory store (state pushed directly by peer)
	d.mu.RLock()
	st, exists := d.lastState[peerID]
	d.mu.RUnlock()
	if exists && st.Verify(d.token, 60*time.Second) {
		return st, nil
	}

	// Otherwise, attempt pull from remoteAddr
	if d.remoteAddr == "" {
		return nil, nil
	}

	url := fmt.Sprintf("http://%s/direct-state?peer_id=%s", d.remoteAddr, peerID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create direct request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+d.token)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("direct pull from %s failed: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("direct peer returned error %d: %s", resp.StatusCode, string(respBody))
	}

	var state PeerState
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		return nil, fmt.Errorf("decode direct peer state: %w", err)
	}

	if !state.Verify(d.token, 60*time.Second) {
		return nil, fmt.Errorf("direct peer state signature invalid or expired")
	}

	return &state, nil
}

func (d *DirectSignaler) IsHealthy(ctx context.Context) bool {
	if d.remoteAddr == "" {
		return false
	}
	conn, err := net.DialTimeout("tcp", d.remoteAddr, 1500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
