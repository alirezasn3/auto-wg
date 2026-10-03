package signaling

import (
	"context"
	"fmt"
	"sync"
	"time"

	"auto-wg/pkg/config"
	"auto-wg/pkg/logger"
)

type BackendStatus struct {
	Name      string    `json:"name"`
	Enabled   bool      `json:"enabled"`
	Healthy   bool      `json:"healthy"`
	LatencyMs int64     `json:"latency_ms"`
	LastCheck time.Time `json:"last_check"`
	LastError string    `json:"last_error,omitempty"`
}

type CompositeSignaler struct {
	backends []Signaler
	statuses map[string]*BackendStatus
	mu       sync.RWMutex
	log      *logger.Logger
}

func NewCompositeSignaler(cfg *config.Config, log *logger.Logger) *CompositeSignaler {
	cs := &CompositeSignaler{
		backends: make([]Signaler, 0),
		statuses: make(map[string]*BackendStatus),
		log:      log,
	}

	timeout := cfg.Signaling.Timeout

	// 1. Cloudflare Worker backend
	if cfg.Signaling.Cloudflare.Enabled && cfg.Signaling.Cloudflare.URL != "" {
		cf := NewCloudflareSignaler(cfg.Signaling.Cloudflare.URL, cfg.Signaling.SecretToken, timeout)
		cs.backends = append(cs.backends, cf)
		cs.statuses[cf.Name()] = &BackendStatus{Name: cf.Name(), Enabled: true}
		log.Info("SIGNAL", "Registered signaling backend: %s (%s)", cf.Name(), cfg.Signaling.Cloudflare.URL)
	}

	// 2. VPS Relay backend
	if cfg.Signaling.VPSRelay.Enabled && cfg.Signaling.VPSRelay.URL != "" {
		relay := NewVPSRelaySignaler(cfg.Signaling.VPSRelay.URL, cfg.Signaling.SecretToken, timeout)
		cs.backends = append(cs.backends, relay)
		cs.statuses[relay.Name()] = &BackendStatus{Name: relay.Name(), Enabled: true}
		log.Info("SIGNAL", "Registered signaling backend: %s (%s)", relay.Name(), cfg.Signaling.VPSRelay.URL)
	}

	// 3. Direct P2P backend
	if cfg.Signaling.Direct.Enabled {
		direct := NewDirectSignaler(cfg.Signaling.Direct.ListenAddr, cfg.Signaling.Direct.RemoteAddr, cfg.Signaling.SecretToken, timeout)
		cs.backends = append(cs.backends, direct)
		cs.statuses[direct.Name()] = &BackendStatus{Name: direct.Name(), Enabled: true}
		log.Info("SIGNAL", "Registered signaling backend: %s (remote: %s)", direct.Name(), cfg.Signaling.Direct.RemoteAddr)
	}

	// Run periodic health checker in background
	go cs.healthCheckLoop()

	return cs
}

func (c *CompositeSignaler) Name() string {
	return "Composite"
}

// PublishState sends state to all enabled backends so any working channel has the latest state.
func (c *CompositeSignaler) PublishState(ctx context.Context, state *PeerState) error {
	if len(c.backends) == 0 {
		return fmt.Errorf("no signaling backends configured")
	}

	var wg sync.WaitGroup
	var successCount int
	var countMu sync.Mutex
	var lastErr error

	for _, backend := range c.backends {
		wg.Add(1)
		go func(b Signaler) {
			defer wg.Done()
			err := b.PublishState(ctx, state)
			countMu.Lock()
			defer countMu.Unlock()
			if err != nil {
				c.log.Warn("SIGNAL", "Publish to %s failed: %v", b.Name(), err)
				lastErr = err
			} else {
				successCount++
			}
		}(backend)
	}

	wg.Wait()

	if successCount == 0 {
		return fmt.Errorf("all signaling backends failed to publish state, last error: %w", lastErr)
	}

	c.log.Debug("SIGNAL", "Published state (role: %s, epoch: %d) successfully to %d/%d backends",
		state.Role, state.Epoch, successCount, len(c.backends))
	return nil
}

// FetchPeerState queries backends and returns the newest valid PeerState.
func (c *CompositeSignaler) FetchPeerState(ctx context.Context, peerID string) (*PeerState, error) {
	if len(c.backends) == 0 {
		return nil, fmt.Errorf("no signaling backends configured")
	}

	var bestState *PeerState
	var bestTimestamp int64

	for _, backend := range c.backends {
		st, err := backend.FetchPeerState(ctx, peerID)
		if err != nil {
			c.log.Debug("SIGNAL", "Fetch from %s: %v", backend.Name(), err)
			continue
		}
		if st != nil && st.Timestamp > bestTimestamp {
			bestTimestamp = st.Timestamp
			bestState = st
		}
	}

	return bestState, nil
}

func (c *CompositeSignaler) IsHealthy(ctx context.Context) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, st := range c.statuses {
		if st.Enabled && st.Healthy {
			return true
		}
	}
	return false
}

func (c *CompositeSignaler) GetStatuses() []BackendStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]BackendStatus, 0, len(c.statuses))
	for _, st := range c.statuses {
		result = append(result, *st)
	}
	return result
}

func (c *CompositeSignaler) healthCheckLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	checkAll := func() {
		for _, b := range c.backends {
			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			healthy := b.IsHealthy(ctx)
			cancel()
			dur := time.Since(start).Milliseconds()

			c.mu.Lock()
			st := c.statuses[b.Name()]
			if st != nil {
				st.Healthy = healthy
				st.LatencyMs = dur
				st.LastCheck = time.Now()
			}
			c.mu.Unlock()
		}
	}

	checkAll()
	for range ticker.C {
		checkAll()
	}
}
