package signaling

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type VPSRelaySignaler struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

func NewVPSRelaySignaler(baseURL, token string, timeout time.Duration) *VPSRelaySignaler {
	baseURL = strings.TrimRight(baseURL, "/")
	return &VPSRelaySignaler{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

func (r *VPSRelaySignaler) Name() string {
	return "VPSRelay"
}

func (r *VPSRelaySignaler) PublishState(ctx context.Context, state *PeerState) error {
	state.Sign(r.token)

	body, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	url := fmt.Sprintf("%s/state/%s", r.baseURL, state.PeerID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.token)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("do post request to %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vps relay returned error status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (r *VPSRelaySignaler) FetchPeerState(ctx context.Context, peerID string) (*PeerState, error) {
	url := fmt.Sprintf("%s/state/%s", r.baseURL, peerID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+r.token)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do get request to %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("vps relay returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var state PeerState
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		return nil, fmt.Errorf("decode peer state: %w", err)
	}

	if !state.Verify(r.token, 60*time.Second) {
		return nil, fmt.Errorf("peer state signature invalid or expired")
	}

	return &state, nil
}

func (r *VPSRelaySignaler) IsHealthy(ctx context.Context) bool {
	url := fmt.Sprintf("%s/health", r.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
