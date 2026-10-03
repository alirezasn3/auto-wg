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

type CloudflareSignaler struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

func NewCloudflareSignaler(baseURL, token string, timeout time.Duration) *CloudflareSignaler {
	baseURL = strings.TrimRight(baseURL, "/")
	return &CloudflareSignaler{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

func (c *CloudflareSignaler) Name() string {
	return "CloudflareWorker"
}

func (c *CloudflareSignaler) PublishState(ctx context.Context, state *PeerState) error {
	state.Sign(c.token)

	body, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	url := fmt.Sprintf("%s/state/%s", c.baseURL, state.PeerID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("do post request to %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("cf worker returned error status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (c *CloudflareSignaler) FetchPeerState(ctx context.Context, peerID string) (*PeerState, error) {
	url := fmt.Sprintf("%s/state/%s", c.baseURL, peerID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do get request to %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // No state posted yet
	}
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("cf worker returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var state PeerState
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		return nil, fmt.Errorf("decode peer state: %w", err)
	}

	if !state.Verify(c.token, 60*time.Second) {
		return nil, fmt.Errorf("peer state signature invalid or expired")
	}

	return &state, nil
}

func (c *CloudflareSignaler) IsHealthy(ctx context.Context) bool {
	url := fmt.Sprintf("%s/health", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
