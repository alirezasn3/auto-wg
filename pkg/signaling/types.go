package signaling

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

type PeerRole string

const (
	RoleIdle        PeerRole = "idle"
	RoleHunting     PeerRole = "hunting"
	RoleProbing     PeerRole = "probing"
	RoleProbeResult PeerRole = "probe_result"
	RoleAgreed      PeerRole = "agreed"
)

type PeerState struct {
	PeerID       string   `json:"peer_id"`
	Role         PeerRole `json:"role"`
	Epoch        int64    `json:"epoch"`
	Timestamp    int64    `json:"timestamp"`
	CurrentPort  int      `json:"current_port"`
	LocalListen  int      `json:"local_listen"`
	WorkingPorts []int    `json:"working_ports,omitempty"`
	Signature    string   `json:"signature"`
}

// Sign calculates HMAC-SHA256 over canonical fields using the shared secret.
func (s *PeerState) Sign(secret string) {
	s.Timestamp = time.Now().Unix()
	payload := fmt.Sprintf("%s:%s:%d:%d:%d:%d:%v", s.PeerID, s.Role, s.Epoch, s.Timestamp, s.CurrentPort, s.LocalListen, s.WorkingPorts)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	s.Signature = hex.EncodeToString(mac.Sum(nil))
}

// Verify checks the HMAC-SHA256 signature against the shared secret.
func (s *PeerState) Verify(secret string, maxAge time.Duration) bool {
	if s.Signature == "" {
		return false
	}
	if maxAge > 0 && time.Since(time.Unix(s.Timestamp, 0)) > maxAge {
		return false
	}
	payload := fmt.Sprintf("%s:%s:%d:%d:%d:%d:%v", s.PeerID, s.Role, s.Epoch, s.Timestamp, s.CurrentPort, s.LocalListen, s.WorkingPorts)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(s.Signature), []byte(expected))
}

// Signaler defines the interface that all signaling backends must implement.
type Signaler interface {
	Name() string
	PublishState(ctx context.Context, state *PeerState) error
	FetchPeerState(ctx context.Context, peerID string) (*PeerState, error)
	IsHealthy(ctx context.Context) bool
}
