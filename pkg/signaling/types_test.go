package signaling

import (
	"testing"
	"time"
)

func TestPeerStateSigningAndVerification(t *testing.T) {
	secret := "secret-key-12345"
	state := &PeerState{
		PeerID:       "peer-a",
		Role:         RoleHunting,
		Epoch:        101,
		CurrentPort:  51820,
		LocalListen:  443,
		WorkingPorts: []int{53, 80, 443},
	}

	state.Sign(secret)

	if state.Signature == "" {
		t.Fatal("expected non-empty signature")
	}

	// Verify valid signature
	if !state.Verify(secret, 10*time.Second) {
		t.Fatal("expected signature verification to succeed")
	}

	// Verify wrong secret fails
	if state.Verify("wrong-secret", 10*time.Second) {
		t.Fatal("expected verification with wrong secret to fail")
	}

	// Verify tampered state fails
	state.CurrentPort = 8080
	if state.Verify(secret, 10*time.Second) {
		t.Fatal("expected verification of tampered payload to fail")
	}
}
