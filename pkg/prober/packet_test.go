package prober

import (
	"testing"
)

func TestBuildAndVerifyProbePacket(t *testing.T) {
	peerID := "peer-test"
	secret := "probe-secret-token-xyz"

	pkt, err := BuildProbePacket(peerID, secret)
	if err != nil {
		t.Fatalf("BuildProbePacket failed: %v", err)
	}

	if len(pkt) != ProbePacketLen {
		t.Fatalf("expected packet length %d, got %d", ProbePacketLen, len(pkt))
	}

	// Verify valid packet
	extractedPeerID, err := ParseAndVerifyProbePacket(pkt, secret)
	if err != nil {
		t.Fatalf("ParseAndVerifyProbePacket failed: %v", err)
	}

	if extractedPeerID != peerID {
		t.Fatalf("expected peerID %q, got %q", peerID, extractedPeerID)
	}

	// Verify wrong secret fails
	_, err = ParseAndVerifyProbePacket(pkt, "wrong-secret")
	if err == nil {
		t.Fatal("expected error with wrong secret, got nil")
	}

	// Verify corrupted magic fails
	corrupted := make([]byte, len(pkt))
	copy(corrupted, pkt)
	corrupted[0] = 'X'
	_, err = ParseAndVerifyProbePacket(corrupted, secret)
	if err == nil {
		t.Fatal("expected error with corrupted magic, got nil")
	}
}
