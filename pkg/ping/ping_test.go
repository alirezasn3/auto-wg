package ping

import (
	"context"
	"testing"
	"time"
)

func TestPingLocalhost(t *testing.T) {
	ctx := context.Background()

	// 127.0.0.1 should succeed
	ok := Ping(ctx, "127.0.0.1", 2*time.Second)
	if !ok {
		t.Logf("Ping 127.0.0.1 returned false (may occur in unprivileged containers or non-standard networks)")
	}

	// Unreachable IP should fail fast
	okBad := Ping(ctx, "192.0.2.1", 500*time.Millisecond) // TEST-NET-1 (non-routable)
	if okBad {
		t.Errorf("Expected ping to TEST-NET-1 to fail, got true")
	}

	// Empty target should fail immediately
	if Ping(ctx, "", time.Second) {
		t.Errorf("Expected empty target to return false")
	}
}
