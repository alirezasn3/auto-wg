package logger

import (
	"bytes"
	"testing"
	"time"
)

func TestLoggerRingBufferAndSubscription(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelDebug, 5)

	ch, unsub := l.Subscribe()
	defer unsub()

	for i := 0; i < 7; i++ {
		l.Info("TEST", "Message %d", i)
	}

	entries := l.GetRecentEntries()
	if len(entries) != 5 {
		t.Fatalf("expected 5 buffered entries, got %d", len(entries))
	}

	if entries[0].Message != "Message 2" {
		t.Errorf("expected oldest buffered message to be 'Message 2', got %q", entries[0].Message)
	}

	// Verify subscriber received events
	select {
	case entry := <-ch:
		if entry.Component != "TEST" {
			t.Errorf("expected component TEST, got %s", entry.Component)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("subscriber channel timed out")
	}
}
