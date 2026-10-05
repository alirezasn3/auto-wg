package cmdexec

import (
	"context"
	"io"
	"testing"

	"auto-wg/pkg/logger"
)

func TestRunCommandsSuccess(t *testing.T) {
	log := logger.New(io.Discard, logger.LevelDebug, 50)
	cmds := []string{
		"echo hello",
		"# this is a comment",
		"",
		"echo world",
	}

	err := RunCommands(context.Background(), cmds, "postup", log)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

func TestRunCommandsFailure(t *testing.T) {
	log := logger.New(io.Discard, logger.LevelDebug, 50)
	cmds := []string{
		"exit 1",
	}

	err := RunCommands(context.Background(), cmds, "predown", log)
	if err == nil {
		t.Fatalf("expected failure, got nil")
	}
}
