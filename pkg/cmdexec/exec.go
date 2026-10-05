package cmdexec

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"auto-wg/pkg/logger"
)

// RunCommands executes a list of shell commands in order.
// Each command is executed via "/bin/sh -c <command>".
func RunCommands(ctx context.Context, commands []string, phase string, log *logger.Logger) error {
	if len(commands) == 0 {
		return nil
	}

	tag := strings.ToUpper(phase)
	if tag == "" {
		tag = "EXEC"
	}

	for i, cmdStr := range commands {
		cmdStr = strings.TrimSpace(cmdStr)
		if cmdStr == "" || strings.HasPrefix(cmdStr, "#") {
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if log != nil {
			log.Info(tag, "[%d/%d] Executing: %s", i+1, len(commands), cmdStr)
		}

		cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		cmd := exec.CommandContext(cmdCtx, "sh", "-c", cmdStr)
		out, err := cmd.CombinedOutput()
		cancel()

		trimmedOut := strings.TrimSpace(string(out))
		if err != nil {
			if log != nil {
				log.Error(tag, "Command failed: %s (error: %v, output: %s)", cmdStr, err, trimmedOut)
			}
			return fmt.Errorf("command %q failed: %w (output: %s)", cmdStr, err, trimmedOut)
		}

		if trimmedOut != "" && log != nil {
			log.Debug(tag, "Output: %s", trimmedOut)
		}
	}

	return nil
}
