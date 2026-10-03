package ping

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Ping sends a single ICMP echo packet to target and returns true if it responds within timeout.
func Ping(ctx context.Context, target string, timeout time.Duration) bool {
	target = strings.TrimSpace(target)
	target = strings.TrimPrefix(target, "[")
	target = strings.TrimSuffix(target, "]")
	if target == "" {
		return false
	}

	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	pCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var cmd *exec.Cmd
	isIPv6 := strings.Contains(target, ":")

	if runtime.GOOS == "darwin" {
		if isIPv6 {
			cmd = exec.CommandContext(pCtx, "ping6", "-c", "1", "-W", "1000", target)
		} else {
			cmd = exec.CommandContext(pCtx, "ping", "-c", "1", "-W", "1000", target)
		}
	} else {
		// Linux
		if isIPv6 {
			cmd = exec.CommandContext(pCtx, "ping", "-6", "-c", "1", "-W", "1", target)
		} else {
			cmd = exec.CommandContext(pCtx, "ping", "-4", "-c", "1", "-W", "1", target)
		}
	}

	err := cmd.Run()
	if err != nil && isIPv6 && runtime.GOOS != "darwin" {
		// Fallback to ping6 executable on systems where ping doesn't support -6
		pCtx2, cancel2 := context.WithTimeout(ctx, timeout)
		defer cancel2()
		cmd2 := exec.CommandContext(pCtx2, "ping6", "-c", "1", "-W", "1", target)
		return cmd2.Run() == nil
	}

	return err == nil
}
