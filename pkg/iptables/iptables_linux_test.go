//go:build linux

package iptables

import (
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"auto-wg/pkg/logger"
)

func natRules(t *testing.T, bin string) string {
	t.Helper()
	out, err := exec.Command(bin, "-t", "nat", "-S", "PREROUTING").CombinedOutput()
	if err != nil {
		t.Fatalf("%s -S: %v: %s", bin, err, out)
	}
	return string(out)
}

// Needs root and iptables, so it is skipped everywhere else.
func TestRemoveStaleRulesAgainstRealIptables(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("iptables not installed")
	}
	add := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("iptables", append([]string{"-t", "nat", "-A", "PREROUTING"}, args...)...).CombinedOutput(); err != nil {
			t.Skipf("cannot add test rule: %v: %s", err, out)
		}
	}
	// Leftovers of a previous run: a UDP and a TCP rule, one of a tunnel that no longer exists, and an
	// unrelated rule that must survive.
	add("-p", "udp", "--dport", "20000:30000", "-m", "comment", "--comment", "autowg-wg0", "-j", "REDIRECT", "--to-ports", "20123")
	add("-p", "tcp", "--dport", "443:8443", "-m", "comment", "--comment", "autowg-wg0-tls", "-j", "REDIRECT", "--to-ports", "4430")
	add("-p", "udp", "--dport", "31000:31100", "-m", "comment", "--comment", "autowg-gone", "-j", "REDIRECT", "--to-ports", "31005")
	add("-p", "udp", "--dport", "5300", "-m", "comment", "--comment", "someone-else", "-j", "REDIRECT", "--to-ports", "5353")
	t.Cleanup(func() {
		_ = exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", "5300", "-m", "comment", "--comment", "someone-else", "-j", "REDIRECT", "--to-ports", "5353").Run()
		for _, c := range []string{"autowg-wg0", "autowg-wg0-tls", "autowg-gone"} {
			_ = exec.Command("sh", "-c", "iptables -t nat -S PREROUTING | grep -- '"+c+"' | sed 's/^-A/-D/' | while read r; do iptables -t nat $r; done").Run()
		}
	})

	m := NewManager(logger.New(io.Discard, logger.LevelDebug, 100))
	if !m.isLinux {
		t.Skip("iptables manager unavailable")
	}
	if n := m.RemoveStaleRules(); n < 3 {
		t.Fatalf("expected the three stale rules to be removed, got %d", n)
	}
	rules := natRules(t, "iptables")
	if strings.Contains(rules, "autowg-") {
		t.Fatalf("stale autowg rules survived:\n%s", rules)
	}
	if !strings.Contains(rules, "someone-else") {
		t.Fatalf("an unrelated rule was removed:\n%s", rules)
	}

	// A rule this process manages is left alone, whatever else is swept.
	if err := m.ApplyForwardingRule("wg0", "20000-30000", 20999); err != nil {
		t.Fatal(err)
	}
	add("-p", "udp", "--dport", "40000:40100", "-m", "comment", "--comment", "autowg-old", "-j", "REDIRECT", "--to-ports", "40001")
	if n := m.RemoveStaleRules(); n != 1 {
		t.Fatalf("expected only the stale rule to be removed, got %d", n)
	}
	rules = natRules(t, "iptables")
	if !strings.Contains(rules, "autowg-wg0") || strings.Contains(rules, "autowg-old") {
		t.Fatalf("managed rule must stay, stale one must go:\n%s", rules)
	}
	_ = m.RemoveAllRules()
	if strings.Contains(natRules(t, "iptables"), "autowg-wg0") {
		t.Fatal("RemoveAllRules left the managed rule behind")
	}
}
