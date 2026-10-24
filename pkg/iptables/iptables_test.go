package iptables

import (
	"io"
	"strings"
	"testing"

	"auto-wg/pkg/logger"
)

func TestFormatIptablesPortRange(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{"20000-30000", "20000:30000", false},
		{"20000:30000", "20000:30000", false},
		{"  5000 - 6000 ", "5000:6000", false},
		{"30000-20000", "", true},
		{"invalid", "", true},
		{"0-100", "", true},
		{"100-70000", "", true},
	}

	for _, tt := range tests {
		res, err := FormatIptablesPortRange(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("FormatIptablesPortRange(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && res != tt.expected {
			t.Errorf("FormatIptablesPortRange(%q) = %q, expected %q", tt.input, res, tt.expected)
		}
	}
}

func TestStaleRuleSpec(t *testing.T) {
	cases := []struct {
		line     string
		wantKey  string
		wantSpec string
		ok       bool
	}{
		{`-A PREROUTING -p udp -m udp --dport 20000:30000 -m comment --comment autowg-wg0 -j REDIRECT --to-ports 20123`, "wg0", `-p udp -m udp --dport 20000:30000 -m comment --comment autowg-wg0 -j REDIRECT --to-ports 20123`, true},
		{`-A PREROUTING -p tcp -m tcp --dport 443:8443 -m comment --comment "autowg-wg0-tls" -j REDIRECT --to-ports 4430`, "wg0-tls", `-p tcp -m tcp --dport 443:8443 -m comment --comment autowg-wg0-tls -j REDIRECT --to-ports 4430`, true},
		{`-A PREROUTING -p udp --dport 53 -m comment --comment other-service -j REDIRECT --to-ports 5353`, "", "", false},
		{`-A PREROUTING -p udp --dport 1000 -j REDIRECT --to-ports 1001`, "", "", false},
		{`-P PREROUTING ACCEPT`, "", "", false},
		{`-A POSTROUTING -m comment --comment autowg-wg0 -j MASQUERADE`, "", "", false},
		{``, "", "", false},
	}
	for _, c := range cases {
		spec, key, ok := staleRuleSpec(c.line)
		if ok != c.ok || key != c.wantKey || strings.Join(spec, " ") != c.wantSpec {
			t.Errorf("staleRuleSpec(%q) = (%q, %q, %v), want (%q, %q, %v)", c.line, strings.Join(spec, " "), key, ok, c.wantSpec, c.wantKey, c.ok)
		}
	}
}

func TestRemoveStaleRulesWithoutIptablesIsANoop(t *testing.T) {
	m := &Manager{log: logger.New(io.Discard, logger.LevelDebug, 10), activeRules: map[string][]string{}}
	if n := m.RemoveStaleRules(); n != 0 {
		t.Fatalf("expected 0 on a system without iptables, got %d", n)
	}
}
