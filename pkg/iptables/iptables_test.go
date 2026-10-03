package iptables

import (
	"testing"
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
