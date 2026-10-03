package wg

import (
	"testing"
)

func TestNormalizeEndpoint(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// IPv4
		{"198.51.100.1:51820", "198.51.100.1:51820"},
		{"127.0.0.1:20000", "127.0.0.1:20000"},
		{"example.com:51820", "example.com:51820"},

		// IPv6 without brackets (the user's reported bug)
		{"2a10:ed40:6:3:20c:29ff:fe6b:7325:20684", "[2a10:ed40:6:3:20c:29ff:fe6b:7325]:20684"},
		{"::1:51820", "[::1]:51820"},
		{"fe80::1:12345", "[fe80::1]:12345"},

		// IPv6 already with brackets
		{"[2a10:ed40:6:3:20c:29ff:fe6b:7325]:20684", "[2a10:ed40:6:3:20c:29ff:fe6b:7325]:20684"},
		{"[::1]:51820", "[::1]:51820"},

		// Whitespace
		{"  [2a10:ed40:6:3:20c:29ff:fe6b:7325]:20684  ", "[2a10:ed40:6:3:20c:29ff:fe6b:7325]:20684"},
		{"", ""},
	}

	for _, tt := range tests {
		res := NormalizeEndpoint(tt.input)
		if res != tt.expected {
			t.Errorf("NormalizeEndpoint(%q) = %q, expected %q", tt.input, res, tt.expected)
		}
	}
}
