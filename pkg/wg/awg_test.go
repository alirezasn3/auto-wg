package wg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"auto-wg/pkg/logger"
)

const (
	peerA = "wCBzxSQCNMXB+7zQ9QmZUrAdoiMm3bAfNF/NZ0F+bBk="
	peerB = "Nv7mWxoUbkhFmj0IzoXLhvsJ1Jt7mFxNQ8GzPpkQ1Ao="
)

// An AmneziaWG 2.x header line: private key, public key, listen port, then a long, release
// dependent run of obfuscation columns and finally the fwmark.
var awgDump = strings.Join([]string{
	strings.Join([]string{"PRIVATEKEY=", "IFACEPUB=", "43210", "6", "40", "120", "50", "90", "30", "8",
		"1000-2000", "3000-4000", "5000-6000", "7000-8000", "(null)", "(null)", "(null)", "(null)", "(null)",
		"(none)", "0-0", "0-0", "0-0", "0-0", "0-0", "0-0", "off", "off", "off"}, "\t"),
	strings.Join([]string{peerA, "(none)", "203.0.113.7:24800", "10.100.0.1/32,10.200.0.0/16", "1700000000", "1234", "5678", "25"}, "\t"),
	strings.Join([]string{peerB, "(none)", "[2001:db8::2]:25001", "(none)", "0", "0", "0", "off"}, "\t"),
}, "\n") + "\n"

func TestParseAWGDump(t *testing.T) {
	now := time.Unix(1700000030, 0)
	info, err := parseAWGDump("wgBridge0", awgDump, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if info.Type != "amneziawg" || info.PublicKey != "IFACEPUB=" || info.ListenPort != 43210 {
		t.Fatalf("bad interface fields: %+v", info)
	}
	if info.PeerPublicKey != peerA || info.PeerEndpoint != "203.0.113.7:24800" || info.PeerEndpointIP != "203.0.113.7" || info.PeerPort != 24800 {
		t.Fatalf("bad peer endpoint: %+v", info)
	}
	if len(info.PeerAllowedIPs) != 2 || info.PeerAllowedIPs[0] != "10.100.0.1" || info.PeerAllowedIPs[1] != "10.200.0.0" {
		t.Fatalf("bad allowed ips: %v", info.PeerAllowedIPs)
	}
	if info.HandshakeAge != 30*time.Second || info.ReceiveBytes != 1234 || info.TransmitBytes != 5678 {
		t.Fatalf("bad stats: age=%v rx=%d tx=%d", info.HandshakeAge, info.ReceiveBytes, info.TransmitBytes)
	}

	info, err = parseAWGDump("wgBridge0", awgDump, peerB, now)
	if err != nil {
		t.Fatal(err)
	}
	if info.PeerPublicKey != peerB || info.PeerEndpoint != "[2001:db8::2]:25001" || info.PeerEndpointIP != "2001:db8::2" {
		t.Fatalf("bad ipv6 peer: %+v", info)
	}
	if !info.LastHandshake.IsZero() || info.HandshakeAge != 0 || len(info.PeerAllowedIPs) != 0 {
		t.Fatalf("peer that never handshook should have zero values: %+v", info)
	}

	info, err = parseAWGDump("wgBridge0", awgDump, "unknown=", now)
	if err != nil || info.PeerPublicKey != "" {
		t.Fatalf("unknown peer must leave peer fields empty, got %+v err=%v", info, err)
	}
}

func TestParseAWGDumpLegacyHeaderAndErrors(t *testing.T) {
	// A WireGuard/AmneziaWG 1.0 style interface with no peers.
	info, err := parseAWGDump("wg0", "PRIV=\tPUB=\t51820\toff\n", "", time.Now())
	if err != nil || info.ListenPort != 51820 || info.PeerPublicKey != "" {
		t.Fatalf("legacy header: %+v err=%v", info, err)
	}
	if _, err := parseAWGDump("wg0", "garbage\n", "", time.Now()); err == nil {
		t.Error("short header must fail")
	}
	if _, err := parseAWGDump("wg0", "PRIV=\tPUB=\tnotaport\n", "", time.Now()); err == nil {
		t.Error("bad port must fail")
	}
}

// fakeAWG writes a shell script that records its arguments and prints awgDump for `show ... dump`.
func fakeAWG(t *testing.T) (bin, calls string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "awg")
	calls = filepath.Join(dir, "calls")
	dumpFile := filepath.Join(dir, "dump")
	if err := os.WriteFile(dumpFile, []byte(awgDump), 0600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\necho \"$@\" >> '" + calls + "'\n" +
		"if [ \"$1\" = show ] && [ \"$3\" = dump ]; then cat '" + dumpFile + "'; exit 0; fi\n" +
		"if [ \"$1\" = fail ]; then echo boom >&2; exit 3; fi\n" +
		"exit 0\n"
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return bin, calls
}

func readCalls(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func TestAWGControllerCommands(t *testing.T) {
	bin, calls := fakeAWG(t)
	c := NewAWGController(logger.Default(), bin)

	if err := c.Available(); err != nil {
		t.Fatal(err)
	}
	info, err := c.GetDeviceInfo("wgBridge0", peerA)
	if err != nil || info.ListenPort != 43210 {
		t.Fatalf("GetDeviceInfo: %+v err=%v", info, err)
	}

	if err := c.UpdateListenPort("wgBridge0", 24123); err != nil {
		t.Fatal(err)
	}
	if err := c.UpdatePeerEndpoint("wgBridge0", peerA, "198.51.100.9:24999"); err != nil {
		t.Fatal(err)
	}
	if err := c.UpdatePeerEndpoint("wgBridge0", peerA, "2001:db8::5:24999"); err != nil {
		t.Fatal(err)
	}

	got := readCalls(t, calls)
	want := []string{
		"show wgBridge0 dump",
		"set wgBridge0 listen-port 24123",
		"show wgBridge0 dump",
		"set wgBridge0 peer " + peerA + " endpoint 198.51.100.9:24999",
		"show wgBridge0 dump",
		"set wgBridge0 peer " + peerA + " endpoint [2001:db8::5]:24999",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected awg invocations:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestAWGControllerRefusesToCreatePeers(t *testing.T) {
	bin, calls := fakeAWG(t)
	c := NewAWGController(logger.Default(), bin)
	if err := c.UpdatePeerEndpoint("wgBridge0", "NotAPeer=", "198.51.100.9:24999"); err == nil {
		t.Fatal("unknown peer must be rejected")
	}
	for _, line := range readCalls(t, calls) {
		if strings.HasPrefix(line, "set ") {
			t.Fatalf("awg set must not run for an unknown peer: %s", line)
		}
	}
}

func TestAWGControllerErrors(t *testing.T) {
	c := NewAWGController(logger.Default(), filepath.Join(t.TempDir(), "missing-awg"))
	if err := c.Available(); err == nil {
		t.Error("missing binary must be reported")
	}
	if _, err := c.GetDeviceInfo("wg0", ""); err == nil {
		t.Error("GetDeviceInfo must fail without the binary")
	}

	bin, _ := fakeAWG(t)
	c = NewAWGController(logger.Default(), bin)
	if _, err := c.run("fail"); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("stderr should be part of the error, got %v", err)
	}

	var nilCtrl *AWGController
	if _, err := nilCtrl.GetDeviceInfo("wg0", ""); err == nil {
		t.Error("nil controller must return an error, not panic")
	}
}
