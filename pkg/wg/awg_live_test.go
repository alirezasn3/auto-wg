package wg

import (
	"net"
	"os"
	"strconv"
	"testing"

	"auto-wg/pkg/logger"
)

// TestAWGControllerLive drives a real AmneziaWG interface. It needs the awg tool, root and an interface
// that has completed a handshake, so it only runs when AWG_TEST_IFACE and AWG_TEST_PEER are set.
func TestAWGControllerLive(t *testing.T) {
	iface, peer := os.Getenv("AWG_TEST_IFACE"), os.Getenv("AWG_TEST_PEER")
	if iface == "" || peer == "" {
		t.Skip("set AWG_TEST_IFACE and AWG_TEST_PEER to run against a live AmneziaWG interface")
	}
	c := NewAWGController(logger.Default(), "")
	if err := c.Available(); err != nil {
		t.Fatal(err)
	}

	info, err := c.GetDeviceInfo(iface, peer)
	if err != nil {
		t.Fatal(err)
	}
	if info.PublicKey == "" || info.ListenPort == 0 || info.PeerPublicKey != peer || info.PeerEndpoint == "" {
		t.Fatalf("incomplete device info: %+v", info)
	}
	if info.LastHandshake.IsZero() || info.ReceiveBytes == 0 || info.TransmitBytes == 0 {
		t.Fatalf("expected a completed handshake with traffic: %+v", info)
	}
	t.Logf("device: %+v", info)

	oldPort := info.ListenPort
	if err := c.UpdateListenPort(iface, oldPort+10); err != nil {
		t.Fatal(err)
	}
	if got, _ := c.GetDeviceInfo(iface, peer); got == nil || got.ListenPort != oldPort+10 {
		t.Fatalf("listen port not changed: %+v", got)
	}

	newEndpoint := net.JoinHostPort(info.PeerEndpointIP, strconv.Itoa(info.PeerPort+7))
	if err := c.UpdatePeerEndpoint(iface, peer, newEndpoint); err != nil {
		t.Fatal(err)
	}
	if got, _ := c.GetDeviceInfo(iface, peer); got == nil || got.PeerEndpoint != newEndpoint {
		t.Fatalf("endpoint not changed: %+v", got)
	}

	if err := c.UpdatePeerEndpoint(iface, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", newEndpoint); err == nil {
		t.Fatal("an unknown peer must not be created")
	}
}
