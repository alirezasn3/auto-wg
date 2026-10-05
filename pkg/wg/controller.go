package wg

import (
	"fmt"
	"net"
	"strings"
	"time"

	"auto-wg/pkg/logger"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type DeviceInfo struct {
	Name           string
	Type           string
	PublicKey      string
	ListenPort     int
	PeerPublicKey  string
	PeerEndpoint   string
	PeerEndpointIP string
	PeerPort       int
	PeerAllowedIPs []string
	LastHandshake  time.Time
	HandshakeAge   time.Duration
	TransmitBytes  int64
	ReceiveBytes   int64
}

type Controller struct {
	client *wgctrl.Client
	log    *logger.Logger
}

// NewController creates a pure wgctrl Netlink/UAPI controller.
func NewController(log *logger.Logger) (*Controller, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl initialization failed: %w", err)
	}

	return &Controller{
		client: client,
		log:    log,
	}, nil
}

func (c *Controller) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

func (c *Controller) GetDeviceInfo(ifaceName, targetPeerPubkey string) (*DeviceInfo, error) {
	if c.client == nil {
		return nil, fmt.Errorf("wgctrl client not initialized")
	}

	dev, err := c.client.Device(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("wgctrl query device %s: %w", ifaceName, err)
	}

	info := &DeviceInfo{
		Name:       dev.Name,
		Type:       dev.Type.String(),
		PublicKey:  dev.PublicKey.String(),
		ListenPort: dev.ListenPort,
	}

	for _, p := range dev.Peers {
		keyStr := p.PublicKey.String()
		if targetPeerPubkey == "" || keyStr == targetPeerPubkey {
			info.PeerPublicKey = keyStr
			if p.Endpoint != nil {
				info.PeerEndpoint = p.Endpoint.String()
				info.PeerEndpointIP = p.Endpoint.IP.String()
				info.PeerPort = p.Endpoint.Port
			}
			info.LastHandshake = p.LastHandshakeTime
			if !p.LastHandshakeTime.IsZero() {
				info.HandshakeAge = time.Since(p.LastHandshakeTime)
			}
			info.TransmitBytes = p.TransmitBytes
			info.ReceiveBytes = p.ReceiveBytes
			for _, ipNet := range p.AllowedIPs {
				info.PeerAllowedIPs = append(info.PeerAllowedIPs, ipNet.IP.String())
			}
			break
		}
	}

	return info, nil
}

// UpdateListenPort changes the local WireGuard listen port dynamically via wgctrl.
func (c *Controller) UpdateListenPort(ifaceName string, port int) error {
	c.log.Info("WG", "Updating local listen port on %s to %d", ifaceName, port)

	if c.client == nil {
		return fmt.Errorf("wgctrl client not initialized")
	}

	cfg := wgtypes.Config{
		ListenPort: &port,
	}
	if err := c.client.ConfigureDevice(ifaceName, cfg); err != nil {
		return fmt.Errorf("wgctrl ConfigureDevice listen-port failed: %w", err)
	}
	return nil
}

// NormalizeEndpoint ensures IPv6 endpoints have enclosing brackets [ipv6]:port.
func NormalizeEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return endpoint
	}
	// If it contains multiple colons and no brackets, it's an unbracketed IPv6:port
	if strings.Count(endpoint, ":") > 1 && !strings.Contains(endpoint, "[") {
		lastColon := strings.LastIndex(endpoint, ":")
		if lastColon != -1 {
			host := endpoint[:lastColon]
			port := endpoint[lastColon+1:]
			return net.JoinHostPort(host, port)
		}
	}
	return endpoint
}

// UpdatePeerEndpoint updates the remote endpoint of the target peer via wgctrl.
func (c *Controller) UpdatePeerEndpoint(ifaceName, peerPubKey, endpoint string) error {
	endpoint = NormalizeEndpoint(endpoint)
	c.log.Info("WG", "Updating peer %s endpoint on %s to %s", peerPubKey, ifaceName, endpoint)

	if c.client == nil {
		return fmt.Errorf("wgctrl client not initialized")
	}

	pubKey, err := wgtypes.ParseKey(peerPubKey)
	if err != nil {
		return fmt.Errorf("parse peer public key: %w", err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return fmt.Errorf("resolve endpoint %s: %w", endpoint, err)
	}

	peerCfg := wgtypes.PeerConfig{
		PublicKey:  pubKey,
		UpdateOnly: true,
		Endpoint:   udpAddr,
	}

	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerCfg},
	}

	if err := c.client.ConfigureDevice(ifaceName, cfg); err != nil {
		return fmt.Errorf("wgctrl ConfigureDevice peer endpoint failed: %w", err)
	}
	return nil
}
