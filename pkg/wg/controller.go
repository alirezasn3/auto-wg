package wg

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
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
	LastHandshake  time.Time
	HandshakeAge   time.Duration
	TransmitBytes  int64
	ReceiveBytes   int64
}

type Controller struct {
	mode       string // "wgctrl" or "cli" / "awg"
	command    string // "wg" or "awg"
	client     *wgctrl.Client
	log        *logger.Logger
}

func NewController(mode, command string, log *logger.Logger) (*Controller, error) {
	if mode == "" {
		mode = "wgctrl"
	}
	if command == "" {
		command = "wg"
	}

	var client *wgctrl.Client
	var err error

	if mode == "wgctrl" {
		client, err = wgctrl.New()
		if err != nil {
			log.Warn("WG", "wgctrl initialization failed (%v); falling back to CLI (%s)", err, command)
			mode = "cli"
		}
	}

	return &Controller{
		mode:    mode,
		command: command,
		client:  client,
		log:     log,
	}, nil
}

func (c *Controller) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

func (c *Controller) GetDeviceInfo(ifaceName, targetPeerPubkey string) (*DeviceInfo, error) {
	if c.mode == "wgctrl" && c.client != nil {
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
				break
			}
		}

		return info, nil
	}

	// CLI fallback (works with wg or awg)
	return c.getDeviceInfoCLI(ifaceName, targetPeerPubkey)
}

func (c *Controller) getDeviceInfoCLI(ifaceName, targetPeerPubkey string) (*DeviceInfo, error) {
	cmd := exec.Command(c.command, "show", ifaceName, "dump")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("exec %s show %s: %w", c.command, ifaceName, err)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty output from %s show %s", c.command, ifaceName)
	}

	// Line 0: Interface info (private_key, public_key, listen_port, fwmark)
	ifaceFields := strings.Fields(lines[0])
	listenPort := 0
	pubKey := ""
	if len(ifaceFields) >= 3 {
		pubKey = ifaceFields[1]
		listenPort, _ = strconv.Atoi(ifaceFields[2])
	}

	info := &DeviceInfo{
		Name:       ifaceName,
		Type:       c.command,
		PublicKey:  pubKey,
		ListenPort: listenPort,
	}

	// Subsequent lines: Peer info (public_key, preshared_key, endpoint, allowed_ips, latest_handshake, transfer_rx, transfer_tx, persistent_keepalive)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) >= 7 {
			peerKey := fields[0]
			if targetPeerPubkey == "" || peerKey == targetPeerPubkey {
				info.PeerPublicKey = peerKey
				info.PeerEndpoint = fields[2]
				if fields[2] != "(none)" && fields[2] != "" {
					host, portStr, err := net.SplitHostPort(fields[2])
					if err == nil {
						info.PeerEndpointIP = host
						p, _ := strconv.Atoi(portStr)
						info.PeerPort = p
					}
				}
				hsUnix, _ := strconv.ParseInt(fields[4], 10, 64)
				if hsUnix > 0 {
					info.LastHandshake = time.Unix(hsUnix, 0)
					info.HandshakeAge = time.Since(info.LastHandshake)
				}
				rx, _ := strconv.ParseInt(fields[5], 10, 64)
				tx, _ := strconv.ParseInt(fields[6], 10, 64)
				info.ReceiveBytes = rx
				info.TransmitBytes = tx
				break
			}
		}
	}

	return info, nil
}

// UpdateListenPort changes the local WireGuard listen port dynamically.
func (c *Controller) UpdateListenPort(ifaceName string, port int) error {
	c.log.Info("WG", "Updating local listen port on %s to %d", ifaceName, port)

	if c.mode == "wgctrl" && c.client != nil {
		cfg := wgtypes.Config{
			ListenPort: &port,
		}
		if err := c.client.ConfigureDevice(ifaceName, cfg); err != nil {
			c.log.Warn("WG", "wgctrl ConfigureDevice failed: %v, trying CLI fallback", err)
			return c.updateListenPortCLI(ifaceName, port)
		}
		return nil
	}

	return c.updateListenPortCLI(ifaceName, port)
}

func (c *Controller) updateListenPortCLI(ifaceName string, port int) error {
	cmd := exec.Command(c.command, "set", ifaceName, "listen-port", strconv.Itoa(port))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s set listen-port failed: %s (%w)", c.command, string(out), err)
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

// UpdatePeerEndpoint updates the remote endpoint of the target peer.
func (c *Controller) UpdatePeerEndpoint(ifaceName, peerPubKey, endpoint string) error {
	endpoint = NormalizeEndpoint(endpoint)
	c.log.Info("WG", "Updating peer %s endpoint on %s to %s", peerPubKey, ifaceName, endpoint)

	if c.mode == "wgctrl" && c.client != nil {
		pubKey, err := wgtypes.ParseKey(peerPubKey)
		if err != nil {
			return fmt.Errorf("parse peer public key: %w", err)
		}

		udpAddr, err := net.ResolveUDPAddr("udp", endpoint)
		if err != nil {
			return fmt.Errorf("resolve endpoint %s: %w", endpoint, err)
		}

		peerCfg := wgtypes.PeerConfig{
			PublicKey:         pubKey,
			UpdateOnly:        true,
			Endpoint:          udpAddr,
		}

		cfg := wgtypes.Config{
			Peers: []wgtypes.PeerConfig{peerCfg},
		}

		if err := c.client.ConfigureDevice(ifaceName, cfg); err != nil {
			c.log.Warn("WG", "wgctrl ConfigureDevice peer failed: %v, trying CLI fallback", err)
			return c.updatePeerEndpointCLI(ifaceName, peerPubKey, endpoint)
		}
		return nil
	}

	return c.updatePeerEndpointCLI(ifaceName, peerPubKey, endpoint)
}

func (c *Controller) updatePeerEndpointCLI(ifaceName, peerPubKey, endpoint string) error {
	cmd := exec.Command(c.command, "set", ifaceName, "peer", peerPubKey, "endpoint", endpoint)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s set peer endpoint failed: %s (%w)", c.command, string(out), err)
	}
	return nil
}
