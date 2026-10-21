package wg

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"auto-wg/pkg/logger"
)

const awgTimeout = 5 * time.Second

// AWGController controls AmneziaWG interfaces (kernel module or amneziawg-go) through the awg
// command from amneziawg-tools. wgctrl cannot be used: the AmneziaWG kernel module registers its own
// netlink family and amneziawg-go its own control socket. Shelling out to awg works with both and
// keeps this code independent of the obfuscation parameters (Jc, S1-S4, H1-H4, I1-I5, ...), which
// live in the interface config and change between AmneziaWG releases.
type AWGController struct {
	bin string
	log *logger.Logger
}

// NewAWGController returns a controller that runs bin, or "awg" from PATH when bin is empty.
func NewAWGController(log *logger.Logger, bin string) *AWGController {
	if bin == "" {
		bin = "awg"
	}
	return &AWGController{bin: bin, log: log}
}

// Available reports whether the awg binary can be found.
func (c *AWGController) Available() error {
	if _, err := exec.LookPath(c.bin); err != nil {
		return fmt.Errorf("%s not found: install amneziawg-tools: %w", c.bin, err)
	}
	return nil
}

func (c *AWGController) run(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), awgTimeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, c.bin, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", c.bin, args[0], err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// GetDeviceInfo reads the interface with `awg show <iface> dump`. Only the fields every AmneziaWG
// release prints in the same place are used: the first line starts with private key, public key and
// listen port (newer releases append more obfuscation columns after them), and every following line is
// one peer in the same eight-column layout as `wg show dump`.
func (c *AWGController) GetDeviceInfo(ifaceName, targetPeerPubkey string) (*DeviceInfo, error) {
	if c == nil {
		return nil, fmt.Errorf("awg controller not initialized")
	}
	out, err := c.run("show", ifaceName, "dump")
	if err != nil {
		return nil, fmt.Errorf("query device %s: %w", ifaceName, err)
	}
	return parseAWGDump(ifaceName, string(out), targetPeerPubkey, time.Now())
}

func parseAWGDump(ifaceName, dump, targetPeerPubkey string, now time.Time) (*DeviceInfo, error) {
	lines := strings.Split(strings.TrimRight(dump, "\r\n"), "\n")
	head := strings.Split(lines[0], "\t")
	if len(head) < 3 {
		return nil, fmt.Errorf("unexpected awg dump header for %s: %q", ifaceName, lines[0])
	}
	port, err := strconv.Atoi(head[2])
	if err != nil {
		return nil, fmt.Errorf("bad listen port %q in awg dump", head[2])
	}
	info := &DeviceInfo{Name: ifaceName, Type: "amneziawg", ListenPort: port}
	if head[1] != "(none)" {
		info.PublicKey = head[1]
	}

	for _, line := range lines[1:] {
		f := strings.Split(line, "\t")
		if len(f) < 7 {
			continue
		}
		if targetPeerPubkey != "" && f[0] != targetPeerPubkey {
			continue
		}
		info.PeerPublicKey = f[0]
		if ap, err := netip.ParseAddrPort(f[2]); err == nil {
			info.PeerEndpoint = net.JoinHostPort(ap.Addr().String(), strconv.Itoa(int(ap.Port())))
			info.PeerEndpointIP = ap.Addr().String()
			info.PeerPort = int(ap.Port())
		}
		if f[3] != "(none)" {
			for _, cidr := range strings.Split(f[3], ",") {
				if ip, _, err := net.ParseCIDR(strings.TrimSpace(cidr)); err == nil {
					info.PeerAllowedIPs = append(info.PeerAllowedIPs, ip.String())
				}
			}
		}
		if ts, err := strconv.ParseInt(f[4], 10, 64); err == nil && ts > 0 {
			info.LastHandshake = time.Unix(ts, 0)
			info.HandshakeAge = now.Sub(info.LastHandshake)
		}
		info.ReceiveBytes, _ = strconv.ParseInt(f[5], 10, 64)
		info.TransmitBytes, _ = strconv.ParseInt(f[6], 10, 64)
		break
	}
	return info, nil
}

// UpdateListenPort changes the local listen port.
func (c *AWGController) UpdateListenPort(ifaceName string, port int) error {
	if c == nil {
		return fmt.Errorf("awg controller not initialized")
	}
	c.log.Info("WG", "Updating local listen port on %s (amneziawg) to %d", ifaceName, port)
	if _, err := c.run("set", ifaceName, "listen-port", strconv.Itoa(port)); err != nil {
		return fmt.Errorf("set listen-port: %w", err)
	}
	return nil
}

// UpdatePeerEndpoint changes the endpoint of an existing peer. Like the wgctrl backend it refuses to
// create the peer, which `awg set peer` would otherwise do for an unknown key.
func (c *AWGController) UpdatePeerEndpoint(ifaceName, peerPubKey, endpoint string) error {
	if c == nil {
		return fmt.Errorf("awg controller not initialized")
	}
	endpoint = NormalizeEndpoint(endpoint)
	if _, err := net.ResolveUDPAddr("udp", endpoint); err != nil {
		return fmt.Errorf("resolve endpoint %s: %w", endpoint, err)
	}
	info, err := c.GetDeviceInfo(ifaceName, peerPubKey)
	if err != nil {
		return err
	}
	if info.PeerPublicKey != peerPubKey {
		return fmt.Errorf("peer %s not found on %s", peerPubKey, ifaceName)
	}
	c.log.Info("WG", "Updating peer %s endpoint on %s (amneziawg) to %s", peerPubKey, ifaceName, endpoint)
	if _, err := c.run("set", ifaceName, "peer", peerPubKey, "endpoint", endpoint); err != nil {
		return fmt.Errorf("set peer endpoint: %w", err)
	}
	return nil
}
