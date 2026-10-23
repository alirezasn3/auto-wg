package hunter

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"time"

	"auto-wg/pkg/config"
	"auto-wg/pkg/tlstun"
)

// A tunnel with a tls block has two paths to the peer. WireGuard's peer endpoint says which one this side
// sends on: the real peer address (direct) or the loopback relay of the TLS link (tls). Receiving is open
// on both paths on both peers at all times, so each side picks its sending path independently and the
// other side follows through WireGuard's endpoint roaming.
const (
	PathDirect = "direct"
	PathTLS    = "tls"

	// A dropped TLS link gets this long to come back before the hunter falls back to the direct path.
	tlsLinkGrace = 3 * time.Second

	EventPath = "PATH"
)

type pathAction int

const (
	pathStay pathAction = iota
	pathToTLS
	pathToDirect
)

// tlsLink is the part of tlstun.Tunnel the hunter uses; tests substitute a fake.
type tlsLink interface {
	Start(ctx context.Context) error
	Stop()
	Connected() bool
	DownFor() time.Duration
	RelayAddr() netip.AddrPort
	SetPrimary(bool)
	SetTargets([]string)
	Reconnect()
	Status() tlstun.Status
}

func newTLSTunnel(cfg config.TLSConfig, deps tlstun.Deps) tlsLink { return tlstun.New(cfg, deps) }

// tlsTargetsLocked are the destinations the TLS link dials: the configured targets, or the current peer IP.
func (h *Hunter) tlsTargetsLocked() []string {
	if len(h.configuredTargets) > 0 {
		seen := make(map[string]bool, len(h.configuredTargets))
		out := make([]string, 0, len(h.configuredTargets))
		for _, t := range h.configuredTargets {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
		return out
	}
	if h.targetIP != "" {
		return []string{h.targetIP}
	}
	return nil
}

func (h *Hunter) startTLS() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.startTLSLocked()
}

func (h *Hunter) startTLSLocked() {
	if !h.cfg.TLS.Enabled || h.tun != nil || h.ctx == nil {
		return
	}
	iface := h.cfg.Interface
	deps := tlstun.Deps{
		Log:         h.log,
		Iface:       iface,
		WGPort:      func() int { return int(h.wgListenPort.Load()) },
		AvoidRanges: []string{h.cfg.PortRange, h.cfg.RemotePortRange},
	}
	if h.cfg.Iptables && h.iptMgr != nil {
		mgr := h.iptMgr
		deps.Redirect = func(portRange string, port int) error {
			return mgr.ApplyRedirect(iface+"-tls", "tcp", portRange, port)
		}
	}
	tun := h.newTunnel(h.cfg.TLS, deps)
	tun.SetTargets(h.tlsTargetsLocked())
	if err := tun.Start(h.ctx); err != nil {
		h.log.Error("TLS", "[%s] Cannot start the TLS path: %v", iface, err)
		return
	}
	h.tun = tun
	h.log.Info("TLS", "[%s] TLS fallback path enabled (switches after %v without connectivity)", iface, h.cfg.TLS.FallbackAfter)
}

func (h *Hunter) stopTLS() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stopTLSLocked()
}

func (h *Hunter) stopTLSLocked() {
	if h.tun == nil {
		return
	}
	h.tun.Stop()
	h.tun = nil
	if h.iptMgr != nil {
		_ = h.iptMgr.RemoveRule(h.cfg.Interface + "-tls")
	}
	h.activePath = PathDirect
}

// relayEndpointLocked reports whether the device's peer endpoint is this tunnel's TLS relay.
func (h *Hunter) relayEndpointLocked(endpointIP string, port int) bool {
	if h.tun == nil {
		return false
	}
	relay := h.tun.RelayAddr()
	return relay.IsValid() && strings.Trim(endpointIP, "[]") == relay.Addr().String() && port == int(relay.Port())
}

// syncPathLocked derives the active path from where WireGuard's endpoint points, so a switch made by the
// other peer (which reaches us through the TLS link and moves our endpoint by roaming) is followed.
func (h *Hunter) syncPathLocked(onRelay bool) {
	if h.tun == nil {
		return
	}
	want := PathDirect
	if onRelay {
		want = PathTLS
	}
	if want == h.activePath {
		return
	}
	prev := h.activePath
	h.activePath = want
	h.lastPathSwitch = h.now()
	h.log.Info("TLS", "[%s] Path is now %s (the peer's traffic moved our endpoint)", h.cfg.Interface, want)
	h.addEvent(EventPath, pathLabel(prev, want), "Remote Peer", "peer switched path; endpoint followed", 0)
}

func pathLabel(from, to string) string {
	return strings.ToUpper(from) + " → " + strings.ToUpper(to)
}

// planFailoverLocked decides, for a link that is currently dead, whether to switch path and whether
// direct hunting must be held back because the TLS path is the active one.
func (h *Hunter) planFailoverLocked() (act pathAction, holdDirect bool) {
	if h.tun == nil {
		return pathStay, false
	}
	deadFor := h.now().Sub(h.deadSince)
	fallback := h.cfg.TLS.FallbackAfter

	if h.activePath == PathTLS {
		if !h.tun.Connected() && h.tun.DownFor() >= tlsLinkGrace {
			return pathToDirect, true
		}
		if deadFor >= fallback {
			return pathToDirect, true
		}
		return pathStay, true
	}
	if deadFor >= fallback && h.tun.Connected() {
		return pathToTLS, false
	}
	return pathStay, false
}

// directEndpointLocked is the endpoint to restore when going back to the direct path: the last direct peer
// address, or a random port of the remote range on the current target.
func (h *Hunter) directEndpointLocked() string {
	if h.targetIP == "" {
		return ""
	}
	port := h.remotePort
	if port <= 0 {
		var err error
		if port, err = config.PickRandomPort(h.cfg.RemotePortRange); err != nil {
			return ""
		}
	}
	return net.JoinHostPort(h.targetIP, strconv.Itoa(port))
}

// switchPath moves WireGuard's peer endpoint to the other path.
func (h *Hunter) switchPath(act pathAction, reason string) {
	h.mu.Lock()
	tun, iface, peerKey := h.tun, h.cfg.Interface, h.peerPubKey
	if tun == nil || peerKey == "" {
		h.mu.Unlock()
		return
	}
	var endpoint, next string
	switch act {
	case pathToTLS:
		endpoint, next = tun.RelayAddr().String(), PathTLS
	case pathToDirect:
		endpoint, next = h.directEndpointLocked(), PathDirect
	default:
		h.mu.Unlock()
		return
	}
	prev := h.activePath
	h.mu.Unlock()

	if endpoint == "" {
		h.log.Warn("TLS", "[%s] Cannot switch to the %s path: no endpoint known", iface, next)
		return
	}
	if err := h.wgCtrl.UpdatePeerEndpoint(iface, peerKey, endpoint); err != nil {
		h.log.Error("TLS", "[%s] Switching to the %s path failed: %v", iface, next, err)
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	h.activePath = next
	h.lastPathSwitch = h.now()
	h.deadSince = h.now() // the new path gets a full fallback window before it is judged
	h.log.Info("TLS", "[%s] Switched to the %s path (endpoint %s): %s", iface, next, endpoint, reason)
	h.addEvent(EventPath, pathLabel(prev, next), "Local Host", reason, 0)
}

// restoreDirectLocked points WireGuard back at the direct peer address; used when the TLS path is removed.
func (h *Hunter) restoreDirectLocked() {
	if h.activePath != PathTLS || h.peerPubKey == "" {
		return
	}
	if ep := h.directEndpointLocked(); ep != "" {
		if err := h.wgCtrl.UpdatePeerEndpoint(h.cfg.Interface, h.peerPubKey, ep); err != nil {
			h.log.Warn("TLS", "[%s] Could not restore the direct endpoint %s: %v", h.cfg.Interface, ep, err)
		}
	}
	h.activePath = PathDirect
}

// reconnectTLSIfActive handles the dashboard's hunt and rebind buttons while the TLS path carries traffic:
// they reconnect the link (new connection, new listener port) instead of rotating the direct ports.
func (h *Hunter) reconnectTLSIfActive() bool {
	h.mu.RLock()
	tun, onTLS := h.tun, h.activePath == PathTLS
	h.mu.RUnlock()
	if tun == nil || !onTLS {
		return false
	}
	h.log.Info("TLS", "[%s] Reconnecting the TLS link", h.cfg.Interface)
	tun.Reconnect()
	return true
}

// remoteDescLocked describes where traffic goes for log lines and history events: the direct peer
// endpoint, or the TLS link while that path is active.
func (h *Hunter) remoteDescLocked() string {
	if h.tun != nil && h.activePath == PathTLS {
		if st := h.tun.Status(); st.Connected {
			return fmt.Sprintf("TLS via %s (%s)", st.Remote, st.Direction)
		}
		return "TLS relay"
	}
	return net.JoinHostPort(h.targetIP, strconv.Itoa(h.remotePort))
}

// tlsConfigChanged tells UpdateConfig whether the TLS path has to be rebuilt.
func tlsConfigChanged(oldCfg, newCfg config.TunnelConfig) bool {
	return !reflect.DeepEqual(oldCfg.TLS, newCfg.TLS) || oldCfg.Iptables != newCfg.Iptables ||
		oldCfg.PortRange != newCfg.PortRange || oldCfg.RemotePortRange != newCfg.RemotePortRange
}

func (h *Hunter) tlsStatusLocked() (tlstun.Status, bool) {
	if h.tun == nil {
		return tlstun.Status{}, false
	}
	return h.tun.Status(), true
}
