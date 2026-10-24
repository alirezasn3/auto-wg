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
	"auto-wg/pkg/transport"
)

// A tunnel whose transport is "tls" or "ssh" does not hunt UDP ports. WireGuard's peer endpoint is the
// loopback relay of the transport link; the link dials the peer's TCP port range and keeps one verified
// connection up. When WireGuard stays dead the hunter rebuilds that connection instead.

// linkTunnel is the part of transport.Tunnel the hunter uses; tests substitute a fake.
type linkTunnel interface {
	Start(ctx context.Context) error
	Stop()
	Connected() bool
	DownFor() time.Duration
	RelayAddr() netip.AddrPort
	SetPrimary(bool)
	SetTargets([]string)
	Reconnect()
	ResetConn() bool
	Status() transport.Status
}

func newLinkTunnel(opts transport.Options, deps transport.Deps) linkTunnel {
	return transport.New(opts, deps)
}

type linkAction int

const (
	linkStay   linkAction = iota
	linkReset             // drop the connection and let a new one be built
	linkRotate            // no connection: also move the listener to another port of the local range
)

// linked reports whether this tunnel runs over a TLS or SSH link instead of direct UDP.
func linked(cfg config.TunnelConfig) bool {
	return cfg.Transport == config.TransportTLS || cfg.Transport == config.TransportSSH
}

// linkTargetsLocked are the destinations the link dials: the configured targets, or the current peer IP.
func (h *Hunter) linkTargetsLocked() []string {
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

func (h *Hunter) startLink() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.startLinkLocked()
}

func (h *Hunter) startLinkLocked() {
	if !linked(h.cfg) || h.tun != nil || h.ctx == nil {
		return
	}
	iface := h.cfg.Interface
	deps := transport.Deps{
		Log:    h.log,
		Iface:  iface,
		WGPort: func() int { return int(h.wgListenPort.Load()) },
	}
	if h.cfg.Iptables && h.iptMgr != nil {
		mgr, key := h.iptMgr, iface+"-"+h.cfg.Transport
		deps.Redirect = func(portRange string, port int) error {
			return mgr.ApplyRedirect(key, "tcp", portRange, port)
		}
	}
	tun := h.newTunnel(transport.OptionsFor(h.cfg), deps)
	tun.SetTargets(h.linkTargetsLocked())
	if err := tun.Start(h.ctx); err != nil {
		h.log.Error("HUNTER", "[%s] Cannot start the %s transport: %v", iface, h.cfg.Transport, err)
		return
	}
	h.tun = tun
}

func (h *Hunter) stopLink() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stopLinkLocked()
}

func (h *Hunter) stopLinkLocked() {
	if h.tun == nil {
		return
	}
	h.tun.Stop()
	h.tun = nil
	if h.iptMgr != nil {
		_ = h.iptMgr.RemoveRule(h.cfg.Interface + "-" + config.TransportTLS)
		_ = h.iptMgr.RemoveRule(h.cfg.Interface + "-" + config.TransportSSH)
	}
}

// ensureRelayEndpointLocked points WireGuard's peer at the link's relay when it points anywhere else.
func (h *Hunter) ensureRelayEndpointLocked(endpointIP string, port int) {
	if h.tun == nil || h.peerPubKey == "" {
		return
	}
	relay := h.tun.RelayAddr()
	if !relay.IsValid() {
		return
	}
	if strings.Trim(endpointIP, "[]") == relay.Addr().String() && port == int(relay.Port()) {
		return
	}
	if err := h.wgCtrl.UpdatePeerEndpoint(h.cfg.Interface, h.peerPubKey, relay.String()); err != nil {
		h.log.Warn("HUNTER", "[%s] Cannot point WireGuard at the %s relay %s: %v", h.cfg.Interface, h.cfg.Transport, relay, err)
		return
	}
	h.log.Info("HUNTER", "[%s] WireGuard peer endpoint set to the %s relay %s", h.cfg.Interface, h.cfg.Transport, relay)
}

// reconnectAfter is how long WireGuard may stay dead before the link is rebuilt.
func (h *Hunter) reconnectAfter() time.Duration {
	d := h.cfg.TLS.ReconnectAfter
	if h.cfg.Transport == config.TransportSSH {
		d = h.cfg.SSH.ReconnectAfter
	}
	if d < 3*time.Second {
		d = 10 * time.Second
	}
	return d
}

// planLinkLocked decides what to do about a link whose WireGuard peer stays dead. A link that passes its own
// probes can still carry a flow that a middlebox singled out, so a new connection is built; with no
// connection at all the listener moves too, which changes the port the peer's dials land on.
func (h *Hunter) planLinkLocked() linkAction {
	if h.tun == nil {
		return linkStay
	}
	now := h.now()
	every := h.reconnectAfter()
	if now.Sub(h.deadSince) < every || (!h.lastLinkReset.IsZero() && now.Sub(h.lastLinkReset) < every) {
		return linkStay
	}
	if h.tun.Connected() {
		return linkReset
	}
	return linkRotate
}

func (h *Hunter) recoverLink(act linkAction, reason string) {
	h.mu.Lock()
	tun, iface, name := h.tun, h.cfg.Interface, h.cfg.Transport
	h.lastLinkReset = h.now()
	h.mu.Unlock()
	if tun == nil {
		return
	}
	switch act {
	case linkReset:
		h.log.Info("HUNTER", "[%s] WireGuard is dead on the %s link although it passes its probes (%s); building a new connection", iface, name, reason)
		tun.ResetConn()
	case linkRotate:
		h.log.Info("HUNTER", "[%s] No %s connection (%s); moving the listener and dialing again", iface, name, reason)
		tun.Reconnect()
	}
}

// reconnectLink handles the dashboard's hunt and rebind buttons on a linked tunnel: they rebuild the
// connection (and move the listener) instead of rotating UDP ports.
func (h *Hunter) reconnectLink() bool {
	h.mu.RLock()
	tun, name := h.tun, h.cfg.Transport
	isLinked := linked(h.cfg)
	h.mu.RUnlock()
	if !isLinked {
		return false
	}
	if tun != nil {
		h.log.Info("HUNTER", "[%s] Reconnecting the %s link", h.cfg.Interface, name)
		tun.Reconnect()
	}
	return true
}

// restoreDirectLocked points WireGuard back at the peer's real address after a linked tunnel went back to
// direct UDP.
func (h *Hunter) restoreDirectLocked() {
	if h.peerPubKey == "" || h.targetIP == "" {
		return
	}
	port := h.remotePort
	if port <= 0 {
		var err error
		if port, err = config.PickRandomPort(h.cfg.RemotePortRange); err != nil {
			return
		}
	}
	ep := net.JoinHostPort(h.targetIP, strconv.Itoa(port))
	if err := h.wgCtrl.UpdatePeerEndpoint(h.cfg.Interface, h.peerPubKey, ep); err != nil {
		h.log.Warn("HUNTER", "[%s] Could not restore the direct endpoint %s: %v", h.cfg.Interface, ep, err)
	}
}

// remoteDescLocked describes where traffic goes for log lines and history events.
func (h *Hunter) remoteDescLocked() string {
	if linked(h.cfg) {
		name := strings.ToUpper(h.cfg.Transport)
		if h.tun != nil {
			if st := h.tun.Status(); st.Connected {
				return fmt.Sprintf("%s via %s (%s)", name, st.Remote, st.Direction)
			}
		}
		return name + " relay"
	}
	return net.JoinHostPort(h.targetIP, strconv.Itoa(h.remotePort))
}

// linkConfigChanged tells UpdateConfig whether the link has to be rebuilt.
func linkConfigChanged(oldCfg, newCfg config.TunnelConfig) bool {
	return oldCfg.Transport != newCfg.Transport || !reflect.DeepEqual(oldCfg.TLS, newCfg.TLS) ||
		!reflect.DeepEqual(oldCfg.SSH, newCfg.SSH) || oldCfg.Iptables != newCfg.Iptables ||
		oldCfg.PortRange != newCfg.PortRange || oldCfg.RemotePortRange != newCfg.RemotePortRange
}

func (h *Hunter) linkStatusLocked() (transport.Status, bool) {
	if h.tun == nil {
		return transport.Status{}, false
	}
	return h.tun.Status(), true
}
