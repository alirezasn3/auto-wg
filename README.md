# Auto-WG: Autonomous WireGuard Port Negotiator & Multi-Interface Gateway

Auto-WG is a high-performance Go application designed to keep WireGuard connections alive in hostile network environments with Deep Packet Inspection (DPI), stateful flow blocking, and asymmetric reachability.

By combining **autonomous symmetrical hunting**, **kernel-level `iptables` port-range forwarding**, and **dynamic policy routing failover**, Auto-WG allows WireGuard peers to dynamically rotate connection 5-tuples and self-heal stalled links **without needing any external server, Cloudflare Worker, or out-of-band negotiator**.

Auto-WG natively supports two primary deployment topologies:
1. **Server Mode (`mode: "server"`)**: A server that maintains resilient connections to one or more clients across independent WireGuard interfaces.
2. **Client Mode (`mode: "client"`)**: A client that has one or more upstream connections and dynamically switches the active route to an available tunnel based on real-time link health.

---

## ⚡ Key Highlights

* **Zero-Negotiator Autonomous Hunting**: No external signaling relays, Cloudflare Workers, or rendezvous servers needed. Both peers monitor link state and recover 100% autonomously.
* **Pure Netlink/UAPI WireGuard Control (`wgctrl`)**: Interacts directly with the Linux WireGuard kernel module via native Netlink without spawning sub-processes.
* **AmneziaWG Support**: Each tunnel can run on stock WireGuard (default) or on [AmneziaWG](https://github.com/amnezia-vpn/amneziawg-go) (`backend: "amneziawg"`), whose junk packets, padded handshakes and custom headers defeat DPI that fingerprints the 148/92-byte WireGuard handshake. Stock and AmneziaWG tunnels can be mixed. See [AmneziaWG](#-amneziawg).
* **UDP-over-TLS Fallback**: Any tunnel can carry a second, TCP/TLS-shaped path (`tls:` block). Both peers keep a TLS connection open (each side listens on a TCP port range and dials the peer's), and WireGuard switches between the direct and the TLS path when one of them stops working. Works with stock WireGuard and AmneziaWG. See [UDP over TLS](#-udp-over-tls-fallback).
* **Multi-Interface Architecture**: Supervise multiple tunnels simultaneously on a single machine, with isolated port ranges, independent health probes, and per-tunnel persistent state.
* **Upstream Route Failover (Policy Routing / Table 200)**: In client mode, Auto-WG monitors upstream health and dynamically updates default routes in a designated routing table (e.g. `table 200`) using `ip route replace default dev <iface> table 200`. The host's main routing table and SSH sessions are never disrupted.
* **PostUp & PreDown Lifecycle Hooks**: Execute custom shell commands (policy routing rules, iptables MASQUERADE, UFW forwardings) automatically upon daemon start and shutdown.
* **Kernel Port Forwarding (`go-iptables`)**: Automatically forwards disjoint UDP port ranges (e.g., `20000–24999`, `25000–29999`) directly to each WireGuard interface's listening port using `iptables -t nat -A PREROUTING -j REDIRECT`. Linux `conntrack` handles reverse translation.
* **Automatic Peer Discovery**: Auto-WG queries each WireGuard interface and automatically extracts the single peer's public key, current endpoint, and handshake statistics directly from the kernel.
* **Deterministic Anti-Collision Staggering**: Uses public key lexicographical comparison (`localPubKey < peerPubKey`) to coordinate turn-taking windows (e.g. 8s cycle) so peers do not collide or flap while hunting.
* **Multi-Destination Dual-Stack Hunting (`target_ips`)**: Tunnels can specify multiple candidate destination endpoints (IPv4 & IPv6, or domain hostnames). If DPI blocks or throttles one address family, Auto-WG automatically round-robins between IPv4 and IPv6 during port hunting to punch through hostile firewalls.
* **Integrated Web Dashboard & Public Status Page**: Modern, mobile-responsive web UI with multi-tunnel telemetry, active route indication, manual hunt/rebind triggers, live SSE logs, and an isolated bilingual (Persian & English) public status page.

---

## 🏗️ Architecture & Topologies

### 1. Server Mode (One Server -> Multiple Clients)

In Server Mode, Auto-WG supervises multiple client interfaces on the server. Each client interface is assigned a disjoint port slice (e.g., `20000-24999` for Client A, `25000-29999` for Client B):

```
                       ┌─────────────────────────────────────┐
                       │           Auto-WG Server            │
                       │                                     │
                       │  wg0 (Client A): UDP 20000-24999    │
                       │  wg1 (Client B): UDP 25000-29999    │
                       └───────────┬─────────────┬───────────┘
                                   │             │
                Autonomous Hunting │             │ Autonomous Hunting
               (UDP 20000-24999)   │             │ (UDP 25000-29999)
                                   ▼             ▼
                            ┌────────────┐ ┌────────────┐
                            │  Client A  │ │  Client B  │
                            │   (wg0)    │ │   (wg0)    │
                            └────────────┘ └────────────┘
```

### 2. Client Mode (Upstream Failover & Policy Routing)

In Client Mode, the machine maintains one or more upstream tunnels (e.g., `wgBridge0`, `wgBridge1`) to foreign servers. Auto-WG continuously monitors the health of each upstream link using handshake age and in-tunnel ICMP ping probes. When the active upstream drops, Auto-WG automatically updates the default route in policy routing table 200:

```
                            ┌────────────────────────┐
                            │    Incoming Traffic    │
                            │ (e.g. user VPN wgServer)
                            └───────────┬────────────┘
                                        │ (lookup table 200)
                                        ▼
                     ┌──────────────────────────────────────┐
                     │            Auto-WG Client            │
                     │                                      │
                     │  Active Route: dev wgBridge0 table 200│
                     │  Backup Route: dev wgBridge1         │
                     └──────────┬─────────────────┬─────────┘
                                │ (Healthy)       │ (Standby / Hunting)
                                ▼                 ▼
                         ┌─────────────┐   ┌─────────────┐
                         │ Upstream A  │   │ Upstream B  │
                         │ (Foreign 1) │   │ (Foreign 2) │
                         └─────────────┘   └─────────────┘
```

---

## 🚀 Quick Start

### 1. Build from Source

```bash
git clone https://github.com/alirezasn3/auto-wg.git
cd auto-wg
go build -o autowg ./cmd/autowg
```

### 2. Configure

Auto-WG provides example configurations for both deployment modes:
- **Server**: `configs/server.example.yaml`
- **Client**: `configs/client.example.yaml`

Copy the appropriate configuration:

```bash
# For a Server node:
cp configs/server.example.yaml config.yaml

# For a Client node:
cp configs/client.example.yaml config.yaml
```

#### Client Configuration Example with Policy Routing (`table 200`):

```yaml
mode: "client"

# Lifecycle hooks: setup policy routing, NAT MASQUERADE, and firewall rules
post_up:
  - "ip rule add to 10.0.0.1 lookup local priority 100"
  - "ip rule add from 10.0.0.0/16 lookup 200 priority 200"
  - "ip rule add to 192.168.69.0/24 lookup 200 priority 201"
  - "ip route add 10.0.0.0/16 dev wgServer table 200"
  - "iptables -t nat -I POSTROUTING -o wgBridge+ -j MASQUERADE"
  - "ufw route allow in on wgServer out on wgBridge+"
  - "ufw route allow in on wgBridge+ out on ens192"

pre_down:
  - "iptables -t nat -D POSTROUTING -o wgBridge+ -j MASQUERADE"
  - "ip rule del from 10.0.0.0/16 lookup 200 priority 200"
  - "ip rule del to 10.0.0.1 lookup local priority 100"
  - "ip rule del to 192.168.69.0/24 lookup 200 priority 201"

routing:
  enabled: true
  table: 200       # Updates 'ip route replace default dev <iface> table 200'
  mode: "sticky"   # "sticky" (avoids flapping) or "priority" (prefers first configured tunnel)
  metric: 100

tunnels:
  - interface: "wgBridge0"
    name: "Upstream-Main"
    port_range: "20000-24999"
    remote_port_range: "20000-24999"
    handshake_timeout: 60s
    cycle_timeout: 8s
    check_interval: 3s
    tunnel_ping:
      enabled: true
      target_ip: "10.100.0.1"
      interval: 2s
      failure_threshold: 3
    history_file: "history-wgBridge0.json"
    iptables: true

  - interface: "wgBridge1"
    name: "Upstream-Backup"
    port_range: "25000-29999"
    remote_port_range: "25000-29999"
    handshake_timeout: 60s
    cycle_timeout: 8s
    check_interval: 3s
    tunnel_ping:
      enabled: true
      target_ip: "10.200.0.1"
      interval: 2s
      failure_threshold: 3
    history_file: "history-wgBridge1.json"
    iptables: true

web:
  enabled: true
  listen_addr: "127.0.0.1:8080"

status_page:
  enabled: true
  listen_addr: "0.0.0.0:8081"
  title: "Gateway Status"
```

### 3. Run or Install as a Service

Run directly with `sudo` (required for netlink device control, iptables, and ICMP ping):

```bash
sudo ./autowg -config config.yaml
```

To enable verbose debug logging:

```bash
sudo ./autowg -config config.yaml -debug
```

#### One-Command Systemd Installation:

Auto-WG includes built-in systemd service management via `github.com/alirezasn3/go-systemd`:

```bash
# Install and start as a background systemd service:
sudo ./autowg --install -config /etc/auto-wg/config.yaml

# Stop and uninstall the systemd service:
sudo ./autowg --uninstall
```

### 4. Access Web Interfaces

- **Admin Dashboard**: `http://<ip>:8080` (or `127.0.0.1:8080`)
  - Real-time connection health across all supervised tunnels.
  - Active upstream route indication and manual switch overrides.
  - Manual port rebind and hunt triggers.
  - Live streaming logs via Server-Sent Events (SSE).
- **Public Status Page**: `http://<ip>:8081`
  - Zero sensitive data, no keys or administrative controls.
  - Real-time uptime percentage, incident history, and bilingual Persian/English UI with RTL support.

---

## ⚙️ Configuration Reference

### Root Level Options

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `mode` | string | `server` | Operating mode: `"server"` (multi-client) or `"client"` (upstream failover) |
| `post_up` | list of string | `[]` | Shell commands executed sequentially after tunnels initialize |
| `pre_down` | list of string | `[]` | Shell commands executed sequentially before daemon exits |

### `routing` (Client Mode Failover)

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `routing.enabled` | bool | `false` | Enable automatic default route switching when links fail |
| `routing.table` | int | `0` | Linux routing table ID (e.g. `200` for policy routing, `0` for main) |
| `routing.mode` | string | `sticky` | `"sticky"` (maintains current tunnel until it drops) or `"priority"` (prefers top tunnel) |
| `routing.metric` | int | `100` | Metric value applied to the kernel route |

### `tunnels[]` (Per-Tunnel Configuration)

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `interface` | string | **Required** | WireGuard interface name (`wg0`, `wgBridge0`, etc.) |
| `backend` | string | `wireguard` | `"wireguard"` (stock WireGuard via netlink) or `"amneziawg"` (AmneziaWG via the `awg` tool) |
| `name` | string | `""` | Human-friendly alias displayed on the web dashboard |
| `target_ip` | string | `""` | Single remote destination IP or fallback |
| `target_ips` | list of string | `[]` | Candidate destination IPs / domain names (IPv4 & IPv6) rotated during hunting |
| `port_range` | string | `20000-30000` | Local port range forwarded to WireGuard listen port |
| `remote_port_range` | string | `20000-30000` | Remote peer's forwarded port range |
| `hunting` | bool | `true` | Enable autonomous port hunting. Set `false` for passive / MikroTik peers |
| `passive` | bool | `false` | Alias for `hunting: false` (monitors tunnel and pings without port rotation) |
| `iptables` | bool | `true` | Automatically manage `iptables -t nat -A PREROUTING` redirect rule |
| `check_interval` | duration | `3s` | Interval between handshake and reachability polls |
| `handshake_timeout` | duration | `60s` | Stale handshake threshold triggering reachability checks |
| `cycle_timeout` | duration | `8s` | Alternating stagger window to prevent peer collision |
| `tunnel_ping.enabled` | bool | `true` | Active ICMP ping verification before hunting |
| `tunnel_ping.target_ip` | string | `""` | In-tunnel IP of the remote peer to ping |
| `tunnel_ping.failure_threshold` | int | `3` | Consecutive ping timeouts before declaring link down |
| `tls.enabled` | bool | `false` | Enable the UDP-over-TLS fallback path (needs Auto-WG on both peers; not for passive tunnels) |
| `tls.secret` | string | **Required** | Shared secret, identical on both peers, at least 16 characters |
| `tls.port_range` | string | tunnel `port_range` | Local **TCP** range, redirected by iptables to the TLS listener |
| `tls.remote_port_range` | string | tunnel `remote_port_range` | Peer's **TCP** range to dial |
| `tls.fallback_after` | duration | `15s` | How long the active path must be dead before switching to the other |
| `tls.dial_interval` | duration | `1s` | Pause between dial attempts while no TLS link is up |
| `tls.health_interval` | duration | `3s` | Pause between health probes (ping/pong) on a live TLS link |
| `tls.health_timeout` | duration | `2s` | How long a probe may stay unanswered |
| `tls.health_failures` | int | `3` | Consecutive unanswered probes after which the connection is dropped and rebuilt |
| `tls.relay_port` | int | `0` (auto) | Loopback UDP port WireGuard talks to while the TLS path is active |
| `tls.sni` | string | `""` | Optional server name sent in the TLS handshake (also the certificate name) |
| `tls.alpn` | list of string | `[]` | Optional ALPN protocols, e.g. `["h2", "http/1.1"]` |
| `history_file` | string | `""` | Persistent history file path (e.g. `"history-wg0.json"`, or `"off"` to disable) |
| `post_up` | list of string | `[]` | Tunnel-specific shell commands executed after this interface starts |
| `pre_down` | list of string | `[]` | Tunnel-specific shell commands executed before this interface stops |

### `web` (Admin Dashboard) & `status_page` (Public Status)

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `web.enabled` | bool | `true` | Enable built-in admin dashboard |
| `web.listen_addr` | string | `0.0.0.0:8080` | Admin dashboard listen address |
| `web.username` | string | `""` | Optional HTTP Basic Auth username |
| `web.password` | string | `""` | Optional HTTP Basic Auth password |
| `web.allowed_ips` | list of string | `[]` | Whitelist of client IPs/CIDRs permitted to access panel |
| `web.https` | bool | `false` | Enable TLS/HTTPS for admin dashboard |
| `web.cert_file` | string | `""` | SSL certificate PEM path |
| `web.key_file` | string | `""` | SSL private key PEM path |
| `status_page.enabled` | bool | `false` | Enable isolated public status page |
| `status_page.listen_addr` | string | `0.0.0.0:8081` | Status page listen address |
| `status_page.title` | string | `Service Status` | Title displayed on the status page |
| `status_page.https` | bool | `false` | Enable TLS/HTTPS for status page |
| `status_page.cert_file` | string | `""` | SSL certificate PEM path |
| `status_page.key_file` | string | `""` | SSL private key PEM path |

---

## 🛡️ AmneziaWG

WireGuard's handshake messages are authenticated, so DPI that fingerprints them (the 148-byte initiation, the 92-byte response and their `01 00 00 00` / `02 00 00 00` headers) cannot be fooled from outside the tunnel. [AmneziaWG](https://github.com/amnezia-vpn/amneziawg-go) changes the wire format itself: junk packets before the handshake, random padding on every message type, custom message headers, protocol-imitating signature packets and, since 3.0, encrypted headers and padded content.

Set the backend per tunnel; everything else (port hunting, failover, ping, the dashboard) works the same:

```yaml
tunnels:
  - interface: "wgBridge0"
    backend: "amneziawg"      # default: "wireguard"
    target_ips: ["198.51.100.1"]
    port_range: "20000-24999"
    remote_port_range: "20000-24999"
```

Auto-WG never touches the obfuscation parameters. They live in the interface config, so new AmneziaWG releases work without changes here. It has been tested against AmneziaWG 3.1 (`amneziawg-go` v3.1.20260828 with `awg` from `amneziawg-tools` 3.1), with both 2.0-style and 3.x parameters.

### Install on the server

Do this on **both** peers and run the same AmneziaWG release on both ends.

*Ubuntu / Debian*, kernel module through the Amnezia PPA (needs kernel headers and `deb-src` enabled, see the [module README](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module#installation) for Debian):

```bash
sudo apt install -y software-properties-common python3-launchpadlib gnupg2 linux-headers-$(uname -r)
sudo add-apt-repository ppa:amnezia/ppa
sudo apt install -y amneziawg
awg --version        # should report amneziawg-tools v3.x
```

*Fedora / RHEL*: `sudo dnf copr enable amneziavpn/amneziawg && sudo dnf install amneziawg-dkms amneziawg-tools`.

*Without a kernel module* (containers, unsupported kernels): build the userspace implementation and the tools. `awg-quick` falls back to `amneziawg-go` automatically when the module is missing.

```bash
git clone https://github.com/amnezia-vpn/amneziawg-go && make -C amneziawg-go && sudo install amneziawg-go/amneziawg-go /usr/local/bin/
git clone https://github.com/amnezia-vpn/amneziawg-tools && make -C amneziawg-tools/src && sudo make -C amneziawg-tools/src install
```

### Interface config

AmneziaWG interfaces are created with `awg-quick`, from `/etc/amnezia/amneziawg/<interface>.conf`, instead of `wg-quick`; stock `wg-quick` rejects the extra keys. As with stock WireGuard, `ListenPort` and `Endpoint` are not needed because Auto-WG sets them. Generate keys with `awg genkey`.

```ini
# /etc/amnezia/amneziawg/wgBridge0.conf
[Interface]
PrivateKey = <private key>
Address = 10.100.0.2/24

# Must be identical on both peers
S1 = 50
S2 = 90
S3 = 40
S4 = 16
H1 = 100000-200000
H2 = 300000-400000
H3 = 500000-600000
H4 = 700000-800000
HeaderProtectionKey = <output of `awg genkey`, shared by both peers>   # AmneziaWG 3+, needs S1-S4 >= 12

# Per peer, may differ
Jc = 6
Jmin = 40
Jmax = 120
ContentPaddingAddition = 10-40                                         # AmneziaWG 3+
# I1 = <b 0x...><r 32>                                                 # optional signature packets, I1-I5

[Peer]
PublicKey = <peer public key>
AllowedIPs = 10.100.0.0/24
PersistentKeepalive = 25
```

`S1`-`S4`, `H1`-`H4` and `HeaderProtectionKey` must match on both peers or no handshake completes; `Jc`/`Jmin`/`Jmax`, `I1`-`I5` and the timing options only shape what a peer sends. See the [amneziawg-go README](https://github.com/amnezia-vpn/amneziawg-go#configuration) for every parameter. Keep `Jmax` and the signature packets below the path MTU, or they get fragmented.

### Start on boot

```bash
sudo systemctl enable --now awg-quick@wgBridge0     # one unit per interface; reads /etc/amnezia/amneziawg/wgBridge0.conf
```

The unit comes with `amneziawg-tools` (it is `awg-quick@.service`, installed when systemd is present). Make Auto-WG wait for the interface with a drop-in, then reload:

```bash
sudo systemctl edit autowg
```

```ini
[Unit]
After=awg-quick@wgBridge0.service
Wants=awg-quick@wgBridge0.service
```

If Auto-WG does start first it keeps retrying until the interface appears, but it picks the initial listen port and endpoint at startup, so the ordering above is the reliable setup. Switching a tunnel's backend in the web editor recreates that tunnel.

---

## 🔐 UDP over TLS fallback

When DPI blocks the direct WireGuard path, a tunnel can fall back to carrying its packets inside a TLS connection. This is configured **inside** the WireGuard tunnel, so the interface, keys and routes stay the same:

```yaml
tunnels:
  - interface: "wg0"
    port_range: "20000-24999"          # UDP, direct path
    remote_port_range: "20000-24999"
    target_ips: ["198.51.100.1"]
    tls:
      enabled: true
      secret: "<the same long random string on both peers>"
      port_range: "443-8443"           # TCP; optional, defaults to port_range
      remote_port_range: "443-8443"    # optional, defaults to remote_port_range
      fallback_after: 15s
      sni: "www.example.com"           # optional
      alpn: ["h2", "http/1.1"]         # optional
```

**How it works**

* **Both peers listen and dial.** Each side opens a TCP listener on a random port of `tls.port_range` (the whole range is redirected to it by iptables, exactly like the UDP range) and keeps dialing a random port of the peer's `tls.remote_port_range`, from a random source port of its own range. Whichever connection comes up first is used, so it works when only one direction is reachable. If two connections come up at once, both sides keep the one the primary peer (the lower public key) dialed.
* **The TLS link stays up in the background** (hot standby), and its health is checked actively. A middlebox can let a TLS connection start (the handshake and the first packets go through) and then stall it, so a connection that is merely open proves nothing. Every new connection must first echo four probe frames, sized like WireGuard's initiation (148 bytes), response (92), keepalive (32) and a near-full packet, before it is used or counted as up. After that each side sends a ping of random size every `health_interval` (with jitter) and expects the peer to echo it; `health_failures` unanswered probes in a row drop the connection and a new one is built within `dial_interval`. Probes are a separate control frame type: they never reach WireGuard, and they share the TLS stream with the data, so a stalled stream fails them too. If WireGuard itself stays dead on a TLS link that still passes its probes (a middlebox singling out what WireGuard sends), the connection is rebuilt once halfway through `fallback_after` before the tunnel gives up on the path. The dashboard shows the round-trip time, lost probes and rebuilds.
* **WireGuard talks to a loopback relay while the TLS path is active.** Switching paths is only a change of the peer endpoint (the real peer, or `127.0.0.1:<relay port>`); WireGuard sessions survive it, so there is no new handshake. It works the same for the `wireguard` and `amneziawg` backends.
* **Sticky failover.** Neither path is preferred. After the active path has been dead for `fallback_after`, the tunnel switches to the other one (the direct path is also still hunted for new ports while it is the active one). If the TLS link drops while it is active, the tunnel goes back to direct after 3 seconds. Each peer decides on its own, and receiving works on both paths on both peers at all times, so one side's switch moves the other side's endpoint by WireGuard roaming.
* **Authentication.** TLS 1.3 with an ephemeral self-signed certificate; the peers then prove knowledge of `tls.secret` with an HMAC bound to the TLS session, so the secret never appears on the wire or in the certificate and a proof cannot be replayed. Unauthenticated connections are closed within 5 seconds. `sni` and `alpn` only make the handshake resemble ordinary HTTPS; they do not imitate a browser's TLS fingerprint.
* **Not wire-compatible** with `reverse-udp-over-tls`: this uses length-prefixed frames and has both peers dial. Peers must run the same version: a peer that predates the health probes drops the connection when it receives one, so update both ends together (the direct path is unaffected meanwhile).

**Notes**

* Both peers must run Auto-WG with `tls.enabled` and the same `secret`. Passive tunnels (`hunting: false`, e.g. a MikroTik peer) cannot use it.
* WireGuard carrying TCP flows over a TCP connection suffers from head-of-line blocking and retransmission interplay: treat TLS as a fallback, not a performance path. Packets are dropped, not queued without limit, when the link cannot keep up.
* **Pick a TCP range that nothing else uses.** With `iptables: true` every incoming TCP connection to a port in `tls.port_range` is redirected to the TLS listener (the same trick as the UDP range), so a service listening on one of those ports becomes unreachable from outside. The range defaults to the UDP `port_range`, which is wide (`20000-30000`) unless you set it: set a narrow `tls.port_range` when other services run on this host.
* The secret is masked in the web UI after saving; read it from the config file when setting up the other peer. The Generate button creates a random one.
* The dashboard shows the active path, the TLS link (dialed or accepted, remote address, traffic) and path switches in the history. The Force hunt and Quick Rebind buttons reconnect the TLS link while it is the active path.

---

## 🧪 Testing

Run the full automated test suite:

```bash
go test -v -cover ./...
```

---

## 📄 License

MIT License.
