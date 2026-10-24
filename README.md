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
* **Three transports per interface**: `direct` (plain UDP with port hunting), `tls` (WireGuard packets inside a TLS 1.3 connection) and `ssh` (inside a genuine OpenSSH session, using the real `ssh` client and the peer's real `sshd`). Both TCP transports use port ranges like the UDP one, health-check the connection and can pad packet sizes. You create one interface per transport and switch between them yourself. Works with stock WireGuard and AmneziaWG. See [WireGuard over TLS or SSH](#-wireguard-over-tls-or-ssh).
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
| `iptables` | bool | `false` | Let Auto-WG manage the NAT redirect rules described under [Firewall rules](#-firewall-rules-auto-wg-creates). **Off when the key is missing**; the web editor and the config generated on first run write `true` |
| `check_interval` | duration | `3s` | Interval between handshake and reachability polls |
| `handshake_timeout` | duration | `60s` | Stale handshake threshold triggering reachability checks |
| `cycle_timeout` | duration | `8s` | Alternating stagger window to prevent peer collision |
| `tunnel_ping.enabled` | bool | `true` | Active ICMP ping verification before hunting |
| `tunnel_ping.target_ip` | string | `""` | In-tunnel IP of the remote peer to ping |
| `tunnel_ping.failure_threshold` | int | `3` | Consecutive ping timeouts before declaring link down |
| `transport` | string | `direct` | How WireGuard's packets travel: `direct` (UDP), `tls` or `ssh`. See [WireGuard over TLS or SSH](#-wireguard-over-tls-or-ssh). With `tls` or `ssh`, `port_range` and `remote_port_range` are **TCP** ranges and the tunnel does not hunt UDP ports |
| `tls.secret` / `ssh.secret` | string | **Required** | Shared secret, identical on both peers, at least 16 characters |
| `*.relay_port` | int | `0` (auto) | Loopback UDP port WireGuard talks to |
| `*.dial_interval` | duration | `1s` | Pause between dial attempts while no link is up |
| `*.health_interval` | duration | `3s` | Pause between health probes (ping/pong) on a live link |
| `*.health_timeout` | duration | `2s` | How long a probe may stay unanswered |
| `*.health_failures` | int | `3` | Consecutive unanswered probes after which the connection is dropped and rebuilt |
| `*.reconnect_after` | duration | `10s` | WireGuard dead this long on a link that passes its probes: build a new connection (repeats every `reconnect_after`) |
| `*.padding` | string | `off` | `off`, `bucket` (every write rounded up to 128/256/512/1024/1500 bytes) or `random` (0-256 random bytes appended) |
| `tls.sni` | string | `""` | Optional server name sent in the TLS handshake (also the certificate name) |
| `tls.alpn` | list of string | `[]` | Optional ALPN protocols, e.g. `["h2", "http/1.1"]` |
| `ssh.user` | string | `autowg` | Account on the peer's sshd |
| `ssh.identity_file` | string | `""` | Private key used to log in. Setting it makes this peer **dial**; without it the peer only accepts |
| `ssh.host_key` | string | `""` | The peer sshd's public key (`ssh-ed25519 AAAA...`); required with `identity_file`, checked strictly |
| `ssh.ssh_path` | string | `ssh` | OpenSSH client binary |
| `ssh.sshd_port` | int | `22` | Port this host's sshd listens on; the local TCP range is redirected there |
| `ssh.link_port` | int | `40022` | Loopback TCP port the peer's ssh forwards to (`-W 127.0.0.1:link_port`); the same on both peers |
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

## 🔐 WireGuard over TLS or SSH

When DPI blocks WireGuard itself, an interface can carry its packets inside a TCP connection instead. Each interface has **one** transport, chosen by `transport:`; Auto-WG does not switch between transports. To have direct, TLS and SSH available, create three WireGuard interfaces (same keys are fine, different listen ports and addresses) and three `tunnels[]` entries, and decide yourself which one carries traffic, for example with the routing manager or your own routes.

```yaml
tunnels:
  - interface: "wg-direct"             # transport: direct is the default
    port_range: "20000-24999"          # UDP
    remote_port_range: "20000-24999"
    target_ips: ["198.51.100.1"]

  - interface: "wg-tls"
    transport: tls
    port_range: "443-8443"             # TCP
    remote_port_range: "443-8443"
    target_ips: ["198.51.100.1"]
    tls:
      secret: "<the same long random string on both peers>"
      padding: bucket                  # optional
      sni: "www.example.com"           # optional
      alpn: ["h2", "http/1.1"]         # optional

  - interface: "wg-ssh"
    transport: ssh
    port_range: "2000-2999"            # TCP, redirected to sshd
    remote_port_range: "2000-2999"
    target_ips: ["198.51.100.1"]
    ssh:
      secret: "<the same long random string on both peers>"
      user: autowg
      identity_file: /etc/auto-wg/id_ed25519
      host_key: "ssh-ed25519 AAAA..."  # the peer's /etc/ssh/ssh_host_ed25519_key.pub
      sshd_port: 22                    # this host's sshd
      link_port: 40022
      padding: random
```

**What is the same for both TCP transports**

* **Port ranges like the UDP side.** Each peer keeps dialing a random port of the peer's `remote_port_range` from a random source port of its own `port_range`; the local range is redirected by iptables (`iptables: true`). Each failed attempt changes both ports.
* **One verified connection.** Both peers dial; the connection the primary peer (lower public key) dialed wins when two come up. A new connection must first echo four probe frames sized like WireGuard's initiation (148 bytes), response (92), keepalive (32) and a near-full packet before it is used; afterwards each side pings with random sizes every `health_interval` and `health_failures` missed probes drop it. Probes are a control frame type that never reaches WireGuard. If WireGuard stays dead for `reconnect_after` on a link that still passes its probes, the connection is rebuilt (and again every `reconnect_after`); with no connection the TLS listener also moves to a new port.
* **Auto-WG points WireGuard at a loopback relay.** It sets the peer's endpoint to `127.0.0.1:<relay port>` itself. WireGuard keeps its configured `ListenPort`; Auto-WG does not rotate UDP ports on these interfaces, and the Force hunt / Quick Rebind buttons reconnect the link instead.
* **Padding.** `bucket` rounds every write up to one of 128/256/512/1024/1500 bytes and `random` appends 0-256 random bytes, using filler frames the peer discards. It hides WireGuard's fixed message sizes (148/92/32) from a size-based classifier at the cost of bandwidth. It does not change timing.
* **Lower the interface MTU** (for example `MTU = 1280`): a TCP connection under a tunnel that carries TCP suffers head-of-line blocking and retransmission interplay, so treat these as transports for getting through, not for speed. Packets are dropped, not queued without limit, when the link cannot keep up.
* Both peers must run Auto-WG and the same version. Passive tunnels (`hunting: false`, e.g. a MikroTik peer) cannot use them. The secret is masked in the web UI after saving; read it from the config file when setting up the other peer.

**TLS**

TLS 1.3 with an ephemeral self-signed certificate, then both peers prove knowledge of `tls.secret` with an HMAC bound to the TLS session (the secret never appears on the wire and a proof cannot be replayed). `sni` and `alpn` only make the handshake resemble ordinary HTTPS; they do not imitate a browser's TLS fingerprint. Auto-WG listens on a random port of the range and the range is redirected to it.

**SSH**

This transport runs the **real OpenSSH client** against the peer's **real sshd**, so the bytes on the wire (banner, key exchange, algorithms) are exactly what your installed OpenSSH produces; Auto-WG does not imitate SSH, it uses it. What it does itself is open the TCP connection (source port from `port_range`, destination from `remote_port_range`) and hand it to `ssh` through a one-shot loopback proxy; `ssh -W 127.0.0.1:<link_port>` then makes the peer's sshd connect to the link listener of the peer's Auto-WG, and the frame stream runs through that session. Auto-WG adds its own proof (`ssh.secret`) on top of SSH's authentication.

Setup, on every peer that should accept connections:

```bash
# an account that can only forward to the link port
useradd -m -s /usr/sbin/nologin autowg
install -d -m 700 -o autowg -g autowg /home/autowg/.ssh
echo 'restrict,port-forwarding,permitopen="127.0.0.1:40022" ssh-ed25519 AAAA...peer-public-key' \
  > /home/autowg/.ssh/authorized_keys
chown autowg: /home/autowg/.ssh/authorized_keys && chmod 600 /home/autowg/.ssh/authorized_keys
```

On the dialing peer create the key pair (`ssh-keygen -t ed25519 -N '' -f /etc/auto-wg/id_ed25519`, no passphrase: Auto-WG runs ssh in batch mode), put its public key into the other peer's `authorized_keys`, and set `host_key` to the other peer's `/etc/ssh/ssh_host_ed25519_key.pub`. The host key is checked strictly. A peer without `identity_file` only accepts; give both peers an identity to let either side dial. With `iptables: true` the local TCP range is redirected to `sshd_port`, so ordinary SSH logins on a port inside the range stop working: pick a range that nothing else uses. The `ssh` binary must be installed on every dialing peer; Auto-WG refuses to start the link without it.

What this does not do: it cannot make a long-lived, constantly busy SSH session look like an interactive one. A DPI that classifies by traffic shape rather than by protocol will still see a steady stream of packet-sized records inside the session; padding and the range hopping reduce, not remove, that signal. I have not tested it against a real DPI.

**Upgrading from the old `tls:` fallback.** A tunnel with `tls.enabled: true` and no `transport` is read as `transport: tls` (its `tls.port_range` / `remote_port_range` become the tunnel's ranges) and no longer switches back to direct on its own: automatic path switching was removed. Rewrite such a tunnel as two interfaces if you want both.

The dashboard shows the transport, the link (dialed or accepted, remote address, round-trip time, traffic, lost probes and rebuilds) and a "link up since" timer.

---

## 🧱 Firewall rules Auto-WG creates

Only for tunnels with `iptables: true`, and only in the NAT table (`iptables` and `ip6tables`, `-t nat`, chain `PREROUTING`):

```
-p udp --dport <port_range> -m comment --comment "autowg-<iface>"     -j REDIRECT --to-ports <WireGuard listen port>   # transport: direct
-p tcp --dport <port_range> -m comment --comment "autowg-<iface>-tls" -j REDIRECT --to-ports <TLS listener port>       # transport: tls
-p tcp --dport <port_range> -m comment --comment "autowg-<iface>-ssh" -j REDIRECT --to-ports <ssh.sshd_port>           # transport: ssh
```

List them with `iptables -t nat -S PREROUTING | grep autowg-` (and `ip6tables`). Nothing else is added: no filter rules, no `MASQUERADE`, no `ufw` or `nft`, no sysctl changes. Your own `post_up` / `pre_down` commands are the only other firewall-related things that run.

* **Lifecycle.** Created at startup, replaced each time the WireGuard listen port (or the TLS listener) moves, removed on clean shutdown, when a tunnel is removed, and when `iptables` is switched off or the transport changes.
* **Leftovers are cleaned up.** After a crash or `kill -9` the rules stay in the kernel; at startup Auto-WG now removes every `autowg-*` rule it does not manage (including ones of tunnels you dropped from the config) before applying its own. Rules without that comment prefix are never touched. Do not run two Auto-WG instances on one host: each would remove the other's rules at startup.
* **Mind the range.** The redirect catches every incoming packet to a port in the range, on every interface (`port_range` defaults to `20000-30000`), so other services on those ports become unreachable from outside. Use narrow ranges on hosts that run other services.

---

## 🧪 Testing

Run the full automated test suite:

```bash
go test -v -cover ./...
```

---

## 📄 License

MIT License.
