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
| `name` | string | `""` | Human-friendly alias displayed on the web dashboard |
| `target_ip` | string | `""` | Single remote destination IP or fallback |
| `target_ips` | list of string | `[]` | Candidate destination IPs / domain names (IPv4 & IPv6) rotated during hunting |
| `port_range` | string | `20000-30000` | Local port range forwarded to WireGuard listen port |
| `remote_port_range` | string | `20000-30000` | Remote peer's forwarded port range |
| `iptables` | bool | `true` | Automatically manage `iptables -t nat -A PREROUTING` redirect rule |
| `check_interval` | duration | `3s` | Interval between handshake and reachability polls |
| `handshake_timeout` | duration | `60s` | Stale handshake threshold triggering reachability checks |
| `cycle_timeout` | duration | `8s` | Alternating stagger window to prevent peer collision |
| `tunnel_ping.enabled` | bool | `true` | Active ICMP ping verification before hunting |
| `tunnel_ping.target_ip` | string | `""` | In-tunnel IP of the remote peer to ping |
| `tunnel_ping.failure_threshold` | int | `3` | Consecutive ping timeouts before declaring link down |
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

## 🧪 Testing

Run the full automated test suite:

```bash
go test -v -cover ./...
```

---

## 📄 License

MIT License.
