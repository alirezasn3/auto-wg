# Auto-WG: Autonomous WireGuard Port Negotiator & DPI Bypass

Auto-WG is a high-performance Go application designed to keep WireGuard connections alive in hostile network environments with Deep Packet Inspection (DPI), stateful flow blocking, and asymmetric reachability.

By combining **autonomous symmetrical hunting** with **kernel-level `iptables` port-range forwarding**, Auto-WG allows two WireGuard peers to dynamically rotate connection 5-tuples and self-heal stalled links **without needing any external server, Cloudflare Worker, or out-of-band negotiator**.

---

## ⚡ Key Highlights

* **Zero-Negotiator Autonomous Hunting**: No external signaling relays, Cloudflare Workers, or rendezvous servers needed. Both peers monitor link state and recover 100% autonomously.
* **Kernel Port Forwarding (`go-iptables`)**: Automatically forwards a large range of UDP ports (e.g. `20000–30000`) directly to WireGuard's listening port using `iptables -t nat -A PREROUTING -j REDIRECT`. Linux `conntrack` automatically manages reverse translation.
* **Auto-Discovery of Peer Key & Target IP**: Neither `peer_public_key` nor `target_ip` is needed in `config.yaml`. Auto-WG queries the WireGuard interface (e.g. `wg0`) and automatically extracts the single peer's public key, current endpoint, and handshake statistics.
* **Client Source-Port Busting**: DPI often detects the WireGuard handshake and blacklists the client's source port. Auto-WG dynamically rotates both local `ListenPort` and remote `Endpoint` port, creating a fresh 5-tuple `(src_ip, new_src_port, dst_ip, new_dst_port, UDP)` to reset DPI filters.
* **Deterministic Anti-Collision Staggering**: Uses public key lexicographical comparison (`localPubKey < peerPubKey`) to coordinate turn-taking windows (e.g. 8s cycle) so peers do not collide or flap while hunting.
* **Integrated Web Dashboard**: Built-in modern, mobile-responsive web UI with live telemetry, handshake tracking, 5-tuple flow visualization, manual hunt triggers, and live streaming logs (SSE).
* **Standard WireGuard & AmneziaWG**: Works natively via `wgctrl` (Netlink / UAPI) and supports CLI mode (`wg` or `awg` for AmneziaWG obfuscated setups).

---

## 🏗️ How It Works

```
        ┌─────────────────────────────────────────────────────────────┐
        │  Peer A (e.g. 198.51.100.1)     Peer B (e.g. 203.0.113.1)   │
        │                                                             │
        │  iptables REDIRECT:             iptables REDIRECT:          │
        │  UDP 20000-30000 -> :51820      UDP 20000-30000 -> :51820   │
        └──────────────┬───────────────────────────────┬──────────────┘
                       │                               │
                       │ ◄─── Auto-WG Autonomous ────► │
                       │      5-Tuple Hunter Loop      │
                       │                               │
                       ▼                               ▼
                ┌──────────────┐                ┌──────────────┐
                │  WireGuard   │                │  WireGuard   │
                │  Interface   │                │  Interface   │
                │    (wg0)     │                │    (wg0)     │
                └──────────────┘                └──────────────┘
```

1. **Both peers forward a port range**: Auto-WG uses `github.com/coreos/go-iptables` to ensure `iptables -t nat -A PREROUTING -p udp --dport 20000:30000 -j REDIRECT --to-ports 51820` is installed.
2. **The receiver is always ready**: Because the entire range is forwarded, Peer A can send to *any* port between 20000 and 30000 on Peer B, and Peer B's WireGuard will automatically receive it on port 51820.
3. **Synchronized Failure Detection**: Both peers inspect WireGuard's `LatestHandshake` timestamp locally. When DPI drops the connection, both peers detect it at the exact same time (e.g., `time.Since(latestHandshake) > 15s`).
4. **Autonomous Port Hunt**:
   - **Local `ListenPort`**: Rotated to a new port in the forwarded range (generating a brand new source port for DPI).
   - **Remote `Endpoint` port**: Rotated to a port in the remote peer's range.
5. **Noise Protocol Simultaneous Handshake**: WireGuard natively handles bidirectional handshake initiation and updates its internal peer endpoint via roaming. Once a handshake completes, both daemons detect `LatestHandshake` updated and return to idle monitoring.

---

## ⚠️ Important Note on Peer Configuration

> [!IMPORTANT]
> **Single Peer Per Interface**: Auto-WG automatically detects the single peer configured on the WireGuard interface. You **do not** need to specify `peer_public_key` or `target_ip` in `config.yaml`.
> 
> If you have multiple WireGuard peers, configure each peer on its own separate interface (e.g., `wg0`, `wg1`) and run separate Auto-WG instances.

---

## 🚀 Quick Start

### 1. Build from Source

```bash
git clone https://github.com/alirezasn3/auto-wg.git
cd auto-wg
go build -o autowg ./cmd/autowg
```

### 2. Configure

Copy the example configuration for each peer:

```bash
cp configs/peer_a.example.yaml config.yaml
```

Minimal `config.yaml`:

```yaml
wireguard:
  interface: "wg0" # Name of your WireGuard interface
  mode: "wgctrl"   # "wgctrl" (native) or "cli"
  command: "wg"    # "wg" or "awg" (AmneziaWG)

iptables:
  enabled: true
  port_range: "20000-30000"

hunter:
  remote_port_range: "20000-30000"
  check_interval: 3s
  handshake_timeout: 15s
  cycle_timeout: 8s

web:
  enabled: true
  listen_addr: "0.0.0.0:8080"
```

### 3. Run or Install as a Service

Run directly with `sudo` (required for netlink device control, iptables, and ICMP ping):

```bash
sudo ./autowg -config config.yaml
```

To enable verbose debug logs:

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

### 4. Access Web Dashboard

Open `http://<your-server-ip>:8080` in your browser:
* **Dashboard View**: View live connection health, active 5-tuple flow, handshake age, transfer stats, and trigger manual port rebinds or hunts.
* **Live Logs View**: Real-time terminal streaming logs via Server-Sent Events (SSE).

---

## ⚙️ Configuration Reference

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `wireguard.interface` | string | `wg0` | WireGuard interface to manage |
| `wireguard.mode` | string | `wgctrl` | Native netlink (`wgctrl`) or executable (`cli`) |
| `wireguard.command` | string | `wg` | Command binary name (`wg` or `awg` for AmneziaWG) |
| `iptables.enabled` | bool | `true` | Auto-install iptables REDIRECT forwarding rule |
| `iptables.port_range` | string | `20000-30000` | Local port range forwarded to WireGuard listen port |
| `hunter.remote_port_range`| string | `20000-30000` | Remote peer's forwarded port range |
| `hunter.check_interval` | duration| `3s` | How often to poll WireGuard handshake age |
| `hunter.handshake_timeout`| duration| `60s` | Stale handshake threshold to trigger ping check |
| `hunter.cycle_timeout` | duration| `8s` | Alternating stagger window to prevent peer collision |
| `hunter.tunnel_ping.enabled` | bool | `true` | Active ICMP ping verification before hunting |
| `hunter.tunnel_ping.target_ip` | string | `""` | Remote peer's in-tunnel IP to ping (e.g. `10.0.0.1`). Auto-derived from `AllowedIPs` if omitted |
| `hunter.tunnel_ping.failure_threshold` | int | `3` | Consecutive ping timeouts before hunting |
| `web.enabled` | bool | `true` | Enable built-in web dashboard |
| `web.listen_addr` | string | `0.0.0.0:8080`| Web dashboard listen address |
| `web.username` | string | `""` | Optional HTTP Basic Auth username |
| `web.password` | string | `""` | Optional HTTP Basic Auth password |
| `web.allowed_ips`| list of string| `[]` | Whitelist of client IPs/CIDRs allowed to access panel (e.g. `["127.0.0.1", "192.168.0.0/16"]`). If empty, all IPs allowed |

---

## 🐧 Systemd Service

Auto-WG can be automatically installed or managed manually:

### Option A: Automatic (`--install` / `--uninstall`)

```bash
# Installs unit file, reloads systemd, enables and starts autowg
sudo ./autowg --install -config /path/to/config.yaml

# Stops service and removes unit file
sudo ./autowg --uninstall
```

### Option B: Manual Unit File

Create `/etc/systemd/system/autowg.service`:

```ini
[Unit]
Description=Auto-WG Dynamic WireGuard Port Negotiator
After=network.target wg-quick@wg0.service
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/auto-wg
ExecStart=/opt/auto-wg/autowg -config /opt/auto-wg/config.yaml
Restart=always
RestartSec=5s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now autowg
sudo systemctl status autowg
```

---

## 🧪 Running Tests

```bash
go test -v -cover ./...
```

---

## 📄 License

MIT License. Feel free to use and adapt in your projects.
