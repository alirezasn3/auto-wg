# Auto-WG: Dynamic WireGuard Port Negotiator & DPI Bypass System

Auto-WG is an automated daemon written in Go that dynamically negotiates, probes, and updates WireGuard ports across censorship firewalls and stateful Deep Packet Inspection (DPI) environments.

---

## ⚡ Core Problem Solved

In high-censorship environments (e.g., Iran, Russia, China), DPI systems deploy stateful flow tracking:
1. **5-Tuple Flow Filtering**: DPI identifies the initial WireGuard handshake and blacklists the 5-tuple `(src_ip, src_port, dst_ip, dst_port, udp)`.
2. **Client Port (Source Port) Sensitivity**: Changing only the destination server port often fails because the DPI has flagged the *client's source port*. Auto-WG dynamically rotates **both** the client's local `ListenPort` and the remote `Endpoint` port.
3. **Asymmetric Reachability**: Sometimes Peer A can initiate connections to Peer B, but Peer B cannot reach Peer A (or vice versa). Auto-WG performs bidirectional candidate probing.
4. **Resilient Out-of-Band Signaling**: DPI often blocks single external channels. Auto-WG employs a **3-tier redundant signaling plane**:
   - **Tier 1 (Cloudflare Worker)**: Serverless HTTPS/KV rendezvous.
   - **Tier 2 (VPS Relay)**: Lightweight standalone Go HTTP/WebSocket daemon.
   - **Tier 3 (Direct P2P)**: Direct control channel over fallback TCP/HTTP ports.

---

## 🚀 Key Features

- **Two-Stage Reactive Recovery**:
  1. *Quick Local Rebind*: When connection drops, it immediately rotates the local `ListenPort` to break the DPI 5-tuple state without waiting for multi-peer coordination.
  2. *Coordinated Candidate Probe*: If the destination port is blocked, peers coordinate across the signaling plane, scan candidate ports with HMAC-authenticated UDP knocks, and atomically update WireGuard endpoints and listen ports.
- **Fast Failure Detection**: Combines passive `wgctrl` handshake inspection with active sub-10-second in-tunnel probing.
- **WireGuard & AmneziaWG Compatible**: Native Linux kernel netlink/UAPI via `wgctrl`, with full CLI fallback support for `awg` (AmneziaWG packet obfuscation).
- **Embedded Web Panel & Live Log Stream**: Built-in dark-themed web dashboard with live Server-Sent Events (SSE) log terminal, real-time telemetry, and manual trigger controls. Single binary with zero external dependencies!

---

## 📋 Architecture Overview

```
                                ┌───────────────────────────────────────────────┐
                                │          Tiered Signaling Plane               │
                                │   [1. Cloudflare]  [2. VPS Relay]  [3. Direct]│
                                └───────┬───────────────────────────────┬───────┘
                                        │ (Out-of-band HTTPS/Token)     │
                                        ▼                               ▼
                 ┌─────────────────────────────┐                 ┌─────────────────────────────┐
                 │       Auto-WG: Peer A       │                 │       Auto-WG: Peer B       │
                 │   (VPS / Remote Gateway)    │                 │       (Client / Node)       │
                 ├─────────────────────────────┤                 ├─────────────────────────────┤
                 │  - Monitor (Passive/Active) │                 │  - Monitor (Passive/Active) │
                 │  - Prober & Listener        │                 │  - Prober & Listener        │
                 │  - Web Dashboard (:8080)    │                 │  - Web Dashboard (:8081)    │
                 └──────────────┬──────────────┘                 └──────────────┬──────────────┘
                                │                                               │
                                │ ◄────── In-tunnel Health Ping (10s) ────────► │
                                │ ◄────── Fast UDP Candidate Knocks ──────────► │
                                │                                               │
                                ▼                                               ▼
                         ┌─────────────┐                                 ┌─────────────┐
                         │  WireGuard  │ ◄═════════════════════════════► │  WireGuard  │
                         │    (wg0)    │     Encrypted Tunnel Data       │    (wg0)    │
                         └─────────────┘                                 └─────────────┘
                         (Dynamic ListenPort & Endpoint via wgctrl / awg)
```

---

## 🛠️ Quick Start

### 1. Build Binaries
```bash
# Build the main Auto-WG daemon
go build -o autowg ./cmd/autowg

# (Optional) Build the VPS fallback relay
go build -o relay ./cmd/relay
```

---

### 2. Set Up Signaling (Pick one or all)

#### Option A: Cloudflare Worker (Recommended)
1. Go to the [Cloudflare Dashboard](https://dash.cloudflare.com) > **Workers & Pages** > **Create Worker**.
2. Paste the contents of `cloudflare/worker.js`.
3. Under **Settings** > **Variables**, add an environment variable `SECRET_TOKEN` with a strong random secret.
4. (Optional) Alternatively deploy via Wrangler:
   ```bash
   cd cloudflare
   wrangler deploy
   ```

#### Option B: Standalone VPS Relay
Run the included relay binary on any external server:
```bash
./relay -addr ":8443" -token "YourSharedSecretToken12345"
```

---

### 3. Configuration

Generate or edit your configuration files. See `configs/peer_a.example.yaml` and `configs/peer_b.example.yaml`.

#### Example `config.yaml` for Peer A:
```yaml
peer_id: "peer-a"
remote_peer_id: "peer-b"

wireguard:
  interface: "wg0"
  peer_public_key: "PEER_B_PUBLIC_KEY="
  remote_host: "peer-b.example.com"
  mode: "wgctrl" # or "awg" for AmneziaWG
  command: "wg"

signaling:
  secret_token: "YourSharedSecretToken12345"
  timeout: 5s
  cloudflare:
    enabled: true
    url: "https://auto-wg-signaling.YOUR_NAME.workers.dev"
  vps_relay:
    enabled: false
    url: "http://relay.example.com:8443"

monitor:
  check_interval: 3s
  handshake_timeout: 150s
  tunnel_ping:
    enabled: true
    target_ip: "10.0.0.2"
    interval: 2s
    failure_threshold: 4

negotiation:
  candidate_ports:
    - "53"
    - "80"
    - "123"
    - "443"
    - "853"
    - "500"
    - "4500"
    - "20000-20030"
  quick_rebind_first: true
  quick_rebind_timeout: 8s
  probe_timeout: 12s

web:
  enabled: true
  listen_addr: "0.0.0.0:8080"
```

---

### 4. Run the Daemon

```bash
# Run with root privileges (required for WireGuard netlink/wgctrl and low-number UDP ports)
sudo ./autowg -config config.yaml -debug
```

Visit the embedded Web Dashboard at `http://localhost:8080` to view live telemetry and streaming logs.

---

## 🖥️ Web Dashboard & Live Logs

The embedded Web Panel (`pkg/web`) requires no external assets or internet access:
- **Tunnel Status & 5-Tuple**: Displays interface name, local `ListenPort`, remote `Endpoint`, handshake age, and bytes transfer counters.
- **Signaling Health**: Shows real-time latency and connectivity status of each signaling backend (Cloudflare, VPS Relay, Direct).
- **Interactive Controls**:
  - `⚡ Quick Local Port Rebind`: Immediately rotates client port to reset DPI 5-tuple state.
  - `🔄 Force Full Port Negotiation`: Forces a complete candidate probe scan and renegotiates endpoints with peer.
- **Live Terminal Log Viewer**:
  - Colored log lines with component badges (`[WG]`, `[SIGNAL]`, `[PROBER]`, `[MONITOR]`, `[ENGINE]`).
  - Search filter, log-level filter, component filter, and auto-scroll toggle.

---

## 🛡️ AmneziaWG (`awg`) Support

If your DPI inspects WireGuard packet headers (148-byte handshake), configure Auto-WG to use AmneziaWG:
```yaml
wireguard:
  interface: "awg0"
  mode: "cli"
  command: "awg"
```
Auto-WG will execute `awg set awg0 listen-port <port> peer <pubkey> endpoint <host:port>`, preserving your custom junk packet count (`Jc`), junk size (`Jmin`/`Jmax`), and header magic bytes (`H1-H4`).

---

## ⚙️ Systemd Service Example

Create `/etc/systemd/system/autowg.service`:
```ini
[Unit]
Description=Auto-WG Dynamic WireGuard Port Negotiator
After=network.target wg-quick@wg0.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/auto-wg
ExecStart=/opt/auto-wg/autowg -config /opt/auto-wg/config.yaml
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now autowg
```

---

## 🧪 Running Tests

```bash
go test -v ./...
```
