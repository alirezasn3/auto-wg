// Auto-WG Client Dashboard Logic

let autoScroll = true;
let allLogs = [];
const logContainer = document.getElementById("logContainer");
const terminal = document.getElementById("terminal");
const streamStatus = document.getElementById("streamStatus");

// Format bytes into readable string
function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

// Fetch Full Telemetry Status
async function updateStatus() {
  try {
    const res = await fetch("/api/status");
    if (!res.ok) return;
    const data = await res.json();

    // Peer IDs
    document.getElementById("localPeerId").textContent = data.peer_id || "-";
    document.getElementById("remotePeerId").textContent = data.remote_peer_id || "-";

    // Server time
    if (data.server_time) {
      const dt = new Date(data.server_time);
      document.getElementById("serverClock").textContent = dt.toLocaleTimeString();
    }

    // Tunnel Health
    const rep = data.tunnel_report || {};
    const badge = document.getElementById("tunnelStateBadge");
    badge.className = "status-pill";
    const state = rep.state || "UNKNOWN";
    badge.textContent = state;

    if (state === "HEALTHY") {
      badge.classList.add("status-healthy");
    } else if (state === "STALLED") {
      badge.classList.add("status-stalled");
    } else if (state === "ASYMMETRIC") {
      badge.classList.add("status-asymmetric");
    } else if (state === "NEGOTIATING") {
      badge.classList.add("status-negotiating");
    } else {
      badge.classList.add("status-unknown");
    }

    document.getElementById("statusReason").textContent = rep.state_reason || "All systems operational";
    document.getElementById("wgInterface").textContent = rep.interface || "-";

    if (rep.handshake_secs > 0) {
      document.getElementById("lastHandshake").textContent = `${rep.handshake_secs}s ago (${new Date(rep.last_handshake).toLocaleTimeString()})`;
    } else {
      document.getElementById("lastHandshake").textContent = "Never";
    }

    // 5-Tuple
    document.getElementById("localPort").textContent = rep.local_port || "-";
    document.getElementById("remoteEndpoint").textContent = rep.peer_endpoint || "Unset";
    document.getElementById("transferStats").textContent = `${formatBytes(rep.rx_bytes || 0)} / ${formatBytes(rep.tx_bytes || 0)}`;

    // Candidate Ports
    if (data.candidate_ports && data.candidate_ports.length > 0) {
      document.getElementById("candidateChips").textContent = data.candidate_ports.slice(0, 10).join(", ") + (data.candidate_ports.length > 10 ? `... (+${data.candidate_ports.length - 10})` : "");
    }

    // Signaling Backends
    const sigContainer = document.getElementById("signalingList");
    if (data.signaling_backends && data.signaling_backends.length > 0) {
      sigContainer.innerHTML = "";
      data.signaling_backends.forEach(ch => {
        const item = document.createElement("div");
        item.className = "signaling-item";
        const isUp = ch.healthy;
        const statusClass = isUp ? "channel-up" : "channel-down";
        const latency = ch.latency_ms ? `${ch.latency_ms}ms` : "-";
        item.innerHTML = `
          <span><strong>${ch.name}</strong> (${latency})</span>
          <span class="channel-status-badge ${statusClass}">${isUp ? "HEALTHY" : "OFFLINE"}</span>
        `;
        sigContainer.appendChild(item);
      });
    }
  } catch (err) {
    console.error("Status fetch error:", err);
  }
}

// Render log entry element
function createLogElement(entry) {
  const row = document.createElement("div");
  row.className = "log-entry";
  row.dataset.level = entry.level;
  row.dataset.component = entry.component;
  row.dataset.message = entry.message.toLowerCase();

  const dt = new Date(entry.timestamp);
  const timeStr = dt.toTimeString().split(" ")[0] + "." + String(dt.getMilliseconds()).padStart(3, "0");

  row.innerHTML = `
    <span class="log-time">${timeStr}</span>
    <span class="log-level log-level-${entry.level}">[${entry.level}]</span>
    <span class="log-component">[${entry.component}]</span>
    <span class="log-msg">${escapeHtml(entry.message)}</span>
  `;

  return row;
}

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// Append log to view with filter checks
function appendLog(entry) {
  allLogs.push(entry);
  if (allLogs.length > 1500) {
    allLogs.shift();
  }

  if (matchesFilter(entry)) {
    const el = createLogElement(entry);
    logContainer.appendChild(el);
    if (autoScroll) {
      terminal.scrollTop = terminal.scrollHeight;
    }
  }
}

// Check if entry satisfies active filters
function matchesFilter(entry) {
  const levelFilter = document.getElementById("filterLevel").value;
  const compFilter = document.getElementById("filterComponent").value;
  const searchFilter = document.getElementById("filterSearch").value.toLowerCase().trim();

  // Level check
  if (levelFilter === "INFO" && entry.level === "DEBUG") return false;
  if (levelFilter === "WARN" && (entry.level === "DEBUG" || entry.level === "INFO")) return false;
  if (levelFilter === "ERROR" && entry.level !== "ERROR") return false;

  // Component check
  if (compFilter !== "ALL" && entry.component !== compFilter) return false;

  // Search query
  if (searchFilter && !entry.message.toLowerCase().includes(searchFilter)) return false;

  return true;
}

// Re-render all logs when filters change
function refilterLogs() {
  logContainer.innerHTML = "";
  allLogs.forEach(entry => {
    if (matchesFilter(entry)) {
      logContainer.appendChild(createLogElement(entry));
    }
  });
  if (autoScroll) {
    terminal.scrollTop = terminal.scrollHeight;
  }
}

// Connect SSE stream for real-time live logs
function connectLogStream() {
  const evtSource = new EventSource("/api/logs/stream");

  evtSource.onopen = () => {
    streamStatus.textContent = "● Live Stream Active";
    streamStatus.style.color = "var(--success)";
  };

  evtSource.onmessage = (event) => {
    try {
      const entry = JSON.parse(event.data);
      appendLog(entry);
    } catch (e) {}
  };

  evtSource.onerror = () => {
    streamStatus.textContent = "○ Reconnecting...";
    streamStatus.style.color = "var(--warning)";
    evtSource.close();
    setTimeout(connectLogStream, 3000);
  };
}

// Load initial log history
async function loadInitialLogs() {
  try {
    const res = await fetch("/api/logs");
    if (!res.ok) return;
    const entries = await res.json();
    entries.forEach(appendLog);
  } catch (err) {}
}

// Event Listeners
document.getElementById("btnAutoScroll").addEventListener("click", function() {
  autoScroll = !autoScroll;
  this.textContent = `Auto-scroll: ${autoScroll ? "ON" : "OFF"}`;
  this.classList.toggle("btn-active", autoScroll);
  if (autoScroll) terminal.scrollTop = terminal.scrollHeight;
});

document.getElementById("btnClearLogs").addEventListener("click", () => {
  allLogs = [];
  logContainer.innerHTML = "";
});

document.getElementById("filterLevel").addEventListener("change", refilterLogs);
document.getElementById("filterComponent").addEventListener("change", refilterLogs);
document.getElementById("filterSearch").addEventListener("input", refilterLogs);

// Action: Quick Rebind
document.getElementById("btnRebind").addEventListener("click", async function() {
  if (!confirm("Trigger Quick Client ListenPort Rebind to reset DPI 5-tuple tracking?")) return;
  this.disabled = true;
  try {
    await fetch("/api/actions/rebind", { method: "POST" });
  } finally {
    setTimeout(() => { this.disabled = false; }, 3000);
  }
});

// Action: Full Negotiation
document.getElementById("btnRenegotiate").addEventListener("click", async function() {
  if (!confirm("Force Full Candidate Port Negotiation with remote peer?")) return;
  this.disabled = true;
  try {
    await fetch("/api/actions/renegotiate", { method: "POST" });
  } finally {
    setTimeout(() => { this.disabled = false; }, 5000);
  }
});

// Initialization
loadInitialLogs();
connectLogStream();
updateStatus();
setInterval(updateStatus, 2000);
