// Auto-WG Dashboard & Settings Application

class AutoWGApp {
  constructor() {
    this.logs = [];
    this.autoScroll = true;
    this.eventSource = null;
    this.statusTimer = null;

    this.initElements();
    this.initTabs();
    this.initActions();
    this.initSettings();
    this.initLogControls();
    this.startStatusPolling();
    this.connectLogStream();
    this.loadSettings();
  }

  initElements() {
    // Header & Clock
    this.serverClock = document.getElementById('serverClock');

    // Telemetry Elements
    this.stateBadge = document.getElementById('tunnelStateBadge');
    this.statusReason = document.getElementById('statusReason');
    this.wgInterface = document.getElementById('wgInterface');
    this.lastHandshake = document.getElementById('lastHandshake');
    this.staggerRole = document.getElementById('staggerRole');
    this.localPort = document.getElementById('localPort');
    this.remoteEndpoint = document.getElementById('remoteEndpoint');
    this.transferStats = document.getElementById('transferStats');
    this.portRangeSummary = document.getElementById('portRangeSummary');
    this.targetIP = document.getElementById('targetIP');
    this.peerPubKey = document.getElementById('peerPubKey');
    this.localPubKey = document.getElementById('localPubKey');
    this.iptablesBadge = document.getElementById('iptablesStatusBadge');
    this.huntStats = document.getElementById('huntStats');

    // Logs & Terminal
    this.terminal = document.getElementById('terminal');
    this.logContainer = document.getElementById('logContainer');
    this.miniLogContainer = document.getElementById('miniLogContainer');
    this.streamStatus = document.getElementById('streamStatus');
    this.streamStatusMini = document.getElementById('streamStatusMini');
    this.filterLevel = document.getElementById('filterLevel');
    this.filterComponent = document.getElementById('filterComponent');
    this.filterSearch = document.getElementById('filterSearch');
    this.btnAutoScroll = document.getElementById('btnAutoScroll');
    this.btnClearLogs = document.getElementById('btnClearLogs');

    // Action Buttons
    this.btnRebind = document.getElementById('btnRebind');
    this.btnHunt = document.getElementById('btnHunt');

    // Toast
    this.toast = document.getElementById('toast');
  }

  initTabs() {
    const tabs = document.querySelectorAll('.nav-tab');
    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        tabs.forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

        tab.classList.add('active');
        const tabId = tab.getAttribute('data-tab');
        const content = document.getElementById(`tab-${tabId}`);
        if (content) {
          content.classList.add('active');
        }

        if (tabId === 'settings') {
          this.loadSettings();
        }
      });
    });
  }

  showToast(message, isError = false) {
    if (!this.toast) return;
    this.toast.textContent = message;
    this.toast.className = isError ? 'toast error' : 'toast';
    setTimeout(() => {
      this.toast.className = 'toast hidden';
    }, 3500);
  }

  initActions() {
    this.btnRebind.addEventListener('click', async () => {
      this.btnRebind.disabled = true;
      try {
        const res = await fetch('/api/actions/rebind', { method: 'POST' });
        if (res.ok) {
          this.showToast('⚡ Local source port rebind initiated');
        } else {
          this.showToast('Failed to trigger rebind', true);
        }
      } catch (err) {
        this.showToast('Network error: ' + err.message, true);
      } finally {
        setTimeout(() => { this.btnRebind.disabled = false; }, 1000);
      }
    });

    this.btnHunt.addEventListener('click', async () => {
      this.btnHunt.disabled = true;
      try {
        const res = await fetch('/api/actions/hunt', { method: 'POST' });
        if (res.ok) {
          this.showToast('🔄 5-Tuple port hunt initiated');
        } else {
          this.showToast('Failed to trigger port hunt', true);
        }
      } catch (err) {
        this.showToast('Network error: ' + err.message, true);
      } finally {
        setTimeout(() => { this.btnHunt.disabled = false; }, 1000);
      }
    });
  }

  async loadSettings() {
    try {
      const res = await fetch('/api/config');
      if (!res.ok) return;
      const cfg = await res.json();

      document.getElementById('cfgInterface').value = cfg.wireguard?.interface || 'wg0';
      document.getElementById('cfgMode').value = cfg.wireguard?.mode || 'wgctrl';
      document.getElementById('cfgCommand').value = cfg.wireguard?.command || 'wg';

      document.getElementById('cfgIptablesEnabled').checked = cfg.iptables?.enabled !== false;
      document.getElementById('cfgLocalPortRange').value = cfg.iptables?.port_range || '20000-30000';

      document.getElementById('cfgRemotePortRange').value = cfg.hunter?.remote_port_range || '20000-30000';
      document.getElementById('cfgHandshakeTimeout').value = formatDuration(cfg.hunter?.handshake_timeout) || '15s';
      document.getElementById('cfgCheckInterval').value = formatDuration(cfg.hunter?.check_interval) || '3s';
      document.getElementById('cfgCycleTimeout').value = formatDuration(cfg.hunter?.cycle_timeout) || '8s';

      document.getElementById('cfgWebListen').value = cfg.web?.listen_addr || '0.0.0.0:8080';
      document.getElementById('cfgWebUsername').value = cfg.web?.username || '';
      document.getElementById('cfgWebPassword').value = cfg.web?.password || '';
    } catch (err) {
      console.error('Failed to load settings:', err);
    }
  }

  initSettings() {
    const form = document.getElementById('settingsForm');
    const saveStatus = document.getElementById('saveStatus');

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      saveStatus.textContent = 'Saving...';
      saveStatus.style.color = 'var(--accent)';

      const payload = {
        wireguard: {
          interface: document.getElementById('cfgInterface').value.trim(),
          mode: document.getElementById('cfgMode').value,
          command: document.getElementById('cfgCommand').value
        },
        iptables: {
          enabled: document.getElementById('cfgIptablesEnabled').checked,
          port_range: document.getElementById('cfgLocalPortRange').value.trim()
        },
        hunter: {
          remote_port_range: document.getElementById('cfgRemotePortRange').value.trim(),
          handshake_timeout: parseDuration(document.getElementById('cfgHandshakeTimeout').value),
          check_interval: parseDuration(document.getElementById('cfgCheckInterval').value),
          cycle_timeout: parseDuration(document.getElementById('cfgCycleTimeout').value),
          tunnel_ping: {
            enabled: false
          }
        },
        web: {
          enabled: true,
          listen_addr: document.getElementById('cfgWebListen').value.trim(),
          username: document.getElementById('cfgWebUsername').value.trim(),
          password: document.getElementById('cfgWebPassword').value.trim()
        }
      };

      try {
        const res = await fetch('/api/config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });

        if (res.ok) {
          saveStatus.textContent = '✓ Saved and applied!';
          saveStatus.style.color = 'var(--success)';
          this.showToast('Settings saved to config.yaml and applied live!');
        } else {
          const errText = await res.text();
          saveStatus.textContent = '✗ ' + errText;
          saveStatus.style.color = 'var(--danger)';
          this.showToast('Save failed: ' + errText, true);
        }
      } catch (err) {
        saveStatus.textContent = '✗ ' + err.message;
        saveStatus.style.color = 'var(--danger)';
        this.showToast('Error: ' + err.message, true);
      } finally {
        setTimeout(() => { saveStatus.textContent = ''; }, 4000);
      }
    });
  }

  startStatusPolling() {
    this.pollStatus();
    this.statusTimer = setInterval(() => this.pollStatus(), 2000);
  }

  async pollStatus() {
    try {
      const res = await fetch('/api/status');
      if (!res.ok) return;
      const data = await res.json();
      this.renderStatus(data);
    } catch (err) {
      console.warn('Status poll error:', err);
    }
  }

  renderStatus(data) {
    // Clock
    this.serverClock.textContent = new Date().toLocaleTimeString();

    // State Badge
    const state = data.state || 'UNKNOWN';
    this.stateBadge.textContent = state;
    this.stateBadge.className = 'status-pill status-' + state.toLowerCase();

    if (state === 'CONNECTED') {
      this.statusReason.textContent = 'Tunnel healthy; packets flowing';
    } else if (state === 'HUNTING') {
      this.statusReason.textContent = `Hunting ports (Attempt #${data.current_attempt || 1})`;
    } else if (state === 'STALLED') {
      this.statusReason.textContent = data.last_hunt_reason || 'Handshake stalled';
    } else {
      this.statusReason.textContent = 'Waiting for interface...';
    }

    // Interface & Handshake
    this.wgInterface.textContent = data.interface || '-';

    if (data.handshake_age_seconds !== undefined && data.handshake_age_seconds > 0) {
      const age = Math.round(data.handshake_age_seconds);
      if (age < 60) {
        this.lastHandshake.textContent = `${age}s ago`;
      } else {
        this.lastHandshake.textContent = `${Math.floor(age / 60)}m ${age % 60}s ago`;
      }
    } else {
      this.lastHandshake.textContent = 'Never / Waiting';
    }

    this.staggerRole.textContent = data.is_primary ? 'Primary (Cycle 0)' : 'Secondary (Cycle 1)';

    // Flow
    this.localPort.textContent = data.local_port > 0 ? `:${data.local_port}` : '-';
    this.remoteEndpoint.textContent = (data.target_ip && data.remote_port) ? `${data.target_ip}:${data.remote_port}` : '-';

    // Transfer
    this.transferStats.textContent = `${formatBytes(data.receive_bytes)} / ${formatBytes(data.transmit_bytes)}`;

    // Port Range Summary
    this.portRangeSummary.textContent = `Local: ${data.local_port_range || '-'} | Remote: ${data.remote_port_range || '-'}`;

    // Target IP & Keys
    this.targetIP.textContent = data.target_ip || 'Auto-discovering...';
    this.peerPubKey.textContent = data.peer_public_key || 'Auto-discovering...';
    this.localPubKey.textContent = data.local_public_key || '-';

    // iptables Status
    if (data.iptables_active) {
      this.iptablesBadge.textContent = `ACTIVE (${data.local_port_range})`;
      this.iptablesBadge.className = 'badge-active';
    } else {
      this.iptablesBadge.textContent = 'OFF / Non-Linux';
      this.iptablesBadge.className = 'badge-neutral';
    }

    // Hunt Stats
    this.huntStats.textContent = `${data.total_hunts || 0} hunts (${data.successful_hunts || 0} recovered)`;
  }

  connectLogStream() {
    if (this.eventSource) {
      this.eventSource.close();
    }

    this.eventSource = new EventSource('/api/logs/stream');

    this.eventSource.onopen = () => {
      this.streamStatus.textContent = '● Live Stream Connected';
      this.streamStatus.style.color = 'var(--success)';
      if (this.streamStatusMini) {
        this.streamStatusMini.textContent = '● Live';
        this.streamStatusMini.style.color = 'var(--success)';
      }
    };

    this.eventSource.onmessage = (e) => {
      try {
        const entry = JSON.parse(e.data);
        this.appendLogEntry(entry);
      } catch (err) {
        console.error('Parse log entry:', err);
      }
    };

    this.eventSource.onerror = () => {
      this.streamStatus.textContent = '● Stream Disconnected (Retrying...)';
      this.streamStatus.style.color = 'var(--danger)';
      if (this.streamStatusMini) {
        this.streamStatusMini.textContent = '● Offline';
        this.streamStatusMini.style.color = 'var(--danger)';
      }
    };
  }

  appendLogEntry(entry) {
    this.logs.push(entry);
    if (this.logs.length > 500) {
      this.logs.shift();
    }

    this.renderLogItem(entry, this.logContainer);
    if (this.miniLogContainer) {
      this.renderLogItem(entry, this.miniLogContainer);
      if (this.miniLogContainer.children.length > 10) {
        this.miniLogContainer.removeChild(this.miniLogContainer.firstChild);
      }
      this.miniLogContainer.scrollTop = this.miniLogContainer.scrollHeight;
    }

    if (this.autoScroll && this.terminal) {
      this.terminal.scrollTop = this.terminal.scrollHeight;
    }
  }

  renderLogItem(entry, container) {
    if (!container) return;

    if (!this.matchesFilter(entry) && container === this.logContainer) {
      return;
    }

    const row = document.createElement('div');
    row.className = 'log-entry';

    const timeStr = entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : '';
    row.innerHTML = `
      <span class="log-time">${timeStr}</span>
      <span class="log-level log-level-${entry.level}">${entry.level}</span>
      <span class="log-component">[${entry.component}]</span>
      <span class="log-msg">${escapeHtml(entry.message)}</span>
    `;

    container.appendChild(row);
  }

  matchesFilter(entry) {
    const levelFilter = this.filterLevel?.value || 'ALL';
    const compFilter = this.filterComponent?.value || 'ALL';
    const searchFilter = (this.filterSearch?.value || '').toLowerCase();

    if (levelFilter === 'INFO' && entry.level === 'DEBUG') return false;
    if (levelFilter === 'WARN' && (entry.level === 'DEBUG' || entry.level === 'INFO')) return false;
    if (levelFilter === 'ERROR' && entry.level !== 'ERROR') return false;

    if (compFilter !== 'ALL' && entry.component !== compFilter) return false;

    if (searchFilter && !entry.message.toLowerCase().includes(searchFilter)) {
      return false;
    }

    return true;
  }

  initLogControls() {
    const rerender = () => {
      if (!this.logContainer) return;
      this.logContainer.innerHTML = '';
      for (const entry of this.logs) {
        if (this.matchesFilter(entry)) {
          this.renderLogItem(entry, this.logContainer);
        }
      }
      if (this.autoScroll && this.terminal) {
        this.terminal.scrollTop = this.terminal.scrollHeight;
      }
    };

    this.filterLevel?.addEventListener('change', rerender);
    this.filterComponent?.addEventListener('change', rerender);
    this.filterSearch?.addEventListener('input', rerender);

    this.btnAutoScroll?.addEventListener('click', () => {
      this.autoScroll = !this.autoScroll;
      this.btnAutoScroll.textContent = `Auto-scroll: ${this.autoScroll ? 'ON' : 'OFF'}`;
      this.btnAutoScroll.className = `btn btn-sm ${this.autoScroll ? 'btn-active' : ''}`;
    });

    this.btnClearLogs?.addEventListener('click', () => {
      this.logs = [];
      if (this.logContainer) this.logContainer.innerHTML = '';
      if (this.miniLogContainer) this.miniLogContainer.innerHTML = '';
    });
  }
}

// Helpers
function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return (bytes / Math.pow(k, i)).toFixed(1) + ' ' + sizes[i];
}

function formatDuration(ns) {
  if (!ns) return '';
  const seconds = ns / 1e9;
  return `${seconds}s`;
}

function parseDuration(str) {
  if (!str) return 3e9;
  str = str.trim().toLowerCase();
  if (str.endsWith('s')) {
    const sec = parseFloat(str.replace('s', ''));
    return Math.round(sec * 1e9);
  }
  if (str.endsWith('m')) {
    const min = parseFloat(str.replace('m', ''));
    return Math.round(min * 60 * 1e9);
  }
  const val = parseFloat(str);
  return Math.round(val * 1e9);
}

function escapeHtml(str) {
  return (str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

document.addEventListener('DOMContentLoaded', () => {
  new AutoWGApp();
});
