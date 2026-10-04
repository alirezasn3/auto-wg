// Auto-WG Modernized Dashboard Application

class AutoWGApp {
  constructor() {
    this.logs = [];
    this.autoScroll = true;
    this.eventSource = null;
    this.statusTimer = null;
    this.currentData = null;
    this.lastPollTimestamp = Date.now();

    this.initElements();
    this.initTabs();
    this.initActions();
    this.initCopyButtons();
    this.initLogControls();
    this.startStatusPolling();
    this.connectLogStream();
  }

  initElements() {
    // Header & Clock
    this.serverClock = document.getElementById('serverClock');

    // Hero 5-Tuple Elements
    this.stateBadge = document.getElementById('tunnelStateBadge');
    this.statusReason = document.getElementById('statusReason');
    this.statusTimeline = document.getElementById('statusTimeline');
    this.wgInterface = document.getElementById('wgInterface');
    this.localPort = document.getElementById('localPort');
    this.localPortRange = document.getElementById('localPortRange');
    this.localPubKey = document.getElementById('localPubKey');

    this.lastHandshake = document.getElementById('lastHandshake');
    this.pingStatus = document.getElementById('pingStatus');
    this.rxTransfer = document.getElementById('rxTransfer');
    this.txTransfer = document.getElementById('txTransfer');

    this.staggerRole = document.getElementById('staggerRole');
    this.targetIP = document.getElementById('targetIP');
    this.remotePort = document.getElementById('remotePort');
    this.remotePortRange = document.getElementById('remotePortRange');
    this.peerPubKey = document.getElementById('peerPubKey');

    // Telemetry Grid Elements
    this.huntRecoverySummary = document.getElementById('huntRecoverySummary');
    this.huntAttemptStatus = document.getElementById('huntAttemptStatus');
    this.connectedTimestamp = document.getElementById('connectedTimestamp');
    this.disconnectedTimestamp = document.getElementById('disconnectedTimestamp');
    this.lastHuntReason = document.getElementById('lastHuntReason');
    this.lastHuntTime = document.getElementById('lastHuntTime');

    this.iptablesStateText = document.getElementById('iptablesStateText');
    this.iptablesSubtext = document.getElementById('iptablesSubtext');
    this.iptablesRange = document.getElementById('iptablesRange');
    this.tunnelPingTarget = document.getElementById('tunnelPingTarget');
    this.failedPingsCount = document.getElementById('failedPingsCount');

    this.totalRx = document.getElementById('totalRx');
    this.totalTx = document.getElementById('totalTx');
    this.ifaceState = document.getElementById('ifaceState');
    this.staggerRoleDetail = document.getElementById('staggerRoleDetail');

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
    this.btnGoToLogs = document.getElementById('btnGoToLogs');

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
        const tabId = tab.getAttribute('data-tab');
        this.switchTab(tabId);
      });
    });

    if (this.btnGoToLogs) {
      this.btnGoToLogs.addEventListener('click', () => {
        this.switchTab('logs');
      });
    }
  }

  switchTab(tabId) {
    const tabs = document.querySelectorAll('.nav-tab');
    tabs.forEach(t => {
      if (t.getAttribute('data-tab') === tabId) {
        t.classList.add('active');
      } else {
        t.classList.remove('active');
      }
    });

    document.querySelectorAll('.tab-content').forEach(c => {
      if (c.id === `tab-${tabId}`) {
        c.classList.add('active');
      } else {
        c.classList.remove('active');
      }
    });

    if (tabId === 'logs' && this.autoScroll && this.terminal) {
      this.terminal.scrollTop = this.terminal.scrollHeight;
    }
  }

  showToast(message, isError = false) {
    if (!this.toast) return;
    this.toast.textContent = message;
    this.toast.className = isError ? 'toast error' : 'toast';
    setTimeout(() => {
      this.toast.className = 'toast hidden';
    }, 3000);
  }

  initCopyButtons() {
    const setupCopy = (btnId, textGetter, label) => {
      const btn = document.getElementById(btnId);
      if (!btn) return;
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const text = textGetter();
        if (!text || text === '--' || text.includes('Auto-')) return;
        try {
          await navigator.clipboard.writeText(text);
          this.showToast(`✓ Copied ${label} to clipboard!`);
        } catch {
          // Fallback
          const ta = document.createElement('textarea');
          ta.value = text;
          document.body.appendChild(ta);
          ta.select();
          document.execCommand('copy');
          document.body.removeChild(ta);
          this.showToast(`✓ Copied ${label} to clipboard!`);
        }
      });
    };

    setupCopy('btnCopyLocalKey', () => this.currentData?.local_public_key || '', 'Local Key');
    setupCopy('btnCopyPeerKey', () => this.currentData?.peer_public_key || '', 'Peer Key');
    setupCopy('btnCopyTargetIP', () => this.currentData?.target_ip || '', 'Target IP');
  }

  initActions() {
    this.btnRebind.addEventListener('click', async () => {
      this.btnRebind.disabled = true;
      try {
        const res = await fetch('/api/actions/rebind', { method: 'POST' });
        if (res.ok) {
          this.showToast('⚡ Local source port rebind initiated');
          this.pollStatus();
        } else {
          this.showToast('Failed to trigger rebind', true);
        }
      } catch (err) {
        this.showToast('Network error: ' + err.message, true);
      } finally {
        setTimeout(() => { this.btnRebind.disabled = false; }, 1200);
      }
    });

    this.btnHunt.addEventListener('click', async () => {
      this.btnHunt.disabled = true;
      try {
        const res = await fetch('/api/actions/hunt', { method: 'POST' });
        if (res.ok) {
          this.showToast('🔄 5-Tuple port hunt initiated');
          this.pollStatus();
        } else {
          this.showToast('Failed to trigger port hunt', true);
        }
      } catch (err) {
        this.showToast('Network error: ' + err.message, true);
      } finally {
        setTimeout(() => { this.btnHunt.disabled = false; }, 1200);
      }
    });
  }

  startStatusPolling() {
    this.pollStatus();
    this.statusTimer = setInterval(() => this.pollStatus(), 2000);

    // Live clock & live handshake increment
    setInterval(() => {
      if (this.serverClock) {
        this.serverClock.textContent = new Date().toLocaleTimeString();
      }
      this.updateLiveHandshakeAge();
    }, 1000);
  }

  async pollStatus() {
    try {
      const res = await fetch('/api/status');
      if (!res.ok) return;
      const data = await res.json();
      this.currentData = data;
      this.lastPollTimestamp = Date.now();
      this.renderStatus(data);
    } catch (err) {
      console.warn('Status poll error:', err);
    }
  }

  updateLiveHandshakeAge() {
    if (!this.currentData || !this.lastHandshake) return;
    const baseAge = this.currentData.handshake_age_seconds;
    if (baseAge !== undefined && baseAge > 0) {
      const elapsed = Math.round((Date.now() - this.lastPollTimestamp) / 1000);
      const totalAge = Math.round(baseAge + elapsed);
      if (totalAge < 60) {
        this.lastHandshake.textContent = `${totalAge}s ago`;
      } else {
        this.lastHandshake.textContent = `${Math.floor(totalAge / 60)}m ${totalAge % 60}s ago`;
      }
    }
    this.renderTimestamps(this.currentData);
  }

  renderTimestamps(data) {
    if (!data) return;
    const state = data.state || 'UNKNOWN';

    if (this.statusTimeline) {
      if (state === 'CONNECTED') {
        if (data.last_connected_at && !data.last_connected_at.startsWith('0001')) {
          this.statusTimeline.innerHTML = `🟢 <strong>Connected:</strong> ${formatTimestampAndAgo(data.last_connected_at)}`;
        } else {
          this.statusTimeline.innerHTML = `🟢 <strong>Connected</strong>`;
        }
      } else if (state === 'HUNTING' || state === 'STALLED') {
        if (data.last_disconnected_at && !data.last_disconnected_at.startsWith('0001')) {
          this.statusTimeline.innerHTML = `🔴 <strong>Disconnected:</strong> ${formatTimestampAndAgo(data.last_disconnected_at)}`;
        } else {
          this.statusTimeline.innerHTML = `🔴 <strong>Link Down / Hunting</strong>`;
        }
      } else {
        this.statusTimeline.innerHTML = `⚪ Checking status...`;
      }
    }

    if (this.connectedTimestamp) {
      this.connectedTimestamp.textContent = formatTimestampAndAgo(data.last_connected_at);
    }
    if (this.disconnectedTimestamp) {
      this.disconnectedTimestamp.textContent = formatTimestampAndAgo(data.last_disconnected_at);
    }
  }

  renderStatus(data) {
    // 1. Status Pill & Reason
    const state = data.state || 'UNKNOWN';
    this.stateBadge.textContent = state;
    this.stateBadge.className = 'status-pill status-' + state.toLowerCase();

    if (state === 'CONNECTED') {
      this.statusReason.textContent = 'Tunnel healthy; packets flowing';
    } else if (state === 'HUNTING') {
      this.statusReason.textContent = `Hunting ports (Attempt #${data.current_attempt || 1})`;
    } else if (state === 'STALLED') {
      this.statusReason.textContent = data.last_hunt_reason || 'Handshake stalled; verifying';
    } else {
      this.statusReason.textContent = 'Waiting for interface...';
    }

    this.renderTimestamps(data);

    // 2. Local Node
    this.wgInterface.textContent = data.interface || 'wg0';
    this.localPort.textContent = data.local_port > 0 ? `:${data.local_port}` : '--';
    this.localPortRange.textContent = data.local_port_range || '--';
    this.localPubKey.textContent = data.local_public_key || '--';
    this.localPubKey.title = data.local_public_key || '';

    // 3. Center Bridge
    this.updateLiveHandshakeAge();
    if (data.handshake_age_seconds === undefined || data.handshake_age_seconds <= 0) {
      this.lastHandshake.textContent = 'Never / Waiting';
    }

    if (data.in_tunnel_ping_target) {
      if (data.failed_pings > 0) {
        this.pingStatus.textContent = `${data.in_tunnel_ping_target} (Retry #${data.failed_pings})`;
        this.pingStatus.style.color = 'var(--warning)';
      } else {
        this.pingStatus.textContent = `${data.in_tunnel_ping_target} (OK)`;
        this.pingStatus.style.color = 'var(--success)';
      }
    } else {
      this.pingStatus.textContent = 'Auto-detecting...';
      this.pingStatus.style.color = 'var(--text-muted)';
    }

    this.rxTransfer.textContent = formatBytes(data.receive_bytes);
    this.txTransfer.textContent = formatBytes(data.transmit_bytes);

    // 4. Remote Node
    this.staggerRole.textContent = data.is_primary ? 'Primary Peer' : 'Secondary Peer';
    this.targetIP.textContent = data.target_ip || 'Auto-discovering...';
    this.targetIP.title = data.target_ip || '';
    this.remotePort.textContent = data.remote_port > 0 ? `:${data.remote_port}` : '--';
    this.remotePortRange.textContent = data.remote_port_range || '--';
    this.peerPubKey.textContent = data.peer_public_key || 'Auto-discovering...';
    this.peerPubKey.title = data.peer_public_key || '';

    // 5. Telemetry Cards
    this.huntRecoverySummary.textContent = `${data.successful_hunts || 0} / ${data.total_hunts || 0}`;

    if (data.current_attempt > 0) {
      this.huntAttemptStatus.textContent = `Hunting (Attempt #${data.current_attempt})`;
      this.huntAttemptStatus.style.color = 'var(--accent)';
    } else if (state === 'CONNECTED') {
      this.huntAttemptStatus.textContent = 'Idle (Connected)';
      this.huntAttemptStatus.style.color = 'var(--success)';
    } else {
      this.huntAttemptStatus.textContent = state;
      this.huntAttemptStatus.style.color = 'var(--text-main)';
    }

    this.lastHuntReason.textContent = data.last_hunt_reason || 'None';
    this.lastHuntReason.title = data.last_hunt_reason || 'None';

    if (data.last_hunt_time && !data.last_hunt_time.startsWith('0001')) {
      const huntDate = new Date(data.last_hunt_time);
      const agoSec = Math.round((Date.now() - huntDate.getTime()) / 1000);
      if (agoSec < 60) {
        this.lastHuntTime.textContent = `${agoSec}s ago`;
      } else {
        this.lastHuntTime.textContent = `${Math.floor(agoSec / 60)}m ago`;
      }
    } else {
      this.lastHuntTime.textContent = 'Never';
    }

    // iptables Card
    if (data.iptables_active) {
      this.iptablesStateText.textContent = 'ACTIVE';
      this.iptablesStateText.style.color = 'var(--success)';
      this.iptablesSubtext.textContent = `REDIRECT -> :${data.local_port || '...'}`;
    } else {
      this.iptablesStateText.textContent = 'OFF';
      this.iptablesStateText.style.color = 'var(--text-muted)';
      this.iptablesSubtext.textContent = 'Disabled / Non-Linux';
    }
    this.iptablesRange.textContent = data.local_port_range || '--';
    this.tunnelPingTarget.textContent = data.in_tunnel_ping_target || 'Auto-detecting...';
    this.failedPingsCount.textContent = `${data.failed_pings || 0} consecutive`;

    // Traffic Card
    this.totalRx.textContent = formatBytes(data.receive_bytes);
    this.totalTx.textContent = formatBytes(data.transmit_bytes);
    this.ifaceState.textContent = state === 'CONNECTED' ? 'ACTIVE (UP)' : 'MONITORING';
    this.staggerRoleDetail.textContent = data.is_primary ? 'Primary (Cycle 0)' : 'Secondary (Cycle 1)';
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
      this.streamStatus.textContent = '● Stream Disconnected';
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
      if (this.miniLogContainer.children.length > 12) {
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
      this.btnAutoScroll.className = `btn btn-sm ${this.autoScroll ? 'btn-active' : 'btn-secondary'}`;
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

function formatTimestampAndAgo(isoString) {
  if (!isoString || isoString.startsWith('0001') || isoString === '') {
    return 'Never';
  }
  const date = new Date(isoString);
  const now = Date.now();
  const diffSec = Math.max(0, Math.round((now - date.getTime()) / 1000));
  const timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

  if (diffSec < 60) {
    return `${diffSec}s ago (${timeStr})`;
  }
  if (diffSec < 3600) {
    const mins = Math.floor(diffSec / 60);
    const secs = diffSec % 60;
    return `${mins}m ${secs}s ago (${timeStr})`;
  }
  const hours = Math.floor(diffSec / 3600);
  const mins = Math.floor((diffSec % 3600) / 60);
  return `${hours}h ${mins}m ago (${timeStr})`;
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
