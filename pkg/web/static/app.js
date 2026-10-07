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
    this.initConfigEditor();
    this.startStatusPolling();
    this.connectLogStream();
  }

  initElements() {
    // Configuration Editor Elements
    this.configYamlEditor = document.getElementById('configYamlEditor');
    this.configFilePath = document.getElementById('configFilePath');
    this.configSyncBadge = document.getElementById('configSyncBadge');
    this.configAlert = document.getElementById('configAlert');
    this.btnSaveConfig = document.getElementById('btnSaveConfig');
    this.btnReloadConfig = document.getElementById('btnReloadConfig');
    this.btnCopyConfigPath = document.getElementById('btnCopyConfigPath');
    this.editorLineCount = document.getElementById('editorLineCount');
    this.btnToggleHelp = document.getElementById('btnToggleHelp');
    this.configHelpContent = document.getElementById('configHelpContent');
    this.configOriginalYaml = '';
    this.configIsDirty = false;
    this.configLoaded = false;

    // View Mode Toggle & Form Containers
    this.btnViewForm = document.getElementById('btnViewForm');
    this.btnViewYaml = document.getElementById('btnViewYaml');
    this.configFormContainer = document.getElementById('configFormContainer');
    this.configRawContainer = document.getElementById('configRawContainer');
    this.activeConfigView = 'form'; // 'form' or 'yaml'

    // Form Controls: Mode & Routing
    this.cfgModeClient = document.getElementById('cfgModeClient');
    this.cfgModeServer = document.getElementById('cfgModeServer');
    this.routingFieldsSection = document.getElementById('routingFieldsSection');
    this.cfgRoutingEnabled = document.getElementById('cfgRoutingEnabled');
    this.cfgRoutingTable = document.getElementById('cfgRoutingTable');
    this.cfgRoutingMode = document.getElementById('cfgRoutingMode');
    this.cfgRoutingMetric = document.getElementById('cfgRoutingMetric');

    // Form Controls: Managed Tunnels
    this.tunnelCardsContainer = document.getElementById('tunnelCardsContainer');
    this.btnAddTunnel = document.getElementById('btnAddTunnel');
    this.tunnelFormCount = document.getElementById('tunnelFormCount');

    // Form Controls: Shell Hooks
    this.headerShellHooks = document.getElementById('headerShellHooks');
    this.bodyShellHooks = document.getElementById('bodyShellHooks');
    this.toggleIconShell = document.getElementById('toggleIconShell');
    this.cfgPostUp = document.getElementById('cfgPostUp');
    this.cfgPreDown = document.getElementById('cfgPreDown');

    // Form Controls: Web & Status
    this.headerWebSettings = document.getElementById('headerWebSettings');
    this.bodyWebSettings = document.getElementById('bodyWebSettings');
    this.toggleIconWeb = document.getElementById('toggleIconWeb');
    this.cfgWebEnabled = document.getElementById('cfgWebEnabled');
    this.cfgWebListen = document.getElementById('cfgWebListen');
    this.cfgWebAllowedIPs = document.getElementById('cfgWebAllowedIPs');
    this.cfgWebUser = document.getElementById('cfgWebUser');
    this.cfgWebPass = document.getElementById('cfgWebPass');
    this.cfgStatusEnabled = document.getElementById('cfgStatusEnabled');
    this.cfgStatusListen = document.getElementById('cfgStatusListen');
    this.cfgStatusTitle = document.getElementById('cfgStatusTitle');

    this.storedWebPassword = '';
    this.parsedConfig = null;

    // Multi-Tunnel Switcher Elements
    this.tunnelSwitcherCard = document.getElementById('tunnelSwitcherCard');
    this.tunnelTabs = document.getElementById('tunnelTabs');
    this.switcherModeTag = document.getElementById('switcherModeTag');
    this.switcherActiveRouteBadge = document.getElementById('switcherActiveRouteBadge');
    this.tunnelHeaderActions = document.getElementById('tunnelHeaderActions');
    this.selectedTunnel = null;

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

    // Bridge Direction & Events History
    this.flowDirectionBadge = document.getElementById('flowDirectionBadge');
    this.eventsList = document.getElementById('eventsList');
    this.eventsCount = document.getElementById('eventsCount');

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

    // Auto switch back to dashboard on mobile screens
    window.addEventListener('resize', () => {
      if (window.innerWidth <= 768) {
        const activeTab = document.querySelector('.nav-tab.active');
        if (activeTab && activeTab.getAttribute('data-tab') === 'logs') {
          this.switchTab('dashboard');
        }
      }
    });
  }

  switchTab(tabId) {
    if (window.innerWidth <= 768 && tabId === 'logs') {
      return;
    }

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

    if (tabId === 'config' && !this.configLoaded) {
      this.loadConfigEditor();
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

  getSelectedTunnelData() {
    if (!this.currentData) return null;
    if (this.currentData.tunnels && this.selectedTunnel && this.currentData.tunnels[this.selectedTunnel]) {
      return this.currentData.tunnels[this.selectedTunnel];
    }
    return this.currentData;
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

    setupCopy('btnCopyLocalKey', () => this.getSelectedTunnelData()?.local_public_key || '', 'Local Key');
    setupCopy('btnCopyPeerKey', () => this.getSelectedTunnelData()?.peer_public_key || '', 'Peer Key');
    setupCopy('btnCopyTargetIP', () => this.getSelectedTunnelData()?.target_ip || '', 'Target IP');
  }

  initActions() {
    this.btnRebind.addEventListener('click', async () => {
      this.btnRebind.disabled = true;
      try {
        const ifaceParam = this.selectedTunnel ? `?interface=${encodeURIComponent(this.selectedTunnel)}` : '';
        const res = await fetch(`/api/actions/rebind${ifaceParam}`, { method: 'POST' });
        if (res.ok) {
          this.showToast(`⚡ Local source port rebind initiated${this.selectedTunnel ? ` for ${this.selectedTunnel}` : ''}`);
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
        const ifaceParam = this.selectedTunnel ? `?interface=${encodeURIComponent(this.selectedTunnel)}` : '';
        const res = await fetch(`/api/actions/hunt${ifaceParam}`, { method: 'POST' });
        if (res.ok) {
          this.showToast(`🔄 5-Tuple port hunt initiated${this.selectedTunnel ? ` for ${this.selectedTunnel}` : ''}`);
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
    const data = this.getSelectedTunnelData();
    if (!data || !this.lastHandshake) return;
    const baseAge = data.handshake_age_seconds;
    if (baseAge !== undefined && baseAge > 0) {
      const elapsed = Math.round((Date.now() - this.lastPollTimestamp) / 1000);
      const totalAge = Math.round(baseAge + elapsed);
      if (totalAge < 60) {
        this.lastHandshake.textContent = `${totalAge}s ago`;
      } else {
        this.lastHandshake.textContent = `${Math.floor(totalAge / 60)}m ${totalAge % 60}s ago`;
      }
    } else {
      this.lastHandshake.textContent = 'Never / Waiting';
    }
    this.renderTimestamps(data);
    if (data && data.events) {
      this.renderEvents(data.events);
    }
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

  renderStatus(fullData) {
    if (!fullData) return;

    // Render multi-tunnel switcher if tunnels map is present
    this.renderTunnelSwitcher(fullData);

    const data = this.getSelectedTunnelData() || fullData;

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

    if (this.flowDirectionBadge) {
      const dir = data.last_direction || 'Local ⇄ Remote';
      this.flowDirectionBadge.textContent = dir;
      this.flowDirectionBadge.className = 'bridge-badge bridge-direction';
      if (dir.includes('Local → Remote')) {
        this.flowDirectionBadge.classList.add('dir-local-to-remote');
      } else if (dir.includes('Remote → Local')) {
        this.flowDirectionBadge.classList.add('dir-remote-to-local');
      }
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
    let displayTarget = data.target_ip || (data.endpoint ? data.endpoint : 'Auto-discovering...');
    if (data.target_ips && data.target_ips.length > 1) {
      this.targetIP.textContent = `${displayTarget} (${data.target_ips.length} IPs)`;
      this.targetIP.title = `Active Target: ${data.target_ip || '--'}\nCandidate Targets:\n${data.target_ips.join('\n')}`;
    } else {
      this.targetIP.textContent = displayTarget;
      this.targetIP.title = data.target_ip || '';
    }
    this.remotePort.textContent = data.remote_port > 0 ? `:${data.remote_port}` : '--';
    this.remotePortRange.textContent = data.remote_port_range || '--';
    this.peerPubKey.textContent = data.peer_public_key || '--';
    this.peerPubKey.title = data.peer_public_key || '';

    // 5. Telemetry Cards
    if (data.hunting === false) {
      this.huntRecoverySummary.textContent = 'Passive';
      this.huntAttemptStatus.textContent = state === 'CONNECTED' ? 'Passive (Connected)' : 'Passive (Monitoring)';
      this.huntAttemptStatus.style.color = state === 'CONNECTED' ? 'var(--success)' : 'var(--warning)';
    } else {
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
    }

    if (this.btnHunt) {
      this.btnHunt.disabled = data.hunting === false;
      this.btnHunt.title = data.hunting === false ? 'Port hunting is disabled for this passive tunnel' : 'Trigger immediate port hunt';
    }
    if (this.btnRebind) {
      this.btnRebind.disabled = data.hunting === false;
      this.btnRebind.title = data.hunting === false ? 'Port rebind is disabled for this passive tunnel' : 'Rotate local listen port';
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

    // Connection Events History
    this.renderEvents(data.events);
  }

  renderTunnelSwitcher(fullData) {
    if (!this.tunnelSwitcherCard || !this.tunnelTabs) return;

    const tunnels = fullData.tunnels;
    const order = fullData.tunnel_order || (tunnels ? Object.keys(tunnels) : []);

    if (!order || order.length <= 1) {
      if (!fullData.active_tunnel) {
        this.tunnelSwitcherCard.style.display = 'none';
        return;
      }
    }

    this.tunnelSwitcherCard.style.display = 'block';

    if (this.switcherModeTag) {
      this.switcherModeTag.textContent = `MODE: ${(fullData.mode || 'GATEWAY').toUpperCase()}`;
    }

    if (this.switcherActiveRouteBadge) {
      if (fullData.active_tunnel) {
        this.switcherActiveRouteBadge.style.display = 'inline-block';
        this.switcherActiveRouteBadge.textContent = `★ Active Route: ${fullData.active_tunnel}`;
      } else {
        this.switcherActiveRouteBadge.style.display = 'none';
      }
    }

    // Default selectedTunnel if unset
    if (!this.selectedTunnel || (tunnels && !tunnels[this.selectedTunnel])) {
      this.selectedTunnel = fullData.active_tunnel || (order.length > 0 ? order[0] : null);
    }

    // Header actions: Switch route button if in client mode and looking at non-active tunnel
    if (this.tunnelHeaderActions) {
      this.tunnelHeaderActions.innerHTML = '';
      if (fullData.mode === 'client' && fullData.routing && fullData.routing.enabled) {
        if (this.selectedTunnel && this.selectedTunnel !== fullData.active_tunnel) {
          const btnSwitch = document.createElement('button');
          btnSwitch.className = 'btn btn-sm btn-accent';
          btnSwitch.textContent = `🔀 Set ${this.selectedTunnel} as Active Route`;
          btnSwitch.addEventListener('click', async () => {
            btnSwitch.disabled = true;
            try {
              const res = await fetch(`/api/actions/switch?interface=${encodeURIComponent(this.selectedTunnel)}`, { method: 'POST' });
              if (res.ok) {
                this.showToast(`✓ Active route switched to ${this.selectedTunnel}`);
                this.pollStatus();
              } else {
                this.showToast('Failed to switch route', true);
              }
            } catch (err) {
              this.showToast('Network error: ' + err.message, true);
            } finally {
              btnSwitch.disabled = false;
            }
          });
          this.tunnelHeaderActions.appendChild(btnSwitch);
        }
      }
    }

    // Render tunnel tabs
    this.tunnelTabs.innerHTML = '';
    for (const iface of order) {
      const t = (tunnels && tunnels[iface]) || {};
      const isSelected = (iface === this.selectedTunnel);
      const isRouteActive = (iface === fullData.active_tunnel);

      let dotClass = 'dot-unknown';
      if (t.state === 'CONNECTED') dotClass = 'dot-connected';
      else if (t.state === 'STALLED') dotClass = 'dot-stalled';
      else if (t.state === 'HUNTING') dotClass = 'dot-hunting';

      const btn = document.createElement('button');
      btn.className = `tunnel-tab-btn ${isSelected ? 'active' : ''}`;
      btn.innerHTML = `
        <span class="tab-dot ${dotClass}"></span>
        <span class="tab-name">${t.name ? `${t.name} (${iface})` : iface}</span>
        ${isRouteActive ? '<span class="tab-badge-route">Active Route</span>' : ''}
      `;

      btn.addEventListener('click', () => {
        this.selectedTunnel = iface;
        this.renderStatus(this.currentData);
      });

      this.tunnelTabs.appendChild(btn);
    }
  }

  renderEvents(events) {
    if (!this.eventsList) return;
    if (!events || events.length === 0) {
      this.eventsList.innerHTML = '<div class="events-empty">No connection events recorded yet.</div>';
      if (this.eventsCount) this.eventsCount.textContent = '0 events';
      return;
    }

    if (this.eventsCount) {
      this.eventsCount.textContent = `${events.length} event${events.length === 1 ? '' : 's'}`;
    }

    let html = '';
    for (const evt of events) {
      const isConnected = evt.type === 'CONNECTED';
      const typeClass = isConnected ? 'connected' : 'disconnected';
      const typeLabel = isConnected ? 'Connected' : 'Disconnected';

      let dirClass = 'bidirectional';
      if (evt.direction && evt.direction.includes('Local → Remote')) {
        dirClass = 'local-to-remote';
      } else if (evt.direction && evt.direction.includes('Remote → Local')) {
        dirClass = 'remote-to-local';
      }

      const date = new Date(evt.timestamp);
      const now = Date.now();
      const diffSec = Math.max(0, Math.round((now - date.getTime()) / 1000));
      const clockTime = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

      let timeAgo = `${diffSec}s ago`;
      if (diffSec >= 3600) {
        timeAgo = `${Math.floor(diffSec / 3600)}h ${Math.floor((diffSec % 3600) / 60)}m ago`;
      } else if (diffSec >= 60) {
        timeAgo = `${Math.floor(diffSec / 60)}m ago`;
      }

      let durationStr = '';
      if (evt.duration_sec && evt.duration_sec > 0) {
        const durSec = Math.round(evt.duration_sec);
        let formattedDur = '';
        if (durSec < 60) {
          formattedDur = `${durSec}s`;
        } else if (durSec < 3600) {
          formattedDur = `${Math.floor(durSec / 60)}m ${durSec % 60}s`;
        } else {
          formattedDur = `${Math.floor(durSec / 3600)}h ${Math.floor((durSec % 3600) / 60)}m`;
        }

        if (isConnected) {
          durationStr = ` • Down for ${formattedDur}`;
        } else {
          durationStr = ` • Was up for ${formattedDur}`;
        }
      }

      const initiatorText = evt.initiator ? ` (Initiator: ${escapeHtml(evt.initiator)})` : '';
      const reasonText = evt.reason ? escapeHtml(evt.reason) : '';
      const roleText = evt.local_role ? `Role: ${escapeHtml(evt.local_role)}` : '';

      html += `
        <div class="event-item">
          <div class="event-left">
            <span class="event-badge ${typeClass}">${typeLabel}</span>
            <span class="event-direction-badge ${dirClass}">${escapeHtml(evt.direction || 'Local ⇄ Remote')}</span>
            <div class="event-info">
              <div class="event-reason">${reasonText}${initiatorText}</div>
              <div class="event-duration">${roleText}${durationStr}</div>
            </div>
          </div>
          <div class="event-right">
            <span class="event-time-ago">${timeAgo}</span>
            <span class="event-time-clock">${clockTime}</span>
          </div>
        </div>
      `;
    }

    this.eventsList.innerHTML = html;
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

  initConfigEditor() {
    if (!this.configYamlEditor && !this.configFormContainer) return;

    // View Mode Toggle (Visual Form vs Raw YAML)
    if (this.btnViewForm && this.btnViewYaml) {
      this.btnViewForm.addEventListener('click', () => this.switchConfigView('form'));
      this.btnViewYaml.addEventListener('click', () => this.switchConfigView('yaml'));
    }

    // Warn before leaving if there are unsaved config edits
    window.addEventListener('beforeunload', (e) => {
      if (this.configIsDirty) {
        e.preventDefault();
        e.returnValue = '';
      }
    });

    // Form: Mode selector changes
    if (this.cfgModeClient && this.cfgModeServer) {
      this.cfgModeClient.addEventListener('change', () => {
        if (this.routingFieldsSection) this.routingFieldsSection.style.display = 'flex';
        this.onConfigFormChange();
      });
      this.cfgModeServer.addEventListener('change', () => {
        if (this.routingFieldsSection) this.routingFieldsSection.style.display = 'none';
        this.onConfigFormChange();
      });
    }

    // Form: Collapsible Shell Hooks & Web Settings
    if (this.headerShellHooks && this.bodyShellHooks) {
      this.headerShellHooks.addEventListener('click', () => {
        const isCollapsed = this.bodyShellHooks.classList.contains('collapsed');
        this.bodyShellHooks.classList.toggle('collapsed', !isCollapsed);
        if (this.toggleIconShell) this.toggleIconShell.textContent = isCollapsed ? '▲' : '▼';
      });
    }

    if (this.headerWebSettings && this.bodyWebSettings) {
      this.headerWebSettings.addEventListener('click', () => {
        const isCollapsed = this.bodyWebSettings.classList.contains('collapsed');
        this.bodyWebSettings.classList.toggle('collapsed', !isCollapsed);
        if (this.toggleIconWeb) this.toggleIconWeb.textContent = isCollapsed ? '▲' : '▼';
      });
    }

    // Form: Add Tunnel Button
    if (this.btnAddTunnel) {
      this.btnAddTunnel.addEventListener('click', () => {
        const count = this.tunnelCardsContainer ? this.tunnelCardsContainer.querySelectorAll('.tunnel-form-card').length : 0;
        const newIface = `wg${count}`;
        this.addTunnelCard({
          interface: newIface,
          name: `Tunnel-${count + 1}`,
          port_range: '20000-30000',
          remote_port_range: '20000-30000',
          hunting: true,
          iptables: true,
          target_ips: [],
          tunnel_ping: { enabled: false, target_ip: '', interval: '2s', failure_threshold: 3 }
        }, true);
        this.onConfigFormChange();
      });
    }

    // Form: Listen for changes across all top-level form controls
    const formInputs = [
      this.cfgRoutingEnabled, this.cfgRoutingTable, this.cfgRoutingMode, this.cfgRoutingMetric,
      this.cfgPostUp, this.cfgPreDown,
      this.cfgWebEnabled, this.cfgWebListen, this.cfgWebAllowedIPs, this.cfgWebUser, this.cfgWebPass,
      this.cfgStatusEnabled, this.cfgStatusListen, this.cfgStatusTitle
    ];
    formInputs.forEach(input => {
      if (input) {
        input.addEventListener('input', () => this.onConfigFormChange());
        input.addEventListener('change', () => this.onConfigFormChange());
      }
    });

    if (this.tunnelCardsContainer) {
      this.tunnelCardsContainer.addEventListener('input', () => this.onConfigFormChange());
      this.tunnelCardsContainer.addEventListener('change', () => this.onConfigFormChange());
    }

    // Raw YAML: Handle Tab key inside textarea
    if (this.configYamlEditor) {
      this.configYamlEditor.addEventListener('keydown', (e) => {
        if (e.key === 'Tab') {
          e.preventDefault();
          const start = this.configYamlEditor.selectionStart;
          const end = this.configYamlEditor.selectionEnd;
          const val = this.configYamlEditor.value;

          if (e.shiftKey) {
            const lineStart = val.lastIndexOf('\n', start - 1) + 1;
            if (val.substr(lineStart, 2) === '  ') {
              this.configYamlEditor.value = val.substring(0, lineStart) + val.substring(lineStart + 2);
              this.configYamlEditor.selectionStart = Math.max(lineStart, start - 2);
              this.configYamlEditor.selectionEnd = Math.max(lineStart, end - 2);
            } else if (val.charAt(lineStart) === ' ') {
              this.configYamlEditor.value = val.substring(0, lineStart) + val.substring(lineStart + 1);
              this.configYamlEditor.selectionStart = Math.max(lineStart, start - 1);
              this.configYamlEditor.selectionEnd = Math.max(lineStart, end - 1);
            }
          } else {
            this.configYamlEditor.value = val.substring(0, start) + '  ' + val.substring(end);
            this.configYamlEditor.selectionStart = this.configYamlEditor.selectionEnd = start + 2;
          }
          this.onConfigEditorChange();
        }
      });

      this.configYamlEditor.addEventListener('input', () => {
        this.onConfigEditorChange();
      });
    }

    // Reload button
    if (this.btnReloadConfig) {
      this.btnReloadConfig.addEventListener('click', async () => {
        if (this.configIsDirty && !confirm('Discard unsaved configuration edits and reload from disk?')) {
          return;
        }
        await this.loadConfigEditor(true);
      });
    }

    // Save button
    if (this.btnSaveConfig) {
      this.btnSaveConfig.addEventListener('click', () => {
        this.saveConfigEditor();
      });
    }

    // Copy path button
    if (this.btnCopyConfigPath) {
      this.btnCopyConfigPath.addEventListener('click', async () => {
        const path = this.configFilePath?.textContent;
        if (path && path !== 'Loading...') {
          try {
            await navigator.clipboard.writeText(path);
            this.showToast('✓ Copied config path to clipboard');
          } catch {
            this.showToast('Path: ' + path);
          }
        }
      });
    }

    // Toggle help card
    if (this.btnToggleHelp && this.configHelpContent) {
      this.btnToggleHelp.addEventListener('click', () => {
        const isHidden = this.configHelpContent.style.display === 'none';
        this.configHelpContent.style.display = isHidden ? 'block' : 'none';
        this.btnToggleHelp.textContent = isHidden ? 'Hide Tips' : 'Toggle Tips';
      });
    }
  }

  switchConfigView(view) {
    if (view === 'yaml') {
      // Sync form data into YAML textarea before displaying raw editor
      if (this.activeConfigView === 'form') {
        try {
          const cfg = this.collectConfigFromForm();
          const yamlStr = this.generateYamlFromConfig(cfg);
          if (this.configYamlEditor) {
            this.configYamlEditor.value = yamlStr;
            this.onConfigEditorChange();
          }
        } catch (e) {
          console.warn('Could not serialize form to YAML:', e);
        }
      }
      if (this.configFormContainer) this.configFormContainer.style.display = 'none';
      if (this.configRawContainer) this.configRawContainer.style.display = 'flex';
      this.btnViewForm?.classList.remove('active');
      this.btnViewYaml?.classList.add('active');
      this.activeConfigView = 'yaml';
    } else {
      // Switch back to visual form UI
      if (this.configRawContainer) this.configRawContainer.style.display = 'none';
      if (this.configFormContainer) this.configFormContainer.style.display = 'flex';
      this.btnViewYaml?.classList.remove('active');
      this.btnViewForm?.classList.add('active');
      this.activeConfigView = 'form';
    }
  }

  onConfigFormChange() {
    this.configIsDirty = true;
    if (this.configSyncBadge) {
      this.configSyncBadge.textContent = '● Unsaved Changes';
      this.configSyncBadge.className = 'config-sync-pill sync-dirty';
    }
  }

  onConfigEditorChange() {
    if (!this.configYamlEditor) return;
    const currentVal = this.configYamlEditor.value;

    // Update line count
    const lines = currentVal.split('\n').length;
    if (this.editorLineCount) {
      this.editorLineCount.textContent = `${lines} line${lines === 1 ? '' : 's'}`;
    }

    // Check dirty state
    this.configIsDirty = (currentVal !== this.configOriginalYaml);
    if (this.configSyncBadge) {
      if (this.configIsDirty) {
        this.configSyncBadge.textContent = '● Unsaved Changes';
        this.configSyncBadge.className = 'config-sync-pill sync-dirty';
      } else {
        this.configSyncBadge.textContent = 'Synced with Disk';
        this.configSyncBadge.className = 'config-sync-pill sync-ok';
      }
    }
  }

  updateTunnelCount() {
    if (!this.tunnelFormCount || !this.tunnelCardsContainer) return;
    const count = this.tunnelCardsContainer.querySelectorAll('.tunnel-form-card').length;
    this.tunnelFormCount.textContent = `${count} tunnel${count === 1 ? '' : 's'}`;
  }

  renderConfigForm(cfg) {
    this.parsedConfig = cfg;

    // 1. Operating Mode
    const isClient = (cfg.mode || '').toLowerCase() === 'client';
    if (this.cfgModeClient) this.cfgModeClient.checked = isClient;
    if (this.cfgModeServer) this.cfgModeServer.checked = !isClient;
    if (this.routingFieldsSection) {
      this.routingFieldsSection.style.display = isClient ? 'flex' : 'none';
    }

    // 2. Client Route Failover
    if (this.cfgRoutingEnabled) this.cfgRoutingEnabled.checked = cfg.routing ? cfg.routing.enabled : true;
    if (this.cfgRoutingTable) this.cfgRoutingTable.value = cfg.routing?.table ?? 200;
    if (this.cfgRoutingMode) this.cfgRoutingMode.value = cfg.routing?.mode || 'sticky';
    if (this.cfgRoutingMetric) this.cfgRoutingMetric.value = cfg.routing?.metric ?? 100;

    // 3. Managed WireGuard Interfaces
    if (this.tunnelCardsContainer) {
      this.tunnelCardsContainer.innerHTML = '';
      const tunnels = cfg.tunnels || [];
      tunnels.forEach(t => {
        this.addTunnelCard(t, false);
      });
      this.updateTunnelCount();
    }

    // 4. Global Shell Hooks
    if (this.cfgPostUp) this.cfgPostUp.value = (cfg.post_up || []).join('\n');
    if (this.cfgPreDown) this.cfgPreDown.value = (cfg.pre_down || []).join('\n');

    // 5. Web Admin Panel
    if (this.cfgWebEnabled) this.cfgWebEnabled.checked = cfg.web ? cfg.web.enabled : true;
    if (this.cfgWebListen) this.cfgWebListen.value = cfg.web?.listen_addr || '0.0.0.0:8080';
    if (this.cfgWebAllowedIPs) this.cfgWebAllowedIPs.value = (cfg.web?.allowed_ips || []).join('\n');
    if (this.cfgWebUser) this.cfgWebUser.value = cfg.web?.username || '';
    if (this.cfgWebPass) {
      this.storedWebPassword = cfg.web?.password || '';
      this.cfgWebPass.value = this.storedWebPassword ? '********' : '';
    }

    // 6. Public Status Page
    if (this.cfgStatusEnabled) this.cfgStatusEnabled.checked = cfg.status_page ? cfg.status_page.enabled : false;
    if (this.cfgStatusListen) this.cfgStatusListen.value = cfg.status_page?.listen_addr || '0.0.0.0:8081';
    if (this.cfgStatusTitle) this.cfgStatusTitle.value = cfg.status_page?.title || 'Service Status';
  }

  addTunnelCard(tunnel = {}, isNew = false) {
    if (!this.tunnelCardsContainer) return;

    const card = document.createElement('div');
    card.className = 'tunnel-form-card';

    const targetIPs = (tunnel.target_ips && tunnel.target_ips.length > 0)
      ? tunnel.target_ips
      : (tunnel.target_ip ? [tunnel.target_ip] : []);
    const targetIPsText = targetIPs.join('\n');

    const isHunting = tunnel.hunting !== false;
    const isIptables = tunnel.iptables !== false;

    card.innerHTML = `
      <div class="tunnel-card-header">
        <div class="tunnel-card-left">
          <span class="tunnel-card-title">${escapeHtml(tunnel.interface || 'new_wg')}</span>
          <span class="badge-count tunnel-card-name-tag">${escapeHtml(tunnel.name || '')}</span>
          <span class="tunnel-card-badge ${isHunting ? 'hunting' : 'passive'}">
            ${isHunting ? 'Hunting Active' : 'Passive (No Rotation)'}
          </span>
        </div>
        <button type="button" class="btn-danger-sm btn-remove-tunnel" title="Remove this tunnel interface">✕ Remove</button>
      </div>

      <div class="form-grid-2">
        <div class="form-group">
          <label class="form-label">WireGuard Interface Name <span style="color:var(--danger)">*</span></label>
          <input type="text" class="form-input t-interface" value="${escapeHtml(tunnel.interface || '')}" placeholder="e.g. wg0 or wgBridge0" required spellcheck="false">
          <span class="form-hint">Matches system interface name (ip link show)</span>
        </div>
        <div class="form-group">
          <label class="form-label">Descriptive Name</label>
          <input type="text" class="form-input t-name" value="${escapeHtml(tunnel.name || '')}" placeholder="e.g. Frankfurt-VPS or Client-A" spellcheck="false">
          <span class="form-hint">Display name shown in web dashboard & logs</span>
        </div>
      </div>

      <div class="form-grid-2">
        <div class="form-group">
          <label class="form-label">Local Forwarded Port Range</label>
          <input type="text" class="form-input t-port-range" value="${escapeHtml(tunnel.port_range || '20000-30000')}" placeholder="20000-30000" spellcheck="false">
          <span class="form-hint">Range redirected by iptables to local WG listen port</span>
        </div>
        <div class="form-group">
          <label class="form-label">Remote Peer Port Range</label>
          <input type="text" class="form-input t-remote-port-range" value="${escapeHtml(tunnel.remote_port_range || '20000-30000')}" placeholder="20000-30000" spellcheck="false">
          <span class="form-hint">Candidate destination ports probed when connection stalls</span>
        </div>
      </div>

      <div class="form-group">
        <label class="form-label">Target Destination IPs / Hostnames (Dual-Stack IPv4 / IPv6 / Domains)</label>
        <textarea class="form-textarea t-target-ips" rows="2" placeholder="198.51.100.1&#10;2001:db8::1&#10;vps.example.com" spellcheck="false">${escapeHtml(targetIPsText)}</textarea>
        <span class="form-hint">One destination per line. Auto-WG rotates through IPv4 and IPv6 targets if DPI blocks one. Domains are resolved on each hunt attempt.</span>
      </div>

      <div class="form-group">
        <label class="form-label">Peer Public Key (optional)</label>
        <input type="text" class="form-input t-peer-pubkey" value="${escapeHtml(tunnel.peer_public_key || '')}" placeholder="Base64 WireGuard peer public key" spellcheck="false">
        <span class="form-hint">Auto-detected from interface if left blank</span>
      </div>

      <div class="tunnel-card-toggles">
        <label class="switch-label">
          <input type="checkbox" class="t-hunting" ${isHunting ? 'checked' : ''}>
          <span class="switch-slider"></span>
          <span class="switch-text">Autonomous Port Hunting (active port rotation on stall)</span>
        </label>
        <label class="switch-label">
          <input type="checkbox" class="t-iptables" ${isIptables ? 'checked' : ''}>
          <span class="switch-slider"></span>
          <span class="switch-text">Manage iptables REDIRECT NAT rule</span>
        </label>
      </div>

      <!-- Collapsible Advanced & Ping Settings -->
      <div class="tunnel-advanced-box">
        <div class="tunnel-advanced-header">
          <span>▶ Advanced & In-Tunnel Ping Settings</span>
          <span class="advanced-toggle-icon">▼</span>
        </div>
        <div class="tunnel-advanced-body collapsed">
          <div class="form-sub-header">
            <h4>In-Tunnel ICMP Ping (Fast Link Failure Detection)</h4>
            <label class="switch-label">
              <input type="checkbox" class="t-ping-enabled" ${tunnel.tunnel_ping?.enabled ? 'checked' : ''}>
              <span class="switch-slider"></span>
              <span class="switch-text">Enable In-Tunnel Ping</span>
            </label>
          </div>

          <div class="form-grid-3">
            <div class="form-group">
              <label class="form-label">Ping Target IP</label>
              <input type="text" class="form-input t-ping-target" value="${escapeHtml(tunnel.tunnel_ping?.target_ip || '')}" placeholder="e.g. 10.100.0.1" spellcheck="false">
              <span class="form-hint">In-tunnel IP of peer</span>
            </div>
            <div class="form-group">
              <label class="form-label">Ping Interval</label>
              <input type="text" class="form-input t-ping-interval" value="${escapeHtml(formatDuration(tunnel.tunnel_ping?.interval, '2s'))}" placeholder="2s" spellcheck="false">
            </div>
            <div class="form-group">
              <label class="form-label">Failure Threshold</label>
              <input type="number" class="form-input t-ping-threshold" value="${tunnel.tunnel_ping?.failure_threshold || 3}" placeholder="3">
              <span class="form-hint">Consecutive failed pings before hunt</span>
            </div>
          </div>

          <div class="form-sub-header" style="margin-top: 10px;">
            <h4>Timing & Timeouts</h4>
          </div>
          <div class="form-grid-3">
            <div class="form-group">
              <label class="form-label">Check Interval</label>
              <input type="text" class="form-input t-check-interval" value="${escapeHtml(formatDuration(tunnel.check_interval, '3s'))}" placeholder="3s" spellcheck="false">
            </div>
            <div class="form-group">
              <label class="form-label">Handshake Timeout</label>
              <input type="text" class="form-input t-handshake-timeout" value="${escapeHtml(formatDuration(tunnel.handshake_timeout, '60s'))}" placeholder="60s" spellcheck="false">
            </div>
            <div class="form-group">
              <label class="form-label">Stagger Cycle Timeout</label>
              <input type="text" class="form-input t-cycle-timeout" value="${escapeHtml(formatDuration(tunnel.cycle_timeout, '8s'))}" placeholder="8s" spellcheck="false">
            </div>
          </div>

          <div class="form-group" style="margin-top: 6px;">
            <label class="form-label">Persistent History File</label>
            <input type="text" class="form-input t-history-file" value="${escapeHtml(tunnel.history_file || '')}" placeholder="Leave empty for default or 'off' to disable" spellcheck="false">
          </div>

          <div class="form-grid-2" style="margin-top: 6px;">
            <div class="form-group">
              <label class="form-label">Tunnel Post-Up Shell Commands (one per line)</label>
              <textarea class="form-textarea t-post-up" rows="2" placeholder="e.g. iptables -t nat -I POSTROUTING ..." spellcheck="false">${escapeHtml((tunnel.post_up || []).join('\n'))}</textarea>
            </div>
            <div class="form-group">
              <label class="form-label">Tunnel Pre-Down Shell Commands (one per line)</label>
              <textarea class="form-textarea t-pre-down" rows="2" placeholder="e.g. iptables -t nat -D POSTROUTING ..." spellcheck="false">${escapeHtml((tunnel.pre_down || []).join('\n'))}</textarea>
            </div>
          </div>
        </div>
      </div>
    `;

    // Interactive element wiring within the card
    const ifaceInput = card.querySelector('.t-interface');
    const nameInput = card.querySelector('.t-name');
    const titleEl = card.querySelector('.tunnel-card-title');
    const nameTagEl = card.querySelector('.tunnel-card-name-tag');
    const huntingInput = card.querySelector('.t-hunting');
    const badgeEl = card.querySelector('.tunnel-card-badge');

    ifaceInput?.addEventListener('input', () => {
      if (titleEl) titleEl.textContent = ifaceInput.value || 'new_wg';
    });
    nameInput?.addEventListener('input', () => {
      if (nameTagEl) nameTagEl.textContent = nameInput.value;
    });
    huntingInput?.addEventListener('change', () => {
      if (badgeEl) {
        if (huntingInput.checked) {
          badgeEl.textContent = 'Hunting Active';
          badgeEl.className = 'tunnel-card-badge hunting';
        } else {
          badgeEl.textContent = 'Passive (No Rotation)';
          badgeEl.className = 'tunnel-card-badge passive';
        }
      }
    });

    // Advanced accordion toggle
    const advHeader = card.querySelector('.tunnel-advanced-header');
    const advBody = card.querySelector('.tunnel-advanced-body');
    const advIcon = card.querySelector('.advanced-toggle-icon');
    advHeader?.addEventListener('click', () => {
      const isCollapsed = advBody.classList.contains('collapsed');
      advBody.classList.toggle('collapsed', !isCollapsed);
      if (advIcon) advIcon.textContent = isCollapsed ? '▲' : '▼';
    });

    // Remove tunnel button
    const btnRemove = card.querySelector('.btn-remove-tunnel');
    btnRemove?.addEventListener('click', () => {
      const iface = ifaceInput?.value.trim() || 'this tunnel';
      if (confirm(`Remove interface "${iface}" from configuration?`)) {
        card.remove();
        this.updateTunnelCount();
        this.onConfigFormChange();
      }
    });

    this.tunnelCardsContainer.appendChild(card);
    this.updateTunnelCount();

    if (isNew) {
      card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      ifaceInput?.focus();
    }
  }

  collectConfigFromForm() {
    const mode = this.cfgModeClient?.checked ? 'client' : 'server';

    const routing = {
      enabled: this.cfgRoutingEnabled ? this.cfgRoutingEnabled.checked : true,
      table: parseInt(this.cfgRoutingTable?.value, 10) || 200,
      mode: this.cfgRoutingMode?.value || 'sticky',
      metric: parseInt(this.cfgRoutingMetric?.value, 10) || 100
    };

    const tunnels = [];
    const cards = this.tunnelCardsContainer ? this.tunnelCardsContainer.querySelectorAll('.tunnel-form-card') : [];
    cards.forEach(card => {
      const iface = card.querySelector('.t-interface')?.value.trim() || '';
      const name = card.querySelector('.t-name')?.value.trim() || iface;
      const portRange = card.querySelector('.t-port-range')?.value.trim() || '20000-30000';
      const remotePortRange = card.querySelector('.t-remote-port-range')?.value.trim() || '20000-30000';
      const hunting = card.querySelector('.t-hunting')?.checked ?? true;
      const iptables = card.querySelector('.t-iptables')?.checked ?? true;
      const peerPubKey = card.querySelector('.t-peer-pubkey')?.value.trim() || '';

      const targetIpsRaw = card.querySelector('.t-target-ips')?.value || '';
      const targetIps = targetIpsRaw.split('\n').map(s => s.trim()).filter(s => s.length > 0);

      const pingEnabled = card.querySelector('.t-ping-enabled')?.checked ?? false;
      const pingTarget = card.querySelector('.t-ping-target')?.value.trim() || '';
      const pingInterval = card.querySelector('.t-ping-interval')?.value.trim() || '2s';
      const pingThreshold = parseInt(card.querySelector('.t-ping-threshold')?.value, 10) || 3;

      const checkInterval = card.querySelector('.t-check-interval')?.value.trim() || '3s';
      const handshakeTimeout = card.querySelector('.t-handshake-timeout')?.value.trim() || '60s';
      const cycleTimeout = card.querySelector('.t-cycle-timeout')?.value.trim() || '8s';
      const historyFile = card.querySelector('.t-history-file')?.value.trim() || '';

      const postUpRaw = card.querySelector('.t-post-up')?.value || '';
      const postUp = postUpRaw.split('\n').map(s => s.trim()).filter(s => s.length > 0);
      const preDownRaw = card.querySelector('.t-pre-down')?.value || '';
      const preDown = preDownRaw.split('\n').map(s => s.trim()).filter(s => s.length > 0);

      const tunnelObj = {
        interface: iface,
        name: name,
        port_range: portRange,
        remote_port_range: remotePortRange,
        hunting: hunting,
        iptables: iptables,
        target_ips: targetIps,
        target_ip: targetIps.length > 0 ? targetIps[0] : '',
        peer_public_key: peerPubKey,
        check_interval: checkInterval,
        handshake_timeout: handshakeTimeout,
        cycle_timeout: cycleTimeout,
        tunnel_ping: {
          enabled: pingEnabled,
          target_ip: pingTarget,
          interval: pingInterval,
          failure_threshold: pingThreshold
        }
      };
      if (historyFile) tunnelObj.history_file = historyFile;
      if (postUp.length > 0) tunnelObj.post_up = postUp;
      if (preDown.length > 0) tunnelObj.pre_down = preDown;

      tunnels.push(tunnelObj);
    });

    const postUpGlobalRaw = this.cfgPostUp?.value || '';
    const postUpGlobal = postUpGlobalRaw.split('\n').map(s => s.trim()).filter(s => s.length > 0);
    const preDownGlobalRaw = this.cfgPreDown?.value || '';
    const preDownGlobal = preDownGlobalRaw.split('\n').map(s => s.trim()).filter(s => s.length > 0);

    const webAllowedRaw = this.cfgWebAllowedIPs?.value || '';
    const webAllowed = webAllowedRaw.split(/[\n,]+/).map(s => s.trim()).filter(s => s.length > 0);

    let passVal = this.cfgWebPass?.value || '';
    if (passVal === '********') {
      passVal = this.storedWebPassword;
    }

    const web = {
      enabled: this.cfgWebEnabled?.checked ?? true,
      listen_addr: this.cfgWebListen?.value.trim() || '0.0.0.0:8080',
      username: this.cfgWebUser?.value.trim() || '',
      password: passVal,
      allowed_ips: webAllowed
    };

    const statusPage = {
      enabled: this.cfgStatusEnabled?.checked ?? false,
      listen_addr: this.cfgStatusListen?.value.trim() || '0.0.0.0:8081',
      title: this.cfgStatusTitle?.value.trim() || 'Service Status'
    };

    return {
      mode: mode,
      routing: routing,
      tunnels: tunnels,
      post_up: postUpGlobal,
      pre_down: preDownGlobal,
      web: web,
      status_page: statusPage
    };
  }

  generateYamlFromConfig(cfg) {
    let lines = [];
    lines.push('# Auto-WG Configuration File');
    lines.push(`mode: "${cfg.mode || 'server'}"`);
    lines.push('');

    if (cfg.mode === 'client' || (cfg.routing && cfg.routing.enabled)) {
      lines.push('routing:');
      lines.push(`  enabled: ${cfg.routing.enabled ? 'true' : 'false'}`);
      lines.push(`  table: ${cfg.routing.table || 200}`);
      lines.push(`  mode: "${cfg.routing.mode || 'sticky'}"`);
      lines.push(`  metric: ${cfg.routing.metric || 100}`);
      lines.push('');
    }

    lines.push('tunnels:');
    for (const t of cfg.tunnels) {
      lines.push(`  - interface: "${t.interface}"`);
      if (t.name) lines.push(`    name: "${t.name}"`);
      if (t.port_range) lines.push(`    port_range: "${t.port_range}"`);
      if (t.remote_port_range) lines.push(`    remote_port_range: "${t.remote_port_range}"`);
      if (t.hunting !== undefined) lines.push(`    hunting: ${t.hunting ? 'true' : 'false'}`);
      if (t.iptables !== undefined) lines.push(`    iptables: ${t.iptables ? 'true' : 'false'}`);
      if (t.peer_public_key) lines.push(`    peer_public_key: "${t.peer_public_key}"`);

      if (t.target_ips && t.target_ips.length > 0) {
        lines.push('    target_ips:');
        for (const ip of t.target_ips) {
          lines.push(`      - "${ip}"`);
        }
      } else if (t.target_ip) {
        lines.push(`    target_ip: "${t.target_ip}"`);
      }

      if (t.tunnel_ping && (t.tunnel_ping.enabled || t.tunnel_ping.target_ip)) {
        lines.push('    tunnel_ping:');
        lines.push(`      enabled: ${t.tunnel_ping.enabled ? 'true' : 'false'}`);
        if (t.tunnel_ping.target_ip) lines.push(`      target_ip: "${t.tunnel_ping.target_ip}"`);
        if (t.tunnel_ping.interval) lines.push(`      interval: "${t.tunnel_ping.interval}"`);
        if (t.tunnel_ping.failure_threshold) lines.push(`      failure_threshold: ${t.tunnel_ping.failure_threshold}`);
      }

      if (t.check_interval && t.check_interval !== '3s') lines.push(`    check_interval: "${t.check_interval}"`);
      if (t.handshake_timeout && t.handshake_timeout !== '60s') lines.push(`    handshake_timeout: "${t.handshake_timeout}"`);
      if (t.cycle_timeout && t.cycle_timeout !== '8s') lines.push(`    cycle_timeout: "${t.cycle_timeout}"`);
      if (t.history_file) lines.push(`    history_file: "${t.history_file}"`);

      if (t.post_up && t.post_up.length > 0) {
        lines.push('    post_up:');
        for (const cmd of t.post_up) {
          lines.push(`      - "${cmd.replace(/"/g, '\\"')}"`);
        }
      }
      if (t.pre_down && t.pre_down.length > 0) {
        lines.push('    pre_down:');
        for (const cmd of t.pre_down) {
          lines.push(`      - "${cmd.replace(/"/g, '\\"')}"`);
        }
      }
      lines.push('');
    }

    if (cfg.post_up && cfg.post_up.length > 0) {
      lines.push('post_up:');
      for (const cmd of cfg.post_up) {
        lines.push(`  - "${cmd.replace(/"/g, '\\"')}"`);
      }
      lines.push('');
    }

    if (cfg.pre_down && cfg.pre_down.length > 0) {
      lines.push('pre_down:');
      for (const cmd of cfg.pre_down) {
        lines.push(`  - "${cmd.replace(/"/g, '\\"')}"`);
      }
      lines.push('');
    }

    lines.push('web:');
    lines.push(`  enabled: ${cfg.web.enabled ? 'true' : 'false'}`);
    lines.push(`  listen_addr: "${cfg.web.listen_addr || '0.0.0.0:8080'}"`);
    if (cfg.web.username) lines.push(`  username: "${cfg.web.username}"`);
    if (cfg.web.password && cfg.web.password !== '********') lines.push(`  password: "${cfg.web.password}"`);
    if (cfg.web.allowed_ips && cfg.web.allowed_ips.length > 0) {
      lines.push('  allowed_ips:');
      for (const aip of cfg.web.allowed_ips) {
        lines.push(`    - "${aip}"`);
      }
    }
    lines.push('');

    if (cfg.status_page && cfg.status_page.enabled) {
      lines.push('status_page:');
      lines.push(`  enabled: true`);
      lines.push(`  listen_addr: "${cfg.status_page.listen_addr || '0.0.0.0:8081'}"`);
      lines.push(`  title: "${cfg.status_page.title || 'Service Status'}"`);
      lines.push('');
    }

    return lines.join('\n');
  }

  async loadConfigEditor(force = false) {
    if (this.configLoaded && !force) return;

    if (this.configSyncBadge) {
      this.configSyncBadge.textContent = 'Loading...';
      this.configSyncBadge.className = 'config-sync-pill sync-saving';
    }

    try {
      const res = await fetch('/api/config');
      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}`);
      }
      const data = await res.json();

      if (this.configFilePath) {
        this.configFilePath.textContent = data.path || 'config.yaml';
      }

      const yamlContent = data.yaml || '';
      if (this.configYamlEditor) {
        this.configYamlEditor.value = yamlContent;
      }
      this.configOriginalYaml = yamlContent;

      // Populate Visual Form from parsed config
      if (data.config) {
        this.renderConfigForm(data.config);
      }

      this.configIsDirty = false;
      this.configLoaded = true;

      this.onConfigEditorChange();
      this.hideConfigAlert();

      if (force) {
        this.showToast('✓ Reloaded configuration from disk');
      }
    } catch (err) {
      this.showConfigAlert('Failed to load configuration from disk: ' + err.message, 'error');
      if (this.configSyncBadge) {
        this.configSyncBadge.textContent = 'Load Failed';
        this.configSyncBadge.className = 'config-sync-pill sync-error';
      }
    }
  }

  async saveConfigEditor() {
    let yamlPayload = '';

    if (this.activeConfigView === 'form') {
      const cfg = this.collectConfigFromForm();

      // Form validation before sending
      if (!cfg.tunnels || cfg.tunnels.length === 0) {
        this.showConfigAlert('Configuration Error: At least one WireGuard tunnel interface must be defined.', 'error');
        return;
      }

      for (let i = 0; i < cfg.tunnels.length; i++) {
        const t = cfg.tunnels[i];
        if (!t.interface) {
          this.showConfigAlert(`Configuration Error: Tunnel #${i + 1} is missing the required Interface Name (e.g. wg0).`, 'error');
          return;
        }
      }

      yamlPayload = this.generateYamlFromConfig(cfg);
      if (this.configYamlEditor) {
        this.configYamlEditor.value = yamlPayload;
      }
    } else {
      if (!this.configYamlEditor) return;
      yamlPayload = this.configYamlEditor.value;
    }

    if (!yamlPayload.trim()) {
      this.showConfigAlert('Configuration cannot be empty.', 'error');
      return;
    }

    if (this.btnSaveConfig) this.btnSaveConfig.disabled = true;
    if (this.configSyncBadge) {
      this.configSyncBadge.textContent = 'Saving & Validating...';
      this.configSyncBadge.className = 'config-sync-pill sync-saving';
    }
    this.hideConfigAlert();

    try {
      const res = await fetch('/api/config', {
        method: 'POST',
        headers: {
          'Content-Type': 'text/yaml'
        },
        body: yamlPayload
      });

      const data = await res.json().catch(() => null);

      if (res.ok) {
        this.configOriginalYaml = yamlPayload;
        this.configIsDirty = false;
        this.onConfigEditorChange();

        this.showConfigAlert(`✓ Configuration successfully written to ${data?.path || 'startup file'} and applied live without restarting!`, 'success');
        this.showToast('✓ Config saved & applied live!');
        this.pollStatus();

        // Refresh parsed config to ensure frontend is 100% in sync with disk and supervisor
        const refRes = await fetch('/api/config');
        if (refRes.ok) {
          const refData = await refRes.json();
          if (refData.config && this.activeConfigView === 'form') {
            this.renderConfigForm(refData.config);
          }
        }
      } else {
        const errMsg = data?.error || `HTTP ${res.status}: Validation or save failed`;
        this.showConfigAlert('Configuration Error: ' + errMsg, 'error');
        if (this.configSyncBadge) {
          this.configSyncBadge.textContent = 'Validation Error';
          this.configSyncBadge.className = 'config-sync-pill sync-error';
        }
        this.showToast('Save failed: check error details below', true);
      }
    } catch (err) {
      this.showConfigAlert('Network request failed: ' + err.message, 'error');
      if (this.configSyncBadge) {
        this.configSyncBadge.textContent = 'Save Failed';
        this.configSyncBadge.className = 'config-sync-pill sync-error';
      }
    } finally {
      if (this.btnSaveConfig) {
        setTimeout(() => { this.btnSaveConfig.disabled = false; }, 600);
      }
    }
  }

  showConfigAlert(message, type = 'error') {
    if (!this.configAlert) return;
    this.configAlert.textContent = message;
    this.configAlert.className = `config-alert ${type}`;
    this.configAlert.style.display = 'block';
  }

  hideConfigAlert() {
    if (!this.configAlert) return;
    this.configAlert.style.display = 'none';
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

function formatDuration(val, fallback = '3s') {
  if (val === undefined || val === null || val === '') return fallback;
  if (typeof val === 'string') return val;
  if (typeof val === 'number') {
    if (val === 0) return '0s';
    if (val >= 1e9 && val % 1e9 === 0) {
      return (val / 1e9) + 's';
    }
    if (val >= 60e9 && val % 60e9 === 0) {
      return (val / 60e9) + 'm';
    }
    if (val >= 1e6 && val % 1e6 === 0) {
      return (val / 1e6) + 'ms';
    }
    return (val / 1e9).toFixed(1) + 's';
  }
  return fallback;
}

document.addEventListener('DOMContentLoaded', () => {
  new AutoWGApp();
});
