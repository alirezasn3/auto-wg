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
    this.cfgPostUp = document.getElementById('cfgPostUp');
    this.cfgPreDown = document.getElementById('cfgPreDown');

    // Form Controls: Web & Status
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
    this.heroPanel = document.getElementById('heroPanel');

    this.lastHandshake = document.getElementById('lastHandshake');
    this.pingStatus = document.getElementById('pingStatus');
    this.rxTransfer = document.getElementById('rxTransfer');
    this.txTransfer = document.getElementById('txTransfer');

    this.staggerRole = document.getElementById('staggerRole');
    this.targetIP = document.getElementById('targetIP');
    this.remotePort = document.getElementById('remotePort');
    this.remotePortRange = document.getElementById('remotePortRange');

    // Telemetry Grid Elements
    this.huntRecoverySummary = document.getElementById('huntRecoverySummary');
    this.huntAttemptStatus = document.getElementById('huntAttemptStatus');
    this.connectedTimestamp = document.getElementById('connectedTimestamp');
    this.disconnectedTimestamp = document.getElementById('disconnectedTimestamp');
    this.lastHuntReason = document.getElementById('lastHuntReason');
    this.lastHuntTime = document.getElementById('lastHuntTime');
    this.lastHuntSep = document.getElementById('lastHuntSep');
    this.timerLinkSince = document.getElementById('timerLinkSince');
    this.linkSinceLabel = document.getElementById('linkSinceLabel');
    this.lastPathSwitch = document.getElementById('lastPathSwitch');
    this.linkSince = document.getElementById('linkSince');


    this.iptablesStateText = document.getElementById('iptablesStateText');
    this.iptablesSubtext = document.getElementById('iptablesSubtext');
    this.rowTransport = document.getElementById('rowTransport');
    this.transportState = document.getElementById('transportState');
    this.rowLink = document.getElementById('rowLink');
    this.linkState = document.getElementById('linkState');
    this.bridgeProtoBadge = document.getElementById('bridgeProtoBadge');


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
          this.statusTimeline.innerHTML = `<span class="legend-dot dot-connected"></span><strong>Connected</strong> ${formatTimestampAndAgo(data.last_connected_at)}`;
        } else {
          this.statusTimeline.innerHTML = `<span class="legend-dot dot-connected"></span><strong>Connected</strong>`;
        }
      } else if (state === 'HUNTING' || state === 'STALLED') {
        if (data.last_disconnected_at && !data.last_disconnected_at.startsWith('0001')) {
          this.statusTimeline.innerHTML = `<span class="legend-dot dot-disconnected"></span><strong>Disconnected</strong> ${formatTimestampAndAgo(data.last_disconnected_at)}`;
        } else {
          this.statusTimeline.innerHTML = `<span class="legend-dot dot-disconnected"></span><strong>Link down / hunting</strong>`;
        }
      } else {
        this.statusTimeline.innerHTML = `Checking status...`;
      }
    }

    if (this.connectedTimestamp) {
      this.connectedTimestamp.textContent = formatTimestampAndAgo(data.last_connected_at);
    }
    if (this.disconnectedTimestamp) {
      this.disconnectedTimestamp.textContent = formatTimestampAndAgo(data.last_disconnected_at);
    }

    // Row that only exists on a TLS/SSH transport
    const linked = data.transport === 'tls' || data.transport === 'ssh';
    if (this.timerLinkSince) this.timerLinkSince.style.display = linked ? '' : 'none';
    if (linked) {
      if (this.linkSinceLabel) this.linkSinceLabel.textContent = `${data.transport.toUpperCase()} link up since`;
      if (this.linkSince) this.linkSince.textContent = data.link_connected ? formatTimestampAndAgo(data.link_since) : 'Link down';
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
    if (this.heroPanel) this.heroPanel.dataset.state = state.toLowerCase();

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
    this.wgInterface.textContent = (data.interface || 'wg0') + (data.backend === 'amneziawg' ? ' · AmneziaWG' : '');
    this.localPort.textContent = data.local_port > 0 ? `:${data.local_port}` : '--';
    this.localPortRange.textContent = data.local_port_range || '--';

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
      if (!data.ping_enabled) {
        this.pingStatus.textContent = `${data.in_tunnel_ping_target} (Disabled)`;
        this.pingStatus.style.color = 'var(--text-muted)';
      } else if (data.ping_verified) {
        this.pingStatus.textContent = `${data.in_tunnel_ping_target} (Verified OK)`;
        this.pingStatus.style.color = 'var(--success)';
      } else if (data.failed_pings > 0) {
        this.pingStatus.textContent = `${data.in_tunnel_ping_target} (Unreachable #${data.failed_pings})`;
        this.pingStatus.style.color = 'var(--danger)';
      } else {
        this.pingStatus.textContent = `${data.in_tunnel_ping_target} (Testing...)`;
        this.pingStatus.style.color = 'var(--warning)';
      }
    } else {
      this.pingStatus.textContent = data.ping_enabled ? 'No Ping Target' : 'Disabled';
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

    // 5. Telemetry Cards
    if (data.hunting === false) {
      this.huntRecoverySummary.textContent = 'Passive';
      this.huntAttemptStatus.textContent = 'Passive (no port rotation)';
      this.huntAttemptStatus.style.color = state === 'CONNECTED' ? 'var(--success)' : 'var(--warning)';
    } else {
      this.huntRecoverySummary.textContent = `${data.successful_hunts || 0} / ${data.total_hunts || 0}`;

      if (data.current_attempt > 0) {
        this.huntAttemptStatus.textContent = `Hunting (Attempt #${data.current_attempt})`;
        this.huntAttemptStatus.style.color = 'var(--accent)';
      } else if (state === 'CONNECTED') {
        this.huntAttemptStatus.textContent = 'Idle';
        this.huntAttemptStatus.style.color = 'var(--success)';
      } else {
        this.huntAttemptStatus.textContent = '—';
        this.huntAttemptStatus.style.color = 'var(--text-muted)';
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

    const huntReason = data.last_hunt_reason || '';
    this.lastHuntReason.textContent = huntReason;
    this.lastHuntReason.title = huntReason;
    if (this.lastHuntSep) this.lastHuntSep.style.display = huntReason ? '' : 'none';

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

    // Network tile
    if (data.iptables_active) {
      this.iptablesStateText.textContent = 'On';
      this.iptablesStateText.style.color = 'var(--success)';
      this.iptablesSubtext.textContent = `→ :${data.local_port || '...'}`;
    } else {
      this.iptablesStateText.textContent = 'Off';
      this.iptablesStateText.style.color = 'var(--text-muted)';
      this.iptablesSubtext.textContent = '';
    }
    this.renderTransport(data);

    // Connection Events History
    this.renderEvents(data.events);
  }

  renderTransport(data) {
    const kind = data.transport || 'direct';
    const linked = kind === 'tls' || kind === 'ssh';
    const label = kind.toUpperCase();
    if (this.rowTransport) this.rowTransport.style.display = linked ? '' : 'none';
    if (this.rowLink) this.rowLink.style.display = linked ? '' : 'none';
    if (this.bridgeProtoBadge) {
      this.bridgeProtoBadge.textContent = linked ? label : 'UDP';
      this.bridgeProtoBadge.classList.toggle('path-tls', linked);
    }
    if (!linked) return;

    if (this.transportState) {
      this.transportState.textContent = `WireGuard over ${label} (relay :${data.link_relay_port || '?'})`;
    }
    if (this.linkState) {
      const traffic = `↓ ${formatBytes(data.link_bytes_rx)} ↑ ${formatBytes(data.link_bytes_tx)}`;
      const resets = data.link_resets > 0 ? ` · ${data.link_resets} rebuilt` : '';
      this.linkState.title = '';
      if (data.link_connected) {
        const rtt = data.link_rtt_ms > 0 ? ` · ${data.link_rtt_ms < 10 ? data.link_rtt_ms.toFixed(1) : Math.round(data.link_rtt_ms)} ms` : '';
        const lost = data.link_probe_failures > 0 ? ` · ${data.link_probe_failures} probes lost` : '';
        this.linkState.textContent = `Up · ${data.link_direction || ''} ${data.link_remote || ''}${rtt} · ${traffic}${lost}${resets}`;
        this.linkState.style.color = 'var(--success)';
      } else if (data.link_verifying) {
        this.linkState.textContent = 'Connected, checking it carries traffic...';
        this.linkState.style.color = 'var(--warning)';
      } else {
        const err = data.link_last_error || '';
        let text = 'Down · dialing';
        if (/authenticat/i.test(err)) text = `Down · authentication failed, check ${kind}.secret`;
        else if (/health|probe/i.test(err)) text = 'Down · connection stalled, reconnecting';
        else if (/Permission denied|Host key|ssh/i.test(err)) text = 'Down · ' + err;
        this.linkState.textContent = text + resets;
        this.linkState.title = err;
        this.linkState.style.color = 'var(--warning)';
      }
    }
    if (this.btnHunt) this.btnHunt.title = `Reconnect the ${label} link`;
    if (this.btnRebind) this.btnRebind.title = `Reconnect the ${label} link and move its listener`;
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
          btnSwitch.textContent = `Set ${this.selectedTunnel} as active route`;
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

    const isFirst = this.tunnelCardsContainer.children.length === 0;
    const card = document.createElement('details');
    card.className = 'tunnel-form-card';
    if (isNew || isFirst) card.open = true;

    const targetIPs = (tunnel.target_ips && tunnel.target_ips.length > 0)
      ? tunnel.target_ips
      : (tunnel.target_ip ? [tunnel.target_ip] : []);

    const isHunting = tunnel.hunting !== false;
    const isIptables = tunnel.iptables !== false;
    const ping = tunnel.tunnel_ping || {};
    const tls = tunnel.tls || {};
    const ssh = tunnel.ssh || {};
    const transport = ['tls', 'ssh'].includes(tunnel.transport) ? tunnel.transport : 'direct';
    const text = (cls, value, placeholder = '') =>
      `<input type="text" class="form-input ${cls}" value="${escapeHtml(value)}" placeholder="${escapeHtml(placeholder)}" spellcheck="false">`;
    const num = (cls, value, placeholder = '') =>
      `<input type="number" class="form-input ${cls}" value="${value}" placeholder="${escapeHtml(placeholder)}" min="0">`;
    const area = (cls, value, rows, placeholder = '') =>
      `<textarea class="form-textarea ${cls}" rows="${rows}" placeholder="${escapeHtml(placeholder)}" spellcheck="false">${escapeHtml(value)}</textarea>`;

    card.innerHTML = `
      <summary class="tunnel-card-header">
        <span class="tunnel-card-title">${escapeHtml(tunnel.interface || 'new_wg')}</span>
        <span class="tunnel-card-name-tag">${escapeHtml(tunnel.name || '')}</span>
        <span class="tunnel-card-badge ${isHunting ? 'hunting' : 'passive'}">${isHunting ? 'Hunting' : 'Passive'}</span>
        <button type="button" class="btn-danger-sm btn-remove-tunnel" title="Remove this tunnel">Remove</button>
      </summary>

      <div class="tunnel-body">
        <div class="group">
          <div class="group-label">Connection</div>
          <div class="form-grid-3">
            ${formField('Interface *', text('t-interface', tunnel.interface || '', 'wg0'), 'System interface name (ip link show)')}
            ${formField('Name', text('t-name', tunnel.name || '', 'Frankfurt-VPS'), 'Shown in the dashboard and logs')}
            ${formField('Backend', backendSelect(tunnel.backend), 'AmneziaWG needs the awg tool and an interface created with awg-quick; its obfuscation settings stay in that interface config.')}
          </div>
          ${formField('Transport', transportSelect(transport), 'How WireGuard\'s packets cross the network. Run one interface per transport and switch between them yourself.')}
          <div class="form-grid-2">
            ${formField('Local port range', text('t-port-range', tunnel.port_range || '20000-30000', '20000-30000'), '<span class="range-note-direct">UDP, redirected to the WireGuard listen port</span><span class="range-note-link">TCP, redirected to the TLS listener or to sshd: keep other services out of it</span>')}
            ${formField('Remote port range', text('t-remote-port-range', tunnel.remote_port_range || '20000-30000', '20000-30000'), 'Ports tried on the peer')}
          </div>
          ${formField('Target IPs / hostnames', area('t-target-ips', targetIPs.join('\n'), 2, '198.51.100.1\n2001:db8::1\nvps.example.com'), 'One per line, IPv4, IPv6 or domains. Rotated when one is blocked; domains are re-resolved on every hunt.')}
          ${formField('Peer public key', text('t-peer-pubkey', tunnel.peer_public_key || '', 'Optional'), 'Detected from the interface when empty')}
          <div class="toggle-row">
            ${formToggle('t-hunting', isHunting, 'Rotate ports automatically when the link stalls')}
            ${formToggle('t-iptables', isIptables, 'Manage the iptables REDIRECT rule')}
          </div>
        </div>

        <div class="group group-link" data-for="tls ssh">
          <div class="group-label">Link</div>
          <p class="group-note" data-for="tls">Both peers keep a TLS 1.3 connection open (Auto-WG on both sides, same secret).</p>
          <p class="group-note" data-for="ssh">A genuine OpenSSH session through the peer's sshd. Needs the ssh client here and sshd on the peer; see the README for the sshd setup.</p>
          <div class="group-fields">
            ${formField('Shared secret', secretInput(transport === 'ssh' ? (ssh.secret || '') : (tls.secret || '')), 'Identical on both peers, at least 16 characters. It is masked after saving, so read it from the config file when setting up the other peer.')}
            <div class="form-grid-3">
              ${formField('Reconnect after', text('t-link-reconnect', formatDuration((transport === 'ssh' ? ssh : tls).reconnect_after, '10s'), '10s'), 'Rebuild the connection when WireGuard stays dead this long')}
              ${formField('Dial interval', text('t-link-dial', formatDuration((transport === 'ssh' ? ssh : tls).dial_interval, '1s'), '1s'))}
              ${formField('Relay port', num('t-link-relay', (transport === 'ssh' ? ssh : tls).relay_port || 0, '0'), '0 = automatic (loopback UDP)')}
            </div>
            <div class="form-grid-3">
              ${formField('Health probe every', text('t-link-health-interval', formatDuration((transport === 'ssh' ? ssh : tls).health_interval, '3s'), '3s'), 'Ping/pong over the link')}
              ${formField('Probe timeout', text('t-link-health-timeout', formatDuration((transport === 'ssh' ? ssh : tls).health_timeout, '2s'), '2s'))}
              ${formField('Failures before reconnect', num('t-link-health-failures', (transport === 'ssh' ? ssh : tls).health_failures || 3, '3'), 'Consecutive unanswered probes')}
            </div>
            ${formField('Packet padding', paddingSelect((transport === 'ssh' ? ssh : tls).padding), 'Hides WireGuard\'s packet sizes: bucket rounds every write up to a few fixed sizes, random appends random filler')}
          </div>
        </div>

        <div class="group group-tls" data-for="tls">
          <div class="group-label">TLS</div>
          <div class="group-fields">
            <div class="form-grid-2">
              ${formField('SNI (optional)', text('t-tls-sni', tls.sni || '', 'www.example.com'), 'Server name sent in the TLS handshake')}
              ${formField('ALPN (optional)', text('t-tls-alpn', (tls.alpn || []).join(', '), 'h2, http/1.1'), 'Comma separated')}
            </div>
          </div>
        </div>

        <div class="group group-ssh" data-for="ssh">
          <div class="group-label">SSH</div>
          <div class="group-fields">
            <div class="form-grid-3">
              ${formField('User', text('t-ssh-user', ssh.user || '', 'autowg'), 'Account on the peer\'s sshd')}
              ${formField('sshd port here', num('t-ssh-sshd-port', ssh.sshd_port || 22, '22'), 'The local port range is redirected to this host\'s sshd')}
              ${formField('Link port', num('t-ssh-link-port', ssh.link_port || 40022, '40022'), 'Loopback port the peer\'s ssh forwards to; same on both peers')}
            </div>
            <div class="form-grid-2">
              ${formField('Identity file', text('t-ssh-identity', ssh.identity_file || '', '/etc/auto-wg/id_ed25519'), 'Private key used to log in. Leave empty to only accept connections.')}
              ${formField('Peer host key', text('t-ssh-hostkey', ssh.host_key || '', 'ssh-ed25519 AAAA...'), 'The peer sshd\'s public key (cat /etc/ssh/ssh_host_ed25519_key.pub)')}
            </div>
            ${formField('ssh binary', text('t-ssh-path', ssh.ssh_path || '', 'ssh'), 'OpenSSH client to run')}
          </div>
        </div>

        <div class="group group-ping ${ping.enabled ? '' : 'off'}">
          <div class="group-label">
            Health check
            ${formToggle('t-ping-enabled', !!ping.enabled, 'In-tunnel ping')}
          </div>
          <div class="group-fields">
            <div class="form-grid-3">
              ${formField('Ping target', text('t-ping-target', ping.target_ip || '', '10.100.0.1'), 'In-tunnel IP of the peer')}
              ${formField('Interval', text('t-ping-interval', formatDuration(ping.interval, '2s'), '2s'))}
              ${formField('Failure threshold', num('t-ping-threshold', ping.failure_threshold || 3, '3'), 'Failed pings before a hunt')}
            </div>
          </div>
          <div class="form-grid-3">
            ${formField('Check interval', text('t-check-interval', formatDuration(tunnel.check_interval, '3s'), '3s'))}
            ${formField('Handshake timeout', text('t-handshake-timeout', formatDuration(tunnel.handshake_timeout, '60s'), '60s'))}
            ${formField('Stagger cycle', text('t-cycle-timeout', formatDuration(tunnel.cycle_timeout, '8s'), '8s'))}
          </div>
        </div>

        <div class="group">
          <div class="group-label">Advanced</div>
          ${formField('History file', text('t-history-file', tunnel.history_file || '', 'Default, or "off" to disable'))}
          <div class="form-grid-2">
            ${formField('Post-up commands', area('t-post-up', (tunnel.post_up || []).join('\n'), 2, 'One per line'))}
            ${formField('Pre-down commands', area('t-pre-down', (tunnel.pre_down || []).join('\n'), 2, 'One per line'))}
          </div>
        </div>
      </div>
    `;

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
      if (!badgeEl) return;
      badgeEl.textContent = huntingInput.checked ? 'Hunting' : 'Passive';
      badgeEl.className = `tunnel-card-badge ${huntingInput.checked ? 'hunting' : 'passive'}`;
    });

    // Dim a group's fields while its master switch is off
    const bindGroupSwitch = (switchSel, groupSel) => {
      const sw = card.querySelector(switchSel);
      const group = card.querySelector(groupSel);
      sw?.addEventListener('change', () => group?.classList.toggle('off', !sw.checked));
    };
    bindGroupSwitch('.t-ping-enabled', '.group-ping');

    // Show only the groups of the selected transport
    const transportEl = card.querySelector('.t-transport');
    const applyTransport = () => {
      const kind = transportEl?.value || 'direct';
      card.querySelectorAll('[data-for]').forEach(el => {
        el.hidden = !el.dataset.for.split(' ').includes(kind);
      });
      card.querySelectorAll('.range-note-direct').forEach(el => { el.hidden = kind !== 'direct'; });
      card.querySelectorAll('.range-note-link').forEach(el => { el.hidden = kind === 'direct'; });
    };
    transportEl?.addEventListener('change', applyTransport);
    applyTransport();

    // Secret field: generate a random secret (shown in clear so it can be copied) or reveal the value
    const secretEl = card.querySelector('.t-link-secret');
    card.querySelector('.btn-gen-secret')?.addEventListener('click', () => {
      const bytes = crypto.getRandomValues(new Uint8Array(24));
      secretEl.value = btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_');
      secretEl.type = 'text';
      secretEl.dispatchEvent(new Event('input', { bubbles: true }));
    });
    card.querySelector('.btn-show-secret')?.addEventListener('click', (e) => {
      secretEl.type = secretEl.type === 'password' ? 'text' : 'password';
      e.currentTarget.textContent = secretEl.type === 'password' ? 'Show' : 'Hide';
    });

    // Remove lives inside <summary>, so keep the click from folding the card
    const btnRemove = card.querySelector('.btn-remove-tunnel');
    btnRemove?.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
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
      const backend = card.querySelector('.t-backend')?.value || 'wireguard';

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

      const intVal = (sel, def) => {
        const n = parseInt(card.querySelector(sel)?.value, 10);
        return Number.isNaN(n) ? def : n;
      };
      const val = (sel) => card.querySelector(sel)?.value.trim() || '';
      const transport = card.querySelector('.t-transport')?.value || 'direct';
      const linkCfg = {
        secret: card.querySelector('.t-link-secret')?.value || '',
        relay_port: intVal('.t-link-relay', 0),
        reconnect_after: val('.t-link-reconnect') || '10s',
        dial_interval: val('.t-link-dial') || '1s',
        health_interval: val('.t-link-health-interval') || '3s',
        health_timeout: val('.t-link-health-timeout') || '2s',
        health_failures: intVal('.t-link-health-failures', 3),
        padding: card.querySelector('.t-link-padding')?.value || 'off'
      };
      const tlsCfg = transport !== 'tls' ? {} : {
        ...linkCfg,
        sni: val('.t-tls-sni'),
        alpn: val('.t-tls-alpn').split(',').map(x => x.trim()).filter(x => x.length > 0)
      };
      const sshCfg = transport !== 'ssh' ? {} : {
        ...linkCfg,
        user: val('.t-ssh-user'),
        identity_file: val('.t-ssh-identity'),
        host_key: val('.t-ssh-hostkey'),
        ssh_path: val('.t-ssh-path'),
        sshd_port: intVal('.t-ssh-sshd-port', 22),
        link_port: intVal('.t-ssh-link-port', 40022)
      };

      const postUpRaw = card.querySelector('.t-post-up')?.value || '';
      const postUp = postUpRaw.split('\n').map(s => s.trim()).filter(s => s.length > 0);
      const preDownRaw = card.querySelector('.t-pre-down')?.value || '';
      const preDown = preDownRaw.split('\n').map(s => s.trim()).filter(s => s.length > 0);

      const tunnelObj = {
        interface: iface,
        backend: backend,
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
        },
        transport: transport,
        tls: tlsCfg,
        ssh: sshCfg
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
      if (t.backend && t.backend !== 'wireguard') lines.push(`    backend: "${t.backend}"`);
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

      if (t.transport && t.transport !== 'direct') lines.push(`    transport: ${t.transport}`);
      const linkBlock = (name, b, extra) => {
        if (!b || !b.secret) return;
        lines.push(`    ${name}:`);
        lines.push(`      secret: ${JSON.stringify(b.secret)}`);
        if (b.relay_port > 0) lines.push(`      relay_port: ${b.relay_port}`);
        if (b.reconnect_after) lines.push(`      reconnect_after: "${b.reconnect_after}"`);
        if (b.dial_interval) lines.push(`      dial_interval: "${b.dial_interval}"`);
        if (b.health_interval) lines.push(`      health_interval: "${b.health_interval}"`);
        if (b.health_timeout) lines.push(`      health_timeout: "${b.health_timeout}"`);
        if (b.health_failures > 0) lines.push(`      health_failures: ${b.health_failures}`);
        if (b.padding && b.padding !== 'off') lines.push(`      padding: ${b.padding}`);
        extra(b);
      };
      if (t.transport === 'tls') linkBlock('tls', t.tls, (b) => {
        if (b.sni) lines.push(`      sni: ${JSON.stringify(b.sni)}`);
        if (b.alpn && b.alpn.length > 0) lines.push(`      alpn: [${b.alpn.map(a => JSON.stringify(a)).join(', ')}]`);
      });
      if (t.transport === 'ssh') linkBlock('ssh', t.ssh, (b) => {
        if (b.user) lines.push(`      user: ${JSON.stringify(b.user)}`);
        if (b.identity_file) lines.push(`      identity_file: ${JSON.stringify(b.identity_file)}`);
        if (b.host_key) lines.push(`      host_key: ${JSON.stringify(b.host_key)}`);
        if (b.ssh_path) lines.push(`      ssh_path: ${JSON.stringify(b.ssh_path)}`);
        if (b.sshd_port) lines.push(`      sshd_port: ${b.sshd_port}`);
        if (b.link_port) lines.push(`      link_port: ${b.link_port}`);
      });

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

function formField(label, control, hint = '') {
  return `<div class="form-group"><label class="form-label">${label}</label>${control}${hint ? `<span class="form-hint">${hint}</span>` : ''}</div>`;
}

function backendSelect(current) {
  const value = current === 'amneziawg' ? 'amneziawg' : 'wireguard';
  const option = (v, label) => `<option value="${v}" ${v === value ? 'selected' : ''}>${label}</option>`;
  return `<select class="form-input t-backend">${option('wireguard', 'WireGuard')}${option('amneziawg', 'AmneziaWG')}</select>`;
}

function transportSelect(current) {
  const option = (v, label) => `<option value="${v}" ${v === current ? 'selected' : ''}>${label}</option>`;
  return `<select class="form-input t-transport">${option('direct', 'Direct (WireGuard over UDP)')}${option('tls', 'WireGuard over TLS')}${option('ssh', 'WireGuard over SSH (real OpenSSH)')}</select>`;
}

function paddingSelect(current) {
  const value = ['bucket', 'random'].includes(current) ? current : 'off';
  const option = (v, label) => `<option value="${v}" ${v === value ? 'selected' : ''}>${label}</option>`;
  return `<select class="form-input t-link-padding">${option('off', 'Off')}${option('bucket', 'Bucket (a few fixed sizes)')}${option('random', 'Random')}</select>`;
}

function secretInput(value) {
  return `<div class="input-row"><input type="password" class="form-input t-link-secret" value="${escapeHtml(value)}" placeholder="Same value on both peers" spellcheck="false" autocomplete="off"><button type="button" class="btn btn-secondary btn-sm btn-gen-secret">Generate</button><button type="button" class="btn btn-ghost btn-sm btn-show-secret">Show</button></div>`;
}

function formToggle(cls, checked, text) {
  return `<label class="switch-label"><input type="checkbox" class="${cls}" ${checked ? 'checked' : ''}><span class="switch-slider"></span><span class="switch-text">${text}</span></label>`;
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
