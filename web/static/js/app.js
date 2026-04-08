'use strict';

/**
 * SambaGuard — Frontend Application
 *
 * Architecture:
 * - Alpine.js manages all reactive state
 * - JWT access token is kept in memory (not localStorage — XSS safe)
 * - Refresh token lives in httpOnly cookie (JS cannot read it — secure)
 * - CSRF double-submit cookie pattern for all state-changing requests
 * - Token refresh happens automatically before expiry
 */

let _accessToken = null;
let _refreshTimer = null;

function app() {
  return {
    // ── Auth state ──────────────────────────────────────────────────────────
    isAuthenticated: false,
    currentUser: {},
    loginForm: { username: '', password: '' },
    loginLoading: false,
    loginError: '',

    // ── Navigation ──────────────────────────────────────────────────────────
    currentPage: 'dashboard',
    pageTitle: 'Dashboard',
    pageSubtitle: 'Overview of your Samba server',

    navItems: [
      { page: 'dashboard', label: 'Dashboard', badge: 0,
        icon: '<svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7h4v4H3V7zm0 8h4v4H3v-4zm8-8h4v4h-4V7zm0 8h4v4h-4v-4zm8-8h4v4h-4V7zm0 8h4v4h-4v-4z"/></svg>' },
      { page: 'users',     label: 'Samba Users', badge: 0,
        icon: '<svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/></svg>' },
      { page: 'groups',    label: 'Groups', badge: 0,
        icon: '<svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/></svg>' },
      { page: 'shares',    label: 'Shares', badge: 0,
        icon: '<svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>' },
      { page: 'config',    label: 'Configuration', badge: 0,
        icon: '<svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>' },
      { page: 'logs',      label: 'Audit Logs', badge: 0,
        icon: '<svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"/></svg>' },
    ],

    // ── Data ────────────────────────────────────────────────────────────────
    users: [], userTotal: 0, userSearch: '', userOffset: 0, userLimit: 50,
    groups: [], groupSearch: '',
    shares: [], shareSearch: '',
    auditLogs: [], logTotal: 0, logSearch: '', logOffset: 0, logLimit: 50, logAction: '',
    stats: {},
    configStatus: { has_pending_changes: false },
    configBackups: [],
    recentLogs: [],
    availableGroups: [],

    // ── Modal ────────────────────────────────────────────────────────────────
    modal: { open: false, type: '', title: '', data: {}, loading: false },

    // ── UI state ─────────────────────────────────────────────────────────────
    toasts: [],
    applying: false,

    // ────────────────────────────────────────────────────────────────────────
    // Lifecycle
    // ────────────────────────────────────────────────────────────────────────

    async init() {
      // Try to restore session via refresh token (cookie-based)
      await this.tryRefresh();
      if (this.isAuthenticated) {
        await this.loadCurrentPage();
        this.startSSE();
      }
    },

    // ────────────────────────────────────────────────────────────────────────
    // Authentication
    // ────────────────────────────────────────────────────────────────────────

    async login() {
      this.loginLoading = true;
      this.loginError = '';
      try {
        const res = await this.post('/api/v1/auth/login', {
          username: this.loginForm.username,
          password: this.loginForm.password,
        }, { skipAuth: true, skipCSRF: true });

        _accessToken = res.access_token;
        this.currentUser = {
          username: this.loginForm.username,
          role: res.role,
          mustChangePass: res.must_change_pass,
        };
        this.isAuthenticated = true;
        this.loginForm = { username: '', password: '' };

        this.scheduleRefresh(res.expires_in);
        await this.loadCurrentPage();
        this.startSSE();

        if (res.must_change_pass) {
          this.toast('warning', 'Password Change Required', 'Please change your password to continue.');
        }
      } catch (err) {
        this.loginError = err.message || 'Login failed. Check your credentials.';
      } finally {
        this.loginLoading = false;
      }
    },

    async tryRefresh() {
      try {
        const res = await this.post('/api/v1/auth/refresh', {}, { skipAuth: true, skipCSRF: true });
        _accessToken = res.access_token;
        this.isAuthenticated = true;

        // Load user info
        const me = await this.get('/api/v1/auth/me');
        this.currentUser = me;

        this.scheduleRefresh(res.expires_in);
      } catch {
        // No valid refresh token — user must log in
        _accessToken = null;
        this.isAuthenticated = false;
      }
    },

    scheduleRefresh(expiresInSeconds) {
      if (_refreshTimer) clearTimeout(_refreshTimer);
      // Refresh 60 seconds before expiry
      const ms = Math.max((expiresInSeconds - 60) * 1000, 5000);
      _refreshTimer = setTimeout(() => this.tryRefresh(), ms);
    },

    async logout() {
      try {
        await this.post('/api/v1/auth/logout', {});
      } catch {}
      _accessToken = null;
      if (_refreshTimer) clearTimeout(_refreshTimer);
      this.isAuthenticated = false;
      this.currentUser = {};
      this.toast('info', 'Signed out', 'You have been logged out.');
    },

    // ────────────────────────────────────────────────────────────────────────
    // Navigation
    // ────────────────────────────────────────────────────────────────────────

    async navigate(page) {
      this.currentPage = page;
      const titles = {
        dashboard: ['Dashboard', 'Overview of your Samba server'],
        users:     ['Samba Users', 'Manage Samba-only user accounts'],
        groups:    ['Groups', 'Manage Linux groups for Samba access control'],
        shares:    ['Shares', 'Configure shared folders and permissions'],
        config:    ['Configuration', 'Manage smb.conf and apply changes'],
        logs:      ['Audit Logs', 'Track all administrative actions'],
      };
      const [title, subtitle] = titles[page] || ['', ''];
      this.pageTitle = title;
      this.pageSubtitle = subtitle;
      await this.loadCurrentPage();
    },

    async loadCurrentPage() {
      switch (this.currentPage) {
        case 'dashboard': await Promise.all([this.loadStats(), this.loadRecentLogs(), this.loadConfigStatus()]); break;
        case 'users':     await Promise.all([this.loadUsers(), this.loadGroups()]); break;
        case 'groups':    await this.loadGroups(); break;
        case 'shares':    await this.loadShares(); break;
        case 'logs':      await this.loadLogs(); break;
        case 'config':    await Promise.all([this.loadConfigStatus(), this.loadConfigBackups()]); break;
      }
    },

    // ────────────────────────────────────────────────────────────────────────
    // Data loaders
    // ────────────────────────────────────────────────────────────────────────

    async loadStats() {
      try { this.stats = await this.get('/api/v1/logs/stats'); } catch {}
    },

    async loadConfigStatus() {
      try { this.configStatus = await this.get('/api/v1/config/status'); } catch {}
    },

    async loadRecentLogs() {
      try {
        const res = await this.get('/api/v1/logs?limit=10');
        this.recentLogs = res.items || [];
      } catch {}
    },

    async loadUsers() {
      try {
        const q = new URLSearchParams({ search: this.userSearch, limit: this.userLimit, offset: this.userOffset });
        const res = await this.get('/api/v1/users?' + q);
        this.users = res.items || [];
        this.userTotal = res.total || 0;
      } catch (err) { this.toast('error', 'Failed to load users', err.message); }
    },

    async loadGroups() {
      try {
        const q = new URLSearchParams({ search: this.groupSearch, limit: 200 });
        const res = await this.get('/api/v1/groups?' + q);
        this.groups = res.items || [];
        this.availableGroups = this.groups; // for user creation form
      } catch (err) { this.toast('error', 'Failed to load groups', err.message); }
    },

    async loadShares() {
      try {
        const q = new URLSearchParams({ search: this.shareSearch, limit: 200 });
        const res = await this.get('/api/v1/shares?' + q);
        this.shares = res.items || [];
      } catch (err) { this.toast('error', 'Failed to load shares', err.message); }
    },

    async loadLogs() {
      try {
        const q = new URLSearchParams({
          search: this.logSearch, action: this.logAction,
          limit: this.logLimit, offset: this.logOffset,
        });
        const res = await this.get('/api/v1/logs?' + q);
        this.auditLogs = res.items || [];
        this.logTotal = res.total || 0;
      } catch (err) { this.toast('error', 'Failed to load logs', err.message); }
    },

    async loadConfigBackups() {
      try {
        const res = await this.get('/api/v1/config/backups?limit=20');
        this.configBackups = res.items || [];
      } catch {}
    },

    // ────────────────────────────────────────────────────────────────────────
    // User actions
    // ────────────────────────────────────────────────────────────────────────

    async toggleUserStatus(user) {
      const newStatus = user.status === 'enabled' ? 'disabled' : 'enabled';
      try {
        await this.put(`/api/v1/users/${user.id}`, { status: newStatus });
        user.status = newStatus;
        this.toast('success', `User ${newStatus}`, `${user.username} is now ${newStatus}.`);
      } catch (err) { this.toast('error', 'Action failed', err.message); }
    },

    async deleteUser(user) {
      if (!confirm(`Delete Samba user "${user.username}"? This cannot be undone.`)) return;
      try {
        await this.delete(`/api/v1/users/${user.id}`);
        this.users = this.users.filter(u => u.id !== user.id);
        this.userTotal--;
        this.toast('success', 'User deleted', `${user.username} has been removed.`);
      } catch (err) { this.toast('error', 'Delete failed', err.message); }
    },

    async deleteGroup(group) {
      if (!confirm(`Delete group "${group.name}"?`)) return;
      try {
        await this.delete(`/api/v1/groups/${group.id}`);
        this.groups = this.groups.filter(g => g.id !== group.id);
        this.toast('success', 'Group deleted', `${group.name} has been removed.`);
      } catch (err) { this.toast('error', 'Delete failed', err.message); }
    },

    async deleteShare(share) {
      if (!confirm(`Delete share "${share.name}"? Samba restart will be needed.`)) return;
      try {
        await this.delete(`/api/v1/shares/${share.id}`);
        this.shares = this.shares.filter(s => s.id !== share.id);
        this.toast('success', 'Share deleted', `${share.name} removed. Apply config to take effect.`);
        await this.loadConfigStatus();
      } catch (err) { this.toast('error', 'Delete failed', err.message); }
    },

    // ────────────────────────────────────────────────────────────────────────
    // Config actions
    // ────────────────────────────────────────────────────────────────────────

    async applyConfig() {
      if (!confirm('Apply configuration and restart Samba? Active connections may be interrupted.')) return;
      this.applying = true;
      try {
        await this.post('/api/v1/config/apply', {});
        await this.loadConfigStatus();
        this.toast('success', 'Configuration applied', 'Samba has been restarted successfully.');
      } catch (err) {
        this.toast('error', 'Apply failed', err.message);
      } finally {
        this.applying = false;
      }
    },

    async backupConfig() {
      try {
        const backup = await this.post('/api/v1/config/backup', { note: 'manual backup' });
        await this.loadConfigBackups();
        this.toast('success', 'Backup created', backup.filename);
      } catch (err) { this.toast('error', 'Backup failed', err.message); }
    },

    // ────────────────────────────────────────────────────────────────────────
    // Modal management
    // ────────────────────────────────────────────────────────────────────────

    openModal(type, data = {}) {
      const defaults = {
        createUser:     { username: '', password: '', display_name: '', comment: '', groups: [] },
        changePassword: { ...data, new_password: '' },
        createGroup:    { name: '', description: '' },
        manageGroup:    { ...data },
        createShare:    { name: '', path: '', comment: '', enabled: true, browseable: true, read_only: false, guest_ok: false, owner_group: '', acl: [] },
        editShare:      { ...data, acl: data.acl ? [...data.acl] : [] },
      };
      const titles = {
        createUser: 'New Samba User',
        changePassword: `Change Password — ${data.username}`,
        createGroup: 'New Group',
        manageGroup: `Manage Group — ${data.name}`,
        createShare: 'New Samba Share',
        editShare: `Edit Share — ${data.name}`,
      };
      this.modal = {
        open: true,
        type,
        title: titles[type] || type,
        data: defaults[type] || data,
        loading: false,
      };
    },

    closeModal() {
      this.modal = { open: false, type: '', title: '', data: {}, loading: false };
    },

    addAclEntry() {
      if (!this.modal.data.acl) this.modal.data.acl = [];
      this.modal.data.acl.push({ principal: '', permission: 'read_only' });
    },

    // ── Modal submit handlers ────────────────────────────────────────────────

    async submitCreateUser() {
      this.modal.loading = true;
      try {
        const user = await this.post('/api/v1/users', this.modal.data);
        this.users.unshift(user);
        this.userTotal++;
        this.closeModal();
        this.toast('success', 'User created', `${user.username} has been created.`);
        await this.loadConfigStatus();
      } catch (err) {
        this.toast('error', 'Creation failed', err.message);
      } finally {
        this.modal.loading = false;
      }
    },

    async submitChangePassword() {
      this.modal.loading = true;
      try {
        await this.post(`/api/v1/users/${this.modal.data.id}/password`, {
          new_password: this.modal.data.new_password,
        });
        this.closeModal();
        this.toast('success', 'Password updated', `Password changed for ${this.modal.data.username}.`);
      } catch (err) {
        this.toast('error', 'Failed', err.message);
      } finally {
        this.modal.loading = false;
      }
    },

    async submitCreateGroup() {
      this.modal.loading = true;
      try {
        const group = await this.post('/api/v1/groups', {
          name: this.modal.data.name,
          description: this.modal.data.description,
        });
        this.groups.unshift(group);
        this.closeModal();
        this.toast('success', 'Group created', `${group.name} has been created.`);
      } catch (err) {
        this.toast('error', 'Creation failed', err.message);
      } finally {
        this.modal.loading = false;
      }
    },

    async submitShare() {
      this.modal.loading = true;
      try {
        let share;
        if (this.modal.type === 'createShare') {
          share = await this.post('/api/v1/shares', this.modal.data);
          this.shares.unshift(share);
          this.toast('success', 'Share created', `${share.name} — apply config to activate.`);
        } else {
          share = await this.put(`/api/v1/shares/${this.modal.data.id}`, {
            comment: this.modal.data.comment,
            browseable: this.modal.data.browseable,
            guest_ok: this.modal.data.guest_ok,
            read_only: this.modal.data.read_only,
            enabled: this.modal.data.enabled,
            acl: this.modal.data.acl,
          });
          const idx = this.shares.findIndex(s => s.id === share.id);
          if (idx !== -1) this.shares[idx] = share;
          this.toast('success', 'Share updated', `${share.name} — apply config to take effect.`);
        }
        this.closeModal();
        await this.loadConfigStatus();
      } catch (err) {
        this.toast('error', 'Save failed', err.message);
      } finally {
        this.modal.loading = false;
      }
    },

    // ────────────────────────────────────────────────────────────────────────
    // SSE (real-time updates)
    // ────────────────────────────────────────────────────────────────────────

    startSSE() {
      if (!_accessToken) return;
      // Note: SSE doesn't support custom headers, so we pass token as query param
      // In production, use a short-lived SSE ticket instead
      const evtSource = new EventSource('/api/v1/events');
      evtSource.addEventListener('config_changed', () => this.loadConfigStatus());
      evtSource.addEventListener('ping', () => {}); // keepalive
      evtSource.onerror = () => evtSource.close();
    },

    // ────────────────────────────────────────────────────────────────────────
    // Toast notifications
    // ────────────────────────────────────────────────────────────────────────

    toast(type, title, message = '', duration = 5000) {
      const id = Date.now() + Math.random();
      this.toasts.push({ id, type, title, message });
      setTimeout(() => this.dismissToast(id), duration);
    },

    dismissToast(id) {
      this.toasts = this.toasts.filter(t => t.id !== id);
    },

    // ────────────────────────────────────────────────────────────────────────
    // RBAC helpers
    // ────────────────────────────────────────────────────────────────────────

    canAdmin() { return this.currentUser.role === 'admin'; },
    canOperate() { return ['admin', 'operator'].includes(this.currentUser.role); },

    // ────────────────────────────────────────────────────────────────────────
    // HTTP helpers — all requests go through here for token injection
    // ────────────────────────────────────────────────────────────────────────

    async get(url) {
      return this.request('GET', url, null);
    },

    async post(url, body, opts = {}) {
      return this.request('POST', url, body, opts);
    },

    async put(url, body) {
      return this.request('PUT', url, body);
    },

    async delete(url) {
      return this.request('DELETE', url, null);
    },

    async request(method, url, body, { skipAuth = false, skipCSRF = false } = {}) {
      const headers = { 'Content-Type': 'application/json' };

      if (!skipAuth && _accessToken) {
        headers['Authorization'] = 'Bearer ' + _accessToken;
      }

      // CSRF: read token from cookie and add as header
      if (!skipCSRF && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
        const csrf = this.getCookie('csrf_token');
        if (csrf) headers['X-CSRF-Token'] = csrf;
      }

      const opts = { method, headers };
      if (body !== null && body !== undefined) {
        opts.body = JSON.stringify(body);
      }

      const res = await fetch(url, opts);

      // Attempt to handle 401 with token refresh
      if (res.status === 401 && !skipAuth) {
        await this.tryRefresh();
        if (_accessToken) {
          headers['Authorization'] = 'Bearer ' + _accessToken;
          const retry = await fetch(url, { ...opts, headers });
          return this.handleResponse(retry);
        }
        this.isAuthenticated = false;
        throw new Error('Session expired. Please log in again.');
      }

      return this.handleResponse(res);
    },

    async handleResponse(res) {
      let data;
      const contentType = res.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        data = await res.json();
      } else {
        data = await res.text();
      }

      if (!res.ok) {
        const msg = data?.message || data || `HTTP ${res.status}`;
        throw new Error(msg);
      }
      return data;
    },

    getCookie(name) {
      const match = document.cookie.match(new RegExp('(^|;\\s*)' + name + '=([^;]*)'));
      return match ? decodeURIComponent(match[2]) : null;
    },

    // ────────────────────────────────────────────────────────────────────────
    // Formatting helpers
    // ────────────────────────────────────────────────────────────────────────

    formatDate(iso) {
      if (!iso) return '';
      try {
        const d = new Date(iso);
        return d.toLocaleString(undefined, {
          year: 'numeric', month: 'short', day: 'numeric',
          hour: '2-digit', minute: '2-digit',
        });
      } catch { return iso; }
    },

    formatBytes(bytes) {
      if (!bytes) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    },

    dashStats: [
      { key: 'total_samba_users', label: 'Samba Users', color: 'bg-indigo-50 text-indigo-600',
        icon: '<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197"/></svg>' },
      { key: 'total_groups',     label: 'Groups',      color: 'bg-blue-50 text-blue-600',
        icon: '<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857"/></svg>' },
      { key: 'enabled_shares',   label: 'Active Shares', color: 'bg-green-50 text-green-600',
        icon: '<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>' },
      { key: 'audit_today',      label: 'Actions Today', color: 'bg-purple-50 text-purple-600',
        icon: '<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/></svg>' },
    ],
  };
}
