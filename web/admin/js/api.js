class AuthPoleAPI {
  constructor(getApiHostFn, getTenantFn, getAdminTokenFn, onCASConflictFn) {
    this.getApiHost = getApiHostFn;
    this.getTenant = getTenantFn;
    this.getAdminToken = getAdminTokenFn;
    this.onCASConflict = onCASConflictFn;
  }

  async request(endpoint, options = {}) {
    const apiHost = this.getApiHost().replace(/\/$/, '');
    const url = `${apiHost}${endpoint}`;

    const headers = options.headers || {};
    headers['X-Tenant-ID'] = this.getTenant();
    
    const adminToken = this.getAdminToken ? this.getAdminToken() : '';
    if (adminToken && !headers['Authorization']) {
      headers['Authorization'] = `Bearer ${adminToken}`;
    }

    if (!headers['Content-Type'] && options.body && typeof options.body === 'string') {
      headers['Content-Type'] = 'application/json';
    }

    const config = {
      ...options,
      headers
    };

    try {
      const response = await fetch(url, config);
      const versionHeader = response.headers.get('ETag');

      if (response.status === 409) {
        // CAS Version Conflict detected!
        if (this.onCASConflict) {
          this.onCASConflict();
        }
        throw new Error('cas_conflict: object version has changed');
      }

      if (!response.ok) {
        let errMsg = `Request failed with status ${response.status}`;
        try {
          const errJson = await response.json();
          if (errJson.message) errMsg = errJson.message;
        } catch (_) {}
        throw new Error(errMsg);
      }

      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        const data = await response.json();
        return { data, version: versionHeader };
      }

      const text = await response.text();
      return { data: text, version: versionHeader };
    } catch (err) {
      if (err.message.includes('cas_conflict')) {
        throw err;
      }
      console.error(`API Error on ${endpoint}:`, err);
      throw err;
    }
  }

  // Tenants API
  async getTenants() { return this.request('/api/v1/tenants'); }
  async getTenant(id) { return this.request(`/api/v1/tenants/${id}`); }
  async saveTenant(tenant, expectedVersion) {
    return this.request('/api/v1/tenants', {
      method: 'POST',
      headers: expectedVersion ? { 'X-Expected-Version': expectedVersion } : {},
      body: JSON.stringify(tenant)
    });
  }

  // Applications API
  async getApps() { return this.request('/api/v1/apps'); }
  async saveApp(app, expectedVersion) {
    return this.request('/api/v1/apps', {
      method: 'POST',
      headers: expectedVersion ? { 'X-Expected-Version': expectedVersion } : {},
      body: JSON.stringify(app)
    });
  }

  // Upstream IDPs API
  async getIDPs() { return this.request('/api/v1/idps'); }
  async saveIDP(idp, expectedVersion) {
    return this.request('/api/v1/idps', {
      method: 'POST',
      headers: expectedVersion ? { 'X-Expected-Version': expectedVersion } : {},
      body: JSON.stringify(idp)
    });
  }

  // Keys & JWKS API
  async getKeys() { return this.request('/api/v1/keys'); }
  async generateKey(appID) {
    return this.request(`/api/v1/keys?app_id=${encodeURIComponent(appID || '')}`, { method: 'POST' });
  }
  async getJWKS() { return this.request(`/.well-known/jwks.json?tenant=${encodeURIComponent(this.getTenant())}`); }

  // RBAC API
  async getUsers() { return this.request('/api/v1/admin/users'); }
  async saveUser(user, expectedVersion) {
    return this.request('/api/v1/admin/users', {
      method: 'POST',
      headers: expectedVersion ? { 'X-Expected-Version': expectedVersion } : {},
      body: JSON.stringify(user)
    });
  }

  async getTeams() { return this.request('/api/v1/admin/teams'); }
  async saveTeam(team, expectedVersion) {
    return this.request('/api/v1/admin/teams', {
      method: 'POST',
      headers: expectedVersion ? { 'X-Expected-Version': expectedVersion } : {},
      body: JSON.stringify(team)
    });
  }

  async getRoles() { return this.request('/api/v1/admin/roles'); }
  async saveRole(role, expectedVersion) {
    return this.request('/api/v1/admin/roles', {
      method: 'POST',
      headers: expectedVersion ? { 'X-Expected-Version': expectedVersion } : {},
      body: JSON.stringify(role)
    });
  }

  // SPIFFE M2M Workloads & Trust Bundle API
  async getWorkloads() { return this.request('/api/v1/admin/spiffe/workloads'); }
  async saveWorkload(workload, expectedVersion) {
    return this.request('/api/v1/admin/spiffe/workloads', {
      method: 'POST',
      headers: expectedVersion ? { 'X-Expected-Version': expectedVersion } : {},
      body: JSON.stringify(workload)
    });
  }
  async getSPIFFEBundle() { return this.request(`/.well-known/spiffe/bundle?tenant=${encodeURIComponent(this.getTenant())}`); }

  // Access Path Validation
  async validateToken(token, appID) {
    const apiHost = this.getApiHost().replace(/\/$/, '');
    const res = await fetch(`${apiHost}/api/v1/auth/validate`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'X-Tenant-ID': this.getTenant(),
        'X-App-ID': appID || ''
      }
    });
    return await res.json();
  }
}
