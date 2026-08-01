document.addEventListener('DOMContentLoaded', () => {
  const apiHostInput = document.getElementById('apiHostInput');
  const adminTokenInput = document.getElementById('adminTokenInput');
  const tenantSelect = document.getElementById('tenantSelect');
  const statusDot = document.getElementById('statusDot');
  const statusText = document.getElementById('statusText');

  // Restore saved token from localStorage
  if (localStorage.getItem('authpole_admin_token')) {
    adminTokenInput.value = localStorage.getItem('authpole_admin_token');
  }

  const pageTitle = document.getElementById('pageTitle');
  const pageDescription = document.getElementById('pageDescription');
  const refreshBtn = document.getElementById('refreshBtn');
  const createBtn = document.getElementById('createBtn');

  const modalOverlay = document.getElementById('modalOverlay');
  const modalTitle = document.getElementById('modalTitle');
  const modalBody = document.getElementById('modalBody');
  const modalCloseBtn = document.getElementById('modalCloseBtn');
  const modalCancelBtn = document.getElementById('modalCancelBtn');
  const modalSaveBtn = document.getElementById('modalSaveBtn');

  const casConflictOverlay = document.getElementById('casConflictOverlay');
  const casConflictRefreshBtn = document.getElementById('casConflictRefreshBtn');

  let currentTab = 'tenants';
  let currentSubTab = 'rbac-users';
  let editingRecord = null;

  // Initialize API client with Admin Token and CAS conflict handler
  const api = new AuthPoleAPI(
    () => apiHostInput.value,
    () => tenantSelect.value,
    () => adminTokenInput.value,
    () => showCASConflictModal()
  );

  adminTokenInput.addEventListener('change', () => {
    localStorage.setItem('authpole_admin_token', adminTokenInput.value);
    loadCurrentTabData();
  });

  // OIDC User Profile & Auth Integration
  const oidcSignInBtn = document.getElementById('oidcSignInBtn');
  const oidcSignOutBtn = document.getElementById('oidcSignOutBtn');
  const unauthProfileView = document.getElementById('unauthProfileView');
  const authProfileView = document.getElementById('authProfileView');
  const adminUserName = document.getElementById('adminUserName');
  const adminUserEmail = document.getElementById('adminUserEmail');

  function renderUserProfile() {
    const token = localStorage.getItem('authpole_admin_token');
    const idToken = localStorage.getItem('authpole_id_token') || token;

    if (!token) {
      unauthProfileView.classList.remove('hidden');
      authProfileView.classList.add('hidden');
      return;
    }

    try {
      // Decode JWT payload
      const parts = idToken.split('.');
      if (parts.length === 3) {
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
        adminUserName.textContent = payload.name || payload.preferred_username || payload.sub || 'Admin User';
        adminUserEmail.textContent = payload.email || `${payload.sub}@authpole.io`;
        
        unauthProfileView.classList.add('hidden');
        authProfileView.classList.remove('hidden');
        return;
      }
    } catch (_) {}

    // Fallback if static secret token used
    if (token) {
      adminUserName.textContent = 'Static Admin';
      adminUserEmail.textContent = 'admin@authpole.io';
      unauthProfileView.classList.add('hidden');
      authProfileView.classList.remove('hidden');
    }
  }

  oidcSignInBtn.addEventListener('click', () => {
    const apiHost = apiHostInput.value.replace(/\/$/, '');
    localStorage.setItem('authpole_api_host', apiHost);

    const redirectURI = `${window.location.origin}/callback.html`;
    const authURL = `${apiHost}/oauth/v2/authorize?tenant=${tenantSelect.value}&client_id=admin_console&redirect_uri=${encodeURIComponent(redirectURI)}&response_type=code&scope=openid profile email`;
    window.location.href = authURL;
  });

  oidcSignOutBtn.addEventListener('click', () => {
    localStorage.removeItem('authpole_admin_token');
    localStorage.removeItem('authpole_id_token');
    renderUserProfile();
    loadCurrentTabData();
  });

  renderUserProfile();

  // Tab Definitions & Subtitles
  const tabInfo = {
    tenants: { title: 'Tenants', desc: 'Multi-tenant isolation management and domain configuration.' },
    apps: { title: 'Applications (Service Providers)', desc: 'Configure registered relying party applications, OAuth credentials, and redirect URIs.' },
    idps: { title: 'Upstream Identity Providers', desc: 'Manage federated IDP integrations (OIDC, OAuth2, SAML, Mock).' },
    keys: { title: 'Signing Keys & JWKS', desc: 'Manage RSA/EdDSA asymmetric key pairs and public JWKS download.' },
    rbac: { title: 'Users, Teams & Roles', desc: 'Console administration RBAC and permission assignments.' },
    workloads: { title: 'M2M & SPIFFE Workload Identities', desc: 'Register machine workloads, bind long-expiry SPIFFE cert fingerprints, and download trust bundles.' },
    simulator: { title: 'Auth Flow & Token Lab', desc: 'Test proxy authentication login flow and access path token validation.' }
  };

  // Event Listeners
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
      item.classList.add('active');

      const tab = item.dataset.tab;
      switchTab(tab);
    });
  });

  document.querySelectorAll('.subnav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.subnav-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.subtab-pane').forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      currentSubTab = btn.dataset.subtab;
      document.getElementById(currentSubTab).classList.add('active');
      loadCurrentTabData();
    });
  });

  refreshBtn.addEventListener('click', () => loadCurrentTabData());
  createBtn.addEventListener('click', () => openCreateModal());
  tenantSelect.addEventListener('change', () => loadCurrentTabData());
  apiHostInput.addEventListener('change', () => checkHealth());

  modalCloseBtn.addEventListener('click', closeModal);
  modalCancelBtn.addEventListener('click', closeModal);
  modalSaveBtn.addEventListener('click', handleSaveRecord);

  casConflictRefreshBtn.addEventListener('click', () => {
    casConflictOverlay.classList.add('hidden');
    closeModal();
    loadCurrentTabData();
  });

  function switchTab(tab) {
    currentTab = tab;
    document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));
    document.getElementById(`tab-${tab}`).classList.add('active');

    pageTitle.textContent = tabInfo[tab].title;
    pageDescription.textContent = tabInfo[tab].desc;

    createBtn.style.display = (tab === 'keys' || tab === 'simulator') ? 'none' : 'inline-flex';

    loadCurrentTabData();
  }

  async function checkHealth() {
    try {
      const res = await fetch(`${apiHostInput.value.replace(/\/$/, '')}/healthz`);
      if (res.ok) {
        statusDot.className = 'status-dot online';
        statusText.textContent = 'Connected';
      } else {
        throw new Error();
      }
    } catch (_) {
      statusDot.className = 'status-dot offline';
      statusText.textContent = 'Disconnected';
    }
  }

  async function loadTenantsList() {
    try {
      const { data } = await api.getTenants();
      const tenants = data || [];

      // Update tenant selector options
      const currentSelected = tenantSelect.value;
      tenantSelect.innerHTML = '';
      tenants.forEach(t => {
        const opt = document.createElement('option');
        opt.value = t.id;
        opt.textContent = `${t.id} (${t.name})`;
        if (t.id === currentSelected) opt.selected = true;
        tenantSelect.appendChild(opt);
      });

      const grid = document.getElementById('tenantsGrid');
      grid.innerHTML = tenants.map(t => `
        <div class="card">
          <div class="section-header">
            <h3>${t.name}</h3>
          </div>
          <p class="subtitle">Domain: <span class="code-inline">${t.domain || 'N/A'}</span></p>
          <p class="subtitle">Tenant ID: <span class="code-inline">${t.id}</span></p>
          <button class="btn btn-secondary btn-block edit-tenant-btn" data-id="${t.id}">Edit Tenant</button>
        </div>
      `).join('');

      document.querySelectorAll('.edit-tenant-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
          const { data: tenant } = await api.getTenant(btn.dataset.id);
          openEditModal('tenant', tenant);
        });
      });
    } catch (err) {
      console.error('Failed to load tenants:', err);
    }
  }

  async function loadCurrentTabData() {
    checkHealth();
    if (currentTab === 'tenants') {
      await loadTenantsList();
    } else if (currentTab === 'apps') {
      await loadApps();
    } else if (currentTab === 'idps') {
      await loadIDPs();
    } else if (currentTab === 'keys') {
      await loadKeysAndJWKS();
    } else if (currentTab === 'rbac') {
      await loadRBAC();
    } else if (currentTab === 'workloads') {
      await loadWorkloads();
    } else if (currentTab === 'simulator') {
      await loadSimulator();
    }
  }

  async function loadApps() {
    try {
      const { data } = await api.getApps();
      const apps = data || [];
      const tbody = document.getElementById('appsTableBody');

      tbody.innerHTML = apps.map(a => `
        <tr>
          <td><strong>${a.name}</strong></td>
          <td><span class="code-inline">${a.client_id}</span></td>
          <td>${(a.redirect_uris || []).map(u => `<div class="code-inline">${u}</div>`).join('')}</td>
          <td>${(a.allowed_idps || []).map(i => `<span class="card-badge badge-cyan">${i}</span>`).join(' ')}</td>
          <td>
            <button class="btn btn-secondary edit-app-btn" data-app='${JSON.stringify(a)}'>Edit</button>
          </td>
        </tr>
      `).join('');

      document.querySelectorAll('.edit-app-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          const app = JSON.parse(btn.dataset.app);
          openEditModal('app', app);
        });
      });
    } catch (err) {
      console.error('Failed to load apps:', err);
    }
  }

  async function loadIDPs() {
    try {
      const { data } = await api.getIDPs();
      const idps = data || [];
      const grid = document.getElementById('idpsGrid');

      grid.innerHTML = idps.map(i => `
        <div class="card">
          <div class="section-header">
            <h3>${i.name}</h3>
            <span class="card-badge ${i.enabled ? 'badge-emerald' : 'badge-amber'}">${i.type.toUpperCase()}</span>
          </div>
          <p class="subtitle">IDP ID: <span class="code-inline">${i.id}</span></p>
          <p class="subtitle">Client ID: <span class="code-inline">${i.client_id}</span></p>
          <button class="btn btn-secondary btn-block edit-idp-btn" style="margin-top: 1rem;" data-idp='${JSON.stringify(i)}'>Configure IDP</button>
        </div>
      `).join('');

      document.querySelectorAll('.edit-idp-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          openEditModal('idp', JSON.parse(btn.dataset.idp));
        });
      });
    } catch (err) {
      console.error('Failed to load IDPs:', err);
    }
  }

  async function loadKeysAndJWKS() {
    try {
      const { data: jwks } = await api.getJWKS();
      document.getElementById('jwksCodeView').textContent = typeof jwks === 'string' ? jwks : JSON.stringify(jwks, null, 2);

      const { data: keys } = await api.getKeys();
      const keyList = keys || [];
      const tbody = document.getElementById('keysTableBody');

      tbody.innerHTML = keyList.map(k => `
        <tr>
          <td><span class="code-inline">${k.kid}</span></td>
          <td><span class="card-badge badge-cyan">${k.algorithm}</span></td>
          <td>${k.app_id || 'Global Tenant Key'}</td>
          <td><span class="card-badge ${k.active ? 'badge-emerald' : 'badge-amber'}">${k.active ? 'ACTIVE' : 'INACTIVE'}</span></td>
          <td>${new Date(k.created_at).toLocaleString()}</td>
        </tr>
      `).join('');
    } catch (err) {
      console.error('Failed to load keys:', err);
    }
  }

  async function loadWorkloads() {
    try {
      const { data: bundle } = await api.getSPIFFEBundle();
      document.getElementById('spiffeBundleCodeView').textContent = typeof bundle === 'string' ? bundle : JSON.stringify(bundle, null, 2);

      const { data: workloads } = await api.getWorkloads();
      const list = workloads || [];
      const tbody = document.getElementById('workloadsTableBody');

      tbody.innerHTML = list.map(w => `
        <tr>
          <td><strong>${w.name}</strong></td>
          <td><span class="code-inline">${w.spiffe_id}</span></td>
          <td><span class="code-inline">${(w.cert_fingerprint || 'N/A').substring(0, 16)}...</span></td>
          <td>${(w.allowed_scopes || []).map(s => `<span class="card-badge badge-cyan">${s}</span>`).join(' ')}</td>
          <td><span class="card-badge ${w.active ? 'badge-emerald' : 'badge-amber'}">${w.active ? 'Active' : 'Disabled'}</span></td>
          <td>
            <button class="btn btn-secondary edit-workload-btn" data-workload='${JSON.stringify(w)}'>Edit</button>
          </td>
        </tr>
      `).join('');

      document.querySelectorAll('.edit-workload-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          openEditModal('workload', JSON.parse(btn.dataset.workload));
        });
      });
    } catch (err) {
      console.error('Failed to load SPIFFE workloads:', err);
    }
  }

  document.getElementById('downloadJwksBtn').addEventListener('click', async () => {
    const { data: jwks } = await api.getJWKS();
    const content = typeof jwks === 'string' ? jwks : JSON.stringify(jwks, null, 2);
    const blob = new Blob([content], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `jwks_${tenantSelect.value}.json`;
    a.click();
  });

  document.getElementById('downloadSpiffeBundleBtn').addEventListener('click', async () => {
    const { data: bundle } = await api.getSPIFFEBundle();
    const content = typeof bundle === 'string' ? bundle : JSON.stringify(bundle, null, 2);
    const blob = new Blob([content], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `spiffe_bundle_${tenantSelect.value}.json`;
    a.click();
  });

  document.getElementById('generateKeyBtn').addEventListener('click', async () => {
    try {
      await api.generateKey('');
      loadKeysAndJWKS();
    } catch (err) {
      alert(`Failed to generate key: ${err.message}`);
    }
  });

  async function loadRBAC() {
    try {
      const { data: users } = await api.getUsers();
      document.getElementById('usersTableBody').innerHTML = (users || []).map(u => `
        <tr>
          <td><strong>${u.name}</strong></td>
          <td>${u.email}</td>
          <td>${(u.role_ids || []).map(r => `<span class="card-badge badge-cyan">${r}</span>`).join(' ')}</td>
          <td>${(u.team_ids || []).map(t => `<span class="card-badge badge-emerald">${t}</span>`).join(' ')}</td>
          <td><span class="card-badge ${u.active ? 'badge-emerald' : 'badge-amber'}">${u.active ? 'Active' : 'Disabled'}</span></td>
          <td>
            <button class="btn btn-secondary edit-user-btn" data-user='${JSON.stringify(u)}'>Edit User</button>
          </td>
        </tr>
      `).join('');

      document.querySelectorAll('.edit-user-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          openEditModal('user', JSON.parse(btn.dataset.user));
        });
      });

      const { data: teams } = await api.getTeams();
      document.getElementById('teamsGrid').innerHTML = (teams || []).map(t => `
        <div class="card">
          <h3>${t.name}</h3>
          <p class="subtitle">${t.description}</p>
          <button class="btn btn-secondary btn-block edit-team-btn" style="margin-top: 1rem;" data-team='${JSON.stringify(t)}'>Edit Team</button>
        </div>
      `).join('');

      document.querySelectorAll('.edit-team-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          openEditModal('team', JSON.parse(btn.dataset.team));
        });
      });

      const { data: roles } = await api.getRoles();
      document.getElementById('rolesGrid').innerHTML = (roles || []).map(r => `
        <div class="card">
          <h3>${r.name}</h3>
          <p class="subtitle">${r.description}</p>
          <div style="margin-bottom: 1rem;">Permissions: ${(r.permissions || []).map(p => `<span class="code-inline">${p}</span> `).join('')}</div>
          <button class="btn btn-secondary btn-block edit-role-btn" data-role='${JSON.stringify(r)}'>Edit Role</button>
        </div>
      `).join('');

      document.querySelectorAll('.edit-role-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          openEditModal('role', JSON.parse(btn.dataset.role));
        });
      });
    } catch (err) {
      console.error('Failed to load RBAC:', err);
    }
  }

  async function loadSimulator() {
    const { data: apps } = await api.getApps();
    const simSelect = document.getElementById('simAppSelect');
    simSelect.innerHTML = (apps || []).map(a => `<option value="${a.client_id}">${a.name} (${a.client_id})</option>`).join('');

    document.getElementById('simStartBtn').onclick = () => {
      const clientID = document.getElementById('simClientID').value;
      const redirectURI = document.getElementById('simRedirectURI').value;
      const scope = document.getElementById('simScope').value;
      const authURL = `${apiHostInput.value.replace(/\/$/, '')}/oauth/v2/authorize?tenant=${tenantSelect.value}&client_id=${clientID}&redirect_uri=${encodeURIComponent(redirectURI)}&scope=${encodeURIComponent(scope)}`;
      window.open(authURL, '_blank');
    };

    document.getElementById('simValidateBtn').onclick = async () => {
      const token = document.getElementById('simTokenInput').value.trim();
      const resultBox = document.getElementById('simValidationResult');
      resultBox.classList.remove('hidden');

      if (!token) {
        resultBox.textContent = 'Error: Please enter a JWT token string.';
        return;
      }

      try {
        const res = await api.validateToken(token);
        resultBox.textContent = JSON.stringify(res, null, 2);
      } catch (err) {
        resultBox.textContent = `Validation Error: ${err.message}`;
      }
    };
  }

  async function openEditModal(type, record) {
    editingRecord = { type, record };
    modalTitle.textContent = `Edit ${type.toUpperCase()} Settings`;

    if (type === 'tenant') {
      modalBody.innerHTML = `
        <div class="form-group">
          <label>Tenant ID</label>
          <input type="text" id="mID" value="${record?.id || ''}" ${record ? 'readonly' : ''} />
        </div>
        <div class="form-group">
          <label>Tenant Name</label>
          <input type="text" id="mName" value="${record?.name || ''}" />
        </div>
        <div class="form-group">
          <label>Primary Domain</label>
          <input type="text" id="mDomain" value="${record?.domain || ''}" />
        </div>
      `;
    } else if (type === 'app') {
      modalBody.innerHTML = `
        <div class="form-group">
          <label>Application ID / Client ID</label>
          <input type="text" id="mID" value="${record?.id || ''}" ${record ? 'readonly' : ''} />
        </div>
        <div class="form-group">
          <label>App Name</label>
          <input type="text" id="mName" value="${record?.name || ''}" />
        </div>
        <div class="form-group">
          <label>Client Secret</label>
          <input type="text" id="mSecret" value="${record?.client_secret || ''}" />
        </div>
        <div class="form-group">
          <label>Redirect URIs (comma separated)</label>
          <input type="text" id="mRedirects" value="${(record?.redirect_uris || []).join(', ')}" />
        </div>
      `;
    } else if (type === 'idp') {
      modalBody.innerHTML = `
        <div class="form-group">
          <label>IDP ID</label>
          <input type="text" id="mID" value="${record?.id || ''}" ${record ? 'readonly' : ''} />
        </div>
        <div class="form-group">
          <label>IDP Name</label>
          <input type="text" id="mName" value="${record?.name || ''}" />
        </div>
        <div class="form-group">
          <label>Protocol Type</label>
          <select id="mType">
            <option value="mock" ${record?.type === 'mock' ? 'selected' : ''}>mock (Developer Testing)</option>
            <option value="oidc" ${record?.type === 'oidc' ? 'selected' : ''}>oidc (Standard OpenID Connect)</option>
            <option value="oauth2" ${record?.type === 'oauth2' ? 'selected' : ''}>oauth2 (Generic OAuth 2.0)</option>
          </select>
        </div>
        <div class="form-group">
          <label>Client ID</label>
          <input type="text" id="mClientID" value="${record?.client_id || ''}" />
        </div>
      `;
    } else if (type === 'workload') {
      modalBody.innerHTML = `
        <div class="form-group">
          <label>Workload ID</label>
          <input type="text" id="mID" value="${record?.id || ''}" ${record ? 'readonly' : ''} />
        </div>
        <div class="form-group">
          <label>Workload Name</label>
          <input type="text" id="mName" value="${record?.name || ''}" />
        </div>
        <div class="form-group">
          <label>SPIFFE ID URI</label>
          <input type="text" id="mSPIFFEID" value="${record?.spiffe_id || ''}" placeholder="spiffe://authpole.local/ns/default/sa/workload-name" />
        </div>
        <div class="form-group">
          <label>Allowed Scopes (comma separated)</label>
          <input type="text" id="mScopes" value="${(record?.allowed_scopes || []).join(', ')}" />
        </div>
        <div class="form-group">
          <label>Long-Expiry Cert SHA-256 Fingerprint</label>
          <input type="text" id="mFingerprint" value="${record?.cert_fingerprint || ''}" />
        </div>
      `;
    } else if (type === 'user') {
      const { data: availableRoles } = await api.getRoles();
      const { data: availableTeams } = await api.getTeams();
      const assignedRoles = record?.role_ids || [];
      const assignedTeams = record?.team_ids || [];

      const rolesHTML = (availableRoles || []).map(r => `
        <label class="checkbox-label">
          <input type="checkbox" name="mUserRoles" value="${r.id}" ${assignedRoles.includes(r.id) ? 'checked' : ''} />
          <span><strong>${r.name}</strong> <span class="code-inline" style="font-size:0.75rem">${r.id}</span></span>
        </label>
      `).join('') || '<div style="font-size:0.8rem; color:var(--text-muted);">No roles available. Create a role first.</div>';

      const teamsHTML = (availableTeams || []).map(t => `
        <label class="checkbox-label">
          <input type="checkbox" name="mUserTeams" value="${t.id}" ${assignedTeams.includes(t.id) ? 'checked' : ''} />
          <span><strong>${t.name}</strong> <span class="code-inline" style="font-size:0.75rem">${t.id}</span></span>
        </label>
      `).join('') || '<div style="font-size:0.8rem; color:var(--text-muted);">No teams available. Create a team first.</div>';

      modalBody.innerHTML = `
        <div class="form-group">
          <label>User ID</label>
          <input type="text" id="mID" value="${record?.id || ''}" ${record ? 'readonly' : ''} placeholder="usr_12345" />
        </div>
        <div class="form-group">
          <label>Full Name</label>
          <input type="text" id="mName" value="${record?.name || ''}" placeholder="Alex Developer" />
        </div>
        <div class="form-group">
          <label>Email Address</label>
          <input type="email" id="mEmail" value="${record?.email || ''}" placeholder="alex@example.com" />
        </div>
        <div class="form-group">
          <label>Select Roles</label>
          <div class="select-list-box">${rolesHTML}</div>
        </div>
        <div class="form-group">
          <label>Select Teams</label>
          <div class="select-list-box">${teamsHTML}</div>
        </div>
      `;
    } else if (type === 'team') {
      const { data: availableRoles } = await api.getRoles();
      const assignedRoles = record?.role_ids || [];

      const rolesHTML = (availableRoles || []).map(r => `
        <label class="checkbox-label">
          <input type="checkbox" name="mTeamRoles" value="${r.id}" ${assignedRoles.includes(r.id) ? 'checked' : ''} />
          <span><strong>${r.name}</strong> <span class="code-inline" style="font-size:0.75rem">${r.id}</span></span>
        </label>
      `).join('') || '<div style="font-size:0.8rem; color:var(--text-muted);">No roles available. Create a role first.</div>';

      modalBody.innerHTML = `
        <div class="form-group">
          <label>Team ID</label>
          <input type="text" id="mID" value="${record?.id || ''}" ${record ? 'readonly' : ''} placeholder="team_eng" />
        </div>
        <div class="form-group">
          <label>Team Name</label>
          <input type="text" id="mName" value="${record?.name || ''}" placeholder="Engineering Team" />
        </div>
        <div class="form-group">
          <label>Description</label>
          <input type="text" id="mDescription" value="${record?.description || ''}" placeholder="Core backend engineering team" />
        </div>
        <div class="form-group">
          <label>Select Team Roles</label>
          <div class="select-list-box">${rolesHTML}</div>
        </div>
      `;
    } else if (type === 'role') {
      modalBody.innerHTML = `
        <div class="form-group">
          <label>Role ID</label>
          <input type="text" id="mID" value="${record?.id || ''}" ${record ? 'readonly' : ''} placeholder="role_admin" />
        </div>
        <div class="form-group">
          <label>Role Name</label>
          <input type="text" id="mName" value="${record?.name || ''}" placeholder="Super Administrator" />
        </div>
        <div class="form-group">
          <label>Description</label>
          <input type="text" id="mDescription" value="${record?.description || ''}" placeholder="Full admin privileges across all resources" />
        </div>
        <div class="form-group">
          <label>Permissions (comma separated)</label>
          <input type="text" id="mPermissions" value="${(record?.permissions || []).join(', ')}" placeholder="tenants:write, apps:write, keys:write" />
        </div>
      `;
    }

    modalOverlay.classList.remove('hidden');
  }

  async function openCreateModal() {
    if (currentTab === 'tenants') openEditModal('tenant', null);
    else if (currentTab === 'apps') openEditModal('app', null);
    else if (currentTab === 'idps') openEditModal('idp', null);
    else if (currentTab === 'workloads') openEditModal('workload', null);
    else if (currentTab === 'rbac') {
      if (currentSubTab === 'rbac-users') openEditModal('user', null);
      else if (currentSubTab === 'rbac-teams') openEditModal('team', null);
      else if (currentSubTab === 'rbac-roles') openEditModal('role', null);
    }
  }

  function closeModal() {
    modalOverlay.classList.add('hidden');
    editingRecord = null;
  }

  function showCASConflictModal() {
    casConflictOverlay.classList.remove('hidden');
  }

  async function handleSaveRecord() {
    if (!editingRecord) return;
    const { type, record } = editingRecord;
    const expectedVersion = record ? record.version : '';

    try {
      if (type === 'tenant') {
        const tenantData = {
          id: document.getElementById('mID').value.trim(),
          name: document.getElementById('mName').value.trim(),
          domain: document.getElementById('mDomain').value.trim(),
          version: expectedVersion
        };
        await api.saveTenant(tenantData, expectedVersion);
      } else if (type === 'app') {
        const appData = {
          id: document.getElementById('mID').value.trim(),
          client_id: document.getElementById('mID').value.trim(),
          name: document.getElementById('mName').value.trim(),
          client_secret: document.getElementById('mSecret').value.trim(),
          redirect_uris: document.getElementById('mRedirects').value.split(',').map(s => s.trim()).filter(Boolean),
          version: expectedVersion
        };
        await api.saveApp(appData, expectedVersion);
      } else if (type === 'idp') {
        const idpData = {
          id: document.getElementById('mID').value.trim(),
          name: document.getElementById('mName').value.trim(),
          type: document.getElementById('mType').value,
          client_id: document.getElementById('mClientID').value.trim(),
          enabled: true,
          version: expectedVersion
        };
        await api.saveIDP(idpData, expectedVersion);
      } else if (type === 'workload') {
        const workloadData = {
          id: document.getElementById('mID').value.trim(),
          name: document.getElementById('mName').value.trim(),
          spiffe_id: document.getElementById('mSPIFFEID').value.trim(),
          allowed_scopes: document.getElementById('mScopes').value.split(',').map(s => s.trim()).filter(Boolean),
          cert_fingerprint: document.getElementById('mFingerprint').value.trim(),
          active: true,
          version: expectedVersion
        };
        await api.saveWorkload(workloadData, expectedVersion);
      } else if (type === 'user') {
        const selectedRoles = Array.from(document.querySelectorAll('input[name="mUserRoles"]:checked')).map(cb => cb.value);
        const selectedTeams = Array.from(document.querySelectorAll('input[name="mUserTeams"]:checked')).map(cb => cb.value);

        const userData = {
          id: document.getElementById('mID').value.trim(),
          name: document.getElementById('mName').value.trim(),
          email: document.getElementById('mEmail').value.trim(),
          role_ids: selectedRoles,
          team_ids: selectedTeams,
          active: true,
          version: expectedVersion
        };
        await api.saveUser(userData, expectedVersion);
      } else if (type === 'team') {
        const selectedRoles = Array.from(document.querySelectorAll('input[name="mTeamRoles"]:checked')).map(cb => cb.value);

        const teamData = {
          id: document.getElementById('mID').value.trim(),
          name: document.getElementById('mName').value.trim(),
          description: document.getElementById('mDescription').value.trim(),
          role_ids: selectedRoles,
          version: expectedVersion
        };
        await api.saveTeam(teamData, expectedVersion);
      } else if (type === 'role') {
        const roleData = {
          id: document.getElementById('mID').value.trim(),
          name: document.getElementById('mName').value.trim(),
          description: document.getElementById('mDescription').value.trim(),
          permissions: document.getElementById('mPermissions').value.split(',').map(s => s.trim()).filter(Boolean),
          version: expectedVersion
        };
        await api.saveRole(roleData, expectedVersion);
      }

      closeModal();
      loadCurrentTabData();
    } catch (err) {
      if (!err.message.includes('cas_conflict')) {
        alert(`Error saving record: ${err.message}`);
      }
    }
  }

  // Initial boot
  switchTab('tenants');
});
