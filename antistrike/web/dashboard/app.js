const API = () => localStorage.getItem('antistrike_api') || 'http://127.0.0.1:7700';
let allFindings = [];
let allModules = [];
let selectedAttacks = new Set();

async function api(path, method = 'GET', body = null) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(`${API()}${path}`, opts);
  return res.json();
}

// Navigation
document.querySelectorAll('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => switchPanel(btn.dataset.panel));
});

function switchPanel(name) {
  document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.panel === name));
  document.querySelectorAll('.panel').forEach(p => p.classList.toggle('active', p.id === `panel-${name}`));
}

// Chip toggles
document.querySelectorAll('.chip').forEach(chip => {
  chip.addEventListener('click', () => {
    chip.classList.toggle('active');
    const role = chip.dataset.role;
    if (role) return;
    const val = chip.querySelector('input')?.value;
    if (val) {
      chip.classList.contains('active') ? selectedAttacks.add(val) : selectedAttacks.delete(val);
    }
  });
});

// Server health
async function checkHealth() {
  const el = document.getElementById('server-status');
  try {
    const h = await api('/api/health');
    el.className = 'status-indicator online';
    el.querySelector('span:last-child').textContent = `${h.version} ${h.codename}`;
    return true;
  } catch {
    el.className = 'status-indicator offline';
    el.querySelector('span:last-child').textContent = 'Offline';
    return false;
  }
}

async function loadStats() {
  try {
    const s = await api('/api/stats');
    document.getElementById('stat-modules').textContent = s.modules.total;
    document.getElementById('stat-modules-sub').textContent = `${s.modules.available} available`;
    document.getElementById('stat-attacks').textContent = s.modules.attack_types;
    document.getElementById('stat-payloads').textContent = s.payloads.total_payloads;
    document.getElementById('stat-jobs').textContent = s.system.active_jobs;
    document.getElementById('cpu-bar').style.width = `${s.system.cpu_percent}%`;
    document.getElementById('cpu-val').textContent = `${s.system.cpu_percent}%`;
    document.getElementById('mem-bar').style.width = `${s.system.memory_percent}%`;
    document.getElementById('mem-val').textContent = `${s.system.memory_percent}%`;
  } catch {}
}

async function loadModules() {
  try {
    const data = await api('/api/tools/');
    allModules = data.tools || [];
    renderModules(allModules);
    const cats = [...new Set(allModules.map(m => m.category))].sort();
    const sel = document.getElementById('module-category');
    sel.innerHTML = '<option value="">All Categories</option>' +
      cats.map(c => `<option value="${c}">${c}</option>`).join('');
    document.getElementById('modules-count').textContent = `${allModules.length} modules registered`;
  } catch {}
}

function renderModules(modules) {
  const grid = document.getElementById('module-grid');
  grid.innerHTML = modules.map(m => `
    <div class="module-card ${m.available ? 'available' : 'unavailable'}">
      <div class="module-name">${m.name}</div>
      <div class="module-cat">${m.category}${m.builtin ? ' · built-in' : ''}</div>
      <div class="module-desc">${m.description}</div>
      <div class="module-tags">${(m.attack_types || []).slice(0, 4).map(t => `<span class="module-tag">${t}</span>`).join('')}</div>
    </div>
  `).join('');
}

document.getElementById('module-category')?.addEventListener('change', e => {
  const cat = e.target.value;
  const search = document.getElementById('module-search').value.toLowerCase();
  filterModules(cat, search);
});

document.getElementById('module-search')?.addEventListener('input', e => {
  const cat = document.getElementById('module-category').value;
  filterModules(cat, e.target.value.toLowerCase());
});

function filterModules(cat, search) {
  let filtered = allModules;
  if (cat) filtered = filtered.filter(m => m.category === cat);
  if (search) filtered = filtered.filter(m =>
    m.name.includes(search) || m.description.toLowerCase().includes(search)
  );
  renderModules(filtered);
}

async function loadAttackTypes() {
  try {
    const data = await api('/api/tools/attack-types');
    const chips = document.getElementById('attack-chips');
    chips.innerHTML = (data.attack_types || []).map(t =>
      `<label class="chip" data-attack="${t}"><input type="checkbox" value="${t}" hidden>${t}</label>`
    ).join('');
    chips.querySelectorAll('.chip').forEach(chip => {
      chip.addEventListener('click', () => {
        chip.classList.toggle('active');
        const t = chip.dataset.attack;
        chip.classList.contains('active') ? selectedAttacks.add(t) : selectedAttacks.delete(t);
      });
    });
  } catch {}
}

async function loadPayloadTypes() {
  try {
    const data = await api('/api/tools/payload-types');
    const sel = document.getElementById('payload-type');
    sel.innerHTML = (data.types || []).map(t => `<option value="${t}">${t}</option>`).join('');
    if (data.types?.length) loadPayloads(data.types[0]);
    sel.addEventListener('change', e => loadPayloads(e.target.value));
  } catch {}
}

async function loadPayloads(type) {
  try {
    const data = await api(`/api/tools/payloads/${type}`);
    const list = document.getElementById('payload-list');
    list.innerHTML = (data.payloads || []).map(p => `
      <div class="payload-item">
        <div class="payload-text">${esc(p.payload)}</div>
        <div class="payload-meta">${Object.entries(p).filter(([k]) => k !== 'payload').map(([k,v]) => `${k}: ${v}`).join(' · ')}</div>
      </div>
    `).join('');
  } catch {}
}

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

function renderFindings(findings) {
  allFindings = findings;
  document.getElementById('findings-count').textContent = `${findings.length} findings`;
  const list = document.getElementById('findings-list');
  if (!findings.length) {
    list.innerHTML = '<div class="empty-state">No findings yet</div>';
    return;
  }
  list.innerHTML = findings.map(f => `
    <div class="finding-card ${f.severity || 'info'}">
      <span class="finding-title">${esc(f.title || 'Unknown')}</span>
      <span class="finding-severity sev-${f.severity || 'info'}">${(f.severity || 'info').toUpperCase()}</span>
      <div class="finding-location">${esc(f.location || '')}</div>
      ${f.evidence ? `<div class="finding-evidence">${esc(f.evidence)}</div>` : ''}
      ${f.payload ? `<div class="finding-evidence">Payload: ${esc(f.payload)}</div>` : ''}
    </div>
  `).join('');
}

// Scanner actions
document.getElementById('btn-authorize')?.addEventListener('click', async () => {
  const target = document.getElementById('scan-target').value;
  const authorizer = document.getElementById('scan-authorizer').value;
  const depth = document.getElementById('scan-depth').value;
  const log = document.getElementById('scan-output');
  if (!target || !authorizer) { log.textContent = 'Target and authorizer required.'; return; }
  log.textContent = 'Registering authorization...';
  try {
    const r = await api('/api/auth/scope', 'POST', { target, authorized_by: authorizer, depth });
    log.textContent = r.valid ? `✓ Authorized: ${target}\n${JSON.stringify(r.scope, null, 2)}` : `✗ ${r.error}`;
  } catch (e) { log.textContent = `Error: ${e.message}`; }
});

document.getElementById('btn-scan')?.addEventListener('click', async () => {
  const target = document.getElementById('scan-target').value;
  const depth = document.getElementById('scan-depth').value;
  const log = document.getElementById('scan-output');
  if (!target) { log.textContent = 'Target required.'; return; }
  log.textContent = `Scanning ${target} (depth: ${depth})...`;
  try {
    const r = await api('/api/attacks/scan', 'POST', {
      target, depth, attack_types: [...selectedAttacks],
    });
    log.textContent = JSON.stringify(r, null, 2);
    if (r.findings) renderFindings(r.findings);
  } catch (e) { log.textContent = `Error: ${e.message}`; }
});

document.getElementById('btn-assess')?.addEventListener('click', async () => {
  const target = document.getElementById('scan-target').value;
  const depth = document.getElementById('scan-depth').value;
  const profile = document.getElementById('scan-profile').value;
  const log = document.getElementById('scan-output');
  if (!target) { log.textContent = 'Target required.'; return; }
  log.textContent = `Running ${profile} assessment...`;
  try {
    const r = await api('/api/attacks/profile', 'POST', { target, profile, depth });
    log.textContent = JSON.stringify(r, null, 2);
    if (r.findings) renderFindings(r.findings);
  } catch (e) { log.textContent = `Error: ${e.message}`; }
});

// Agents
document.getElementById('btn-spawn-agents')?.addEventListener('click', async () => {
  const target = document.getElementById('agent-target').value;
  if (!target) return;
  const roles = [...document.querySelectorAll('.agent-roles .chip.active')].map(c => c.dataset.role);
  try {
    const r = await api('/api/agents/spawn', 'POST', { target, roles });
    const graph = document.getElementById('agent-graph');
    const nodes = [r.orchestrator, ...(r.agents || [])];
    graph.innerHTML = nodes.map(n => `
      <div class="agent-node ${n.role === 'orchestrator' ? 'orchestrator' : ''}">
        <div class="agent-role">${n.role}</div>
        <div class="agent-id">${n.agent_id}</div>
        <div class="agent-status ${n.status}">${n.status}</div>
      </div>
    `).join('');
  } catch (e) {
    document.getElementById('agent-graph').textContent = `Error: ${e.message}`;
  }
});

// Reports
document.getElementById('btn-report')?.addEventListener('click', async () => {
  const target = document.getElementById('report-target').value;
  const formats = [...document.querySelectorAll('#panel-reports .chip.active input')].map(i => i.value);
  const log = document.getElementById('report-output');
  try {
    const r = await api('/api/attacks/report', 'POST', { target, findings: allFindings, formats });
    log.textContent = JSON.stringify(r, null, 2);
  } catch (e) { log.textContent = `Error: ${e.message}`; }
});

// Settings
document.getElementById('btn-save-settings')?.addEventListener('click', () => {
  localStorage.setItem('antistrike_api', document.getElementById('api-url').value);
  localStorage.setItem('antistrike_depth', document.getElementById('default-depth').value);
  checkHealth();
  loadStats();
});

document.getElementById('mcp-config').textContent = JSON.stringify({
  mcpServers: {
    antistrike: {
      command: 'python3',
      args: ['-m', 'antistrike.mcp.bridge', '--server', API()],
      timeout: 600,
    },
  },
}, null, 2);

// Init
(async () => {
  const saved = localStorage.getItem('antistrike_api');
  if (saved) document.getElementById('api-url').value = saved;
  await checkHealth();
  await Promise.all([loadStats(), loadModules(), loadAttackTypes(), loadPayloadTypes()]);
  setInterval(() => { checkHealth(); loadStats(); }, 15000);
})();