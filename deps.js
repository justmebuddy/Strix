// deps.js — dependency / supply-chain audit using the public OSV.dev API (CORS-enabled, no key needed).

const OSV = 'https://api.osv.dev/v1';

function fromLock(text) {
  const lock = JSON.parse(text);
  const deps = new Map();
  if (lock.packages) {
    for (const [key, val] of Object.entries(lock.packages)) {
      const i = key.lastIndexOf('node_modules/');
      if (i === -1 || !val.version) continue;
      deps.set(`${key.slice(i + 13)}@${val.version}`, { name: key.slice(i + 13), version: val.version });
    }
  } else if (lock.dependencies) {
    const rec = (d) => {
      for (const [name, v] of Object.entries(d)) {
        if (v.version) deps.set(`${name}@${v.version}`, { name, version: v.version });
        if (v.dependencies) rec(v.dependencies);
      }
    };
    rec(lock.dependencies);
  }
  return [...deps.values()];
}

function fromPackageJson(text) {
  const pkg = JSON.parse(text);
  const out = [];
  for (const section of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    for (const [name, range] of Object.entries(pkg[section] || {})) {
      const m = String(range).match(/\d+\.\d+\.\d+(?:-[\w.]+)?/);
      if (m) out.push({ name, version: m[0], approx: true });
    }
  }
  return out;
}

const mapSeverity = (s) => {
  s = String(s || '').toUpperCase();
  if (s === 'MODERATE') return 'MEDIUM';
  return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(s) ? s : 'MEDIUM';
};

/**
 * @param {{lockText?: string, pkgText?: string}} input
 * @returns {Promise<{findings: Array, checked: number, note: string}>}
 */
export async function auditDependencies({ lockText, pkgText }) {
  let deps = [];
  let note = '';
  try {
    if (lockText) { deps = fromLock(lockText); note = 'package-lock.json (exact versions)'; }
    else if (pkgText) { deps = fromPackageJson(pkgText); note = 'package.json (versions approximated from ranges; add a lockfile for exact results)'; }
  } catch {
    return { findings: [], checked: 0, note: 'Could not parse dependency manifest.' };
  }
  if (!deps.length) return { findings: [], checked: 0, note: note || 'No package.json found.' };

  const hits = []; // {dep, id}
  for (let i = 0; i < deps.length; i += 500) {
    const chunk = deps.slice(i, i + 500);
    const res = await fetch(`${OSV}/querybatch`, {
      method: 'POST',
      body: JSON.stringify({
        queries: chunk.map((d) => ({ package: { name: d.name, ecosystem: 'npm' }, version: d.version })),
      }),
    });
    if (!res.ok) throw new Error(`OSV query failed (${res.status})`);
    const data = await res.json();
    data.results.forEach((r, idx) => (r.vulns || []).forEach((v) => hits.push({ dep: chunk[idx], id: v.id })));
  }

  const ids = [...new Set(hits.map((h) => h.id))].slice(0, 60);
  const details = {};
  await Promise.all(
    ids.map(async (id) => {
      try {
        const r = await fetch(`${OSV}/vulns/${encodeURIComponent(id)}`);
        if (r.ok) details[id] = await r.json();
      } catch { /* ignore single failure */ }
    })
  );

  const findings = hits.map(({ dep, id }) => {
    const d = details[id] || {};
    return {
      category: 'Dependency',
      name: `${dep.name}@${dep.version}`,
      severity: mapSeverity(d.database_specific && d.database_specific.severity),
      line: 0,
      description: `${id}: ${d.summary || 'Known vulnerability'}${dep.approx ? ' (version approximated)' : ''}`,
      snippet: '',
      link: `https://osv.dev/vulnerability/${id}`,
    };
  });

  return { findings, checked: deps.length, note };
}
