import { useState, useMemo } from 'react';
import { useScanner } from '../../context/ScannerContext';
import '../../styles/sbom.scss';

function licClass(lic = '') {
  const l = lic.toLowerCase();
  if (l.includes('gpl') || l.includes('agpl')) return 'badge-gpl';
  if (l.includes('apache'))                    return 'badge-apache';
  if (l.includes('mit'))                       return 'badge-mit';
  if (l.includes('bsd') || l.includes('isc')) return 'badge-bsd';
  return 'badge-bsd';
}

function sevClass(s = '') {
  switch (s.toUpperCase()) {
    case 'CRITICAL': return 'sev-critical';
    case 'HIGH':     return 'sev-high';
    case 'MEDIUM':   return 'sev-medium';
    default:         return 'sev-low';
  }
}

function scoreColor(v, type) {
  const n = parseFloat(v) || 0;
  if (type === 'cvss') return n >= 9 ? 'red' : n >= 7 ? 'orange' : 'purple';
  if (type === 'epss') return n >= 0.5 ? 'red' : n >= 0.1 ? 'orange' : 'purple';
  return 'purple';
}

function vulnInfo(cves) {
  if (!cves.length) return { dot: 'none', label: '0' };
  const hasCrit = cves.some(c => (c.severity || '').toUpperCase() === 'CRITICAL');
  const hasHigh = cves.some(c => (c.severity || '').toUpperCase() === 'HIGH');
  const dot     = hasCrit ? 'critical' : hasHigh ? 'high' : 'medium';
  const label   = hasCrit
    ? `${cves.filter(c => (c.severity||'').toUpperCase() === 'CRITICAL').length} critical`
    : hasHigh
      ? `${cves.filter(c => (c.severity||'').toUpperCase() === 'HIGH').length} high`
      : `${cves.length}`;
  return { dot, label };
}

function buildSBOM(results) {
  const pkgMap = new Map();

  results.forEach(result => {
    const imageLabel = `${result.name || result.image}:${result.tag || 'latest'}`;
    ;(result.cves || []).forEach(cve => {
      const key = `${cve.pkgName}__${cve.pkgVersion}__${cve.pkgType || ''}`;
      if (!pkgMap.has(key)) {
        pkgMap.set(key, {
          name:    cve.pkgName    || '',
          version: cve.pkgVersion || '',
          type:    cve.pkgType    || 'deb',
          license: '',
          cves:    [],
          images:  new Set(),
        });
      }
      const pkg = pkgMap.get(key);
      if (!pkg.cves.find(c => c.id === cve.id)) pkg.cves.push(cve);
      pkg.images.add(imageLabel);
    });
  });

  const out = [];
  pkgMap.forEach(p => out.push({ ...p, images: [...p.images] }));

  return out.sort((a, b) => {
    const ac = a.cves.filter(c => (c.severity||'').toUpperCase() === 'CRITICAL').length;
    const bc = b.cves.filter(c => (c.severity||'').toUpperCase() === 'CRITICAL').length;
    if (bc !== ac) return bc - ac;
    return b.cves.length - a.cves.length || a.name.localeCompare(b.name);
  });
}

export function SBOM() {
  const { results } = useScanner();

  const [search,      setSearch]      = useState('');
  const [filter,      setFilter]      = useState('all');
  const [selectedIdx, setSelectedIdx] = useState(null);

  const packages = useMemo(() => buildSBOM(results), [results]);

  const visible = useMemo(() => packages.filter(p => {
    const q = search.toLowerCase();
    if (q && !p.name.toLowerCase().includes(q) && !p.version.includes(q)) return false;
    if (filter === 'cve'   && p.cves.length === 0)  return false;
    if (filter === 'gpl'   && !p.license.toLowerCase().includes('gpl')) return false;
    if (filter === 'multi' && p.images.length < 2)  return false;
    return true;
  }), [packages, search, filter]);

  const selected = selectedIdx !== null ? packages[selectedIdx] : null;

  const withCVE  = packages.filter(p => p.cves.length > 0).length;
  const gplCount = packages.filter(p => p.license.toLowerCase().includes('gpl')).length;
  const multiImg = packages.filter(p => p.images.length >= 2).length;

  const imageName = results.length > 0
    ? `${results[0].name || results[0].image}:${results[0].tag || 'latest'}`
    : '—';
  const imageDigest = results.length > 0
    ? `${results[0].image?.slice(0,20) || ''}  ·  scanned ${new Date(results[0].scannedAt || Date.now()).toLocaleTimeString()}  ·  ${packages.length} packages`
    : '';

  if (results.length === 0) {
    return (
      <div className="sbom-page">
        <div className="sbom-empty">
          <div style={{ fontSize: 32 }}>📦</div>
          <div style={{ fontSize: 15, fontWeight: 600 }}>No scan results</div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Run a scan first — SBOM is built from scanner results.</div>
        </div>
      </div>
    );
  }

  return (
    <div className="sbom-page">

      {}
      <div className="sbom-img-header">
        <div className="sbom-img-title">
          <div>
            <div className="sbom-img-name">{imageName}</div>
            <div className="sbom-img-digest">{imageDigest}</div>
          </div>
          <div className="sbom-export-btns">
            <button className="sbom-export-btn">↓ CycloneDX JSON</button>
            <button className="sbom-export-btn">↓ SPDX</button>
          </div>
        </div>
        <div className="sbom-tabs">
          <div className="sbom-tab">Vulnerabilities</div>
          <div className="sbom-tab active">SBOM</div>
          <div className="sbom-tab">History</div>
        </div>
      </div>

      {}
      <div className="sbom-body">

        {}
        <div className={`sbom-left${selected ? ' sbom-left--narrow' : ''}`}>

          <div className="sbom-stats">
            <div className="sbom-stat"><div className="sbom-stat-label">Total packages</div><div className="sbom-stat-val">{packages.length}</div></div>
            <div className="sbom-stat"><div className="sbom-stat-label">With CVEs</div><div className="sbom-stat-val danger">{withCVE}</div></div>
            <div className="sbom-stat"><div className="sbom-stat-label">GPL licenses</div><div className="sbom-stat-val warn">{gplCount}</div></div>
            <div className="sbom-stat"><div className="sbom-stat-label">In 2+ images</div><div className="sbom-stat-val info">{multiImg}</div></div>
          </div>

          <div className="sbom-toolbar">
            <input
              className="sbom-search"
              type="text"
              placeholder="Search package name, license…"
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
            {[
              { id:'all',   label:'All' },
              { id:'cve',   label:'Has CVE' },
              { id:'gpl',   label:'GPL only' },
              { id:'multi', label:'In 2+ images' },
            ].map(f => (
              <button
                key={f.id}
                className={`sbom-filter-btn${filter === f.id ? (f.id === 'gpl' ? ' gpl-active' : ' active') : ''}`}
                onClick={() => setFilter(f.id)}
              >{f.label}</button>
            ))}
          </div>

          <div className="sbom-tbl-wrap">
            <table className="sbom-tbl">
              <thead>
                <tr>
                  <th>Package</th>
                  <th>Version</th>
                  <th>Type</th>
                  <th>License</th>
                  <th>CVEs</th>
                </tr>
              </thead>
              <tbody>
                {visible.map(p => {
                  const i = packages.indexOf(p);
                  const { dot, label } = vulnInfo(p.cves);
                  return (
                    <tr
                      key={`${p.name}__${p.version}`}
                      className={selectedIdx === i ? 'selected' : ''}
                      onClick={() => setSelectedIdx(selectedIdx === i ? null : i)}
                    >
                      <td><span className="pkg-name">{p.name}</span></td>
                      <td className="mono">{p.version}</td>
                      <td className="mono" style={{ color: 'var(--text-muted)' }}>{p.type}</td>
                      <td>
                        {p.license
                          ? <span className={`badge ${licClass(p.license)}`}>{p.license}</span>
                          : <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>—</span>
                        }
                      </td>
                      <td>
                        <div className="vuln">
                          <span className={`vuln-dot ${dot}`}/>
                          {label}
                        </div>
                      </td>
                    </tr>
                  );
                })}
                {visible.length === 0 && (
                  <tr>
                    <td colSpan={5} style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)', fontSize: 12 }}>
                      No packages match
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
            <div className="sbom-tbl-footer">Showing {visible.length} of {packages.length} packages</div>
          </div>
        </div>

        {}
        {selected && (
          <div className="sbom-panel">
            <div className="dp-header">
              <div>
                <div className="dp-pkg-name">{selected.name}</div>
                <div className="dp-pkg-sub">{selected.version} · {selected.type}{selected.license ? ` · ${selected.license}` : ''}</div>
              </div>
              <button className="dp-close" onClick={() => setSelectedIdx(null)}>✕</button>
            </div>

            <div className="dp-body">

              <div className="dp-section">
                <div className="dp-section-title">CVEs ({selected.cves.length})</div>
                {selected.cves.length === 0
                  ? <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: '8px 0' }}>No known vulnerabilities</div>
                  : selected.cves.map(c => (
                    <div key={c.id} className="cve-card">
                      <div className="cve-card-top">
                        <span className="cve-id">
                          {c.id}
                          {c.inKev && <span className="kev-badge">KEV</span>}
                          {c.pocs?.length > 0 && <span className="poc-badge">PoC</span>}
                        </span>
                        <span className={`sev-badge ${sevClass(c.severity)}`}>{(c.severity||'').toUpperCase()}</span>
                      </div>
                      {(c.title || c.description) && (
                        <div className="cve-desc">
                          {c.title || (c.description?.length > 120 ? c.description.slice(0, 120) + '…' : c.description)}
                        </div>
                      )}
                      <div className="cve-scores">
                        <div className="score-item">
                          <div className="score-label">CVSS v3</div>
                          <div className={`score-val ${scoreColor(c.cvssV3Score, 'cvss')}`}>
                            {c.cvssV3Score ? c.cvssV3Score.toFixed(1) : '—'}
                          </div>
                        </div>
                        <div className="score-item">
                          <div className="score-label">EPSS</div>
                          <div className={`score-val ${scoreColor(c.epssScore, 'epss')}`}>
                            {c.epssScore ? (c.epssScore * 100).toFixed(1) + '%' : '—'}
                          </div>
                        </div>
                        <div className="score-item">
                          <div className="score-label">Fix</div>
                          <div className="score-val" style={{ fontSize: 11, color: c.hasFix ? 'var(--success)' : 'var(--text-muted)' }}>
                            {c.hasFix ? (c.fixedIn || 'Available') : 'None'}
                          </div>
                        </div>
                      </div>
                    </div>
                  ))
                }
              </div>

              <div className="dp-section">
                <div className="dp-section-title">
                  Lib uses — appears in {selected.images.length} {selected.images.length === 1 ? 'image' : 'images'}
                </div>
                <div className="uses-list">
                  {selected.images.map(img => (
                    <div key={img} className="uses-item">
                      <div>
                        <div className="uses-img-name">{img.split(':')[0]}</div>
                        <div className="uses-img-tag">{img}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

            </div>
          </div>
        )}
      </div>
    </div>
  );
}
