import { SevBadge } from '../../components/ui';
import { EmptyState } from '../../components/EmptyState';
import { sevColor } from '../../data/scanner';
import { Pager } from './VulnPager';

export function VulnImagesTab({
  imageDrill, setImageDrill,
  imageRows,
  q, results, agentOnline, handleScanAll,
  paginate, pageSize, page, setPage, setPageSize,
  setSelected, filterInput,
}) {
  return (
    <div className="card" style={{ marginTop: 16, marginRight: 24 }}>
      <div className="card-header">
        <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {imageDrill ? <><span style={{ color: 'var(--text-muted)', cursor: 'pointer' }} onClick={() => setImageDrill(null)}>Images</span><span style={{ color: 'var(--text-muted)' }}>›</span><span style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 12 }}>{imageDrill.name}</span><span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 400 }}>({imageDrill.cves?.length || 0} CVEs)</span></>
            : <>Container Images ({imageRows.length})</>}
        </div>
        {imageDrill ? <button onClick={() => setImageDrill(null)} style={{ fontSize: 11, padding: '3px 10px', borderRadius: 5, cursor: 'pointer', background: 'var(--bg-elevated)', border: '1px solid var(--border)', color: 'var(--text-muted)' }}>← Back</button> : filterInput}
      </div>
      {!imageDrill ? (() => {
        const filtered = imageRows.filter(r => {
          if (!q) return true;
          try {
            const re = new RegExp(q, 'i');
            return re.test(r.image || '') || re.test(r.name || '') || re.test(r.ref || '') || re.test(r.tag || '');
          } catch { return (r.image||r.name||'').toLowerCase().includes(q); }
        });
        return (
          <>
            <div className="table-wrap">
              <table className="data-table">
                <thead><tr><th>Image</th><th>Tag</th><th>Total CVEs</th><th>Digest</th><th>Scanned</th></tr></thead>
                <tbody>
                  {results.length === 0 ? <tr><td colSpan={5}><EmptyState icon="📦" title="No images scanned" sub="Run a scan to see vulnerability data for cluster images." action={agentOnline && <button className="btn btn-primary" style={{ marginTop: 4 }} onClick={handleScanAll}>Scan Now</button>} /></td></tr>
                    : paginate(filtered).map((r, i) => {
                        const age = r._res?.scannedAt ? Math.round((Date.now() - new Date(r._res.scannedAt)) / 60000) : null;
                        const currentDigest  = r._res?.digest         || r.digest         || '';
                        const previousDigest = r._res?.previousDigest || r.previousDigest || '';
                        const _changedFlag   = !!(r._res?.digestChanged ?? r.digestChanged);
                        const _changedTs     = r._res?.digestChangedAt || r._res?.scannedAt;
                        const _changedAge    = _changedTs ? Date.now() - new Date(_changedTs).getTime() : 0;
                        const changed        = _changedFlag && _changedAge < 60 * 60 * 1000;
                        return (
                          <tr key={i} style={{ cursor: 'pointer' }} onClick={() => setImageDrill(r._res || { name: r.name, tag: r.tag, cves: [] })}>
                            <td className="td-primary mono" style={{ fontSize: 11 }}>{r.name}</td>
                            <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>{r.tag || 'latest'}</td>
                            <td className="mono" style={{ fontSize: 12, color: r.summary?.total > 0 ? 'var(--danger)' : 'var(--text-muted)' }}>{r.summary?.total || '—'}</td>
                            <td>
                              {!currentDigest
                                ? <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>—</span>
                                : changed
                                  ? <span
                                      title={`Baseline: ${previousDigest.slice(7,19)}…\nCurrent:  ${currentDigest.slice(7,19)}…`}
                                      style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 10, fontWeight: 700, fontFamily: 'JetBrains Mono,monospace', padding: '2px 7px', borderRadius: 4, background: 'rgba(239,68,68,.12)', border: '1px solid rgba(239,68,68,.35)', color: 'var(--danger)', cursor: 'help' }}
                                    >⚠ changed</span>
                                  : <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono,monospace' }}>not changed</span>
                              }
                            </td>
                            <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{age !== null ? (age < 60 ? `${age}m ago` : `${Math.round(age / 60)}h ago`) : '—'}</td>
                          </tr>
                        );
                      })
                  }
                </tbody>
              </table>
            </div>
            <Pager pageSize={pageSize} page={page} setPage={setPage} setPageSize={setPageSize} total={filtered.length} />
          </>
        );
      })() : (() => {
        const drillSorted = [...(imageDrill.cves || [])].sort((a, b) => (b.cvssV3Score || 0) - (a.cvssV3Score || 0));
        return (
          <>
            <div className="table-wrap">
              <table className="data-table">
                <thead><tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Package</th><th>Version</th><th>Fix</th></tr></thead>
                <tbody>
                  {!drillSorted.length ? <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 32, fontSize: 13 }}>No CVEs found for this image</td></tr>
                    : paginate(drillSorted).map((c, i) => (
                        <tr key={i} style={{ cursor: 'pointer' }} onClick={() => setSelected(c)}>
                          <td className="td-primary mono" style={{ fontSize: 11 }}>{c.id}</td>
                          <td><SevBadge sev={c.severity?.toUpperCase()} /></td>
                          <td className="mono" style={{ fontSize: 12, fontWeight: 700, color: sevColor(c.severity) }}>{c.cvssV3Score > 0 ? c.cvssV3Score.toFixed(1) : '—'}</td>
                          <td style={{ fontSize: 12 }}>{c.pkgName}</td>
                          <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>{c.pkgVersion}</td>
                          <td style={{ color: c.hasFix ? 'var(--accent-3)' : 'var(--text-muted)', fontSize: 11 }}>{c.hasFix ? `→ ${c.fixedIn}` : '—'}</td>
                        </tr>
                      ))
                  }
                </tbody>
              </table>
            </div>
            <Pager pageSize={pageSize} page={page} setPage={setPage} setPageSize={setPageSize} total={drillSorted.length} />
          </>
        );
      })()}
    </div>
  );
}
