import { buildSBOM, sbomLicClass, sbomSevClass, sbomScoreColor, sbomVulnInfo } from './vulnUtils';
import { Pager } from './VulnPager';

export function VulnLibsTab({
  results,
  sbomSearch, setSbomSearch,
  sbomFilter, setSbomFilter,
  sbomSelected, setSbomSelected,
  libsExtraH, onLibsResizeDown, setLibsExtraH,
  paginate, pageSize, page, setPage, setPageSize,
}) {
const sbomPackages = buildSBOM(results);
const sbomVisible  = sbomPackages.filter(p => {
  const q = sbomSearch.toLowerCase();
  if (q && !p.name.toLowerCase().includes(q) && !p.version.includes(q)) return false;
  if (sbomFilter === 'cve'   && p.cves.length === 0)  return false;
  if (sbomFilter === 'gpl'   && !p.license.toLowerCase().includes('gpl')) return false;
  if (sbomFilter === 'multi' && p.images.length < 2)  return false;
  return true;
});
const withCVE  = sbomPackages.filter(p => p.cves.length > 0).length;
const gplCount = sbomPackages.filter(p => p.license.toLowerCase().includes('gpl')).length;
const multiImg = sbomPackages.filter(p => p.images.length >= 2).length;

  return (
    <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
      {}
      <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 12, minWidth: 0 }}>
        {}
        <div style={{ overflow: 'hidden', maxHeight: Math.max(0, 80 - libsExtraH), opacity: Math.max(0, 1 - libsExtraH / 80), transition: libsExtraH === 0 ? 'max-height .15s, opacity .15s' : 'none', flexShrink: 0 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 10 }}>
            {[
              { label: 'Total packages', val: sbomPackages.length, cls: '' },
              { label: 'With CVEs',      val: withCVE,             cls: 'danger' },
              { label: 'GPL licenses',   val: gplCount,            cls: 'warn' },
              { label: 'In 2+ images',   val: multiImg,            cls: 'info' },
            ].map(s => (
              <div key={s.label} style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8, padding: '10px 14px' }}>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '.05em', marginBottom: 4 }}>{s.label}</div>
                <div style={{ fontSize: 20, fontWeight: 600, color: s.cls === 'danger' ? 'var(--danger)' : s.cls === 'warn' ? 'var(--warning)' : s.cls === 'info' ? 'var(--accent)' : 'var(--text-primary)' }}>{s.val}</div>
              </div>
            ))}
          </div>
        </div>
        {}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <input
            style={{ flex: 1, minWidth: 160, background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8, padding: '6px 12px', color: 'var(--text-primary)', fontFamily: 'var(--font-sans)', fontSize: 13, outline: 'none' }}
            placeholder="Search package name, license…"
            value={sbomSearch}
            onChange={e => setSbomSearch(e.target.value)}
          />
          {[
            { id: 'all',   label: 'All' },
            { id: 'cve',   label: 'Has CVE' },
            { id: 'gpl',   label: 'GPL only' },
            { id: 'multi', label: 'In 2+ images' },
          ].map(f => (
            <button
              key={f.id}
              onClick={() => setSbomFilter(f.id)}
              style={{
                padding: '5px 12px', fontSize: 11, cursor: 'pointer',
                border: '1px solid var(--border)', borderRadius: 6,
                fontFamily: 'var(--font-sans)', transition: 'all .12s',
                background: sbomFilter === f.id ? (f.id === 'gpl' ? 'rgba(239,68,68,.1)' : 'rgba(0,200,255,.1)') : 'transparent',
                borderColor: sbomFilter === f.id ? (f.id === 'gpl' ? 'rgba(239,68,68,.3)' : 'rgba(0,200,255,.3)') : 'var(--border)',
                color: sbomFilter === f.id ? (f.id === 'gpl' ? 'var(--danger)' : 'var(--accent)') : 'var(--text-muted)',
              }}
            >{f.label}</button>
          ))}
        </div>
        {}
        <div
          onMouseDown={onLibsResizeDown}
          onDoubleClick={() => setLibsExtraH(0)}
          title="Drag to resize · double-click to reset"
          style={{ height: 6, margin: '-4px 0 -2px', cursor: 'row-resize', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}
        >
          <div style={{ width: 40, height: 3, borderRadius: 2, background: 'var(--border)' }} />
        </div>
        {}
        <div style={{ flex: 1, overflow: 'auto', border: '1px solid var(--border)', borderRadius: 8 }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr>
                {['Package','Version','Type','License','CVEs'].map(h => (
                  <th key={h} style={{ textAlign: 'left', padding: '7px 12px', fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', borderBottom: '1px solid var(--border)', textTransform: 'uppercase', letterSpacing: '.06em', background: 'var(--bg-surface)', position: 'sticky', top: 0, zIndex: 1 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {paginate(sbomVisible).map(p => {
                const isSel   = sbomSelected?.name === p.name && sbomSelected?.version === p.version;
                const { dot, label } = sbomVulnInfo(p.cves);
                const dotColor = { critical: 'var(--danger)', high: 'var(--warning)', medium: 'var(--accent-2)', none: 'var(--text-muted)' }[dot];
                return (
                  <tr
                    key={`${p.name}__${p.version}`}
                    onClick={() => setSbomSelected(isSel ? null : p)}
                    style={{ cursor: 'pointer', background: isSel ? 'rgba(0,200,255,.06)' : 'transparent' }}
                  >
                    <td style={{ padding: '9px 12px', borderBottom: '1px solid var(--border)', borderLeft: isSel ? '2px solid var(--accent)' : '2px solid transparent' }}>
                      <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: 12 }}>{p.name}</span>
                    </td>
                    <td style={{ padding: '9px 12px', borderBottom: '1px solid var(--border)', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)' }}>{p.version}</td>
                    <td style={{ padding: '9px 12px', borderBottom: '1px solid var(--border)', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>{p.type}</td>
                    <td style={{ padding: '9px 12px', borderBottom: '1px solid var(--border)' }}>
                      {p.license
                        ? <span className={`badge ${sbomLicClass(p.license)}`}>{p.license}</span>
                        : <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>—</span>
                      }
                    </td>
                    <td style={{ padding: '9px 12px', borderBottom: '1px solid var(--border)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)' }}>
                        <span style={{ width: 7, height: 7, borderRadius: '50%', background: dotColor, flexShrink: 0, display: 'inline-block' }}/>
                        {label}
                      </div>
                    </td>
                  </tr>
                );
              })}
              {sbomVisible.length === 0 && (
                <tr><td colSpan={5} style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)', fontSize: 12 }}>No packages match</td></tr>
              )}
            </tbody>
          </table>
          <Pager pageSize={pageSize} page={page} setPage={setPage} setPageSize={setPageSize} total={sbomVisible.length} />
        </div>
      </div>
    </div>
  );
}
