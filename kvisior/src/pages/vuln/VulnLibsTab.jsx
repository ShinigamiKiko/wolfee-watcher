import { buildSBOM, sbomLicTone, sbomVulnInfo } from './vulnUtils';
import { Pager } from './VulnPager';
import { Stat, Seg, SearchInput, Badge, EmptyRow } from '../../components/kit';

const DOT = { critical: 'dot--danger', high: 'dot--warning', medium: 'dot--accent', none: '' };

const FILTERS = [
  { value: 'all',   label: 'All' },
  { value: 'cve',   label: 'Has CVE' },
  { value: 'gpl',   label: 'GPL only' },
  { value: 'multi', label: 'In 2+ images' },
];

export function VulnLibsTab({
  results,
  sbomSearch, setSbomSearch,
  sbomFilter, setSbomFilter,
  sbomSelected, setSbomSelected,
  libsExtraH, onLibsResizeDown, setLibsExtraH,
  paginate, pageSize, page, setPage, setPageSize,
}) {
  const sbomPackages = buildSBOM(results);
  const q = sbomSearch.toLowerCase();
  const sbomVisible = sbomPackages.filter(p => {
    if (q && !p.name.toLowerCase().includes(q) && !p.version.includes(q)) return false;
    if (sbomFilter === 'cve'   && p.cves.length === 0) return false;
    if (sbomFilter === 'gpl'   && !p.license.toLowerCase().includes('gpl')) return false;
    if (sbomFilter === 'multi' && p.images.length < 2) return false;
    return true;
  });
  const withCVE  = sbomPackages.filter(p => p.cves.length > 0).length;
  const gplCount = sbomPackages.filter(p => p.license.toLowerCase().includes('gpl')).length;
  const multiImg = sbomPackages.filter(p => p.images.length >= 2).length;

  return (
    <div className="split-body">
      <div className="split-main stack libs-main">
        <div className="libs-summary" style={{ maxHeight: Math.max(0, 96 - libsExtraH), opacity: Math.max(0, 1 - libsExtraH / 96) }}>
          <div className="stats-grid stats-grid--4 mb-0">
            <Stat label="Total packages" value={sbomPackages.length} />
            <Stat label="With CVEs" value={withCVE} tone="danger" />
            <Stat label="GPL licenses" value={gplCount} tone="warning" />
            <Stat label="In 2+ images" value={multiImg} tone="accent" />
          </div>
        </div>

        <div className="toolbar mb-0">
          <SearchInput value={sbomSearch} onChange={setSbomSearch} placeholder="Search package name, version…" />
          <Seg options={FILTERS} value={sbomFilter} onChange={setSbomFilter} label="Package filter" />
        </div>

        <div className="resize-grip libs-grip" onMouseDown={onLibsResizeDown} onDoubleClick={() => setLibsExtraH(0)}
          title="Drag to resize · double-click to reset" />

        <div className="dw grow">
          <table className="data-table">
            <thead><tr><th>Package</th><th>Version</th><th>Type</th><th>License</th><th>CVEs</th></tr></thead>
            <tbody>
              {paginate(sbomVisible).map(p => {
                const isSel = sbomSelected?.name === p.name && sbomSelected?.version === p.version;
                const { dot, label } = sbomVulnInfo(p.cves);
                return (
                  <tr key={`${p.name}__${p.version}`} className={isSel ? 'selected' : ''} onClick={() => setSbomSelected(isSel ? null : p)}>
                    <td className="td-primary">{p.name}</td>
                    <td className="mono t-xs">{p.version}</td>
                    <td className="mono t-xs t-muted">{p.type}</td>
                    <td>{p.license ? <Badge tone={sbomLicTone(p.license)}>{p.license}</Badge> : <span className="t-muted">—</span>}</td>
                    <td><span className="row row--tight mono t-xs"><span className={`dot ${DOT[dot] || ''}`} />{label}</span></td>
                  </tr>
                );
              })}
              {sbomVisible.length === 0 && <EmptyRow cols={5}>No packages match</EmptyRow>}
            </tbody>
          </table>
        </div>
        <Pager pageSize={pageSize} page={page} setPage={setPage} setPageSize={setPageSize} total={sbomVisible.length} />
      </div>
    </div>
  );
}
