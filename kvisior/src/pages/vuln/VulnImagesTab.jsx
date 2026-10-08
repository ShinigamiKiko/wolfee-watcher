import { SevBadge } from '../../components/ui';
import { EmptyState } from '../../components/EmptyState';
import { Crumbs, Tag, EmptyRow, sevTone, cx } from '../../components/kit';
import { Pager } from './VulnPager';
import { Icon } from '../../components/Icon';

const ago = iso => {
  if (!iso) return null;
  const m = Math.round((Date.now() - new Date(iso)) / 60000);
  return m < 60 ? `${m}m ago` : `${Math.round(m / 60)}h ago`;
};

const HOUR = 60 * 60 * 1000;

export function VulnImagesTab({
  imageDrill, setImageDrill,
  imageRows,
  q, results, agentOnline, handleScanAll,
  paginate, pageSize, page, setPage, setPageSize,
  setSelected, filterInput,
}) {
  const pagerProps = { pageSize, page, setPage, setPageSize };
  return (
    <div className="card">
      <div className="card-header">
        <div className="card-title">
          {imageDrill
            ? <Crumbs items={[{ label: 'Images', onClick: () => setImageDrill(null) }, { label: <span className="mono t-sm">{imageDrill.name}</span> }]} meta={`${imageDrill.cves?.length || 0} CVEs`} />
            : <>Container Images <span className="card-sub">({imageRows.length})</span></>}
        </div>
        {imageDrill
          ? <button type="button" onClick={() => setImageDrill(null)} className="btn btn-outline btn-sm"><Icon name="arrow-left" /> Back</button>
          : filterInput}
      </div>
      {!imageDrill ? (() => {
        const query = (q || '').toLowerCase();
        const filtered = imageRows.filter(r => !query || [r.image, r.name, r.ref, r.tag].some(v => String(v || '').toLowerCase().includes(query)));
        return (
          <>
            <div className="table-wrap">
              <table className="data-table">
                <thead><tr><th>Image</th><th>Tag</th><th>Total CVEs</th><th>Digest</th><th>Scanned</th></tr></thead>
                <tbody>
                  {results.length === 0
                    ? <tr className="static"><td colSpan={5}>
                        <EmptyState icon="package" title="No images scanned" sub="Run a scan to see vulnerability data for cluster images."
                          action={agentOnline && <button type="button" className="btn btn-primary" onClick={handleScanAll}>Scan Now</button>} />
                      </td></tr>
                    : paginate(filtered).map((r, i) => {
                        const currentDigest  = r._res?.digest         || r.digest         || '';
                        const previousDigest = r._res?.previousDigest || r.previousDigest || '';
                        const changedTs      = r._res?.digestChangedAt || r._res?.scannedAt;
                        const changed        = !!(r._res?.digestChanged ?? r.digestChanged) && changedTs && Date.now() - new Date(changedTs).getTime() < HOUR;
                        return (
                          <tr key={i} onClick={() => setImageDrill(r._res || { name: r.name, tag: r.tag, cves: [] })}>
                            <td className="td-primary mono t-xs">{r.name}</td>
                            <td className="mono t-xs t-muted">{r.tag || 'latest'}</td>
                            <td className={cx('mono t-sm', r.summary?.total > 0 ? 't-danger' : 't-muted')}>{r.summary?.total || '—'}</td>
                            <td>
                              {!currentDigest
                                ? <span className="t-muted">—</span>
                                : changed
                                  ? <Tag tone="danger" mono outline title={`Baseline: ${previousDigest.slice(7, 19)}…\nCurrent:  ${currentDigest.slice(7, 19)}…`}><Icon name="alert" /> changed</Tag>
                                  : <span className="mono t-xs t-muted">not changed</span>}
                            </td>
                            <td className="t-sm t-muted">{ago(r._res?.scannedAt) || '—'}</td>
                          </tr>
                        );
                      })}
                </tbody>
              </table>
            </div>
            <Pager {...pagerProps} total={filtered.length} />
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
                  {!drillSorted.length
                    ? <EmptyRow cols={6}>No CVEs found for this image</EmptyRow>
                    : paginate(drillSorted).map((c, i) => {
                        const tone = sevTone(c.severity);
                        return (
                          <tr key={i} onClick={() => setSelected(c)}>
                            <td className="td-primary mono t-xs">{c.id}</td>
                            <td><SevBadge sev={c.severity?.toUpperCase()} /></td>
                            <td className={cx('mono t-sm t-strong', tone && `t-${tone}`)}>{c.cvssV3Score > 0 ? c.cvssV3Score.toFixed(1) : '—'}</td>
                            <td className="t-sm">{c.pkgName}</td>
                            <td className="mono t-xs t-muted">{c.pkgVersion}</td>
                            <td className={cx('t-xs', c.hasFix ? 't-ok' : 't-muted')}>{c.hasFix ? `→ ${c.fixedIn}` : '—'}</td>
                          </tr>
                        );
                      })}
                </tbody>
              </table>
            </div>
            <Pager {...pagerProps} total={drillSorted.length} />
          </>
        );
      })()}
    </div>
  );
}
