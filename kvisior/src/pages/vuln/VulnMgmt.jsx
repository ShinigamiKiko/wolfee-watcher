import { useState, useMemo, useEffect, useRef } from 'react';
import { useScanner } from '../../context/ScannerContext';
import { useBridge }  from '../../context/BridgeContext';
import { useApp }     from '../../context/AppContext';
import { useSensor }  from '../../context/SensorContext';
import { SevBadge, StatusDot, Tabs } from '../../components/ui';
import { EmptyState }  from '../../components/EmptyState';
import { PageHeader, SearchInput, Stat, Crumbs, SortTh, Tag, KindBadge, EmptyRow, Notice, sevTone, cx } from '../../components/kit';
import { epssLabel, epssTone } from '../../data/scanner';
import { CveDetail }     from './CveDetail';
import { SbomDetail }    from './SbomDetail';
import { ScheduleModal } from './vulnWidgets';
import { TABS } from './vulnUtils';
import { Pager } from './VulnPager';
import { usePageSize } from '../../hooks/usePaged';
import { VulnLibsTab } from './VulnLibsTab';
import { VulnImagesTab } from './VulnImagesTab';
import { Icon } from '../../components/Icon';
import { ProgressLine } from '../../components/ProgressLine';
import { useReportDownload } from '../../reports/useReportDownload';
import '../../styles/vuln.scss';

const SYSTEM_NS = ['kube-system', 'kube-public', 'kube-node-lease', 'metallb-system', 'calico-system', 'cert-manager'];

const ago = iso => {
  if (!iso) return null;
  const m = Math.round((Date.now() - new Date(iso)) / 60000);
  return m < 60 ? `${m}m ago` : `${Math.round(m / 60)}h ago`;
};

const fmt = v => (typeof v === 'number' && v > 999 ? v.toLocaleString() : v);

export function VulnMgmt() {
  const { toast } = useApp();
  const { allCVEs, results, summary, clusterImages, agentOnline, scanning,
          startScan, stopScan, schedule, updateSchedule, progress, scanErrors } = useScanner();
  const { nodeStats }         = useBridge();
  const { nodes: sensorNodes, workloads } = useSensor();

  const [tab, setTab] = useState(() => {
    return localStorage.getItem('wv_vuln_image') ? 'Images' : 'CVEs';
  });
  const [selected,      setSelected]      = useState(null);
  const [search,        setSearch]        = useState(() => {
    const img = localStorage.getItem('wv_vuln_image');
    if (img) localStorage.removeItem('wv_vuln_image');
    return img || '';
  });
  const [sortCol,       setSortCol]       = useState('cvss');
  const [sortDir,       setSortDir]       = useState('desc');
  const [pageSize,      setPageSize]      = usePageSize('vuln');
  const [page,          setPage]          = useState(1);
  const [nodeDrill,     setNodeDrill]     = useState(null);
  const [deployDrill,   setDeployDrill]   = useState(null);
  const [imageDrill,    setImageDrill]    = useState(null);
  const [scheduleOpen,  setScheduleOpen]  = useState(false);
  const [showProgress,  setShowProgress]  = useState(false);
  const [errorsDismissed, setErrorsDismissed] = useState(false);
  const [logCollapsed,  setLogCollapsed]  = useState(false);
  const [sbomSelected,  setSbomSelected]  = useState(null);
  const [sbomSearch,    setSbomSearch]    = useState('');
  const [sbomFilter,    setSbomFilter]    = useState('all');
  const [libsExtraH,    setLibsExtraH]    = useState(0);
  const [summaryH,      setSummaryH]      = useState(null);
  const summaryRef = useRef(null);

  const [starting, setStarting] = useState(false);
  const { busy: reporting, download } = useReportDownload();

  const exportPDF = () => download('vuln', async ctx => {
    const { vulnReport } = await import('../../reports/vulnReport');
    return vulnReport({ results, cves: allCVEs, summary, ...ctx });
  });

  const handleScanAll = async () => {
    setShowProgress(true);
    setLogCollapsed(false);
    setErrorsDismissed(false);
    setSummaryH(null);
    setStarting(true);
    const res = await startScan([]);
    setStarting(false);
    if (res?.ok) {
      toast('info', 'Scan started', `Queued ${res.queued} image${res.queued === 1 ? '' : 's'} for scanning…`);
    } else if (res?.reason === 'empty') {
      toast('warn', 'Nothing to scan', res.message);
    } else if (res?.reason === 'busy') {
      toast('warn', 'Scan already running', res.message);
    } else {
      toast('error', 'Scan failed to start', res?.message || 'Scanner did not respond');
    }
  };

  const failedResults = useMemo(
    () => results.filter(r => r.status === 'error' || r.error),
    [results]);
  const okResults = results.length - failedResults.length;

  const wasScanningRef = useRef(false);
  useEffect(() => {
    if (wasScanningRef.current && !scanning) {
      const failed = failedResults.length || scanErrors.length;
      if (failed > 0) {
        toast('error', 'Scan finished with errors',
          `${failed} image${failed === 1 ? '' : 's'} failed — see the banner above the table`);
      } else {
        toast('success', 'Scan complete', `${okResults} image${okResults === 1 ? '' : 's'} scanned`);
      }
    }
    wasScanningRef.current = scanning;
  }, [scanning]);

  const dragCleanupRef = useRef(null);
  useEffect(() => () => { dragCleanupRef.current?.(); }, []);
  const startRowDrag = (e, onMove) => {
    e.preventDefault();
    dragCleanupRef.current?.();
    const startY = e.clientY;
    const move = (ev) => onMove(startY - ev.clientY);
    const cleanup = () => {
      window.removeEventListener('mousemove', move);
      window.removeEventListener('mouseup', cleanup);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      dragCleanupRef.current = null;
    };
    dragCleanupRef.current = cleanup;
    document.body.style.cursor = 'row-resize';
    document.body.style.userSelect = 'none';
    window.addEventListener('mousemove', move);
    window.addEventListener('mouseup', cleanup);
  };
  const onLibsResizeDown = (e) => {
    const startH = libsExtraH;
    startRowDrag(e, dy => setLibsExtraH(Math.max(0, Math.min(400, startH + dy))));
  };
  const onSummaryResizeDown = (e) => {
    const el = summaryRef.current;
    if (!el) return;
    const full = el.scrollHeight;
    const startH = el.offsetHeight;
    startRowDrag(e, dy => {
      const h = Math.max(0, Math.min(full, startH - dy));
      setSummaryH(h >= full ? null : h);
    });
  };
  const handleStop = async () => {
    const res = await stopScan();
    if (res?.ok) toast('info', 'Stopping scan', 'Cancelling running Trivy processes…');
    else toast('error', 'Stop failed', res?.message || 'Could not stop the scan');
  };

  const totalCVEs   = summary?.total    || allCVEs.length;
  const critCVEs    = summary?.critical || allCVEs.filter(c => c.severity?.toUpperCase() === 'CRITICAL').length;
  const highCVEs    = summary?.high     || allCVEs.filter(c => c.severity?.toUpperCase() === 'HIGH').length;
  const fixableCVEs = summary?.fixable  || allCVEs.filter(c => c.hasFix).length;
  const critImages  = results.filter(r => r.summary?.critical > 0).length;

  const imageRows = useMemo(() => {
    return clusterImages.filter(img => { const r = img.ref || img.name || ''; return !r.startsWith('sha256:') && !r.match(/^[0-9a-f]{64}$/); })
      .map(img => { const res = results.find(r => r.image === img.ref || r.name === img.name); return { ...img, summary: res?.summary || null, scanned: !!res, _res: res }; })
      .sort((a, b) => (b.summary?.critical || 0) - (a.summary?.critical || 0));
  }, [clusterImages, results]);

  const deployRows = useMemo(() => {
    const resultByImage = {};
    results.forEach(r => { resultByImage[r.image] = r; resultByImage[r.name] = r; });
    return workloads
      .filter(w => !SYSTEM_NS.includes(w.metadata?.namespace))
      .map(w => {
        const allC = [...(w.spec?.template?.spec?.containers || []), ...(w.spec?.template?.spec?.initContainers || [])];
        const images = [...new Set(allC.map(c => c.image).filter(img => img && !img.startsWith('sha256:')))];
        const imageResults = images.map(img => resultByImage[img] || resultByImage[img.split(':')[0]] || null).filter(Boolean);
        return { name: w.metadata?.name || '', ns: w.metadata?.namespace || '', kind: w._kind, images, imageResults, totalCVEs: imageResults.reduce((s, r) => s + (r.summary?.total || 0), 0) };
      }).sort((a, b) => b.totalCVEs - a.totalCVEs || a.name.localeCompare(b.name));
  }, [workloads, results]);

  const nodeRows = useMemo(() => {
    const nodeImages = {};
    results.forEach(r => { (r.nodes || []).forEach(n => { if (!nodeImages[n]) nodeImages[n] = []; nodeImages[n].push(r); }); });
    clusterImages.forEach(img => { (img.nodes || []).forEach(n => { if (!nodeImages[n]) nodeImages[n] = []; const r = results.find(res => res.image === img.ref || res.name === img.name); if (r && !nodeImages[n].find(x => x.name === r.name)) nodeImages[n].push(r); }); });
    const nodeList = sensorNodes.length > 0 ? sensorNodes.map(n => n.metadata?.name).filter(Boolean) : Object.keys({ ...nodeImages, ...(nodeStats || {}) });
    return nodeList.map(name => { const imgs = nodeImages[name] || []; return { name, imageCount: imgs.length, total: imgs.reduce((s, r) => s + (r.summary?.total || 0), 0), events: nodeStats?.[name] || 0, imageResults: imgs }; })
      .sort((a, b) => b.total - a.total || b.events - a.events);
  }, [sensorNodes, clusterImages, results, nodeStats]);

  const q = search.toLowerCase();
  const toggleSort = col => { if (sortCol === col) setSortDir(d => d === 'desc' ? 'asc' : 'desc'); else { setSortCol(col); setSortDir('desc'); } };
  const sortProps = { sort: sortCol, dir: sortDir, onSort: toggleSort };

  const sortedFiltered = useMemo(() => {
    const filtered = allCVEs.filter(c => !q || c.id?.toLowerCase().includes(q) || c.bduId?.toLowerCase().includes(q) || c.pkgName?.toLowerCase().includes(q) || c._imageName?.toLowerCase().includes(q));
    const dir = sortDir === 'desc' ? 1 : -1;
    return [...filtered].sort((a, b) => {
      if (sortCol === 'cvss') return dir * ((b.cvssV3Score || 0) - (a.cvssV3Score || 0));
      if (sortCol === 'risk') return dir * ((b.riskScore || 0)   - (a.riskScore || 0));
      if (sortCol === 'epss') return dir * ((b.epssScore || 0)   - (a.epssScore || 0));
      return 0;
    });
  }, [allCVEs, q, sortCol, sortDir]);

  useEffect(() => { setPage(1); }, [q, sortCol, sortDir, pageSize, tab, imageDrill, deployDrill, nodeDrill, sbomSearch, sbomFilter]);

  const paginate = (arr) => {
    const tp = Math.max(1, Math.ceil(arr.length / pageSize));
    const cp = Math.min(page, tp);
    return arr.slice((cp - 1) * pageSize, cp * pageSize);
  };

  const filterInput = (
    <SearchInput size="sm" value={search} onChange={setSearch} placeholder={`Filter ${tab.toLowerCase()}…`} />
  );

  const exportCSV = () => {
    const rows = [['CVE ID','BDU ID','BDU Severity','Severity','CVSS','EPSS','Package','Version','Has Fix','Image']];
    allCVEs.forEach(c => rows.push([c.id, c.bduId || '', c.bduSeverity || '', c.severity, c.cvssV3Score, c.epssScore?.toFixed(4) || '', c.pkgName, c.pkgVersion, c.hasFix ? 'Yes' : 'No', c._imageName || '']));
    const blob = new Blob([rows.map(r => r.join(',')).join('\n')], { type: 'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = 'vulns.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
    toast('success', 'Exported', `${allCVEs.length} CVEs`);
  };

  const switchTab = t => { setTab(t); setSelected(null); setSearch(''); setNodeDrill(null); setDeployDrill(null); setImageDrill(null); };
  const doneCount = progress.filter(p => p.kind === 'ok').length;
  const failCount = progress.filter(p => p.kind === 'fail').length;
  const pagerProps = { pageSize, page, setPage, setPageSize };
  const shown = v => (scanning && !v ? '…' : fmt(v || 0));

  return (
    <div className="page active flex-page split-page" id="page-vulnmgmt">
      <div className="split-head">
        <PageHeader
          className="mb-12"
          title="Vulnerability Management"
          subtitle={
            <span className="row row--wrap">
              CVEs across images, deployments and nodes
              {agentOnline
                ? <span className="row row--tight t-ok t-xs"><span className="dot dot--ok" /> scanner online · {okResults} images scanned
                    {failedResults.length > 0 && <span className="t-danger"> · {failedResults.length} failed</span>}</span>
                : <span className="row row--tight t-warning t-xs"><Icon name="alert" /> scanner offline</span>}
            </span>
          }
          actions={<>
            <button type="button" className="btn btn-outline" onClick={() => setScheduleOpen(true)}>
              <Icon name="clock" /> Schedule
              {schedule?.enabled && <Tag tone="accent">ON</Tag>}
            </button>
            {!scanning && (
              <button type="button" className="btn btn-primary" onClick={handleScanAll} disabled={!agentOnline || starting}
                title={agentOnline ? 'Scan every image running in the cluster' : 'Scanner agent is offline'}>
                {starting ? <><Icon name="loader" /> Starting…</> : <><Icon name="scan" /> Scan All Images</>}
              </button>
            )}
            {scanning && (
              <button type="button" className="btn btn-danger" onClick={handleStop} title="Cancel running Trivy processes and clear the queue">
                <Icon name="loader" /> Stop Scan
              </button>
            )}
            {allCVEs.length > 0 && <button type="button" className="btn btn-outline" onClick={exportCSV}><Icon name="download" /> CSV</button>}
            {results.length > 0 && (
              <button type="button" className="btn btn-outline" onClick={exportPDF} disabled={!!reporting || scanning}
                title={scanning ? 'Wait for the scan to finish' : 'Download a PDF report of images and vulnerabilities'}>
                <Icon name={reporting ? 'loader' : 'download'} /> {reporting ? 'Building…' : 'PDF'}
              </button>
            )}
          </>}
        />

        <div ref={summaryRef} className="vuln-summary"
          style={summaryH == null ? undefined : { maxHeight: summaryH, opacity: Math.min(1, summaryH / 60) }}>
          {failedResults.length > 0 && !errorsDismissed && (
            <Notice tone="danger" icon="circle-x">
              <div className="row row--between">
                <span className="t-strong">{failedResults.length} image{failedResults.length === 1 ? '' : 's'} failed to scan</span>
                <button type="button" className="btn-icon btn-icon--sm" aria-label="Close scan errors" onClick={() => setErrorsDismissed(true)}><Icon name="x" /></button>
              </div>
              <div className="scan-errors">
                {failedResults.slice(0, 6).map(r => (
                  <div key={r.image}><b>{r.image}</b> — {r.error || 'unknown error'}</div>
                ))}
                {failedResults.length > 6 && <div>…and {failedResults.length - 6} more</div>}
              </div>
            </Notice>
          )}

          <div className="stats-grid stats-grid--5 mb-16">
            <Stat label="Total CVEs" tone="danger" value={shown(totalCVEs)}
              sub={critCVEs > 0 ? `${critCVEs} critical · ${highCVEs} high` : 'No critical CVEs'} />
            <Stat label="Images Scanned" tone="warning" value={shown(okResults)}
              sub={failedResults.length > 0 ? `${failedResults.length} failed to scan` : (critImages > 0 ? `${critImages} with critical` : 'No critical images')} />
            <Stat label="Fixable" tone="ok" value={shown(fixableCVEs)}
              sub={totalCVEs > 0 ? `${Math.round(fixableCVEs / totalCVEs * 100)}% of total` : '—'} />
            <Stat label="CISA KEV" tone="danger" value={shown(summary?.inKev)} sub="Actively exploited" />
            <Stat label="With PoC" tone="warning" value={shown(summary?.hasPoc)} sub="Public exploit code" />
          </div>

          {(scanning || (showProgress && progress.length > 0)) && (
            <div className="scan-log" data-open={!logCollapsed}>
              <div className="scan-log-head">
                <button type="button" className="scan-log-toggle" aria-expanded={!logCollapsed} onClick={() => setLogCollapsed(c => !c)}>
                  <Icon name={logCollapsed ? 'chevron-right' : 'chevron-down'} />
                  {scanning
                    ? <span className="row row--tight t-accent t-strong"><Icon name="loader" /> Scanning images…</span>
                    : <span className="row row--tight t-ok t-strong"><Icon name="check" /> Scan complete</span>}
                  <span className="t-xs t-muted">{doneCount} done{failCount > 0 && ` · ${failCount} errors`}</span>
                </button>
                <button type="button" className="btn-icon btn-icon--sm" aria-label="Hide scan log" onClick={() => setShowProgress(false)}><Icon name="x" /></button>
              </div>
              {!logCollapsed && (
                <div className="scan-log-body">
                  {progress.slice(-30).map((line, i) => <ProgressLine key={i} line={line} compact />)}
                </div>
              )}
            </div>
          )}
        </div>

        <Tabs tabs={TABS.map(t => ({ id: t, label: t }))} active={tab} onSwitch={switchTab} />
        <div className="resize-grip vuln-grip" onMouseDown={onSummaryResizeDown} onDoubleClick={() => setSummaryH(null)}
          title="Drag up to enlarge the table · double-click to reset" />
      </div>

      {tab !== 'Libs' && (
        <div className="split-body">
          <div className="split-main">
            {tab === 'CVEs' && (
              <div className="card">
                <div className="card-header">
                  <div className="card-title">CVEs {allCVEs.length > 0 && <span className="card-sub">({allCVEs.length.toLocaleString()})</span>}</div>
                  {filterInput}
                </div>
                <div className="table-wrap">
                  <table className="data-table">
                    <thead><tr>
                      <th>CVE ID</th><th title="FSTEC BDU — Russian national vulnerability database identifier">BDU</th><th>Severity</th>
                      <SortTh col="cvss" label="CVSS" {...sortProps} /><SortTh col="epss" label="EPSS" {...sortProps} /><SortTh col="risk" label="Risk" {...sortProps} />
                      <th>Package</th><th>Version</th><th>Image</th><th>KEV</th><th>PoC</th><th>Fix</th>
                    </tr></thead>
                    <tbody>
                      {allCVEs.length === 0
                        ? <tr className="static"><td colSpan={12}>
                            <EmptyState icon={agentOnline ? 'search' : 'wifi-off'}
                              title={agentOnline ? 'No scan results yet' : 'Scanner agent offline'}
                              sub={agentOnline ? 'Run a scan to detect CVEs in your cluster images.' : 'Deploy scanner-agent to start vulnerability detection.'}
                              action={agentOnline && <button type="button" className="btn btn-primary" onClick={handleScanAll}>Start Scan</button>} />
                          </td></tr>
                        : paginate(sortedFiltered).map((c, i) => {
                            const epss = c.epssScore > 0 ? epssLabel(c.epssScore) : null;
                            const tone = sevTone(c.severity);
                            return (
                              <tr key={i} className={selected === c ? 'selected' : ''} onClick={() => setSelected(selected === c ? null : c)}>
                                <td className="td-primary mono t-sm">{c.id}</td>
                                <td title={c.bduId ? `${c.bduId}${c.bduSeverity ? ` · ${c.bduSeverity}` : ''}` : 'Not found in the FSTEC BDU'}>
                                  {c.bduId ? <Tag tone="danger" mono>{c.bduId}</Tag> : <span className="t-muted">—</span>}
                                </td>
                                <td><SevBadge sev={c.severity?.toUpperCase()} /></td>
                                <td className={cx('mono t-sm t-strong', tone && `t-${tone}`)}>{c.cvssV3Score > 0 ? c.cvssV3Score.toFixed(1) : '—'}</td>
                                <td className={cx('mono t-xs', epssTone(c.epssScore) ? `t-${epssTone(c.epssScore)}` : 't-muted')}>{epss?.text || '—'}</td>
                                <td>{c.riskScore > 0 ? <Tag tone={sevTone(c.riskLabel)} mono>{Number(c.riskScore).toFixed(1)}</Tag> : <span className="t-muted">—</span>}</td>
                                <td className="t-sm">{c.pkgName}</td>
                                <td className="mono t-xs t-muted">{c.pkgVersion}</td>
                                <td className="mono t-xs t-muted clip clip--sm" title={c._imageName}>{c._imageName || '—'}</td>
                                <td>{c.inKev ? <span className="t-danger" title="CISA KEV — actively exploited"><Icon name="flame" /></span> : <span className="t-muted">—</span>}</td>
                                <td>{c.pocs?.length > 0 ? <span className="ic-label t-sm" title={`${c.pocs.length} PoC(s)`}><Icon name="code" />{c.pocs.length}</span> : <span className="t-muted">—</span>}</td>
                                <td><StatusDot type={c.hasFix ? 'active' : 'error'} label={c.hasFix ? 'Yes' : 'No'} /></td>
                              </tr>
                            );
                          })}
                    </tbody>
                  </table>
                </div>
                <Pager {...pagerProps} total={sortedFiltered.length} />
              </div>
            )}

            {tab === 'Images' && (
              <VulnImagesTab
                imageDrill={imageDrill} setImageDrill={setImageDrill}
                imageRows={imageRows}
                q={q} results={results} agentOnline={agentOnline} handleScanAll={handleScanAll}
                paginate={paginate} pageSize={pageSize} page={page} setPage={setPage} setPageSize={setPageSize}
                setSelected={setSelected} filterInput={filterInput}
              />
            )}

            {tab === 'Deployments' && (
              <div className="card">
                <div className="card-header">
                  <div className="card-title">
                    {deployDrill
                      ? <Crumbs items={[{ label: 'Workloads', onClick: () => setDeployDrill(null) }, { label: deployDrill.name }]} meta={`${deployDrill.images.length} images`} />
                      : <>Workloads <span className="card-sub">({deployRows.length})</span></>}
                  </div>
                  {deployDrill
                    ? <button type="button" onClick={() => setDeployDrill(null)} className="btn btn-outline btn-sm"><Icon name="arrow-left" /> Back</button>
                    : filterInput}
                </div>
                {!deployDrill ? (() => {
                  const filtered = deployRows.filter(r => !q || r.name.toLowerCase().includes(q) || r.ns.includes(q) || r.kind.toLowerCase().includes(q));
                  return (
                    <>
                      <div className="table-wrap">
                        <table className="data-table">
                          <thead><tr><th>Name</th><th>Controller</th><th>Namespace</th><th>Images</th><th>Total CVEs</th><th aria-label="Open" /></tr></thead>
                          <tbody>
                            {deployRows.length === 0
                              ? <tr className="static"><td colSpan={6}><EmptyState icon="layers" title="No workload data" sub="Sensor must be online to load real workloads from the cluster." /></td></tr>
                              : paginate(filtered).map((r, i) => (
                                  <tr key={i} onClick={() => setDeployDrill(r)}>
                                    <td className="td-primary">{r.name}</td>
                                    <td><KindBadge kind={r.kind} /></td>
                                    <td className="t-sm">{r.ns}</td>
                                    <td className="t-sm t-muted">{r.images.length}</td>
                                    <td className={cx('mono t-sm', r.totalCVEs > 0 ? 't-danger' : 't-muted')}>{r.totalCVEs || '—'}</td>
                                    <td className="t-muted"><Icon name="chevron-right" /></td>
                                  </tr>
                                ))}
                          </tbody>
                        </table>
                      </div>
                      <Pager {...pagerProps} total={filtered.length} />
                    </>
                  );
                })() : (
                  <>
                    <div className="table-wrap">
                      <table className="data-table">
                        <thead><tr><th>Image</th><th>Severity</th><th>Total CVEs</th><th>Scanned</th><th aria-label="Open" /></tr></thead>
                        <tbody>
                          {paginate(deployDrill.images).map((img, i) => {
                            const res = deployDrill.imageResults.find(r => r.image === img || r.name === img || img.startsWith(r.name));
                            const topSev = res ? (['critical','high','medium','low'].find(s => res.summary?.[s] > 0) || '').toUpperCase() : null;
                            return (
                              <tr key={i} className={res ? '' : 'static t-muted'} onClick={() => res && (setTab('Images'), setImageDrill(res))}>
                                <td className="td-primary mono t-xs">{img}</td>
                                <td>{topSev ? <SevBadge sev={topSev} /> : <span className="t-muted t-xs">{res ? 'Clean' : '—'}</span>}</td>
                                <td className={cx('mono t-sm', res?.summary?.total > 0 ? 't-danger' : 't-muted')}>{res?.summary?.total != null ? res.summary.total : '—'}</td>
                                <td className="t-sm t-muted">{ago(res?.scannedAt) || 'Not scanned'}</td>
                                <td className="t-muted">{res && <Icon name="chevron-right" />}</td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                    <Pager {...pagerProps} total={deployDrill.images.length} />
                  </>
                )}
              </div>
            )}

            {tab === 'Nodes' && (
              <div className="card">
                <div className="card-header">
                  <div className="card-title">
                    {nodeDrill
                      ? <Crumbs items={[{ label: 'Nodes', onClick: () => setNodeDrill(null) }, { label: nodeDrill.name }]} meta={`${nodeDrill.imageResults.length} images`} />
                      : <>Nodes — Image CVE Exposure <span className="card-sub">({nodeRows.length})</span></>}
                  </div>
                  {nodeDrill
                    ? <button type="button" onClick={() => setNodeDrill(null)} className="btn btn-outline btn-sm"><Icon name="arrow-left" /> Back</button>
                    : filterInput}
                </div>
                {!nodeDrill ? (() => {
                  const filtered = nodeRows.filter(n => !q || n.name.includes(q));
                  return (
                    <>
                      <div className="table-wrap">
                        <table className="data-table">
                          <thead><tr><th>Node</th><th>Images</th><th>Total CVEs</th><th>Live Events</th></tr></thead>
                          <tbody>
                            {nodeRows.length === 0
                              ? <tr className="static"><td colSpan={4}><EmptyState icon="server" title="No node data" sub="Nodes are loaded from the sensor. Make sure sensor is deployed." /></td></tr>
                              : paginate(filtered).map((n, i) => (
                                  <tr key={i} onClick={() => setNodeDrill(n)}>
                                    <td className="td-primary mono t-sm">{n.name}</td>
                                    <td className={cx('t-sm', n.imageCount > 0 ? 't-primary' : 't-muted')}>{n.imageCount || '—'}</td>
                                    <td className={cx('mono t-sm', n.total > 0 ? 't-danger' : 't-muted')}>{n.total || '—'}</td>
                                    <td className={cx('mono t-sm', n.events > 0 ? 't-accent' : 't-muted')}>{n.events || '—'}</td>
                                  </tr>
                                ))}
                          </tbody>
                        </table>
                      </div>
                      <Pager {...pagerProps} total={filtered.length} />
                    </>
                  );
                })() : (
                  <>
                    <div className="table-wrap">
                      <table className="data-table">
                        <thead><tr><th>Image</th><th>Total CVEs</th><th>Fixable</th><th>Scanned</th></tr></thead>
                        <tbody>
                          {paginate(nodeDrill.imageResults).map((r, i) => (
                            <tr key={i} onClick={() => { setNodeDrill(null); setTab('Images'); setImageDrill(r); }}>
                              <td className="td-primary mono t-xs">{r.name}</td>
                              <td className={cx('mono t-sm', r.summary?.total > 0 ? 't-danger' : 't-ok')}>{r.summary?.total || '—'}</td>
                              <td className="t-sm t-ok">{r.summary?.fixable || '—'}</td>
                              <td className="t-sm t-muted">{ago(r.scannedAt) || '—'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <Pager {...pagerProps} total={nodeDrill.imageResults.length} />
                  </>
                )}
              </div>
            )}
          </div>

          <CveDetail item={selected} onClose={() => setSelected(null)} />
        </div>
      )}

      {tab === 'Libs' && (
        <VulnLibsTab
          results={results}
          sbomSearch={sbomSearch} setSbomSearch={setSbomSearch}
          sbomFilter={sbomFilter} setSbomFilter={setSbomFilter}
          sbomSelected={sbomSelected} setSbomSelected={setSbomSelected}
          libsExtraH={libsExtraH} onLibsResizeDown={onLibsResizeDown} setLibsExtraH={setLibsExtraH}
          paginate={paginate} pageSize={pageSize} page={page} setPage={setPage} setPageSize={setPageSize}
        />
      )}

      <SbomDetail pkg={sbomSelected} onClose={() => setSbomSelected(null)} />

      {scheduleOpen && <ScheduleModal schedule={schedule} onSave={updateSchedule} onClose={() => setScheduleOpen(false)} />}
    </div>
  );
}
