import { useState, useMemo, useEffect, useRef } from 'react';
import { useScanner } from '../../context/ScannerContext';
import { useBridge }  from '../../context/BridgeContext';
import { useApp }     from '../../context/AppContext';
import { useSensor }  from '../../context/SensorContext';
import { SevBadge, StatusDot } from '../../components/ui';
import { EmptyState }  from '../../components/EmptyState';
import { sevColor, epssLabel } from '../../data/scanner';
import { CveDetail }     from './CveDetail';
import { SbomDetail }    from './SbomDetail';
import { ScheduleModal } from './vulnWidgets';
import { TABS } from './vulnUtils';
import { Pager } from './VulnPager';
import { VulnLibsTab } from './VulnLibsTab';
import { VulnImagesTab } from './VulnImagesTab';

export function VulnMgmt() {
  const { toast } = useApp();
  const { allCVEs, results, summary, clusterImages, agentOnline, scanning,
          startScan, stopScan, schedule, updateSchedule, progress } = useScanner();
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
  const [pageSize,      setPageSize]      = useState(20);
  const [page,          setPage]          = useState(1);
  const [nodeDrill,     setNodeDrill]     = useState(null);
  const [deployDrill,   setDeployDrill]   = useState(null);
  const [imageDrill,    setImageDrill]    = useState(null);
  const [scheduleOpen,  setScheduleOpen]  = useState(false);
  const [showProgress,  setShowProgress]  = useState(false);
  const [logCollapsed,  setLogCollapsed]  = useState(false);
  const [sbomSelected,  setSbomSelected]  = useState(null);
  const [sbomSearch,    setSbomSearch]    = useState('');
  const [sbomFilter,    setSbomFilter]    = useState('all');
  const [libsExtraH,    setLibsExtraH]    = useState(0);

  const handleScanAll = () => { setShowProgress(true); setLogCollapsed(false); startScan([]); toast('info', 'Scan started', 'Scanner is collecting cluster images…'); };

  const libsDragCleanupRef = useRef(null);
  useEffect(() => () => { libsDragCleanupRef.current?.(); }, []);
  const onLibsResizeDown = (e) => {
    e.preventDefault();
    libsDragCleanupRef.current?.();
    const startY = e.clientY;
    const startH = libsExtraH;
    const onMove = (ev) => setLibsExtraH(Math.max(0, Math.min(400, startH + (startY - ev.clientY))));
    const cleanup = () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', cleanup);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      libsDragCleanupRef.current = null;
    };
    libsDragCleanupRef.current = cleanup;
    document.body.style.cursor = 'row-resize';
    document.body.style.userSelect = 'none';
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', cleanup);
  };
  const handleStop = () => { stopScan(); toast('info', 'Stopping scan', 'Cancelling running grype processes…'); };

  const totalCVEs   = summary?.total    || allCVEs.length;
  const critCVEs    = summary?.critical || allCVEs.filter(c => c.severity?.toUpperCase() === 'CRITICAL').length;
  const highCVEs    = summary?.high     || allCVEs.filter(c => c.severity?.toUpperCase() === 'HIGH').length;
  const fixableCVEs = summary?.fixable  || allCVEs.filter(c => c.hasFix).length;

  const imageRows = useMemo(() => {
    return clusterImages.filter(img => { const r = img.ref || img.name || ''; return !r.startsWith('sha256:') && !r.match(/^[0-9a-f]{64}$/); })
      .map(img => { const res = results.find(r => r.image === img.ref || r.name === img.name); return { ...img, summary: res?.summary || null, scanned: !!res, _res: res }; })
      .sort((a, b) => (b.summary?.critical || 0) - (a.summary?.critical || 0));
  }, [clusterImages, results]);

  const deployRows = useMemo(() => {
    const resultByImage = {};
    results.forEach(r => { resultByImage[r.image] = r; resultByImage[r.name] = r; });
    return workloads
      .filter(w => !['kube-system','kube-public','kube-node-lease','metallb-system','calico-system','cert-manager'].includes(w.metadata?.namespace))
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

  const imageToController = useMemo(() => {
    const m = {};
    deployRows.forEach(r => r.images.forEach(img => { m[img] = { name: r.name, kind: r.kind }; m[img.split(':')[0]] = { name: r.name, kind: r.kind }; }));
    return m;
  }, [deployRows]);

  const q = search.toLowerCase();
  const toggleSort = col => { if (sortCol === col) setSortDir(d => d === 'desc' ? 'asc' : 'desc'); else { setSortCol(col); setSortDir('desc'); } };
  const SortTh = ({ col, label }) => <th style={{ cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap' }} onClick={() => toggleSort(col)}>{label} {sortCol === col ? (sortDir === 'desc' ? '↓' : '↑') : <span style={{ opacity: .3 }}>↕</span>}</th>;

  const sortedFiltered = useMemo(() => {
    const filtered = allCVEs.filter(c => !q || c.id?.toLowerCase().includes(q) || c.bduId?.toLowerCase().includes(q) || c.pkgName?.toLowerCase().includes(q) || c._imageName?.toLowerCase().includes(q));
    const dir = sortDir === 'desc' ? -1 : 1;
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
    <input
      type="text"
      placeholder={`Filter ${tab.toLowerCase()}...`}
      value={search}
      onChange={e => setSearch(e.target.value)}
      style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 7, padding: '5px 10px', fontSize: 12, color: 'var(--text-primary)', outline: 'none', fontFamily: 'DM Sans,sans-serif' }}
    />
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

  const kindColors = { Deployment: ['rgba(0,200,255,.08)', 'var(--accent)'], StatefulSet: ['rgba(124,58,237,.12)', '#a78bfa'], DaemonSet: ['rgba(16,185,129,.1)', 'var(--accent-3)'] };

  return (
    <div className="page active flex-page" id="page-vulnmgmt" style={{ flexDirection: 'column', padding: 0 }}>
      <div style={{ padding: '20px 24px 0', flexShrink: 0 }}>
        <div className="page-header" style={{ marginBottom: 14 }}>
          <div>
            <div className="page-title">Vulnerability Management</div>
            <div className="page-subtitle">
              CVEs across images, deployments and nodes
              {agentOnline ? <span style={{ color: 'var(--accent-3)', marginLeft: 8, fontSize: 11 }}>● scanner online · {results.length} images scanned</span>
                           : <span style={{ color: 'var(--warning)', marginLeft: 8, fontSize: 11 }}>⚠ scanner offline</span>}
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-outline" onClick={() => setScheduleOpen(true)} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              ⏱ Schedule
              {schedule?.enabled && <span style={{ fontSize: 10, background: 'var(--accent)', color: '#000', padding: '1px 6px', borderRadius: 10, fontWeight: 600 }}>ON</span>}
            </button>
            {agentOnline && !scanning && <button className="btn btn-primary" onClick={handleScanAll}>🔍 Scan All Images</button>}
            {scanning && <button className="btn btn-danger" onClick={handleStop} title="Cancel running grype processes and clear the queue">
              <span style={{ display: 'inline-block', animation: 'spin 1s linear infinite' }}>⟳</span>&nbsp;Stop Scan
            </button>}
            {allCVEs.length > 0 && <button className="btn btn-outline" onClick={exportCSV}>📥 CSV</button>}
          </div>
        </div>

        {}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 12, marginBottom: 16 }}>
          {[['Total CVEs', totalCVEs, 'var(--danger)', critCVEs > 0 ? `${critCVEs} critical · ${highCVEs} high` : 'No critical CVEs'],
            ['Images Scanned', results.length, 'var(--warning)', results.filter(r => r.summary?.critical > 0).length > 0 ? `${results.filter(r => r.summary?.critical > 0).length} with critical` : 'No critical images'],
            ['Fixable', fixableCVEs, 'var(--accent-3)', totalCVEs > 0 ? `${Math.round(fixableCVEs / totalCVEs * 100)}% of total` : '—'],
            ['CISA KEV', summary?.inKev || 0, 'var(--danger)', 'Actively exploited'],
            ['With PoC', summary?.hasPoc || 0, 'var(--warning)', 'Public exploit code'],
          ].map(([label, val, color, sub]) => (
            <div key={label} className="card" style={{ padding: '14px 16px', marginBottom: 0 }}>
              <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '.07em', color: 'var(--text-muted)', marginBottom: 6 }}>{label}</div>
              <div style={{ fontSize: 26, fontWeight: 700, color, fontFamily: 'JetBrains Mono,monospace' }}>{scanning && val === 0 ? '…' : (typeof val === 'number' && val > 999 ? val.toLocaleString() : val)}</div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>{sub}</div>
            </div>
          ))}
        </div>

        {}
        {(scanning || (showProgress && progress.length > 0)) && (
          <div style={{ marginBottom: 12, background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
            <div
              onClick={() => setLogCollapsed(c => !c)}
              title={logCollapsed ? 'Click to expand log' : 'Click to collapse log'}
              style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 14px', borderBottom: logCollapsed ? 'none' : '1px solid var(--border)', cursor: 'pointer', userSelect: 'none' }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ color: 'var(--text-muted)', fontSize: 10, width: 10, display: 'inline-block' }}>{logCollapsed ? '▶' : '▼'}</span>
                {scanning ? <span style={{ color: 'var(--accent)', fontSize: 12, fontWeight: 600 }}><span style={{ display: 'inline-block', animation: 'spin 1s linear infinite', marginRight: 6 }}>⟳</span>Scanning images…</span>
                           : <span style={{ color: 'var(--accent-3)', fontSize: 12, fontWeight: 600 }}>✓ Scan complete</span>}
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{progress.filter(p => p.startsWith('✓')).length} done{progress.filter(p => p.startsWith('✗')).length > 0 && ` · ${progress.filter(p => p.startsWith('✗')).length} errors`}</span>
              </div>
              <button onClick={e => { e.stopPropagation(); setShowProgress(false); }} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 13, padding: '2px 6px' }}>✕</button>
            </div>
            {!logCollapsed && (
              <div style={{ maxHeight: 120, overflowY: 'auto', padding: '6px 14px 8px', fontFamily: 'JetBrains Mono,monospace', fontSize: 11 }}>
                {progress.slice(-30).map((line, i) => (
                  <div key={i} style={{ color: line.startsWith('✓') ? 'var(--accent-3)' : line.startsWith('✗') ? 'var(--danger)' : 'var(--text-muted)', lineHeight: 1.7, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{line}</div>
                ))}
              </div>
            )}
          </div>
        )}

        <div className="tabs">
          {TABS.map(t => <div key={t} className={`tab${tab === t ? ' active' : ''}`} onClick={() => { setTab(t); setSelected(null); setSearch(''); setNodeDrill(null); setDeployDrill(null); setImageDrill(null); }}>{t}</div>)}
        </div>
      </div>

      <div style={{ display: tab === 'Libs' ? 'none' : 'flex', flex: 1, overflow: 'hidden' }}>
        <div style={{ flex: 1, overflowY: 'auto', padding: '0 0 24px 24px', minWidth: 0 }}>

          {}
          {tab === 'CVEs' && (
            <div className="card" style={{ marginTop: 16, marginRight: 24 }}>
              <div className="card-header">
                <div className="card-title">CVEs {allCVEs.length > 0 && <span style={{ fontSize: 12, color: 'var(--text-muted)', marginLeft: 6 }}>({allCVEs.length.toLocaleString()})</span>}</div>
                {filterInput}
              </div>
              <div className="table-wrap">
                <table className="data-table">
                  <thead><tr><th>CVE ID</th><th title="ФСТЭК БДУ — идентификатор российского банка данных угроз">БДУ</th><th>Severity</th><SortTh col="cvss" label="CVSS" /><SortTh col="epss" label="EPSS" /><SortTh col="risk" label="Risk" /><th>Package</th><th>Version</th><th>Image</th><th>KEV</th><th>PoC</th><th>Fix</th></tr></thead>
                  <tbody>
                    {allCVEs.length === 0
                      ? <tr><td colSpan={12}><EmptyState icon={agentOnline ? '🔍' : '📡'} title={agentOnline ? 'No scan results yet' : 'Scanner agent offline'} sub={agentOnline ? 'Run a scan to detect CVEs in your cluster images.' : 'Deploy scanner-agent to start vulnerability detection.'} action={agentOnline && <button className="btn btn-primary" style={{ marginTop: 4 }} onClick={handleScanAll}>Start Scan</button>} /></td></tr>
                      : paginate(sortedFiltered).map((c, i) => {
                          const epss = c.epssScore > 0 ? epssLabel(c.epssScore) : null;
                          const riskCol = { CRITICAL: 'var(--danger)', HIGH: 'var(--warning)', MEDIUM: '#a78bfa', LOW: 'var(--accent-3)' }[c.riskLabel] || 'var(--text-muted)';
                          return (
                            <tr key={i} className={selected === c ? 'selected' : ''} style={{ cursor: 'pointer' }} onClick={() => setSelected(selected === c ? null : c)}>
                              <td className="td-primary mono" style={{ fontSize: 12 }}>{c.id}</td>
                              <td className="mono" style={{ fontSize: 11 }} title={c.bduId ? `${c.bduId}${c.bduSeverity ? ` · ${c.bduSeverity}` : ''}` : 'Не найдено в БДУ ФСТЭК'}>
                                {c.bduId
                                  ? <span style={{ fontSize: 10, padding: '1px 6px', borderRadius: 3, background: 'rgba(239,68,68,.12)', color: 'var(--danger)', fontWeight: 600, whiteSpace: 'nowrap' }}>{c.bduId}</span>
                                  : <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>—</span>}
                              </td>
                              <td><SevBadge sev={c.severity?.toUpperCase()} /></td>
                              <td className="mono" style={{ fontSize: 12, fontWeight: 700, color: sevColor(c.severity) }}>{c.cvssV3Score > 0 ? c.cvssV3Score.toFixed(1) : '—'}</td>
                              <td className="mono" style={{ fontSize: 11, color: epss?.color || 'var(--text-muted)' }}>{epss?.text || '—'}</td>
                              <td>{c.riskScore > 0 ? <span style={{ fontSize: 10, fontFamily: 'JetBrains Mono,monospace', color: riskCol, fontWeight: 700, background: `${riskCol}18`, padding: '1px 6px', borderRadius: 4 }}>{c.riskScore}</span> : <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>—</span>}</td>
                              <td style={{ fontSize: 12 }}>{c.pkgName}</td>
                              <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>{c.pkgVersion}</td>
                              <td className="mono" style={{ fontSize: 10, color: 'var(--text-muted)', maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={c._imageName}>{c._imageName || '—'}</td>
                              <td style={{ fontSize: 12 }}>{c.inKev ? <span title="CISA KEV — actively exploited">🔥</span> : <span style={{ color: 'var(--text-muted)' }}>—</span>}</td>
                              <td style={{ fontSize: 12 }}>{c.pocs?.length > 0 ? <span title={`${c.pocs.length} PoC(s)`}>💣{c.pocs.length}</span> : <span style={{ color: 'var(--text-muted)' }}>—</span>}</td>
                              <td><StatusDot type={c.hasFix ? 'active' : 'error'} label={c.hasFix ? 'Yes' : 'No'} /></td>
                            </tr>
                          );
                        })
                    }
                  </tbody>
                </table>
              </div>
              <Pager pageSize={pageSize} page={page} setPage={setPage} setPageSize={setPageSize} total={sortedFiltered.length} />
            </div>
          )}

          {}
          {tab === 'Images' && (
            <VulnImagesTab
              imageDrill={imageDrill} setImageDrill={setImageDrill}
              imageRows={imageRows}
              q={q} results={results} agentOnline={agentOnline} handleScanAll={handleScanAll}
              paginate={paginate} pageSize={pageSize} page={page} setPage={setPage} setPageSize={setPageSize}
              setSelected={setSelected} filterInput={filterInput}
            />
          )}

          {}
          {tab === 'Deployments' && (
            <div className="card" style={{ marginTop: 16, marginRight: deployDrill ? 0 : 24 }}>
              <div className="card-header">
                <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  {deployDrill ? <><span style={{ color: 'var(--text-muted)', cursor: 'pointer' }} onClick={() => setDeployDrill(null)}>Workloads</span><span style={{ color: 'var(--text-muted)' }}>›</span><span>{deployDrill.name}</span><span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 400 }}>({deployDrill.images.length} images)</span></>
                    : <>Workloads ({deployRows.length})</>}
                </div>
                {deployDrill ? <button onClick={() => setDeployDrill(null)} style={{ fontSize: 11, padding: '3px 10px', borderRadius: 5, cursor: 'pointer', background: 'var(--bg-elevated)', border: '1px solid var(--border)', color: 'var(--text-muted)' }}>← Back</button> : filterInput}
              </div>
              {!deployDrill ? (() => {
                const filtered = deployRows.filter(r => !q || r.name.toLowerCase().includes(q) || r.ns.includes(q) || r.kind.toLowerCase().includes(q));
                return (
                  <>
                    <div className="table-wrap">
                      <table className="data-table">
                        <thead><tr><th>Name</th><th>Controller</th><th>Namespace</th><th>Images</th><th>Total CVEs</th><th style={{ width: 24 }}></th></tr></thead>
                        <tbody>
                          {deployRows.length === 0 ? <tr><td colSpan={6}><EmptyState icon="🚀" title="No workload data" sub="Sensor must be online to load real workloads from the cluster." /></td></tr>
                            : paginate(filtered).map((r, i) => {
                                const [bg, col] = kindColors[r.kind] || kindColors.Deployment;
                                return (
                                  <tr key={i} style={{ cursor: 'pointer' }} onClick={() => setDeployDrill(r)}>
                                    <td className="td-primary">{r.name}</td>
                                    <td><span style={{ fontSize: 11, padding: '2px 7px', borderRadius: 4, background: bg, color: col }}>{r.kind}</span></td>
                                    <td style={{ fontSize: 12 }}>{r.ns}</td>
                                    <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{r.images.length}</td>
                                    <td className="mono" style={{ fontSize: 12, color: r.totalCVEs > 0 ? 'var(--danger)' : 'var(--text-muted)' }}>{r.totalCVEs || '—'}</td>
                                    <td style={{ color: 'var(--text-muted)', fontSize: 14 }}>›</td>
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
                const drillImages = deployDrill.images;
                return (
                  <>
                    <div className="table-wrap">
                      <table className="data-table">
                        <thead><tr><th>Image</th><th>Severity</th><th>Total CVEs</th><th>Scanned</th><th style={{ width: 24 }}></th></tr></thead>
                        <tbody>
                          {paginate(drillImages).map((img, i) => {
                            const res = deployDrill.imageResults.find(r => r.image === img || r.name === img || img.startsWith(r.name));
                            const age = res?.scannedAt ? Math.round((Date.now() - new Date(res.scannedAt)) / 60000) : null;
                            const topSev = res ? (['critical','high','medium','low'].find(s => res.summary?.[s] > 0) || '').toUpperCase() : null;
                            return (
                              <tr key={i} style={{ cursor: res ? 'pointer' : 'default', opacity: res ? 1 : 0.5 }} onClick={() => res && (setTab('Images'), setImageDrill(res))}>
                                <td className="td-primary mono" style={{ fontSize: 11 }}>{img}</td>
                                <td>{topSev ? <SevBadge sev={topSev} /> : <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>{res ? 'Clean' : '—'}</span>}</td>
                                <td className="mono" style={{ fontSize: 12, color: res?.summary?.total > 0 ? 'var(--danger)' : 'var(--text-muted)' }}>{res?.summary?.total != null ? res.summary.total : '—'}</td>
                                <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{age !== null ? (age < 60 ? `${age}m ago` : `${Math.round(age / 60)}h ago`) : 'Not scanned'}</td>
                                <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{res ? '›' : ''}</td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                    <Pager pageSize={pageSize} page={page} setPage={setPage} setPageSize={setPageSize} total={drillImages.length} />
                  </>
                );
              })()}
            </div>
          )}

          {}
          {tab === 'Nodes' && (
            <div className="card" style={{ marginTop: 16, marginRight: 24 }}>
              <div className="card-header">
                <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  {nodeDrill ? <><span style={{ color: 'var(--text-muted)', cursor: 'pointer' }} onClick={() => setNodeDrill(null)}>Nodes</span><span style={{ color: 'var(--text-muted)' }}>›</span><span>{nodeDrill.name}</span><span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 400 }}>({nodeDrill.imageResults.length} images)</span></>
                    : <>Nodes — Image CVE Exposure ({nodeRows.length})</>}
                </div>
                {nodeDrill ? <button onClick={() => setNodeDrill(null)} style={{ fontSize: 11, padding: '3px 10px', borderRadius: 5, cursor: 'pointer', background: 'var(--bg-elevated)', border: '1px solid var(--border)', color: 'var(--text-muted)' }}>← Back</button> : filterInput}
              </div>
              {!nodeDrill ? (() => {
                const filtered = nodeRows.filter(n => !q || n.name.includes(q));
                return (
                  <>
                    <div className="table-wrap">
                      <table className="data-table">
                        <thead><tr><th>Node</th><th>Images</th><th>Total CVEs</th><th>Live Events</th></tr></thead>
                        <tbody>
                          {nodeRows.length === 0 ? <tr><td colSpan={4}><EmptyState icon="🖥" title="No node data" sub="Nodes are loaded from the sensor. Make sure sensor is deployed." /></td></tr>
                            : paginate(filtered).map((n, i) => (
                                <tr key={i} style={{ cursor: 'pointer' }} onClick={() => setNodeDrill(n)}>
                                  <td className="td-primary mono" style={{ fontSize: 12 }}>{n.name}</td>
                                  <td style={{ fontSize: 12, color: n.imageCount > 0 ? 'var(--text-primary)' : 'var(--text-muted)' }}>{n.imageCount || '—'}</td>
                                  <td className="mono" style={{ fontSize: 12, color: n.total > 0 ? 'var(--danger)' : 'var(--text-muted)' }}>{n.total || '—'}</td>
                                  <td style={{ color: n.events > 0 ? 'var(--accent)' : 'var(--text-muted)', fontFamily: 'JetBrains Mono,monospace', fontSize: 12 }}>{n.events || '—'}</td>
                                </tr>
                              ))
                          }
                        </tbody>
                      </table>
                    </div>
                    <Pager pageSize={pageSize} page={page} setPage={setPage} setPageSize={setPageSize} total={filtered.length} />
                  </>
                );
              })() : (() => {
                const drillImages = nodeDrill.imageResults;
                return (
                  <>
                    <div className="table-wrap">
                      <table className="data-table">
                        <thead><tr><th>Image</th><th>Total CVEs</th><th>Fixable</th><th>Scanned</th></tr></thead>
                        <tbody>
                          {paginate(drillImages).map((r, i) => {
                            const age = r.scannedAt ? Math.round((Date.now() - new Date(r.scannedAt)) / 60000) : null;
                            return (
                              <tr key={i} style={{ cursor: 'pointer' }} onClick={() => { setNodeDrill(null); setTab('Images'); setImageDrill(r); }}>
                                <td className="td-primary mono" style={{ fontSize: 11 }}>{r.name}</td>
                                <td className="mono" style={{ fontSize: 12, color: r.summary?.total > 0 ? 'var(--danger)' : 'var(--accent-3)' }}>{r.summary?.total || '—'}</td>
                                <td style={{ fontSize: 12, color: 'var(--accent-3)' }}>{r.summary?.fixable || '—'}</td>
                                <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{age !== null ? (age < 60 ? `${age}m ago` : `${Math.round(age / 60)}h ago`) : '—'}</td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                    <Pager pageSize={pageSize} page={page} setPage={setPage} setPageSize={setPageSize} total={drillImages.length} />
                  </>
                );
              })()}
            </div>
          )}
        </div>

        <CveDetail item={selected} onClose={() => setSelected(null)} />
      </div>

      {}
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
