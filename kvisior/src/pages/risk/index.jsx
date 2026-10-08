import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useScanner } from '../../context/ScannerContext';
import { useSensor }  from '../../context/SensorContext';
import { SevBadge }   from '../../components/ui';
import { PageHeader, SearchInput, SidePanel, DetailSection, Tag, EmptyRow, Meter, sevTone, cx } from '../../components/kit';
import { DataWindow } from '../../components/DataWindow';
import { Icon } from '../../components/Icon';
import { Pager } from '../../components/Pager';
import { usePaged } from '../../hooks/usePaged';

const SEV_LABEL  = s => s>=8?'CRITICAL':s>=6?'HIGH':s>=4?'MEDIUM':'LOW';
const RING_COLOR = { danger: 'var(--danger)', warning: 'var(--warning)', info: 'var(--info)', ok: 'var(--ok-text)' };

const SYS_NS = new Set(['kube-system','kube-public','kube-node-lease',
  'metallb-system','calico-system','cert-manager','wolfee-watcher']);

function buildFactors(w, imageResults) {
  const factors = [];
  let score = 0;

  const allCVEs   = imageResults.flatMap(r => r.cves || []);
  const sevOf     = c => String(c.severity || '').toUpperCase();
  const critCount = allCVEs.filter(c => sevOf(c) === 'CRITICAL').length;
  const highCount = allCVEs.filter(c => sevOf(c) === 'HIGH').length;
  const kevCount  = allCVEs.filter(c => c.inKev).length;
  const maxCVSS   = allCVEs.reduce((m, c) => Math.max(m, c.cvssV3Score || 0), 0);
  const maxEPSS   = allCVEs.reduce((m, c) => Math.max(m, c.epssScore   || 0), 0);
  const maxRisk   = allCVEs.reduce((m, c) => Math.max(m, c.riskScore   || 0), 0);

  if (allCVEs.length > 0) {
    const s = Math.min(4.0, maxRisk * 0.04);
    score += s;
    factors.push({
      icon:'bug', label:'Vulnerabilities',
      detail:`${allCVEs.length} CVEs · ${critCount} critical · ${highCount} high`,
      score:s, tone: critCount>0?'danger':highCount>0?'warning':'muted',
    });
  }

  if (kevCount > 0) {
    const s = Math.min(2.0, kevCount * 0.8);
    score += s;
    factors.push({ icon:'flame', label:'Known Exploited (CISA KEV)',
      detail:`${kevCount} CVE${kevCount>1?'s':''} actively exploited in the wild`,
      score:s, tone:'danger' });
  }

  if (maxEPSS >= 0.5) {
    const s = Math.min(0.8, maxEPSS * 0.8);
    score += s;
    factors.push({ icon:'target', label:'High Exploit Probability',
      detail:`EPSS ${(maxEPSS*100).toFixed(1)}% — likely to be exploited`,
      score:s, tone:'warning' });
  }

  const containers = [
    ...(w.raw?.spec?.template?.spec?.containers||[]),
    ...(w.raw?.spec?.template?.spec?.initContainers||[]),
  ];
  const privC = containers.filter(c=>c.securityContext?.privileged===true);
  if (privC.length > 0) {
    score += 1.5;
    factors.push({ icon:'unlock', label:'Privileged Containers',
      detail:`${privC.length} container${privC.length>1?'s':''}: ${privC.map(c=>c.name).join(', ')}`,
      score:1.5, tone:'danger' });
  }

  const spec = w.raw?.spec?.template?.spec||{};
  if (spec.hostNetwork) {
    score += 1.0;
    factors.push({ icon:'globe', label:'Host Network Access', detail:'Pod uses host network namespace', score:1.0, tone:'warning' });
  }
  if (spec.hostPID) {
    score += 0.8;
    factors.push({ icon:'eye', label:'Host PID Access', detail:'Pod can see all host processes', score:0.8, tone:'warning' });
  }

  const noLimits = containers.filter(c=>!c.resources?.limits?.memory&&!c.resources?.limits?.cpu);
  if (noLimits.length > 0 && containers.length > 0) {
    score += 0.3;
    factors.push({ icon:'trending-up', label:'No Resource Limits',
      detail:`${noLimits.length}/${containers.length} containers without CPU/memory limits`,
      score:0.3, tone:'muted' });
  }

  return { score: Math.min(9.9, score), factors, allCVEs,
    critCount, highCount, kevCount, maxCVSS, maxEPSS };
}

export function Risk() {
  const { results }                       = useScanner();
  const { workloads, sensorOnline }       = useSensor();
  const navigate                          = useNavigate();
  const [selected, setSelected]           = useState(null);
  const [search, setSearch]               = useState('');
  const [showSys, setShowSys]             = useState(false);

  const resultByImage = useMemo(() => {
    const m = {};
    results.forEach(r => {
      m[r.image] = r;
      m[r.name]  = r;
      if (r.image) m[r.image.split(':')[0]] = r;
    });
    return m;
  }, [results]);

  const riskRows = useMemo(() => {
    return workloads
      .filter(w => showSys || !SYS_NS.has(w.metadata?.namespace))
      .map(w => {
        const ns   = w.metadata?.namespace || '';
        const name = w.metadata?.name || '';
        const kind = w._kind || 'Deployment';
        const containers = [
          ...(w.spec?.template?.spec?.containers||[]),
          ...(w.spec?.template?.spec?.initContainers||[]),
        ];
        const images = [...new Set(
          containers.map(c=>c.image).filter(img=>img&&!img.startsWith('sha256:'))
        )];
        const imageResults = images
          .map(img => resultByImage[img] || resultByImage[img.split(':')[0]] || null)
          .filter(Boolean);

        const built = buildFactors({ name, ns, kind, raw: w }, imageResults);
        const age = w.metadata?.creationTimestamp
          ? Math.floor((Date.now()-new Date(w.metadata.creationTimestamp))/86400000)
          : null;
        return { name, ns, kind, images, ...built,
          age: age===null?'—':age<1?'today':age+'d' };
      })
      .sort((a,b) => b.score-a.score || b.critCount-a.critCount)
      .map((r,i) => ({ ...r, rank:i+1 }));
  }, [workloads, resultByImage, showSys]);

  const filtered = riskRows.filter(r => {
    if (!search) return true;
    const q = search.toLowerCase();
    return r.name.toLowerCase().includes(q) || r.ns.toLowerCase().includes(q);
  });

  const { pageItems: pageRisk, pager } = usePaged(filtered, 'risk', [search, showSys]);
  const hasData = workloads.length > 0;

  return (
    <div className="page active flex-page split-page" id="page-risk">
      <div className="split-head">
        <PageHeader
          className="mb-12"
          title="Risk"
          subtitle="Workloads ranked by CVEs · KEV · CIS security posture"
          actions={
            <label className="check t-sm t-secondary">
              <input type="checkbox" checked={showSys} onChange={e => setShowSys(e.target.checked)} />
              show system namespaces
            </label>
          }
        />
        <div className="toolbar">
          <SearchInput value={search} onChange={setSearch} placeholder="Search workloads…" />
        </div>
      </div>

      <div className="split-body">
        <div className="split-main">
          {!hasData && (
            <div className="pane empty-state">Sensor offline — waiting for workload data.</div>
          )}
          {hasData && (
            <DataWindow label="Workloads by risk" deps={[!!selected]} footer={<Pager {...pager} noun="workloads" />}>
              <table className="data-table">
                <thead><tr>
                  <th>#</th><th>Workload</th><th>Namespace</th><th>Risk Score</th><th>CVEs</th><th>KEV</th><th>Age</th>
                </tr></thead>
                <tbody>
                  {filtered.length === 0 && <EmptyRow cols={7}>No workloads matching filter</EmptyRow>}
                  {pageRisk.map(r => {
                    const tone = sevTone(SEV_LABEL(r.score));
                    const isSel = selected?.name === r.name && selected?.ns === r.ns;
                    return (
                      <tr key={r.name + r.ns} className={isSel ? 'selected' : ''} onClick={() => setSelected(isSel ? null : r)}>
                        <td><Tag tone={tone} mono>#{r.rank}</Tag></td>
                        <td className="td-primary">{r.name} <span className="t-2xs t-muted">{r.kind}</span></td>
                        <td className="t-sm t-muted">{r.ns}</td>
                        <td>
                          <div className="row risk-cell">
                            <span className={cx('mono t-md t-strong', `t-${tone}`)}>{r.score > 0 ? r.score.toFixed(1) : '—'}</span>
                            {r.score > 0 && <Meter value={r.score} max={10} color={RING_COLOR[tone]} showValue={false} label="Risk score" />}
                          </div>
                        </td>
                        <td className="t-sm">
                          {r.allCVEs.length > 0
                            ? <>{r.critCount > 0 && <span className="t-danger t-strong">{r.critCount}C </span>}
                                {r.highCount > 0 && <span className="t-warning t-strong">{r.highCount}H </span>}
                                <span className="t-muted">{r.allCVEs.length}</span></>
                            : <span className="t-muted">—</span>}
                        </td>
                        <td>{r.kevCount > 0 ? <Tag tone="danger"><Icon name="alert" /> {r.kevCount}</Tag> : <span className="t-muted">—</span>}</td>
                        <td className="t-sm t-muted">{r.age}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </DataWindow>
          )}
        </div>

        {selected && (() => {
          const tone = sevTone(SEV_LABEL(selected.score));
          const color = RING_COLOR[tone];
          const deg = selected.score * 36;
          return (
            <SidePanel title={selected.name} meta={`${selected.kind} · ${selected.ns}`} onClose={() => setSelected(null)}>
              <div className="item-card row row--loose mb-16">
                <div className="score-ring" style={{ background: `conic-gradient(${color} 0deg ${deg}deg, var(--bg-card) ${deg}deg 360deg)` }}>
                  <span className={cx('mono', `t-${tone}`)}>{selected.score > 0 ? selected.score.toFixed(1) : '0'}</span>
                </div>
                <div>
                  <div className="section-label mb-4">Risk score</div>
                  <div className={cx('t-lg t-strong', `t-${tone}`)}>{SEV_LABEL(selected.score)}</div>
                  <div className="t-xs t-muted mt-4">
                    {selected.images.length} image{selected.images.length !== 1 ? 's' : ''} · {selected.allCVEs.length} CVEs
                  </div>
                </div>
              </div>

              <DetailSection title="Risk factors">
                {selected.factors.length === 0
                  ? <div className="item-card t-center t-sm t-muted">No risk factors detected</div>
                  : [...selected.factors].sort((a, b) => b.score - a.score).map((f, i) => (
                      <div key={i} className="item-card row row--top">
                        <span className={`t-lg t-${f.tone}`}><Icon name={f.icon} /></span>
                        <div className="grow">
                          <div className="row row--between">
                            <span className={`t-sm t-strong t-${f.tone}`}>{f.label}</span>
                            <span className="mono t-xs t-muted">+{f.score.toFixed(1)}</span>
                          </div>
                          <div className="t-xs t-muted mt-4">{f.detail}</div>
                        </div>
                      </div>
                    ))}
              </DetailSection>

              {selected.allCVEs.length > 0 && (
                <DetailSection title="Top CVEs">
                  {[...selected.allCVEs].sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0)).slice(0, 6).map((c, i) => (
                    <div key={i} className="item-card row">
                      <span className="mono t-xs t-accent cve-id">{c.id}</span>
                      <SevBadge sev={String(c.severity || '').toUpperCase()} />
                      <span className="grow" />
                      <span className="mono t-xs t-muted">{(c.cvssV3Score || 0).toFixed(1)}</span>
                      {c.inKev && <Tag tone="danger">KEV</Tag>}
                    </div>
                  ))}
                  {selected.allCVEs.length > 6 && <div className="t-xs t-muted t-center mt-8">+{selected.allCVEs.length - 6} more</div>}
                </DetailSection>
              )}

              {selected.images.length > 0 && (
                <DetailSection title="Images">
                  {selected.images.map((img, i) => (
                    <button key={i} type="button" className="item-card item-card--link link-card"
                      onClick={() => { localStorage.setItem('wv_vuln_image', img); navigate('/vulnmgmt'); }}>
                      <Icon name="package" />
                      <span className="mono t-xs break grow">{img}</span>
                      <Icon name="chevron-right" />
                    </button>
                  ))}
                </DetailSection>
              )}
            </SidePanel>
          );
        })()}
      </div>
    </div>
  );
}
