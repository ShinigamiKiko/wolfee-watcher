import { useState, useMemo, useRef, useEffect } from 'react';
import { podName, podNS, podContainers } from '../../utils/format';
import { TimelineBars }   from './TimelineBars';
import { EventRow }       from './EventRow';
import { BinaryFilter }   from './BinaryFilter';
import { WatchPicker }     from './WatchPicker';
import { SYSCALL_GROUPS }  from './watchableSyscalls';
import { LSM_HOOKS, LSM_GROUPS, LSM_NAMES } from '../lsm/lsmCatalog';
import { TRACEPOINTS, TRACEPOINT_GROUPS, TRACEPOINT_NAMES } from '../tracepoints/tracepointsCatalog';

import { PAGE_SIZES, Pager } from './Pager';

const groupCatalog = (items, groupNames) =>
  groupNames.map(g => ({
    label: g,
    items: items.filter(it => it.group === g).map(it => ({ name: it.name, desc: it.desc })),
  }));
const LSM_GROUPS_UI = groupCatalog(LSM_HOOKS, LSM_GROUPS);
const TP_GROUPS_UI  = groupCatalog(TRACEPOINTS, TRACEPOINT_GROUPS);
const SYSCALL_NAME_SET = new Set(SYSCALL_GROUPS.flatMap(g => g.items.map(i => i.name)));
const LSM_NAME_SET     = new Set(LSM_NAMES);
const TP_NAME_SET      = new Set(TRACEPOINT_NAMES);

const SEV_RANK = { anomaly: 5, critical: 4, high: 3, medium: 2, low: 1, none: 0, syscall: 0 };
const FNS_COLUMNS = [
  { key: 'ts',        label: 'Timestamp' },
  { key: 'sev',       label: 'Severity' },
  { key: 'syscall',   label: 'Syscall' },
  { key: 'cmdline',   label: 'Cmdline / Args' },
  { key: 'process',   label: 'Process' },
  { key: 'container', label: 'Container ID' },
  { key: 'pid',       label: 'PID' },
];

export function PodDetail({ pod, ns, allEvents, getSev, onBack }) {
  const [windowH,         setWindowH]         = useState(24);
  const [filterSev,       setFilterSev]       = useState(new Set());
  const [filterBins,      setFilterBins]      = useState(new Set());
  const [activeContainer, setActiveContainer] = useState(null);
  const [page,            setPage]            = useState(1);
  const [pageSize,        setPageSize]        = useState(40);
  const [sortCol,         setSortCol]         = useState('ts');
  const [sortDir,         setSortDir]         = useState('desc');
  const [logsOpen,        setLogsOpen]        = useState(false);
  const [logsHours,       setLogsHours]       = useState(6);
  const [logsLoading,     setLogsLoading]     = useState(false);
  const [logsError,       setLogsError]       = useState(null);
  const [watching,        setWatching]        = useState(false);
  const [upperLoading,    setUpperLoading]    = useState(false);
  const [diff,            setDiff]            = useState([]);
  const [diffLoading,     setDiffLoading]     = useState(false);
  const [contentTab,      setContentTab]      = useState('syscalls');
  const [watchedSyscalls, setWatchedSyscalls] = useState([]);
  const [watchEvents,     setWatchEvents]     = useState([]);
  const [watchNoStore,    setWatchNoStore]    = useState(false);

  const logsWrapRef = useRef(null);

  const pName = podName(pod);
  const pNS   = podNS(pod);

  useEffect(() => {
    if (!watching) return;
    const t = setInterval(fetchDiff, 30_000);
    return () => clearInterval(t);
  }, [watching, pNS, pName]);

  useEffect(() => {
    const handler = (e) => {
      if (logsWrapRef.current && !logsWrapRef.current.contains(e.target)) { setLogsOpen(false); setLogsError(null); }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const fetchWatchEvents = async () => {
    try {
      const res = await fetch(`/v1/pod-syscall-events?ns=${encodeURIComponent(pNS)}&pod=${encodeURIComponent(pName)}`, { credentials: 'same-origin' });
      if (res.ok) {
        const data = await res.json();
        const parsed = (data.events || []).map(e => typeof e === 'string' ? JSON.parse(e) : e);
        setWatchEvents(parsed);
      }
    } catch {}
  };

  useEffect(() => {
    if (watchedSyscalls.length === 0) { setWatchEvents([]); return; }
    fetchWatchEvents();
    const t = setInterval(fetchWatchEvents, 30_000);
    return () => clearInterval(t);
  }, [watchedSyscalls.join(','), pNS, pName]);

  useEffect(() => {
    let cancelled = false;
    fetch(`/v1/pod-watch?ns=${encodeURIComponent(pNS)}&pod=${encodeURIComponent(pName)}`, { credentials: 'same-origin' })
      .then(r => {
        if (r.status === 503) { if (!cancelled) setWatchNoStore(true); return null; }
        return r.ok ? r.json() : null;
      })
      .then(d => { if (!cancelled && d?.syscalls) setWatchedSyscalls(d.syscalls); })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [pNS, pName]);

  const saveWatch = async (next) => {
    setWatchedSyscalls(next);
    const url = `/v1/pod-watch?ns=${encodeURIComponent(pNS)}&pod=${encodeURIComponent(pName)}`;
    try {
      if (next.length === 0) {
        await fetch(url, { method: 'DELETE', credentials: 'same-origin' });
      } else {
        await fetch(url, {
          method: 'PUT', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ syscalls: next }),
        });
      }
    } catch {}
  };
  const toggleWatch = (name, famSet, max) => {
    const isOn = watchedSyscalls.includes(name);
    if (!isOn && watchedSyscalls.filter(n => famSet.has(n)).length >= max) return;
    saveWatch(isOn ? watchedSyscalls.filter(n => n !== name) : [...watchedSyscalls, name]);
  };

  const fetchDiff = async () => {
    setDiffLoading(true);
    try {
      const res = await fetch(`/sensor/api/forensic/diff/${pNS}/${pName}`, { credentials: 'same-origin' });
      if (res.ok) {
        const data = await res.json();
        setDiff(data.entries || []);
      }
    } catch {}
    setDiffLoading(false);
  };

  const doWatch = async () => {
    try {
      const res = await fetch(`/sensor/api/forensic/watch/${pNS}/${pName}`, { method: 'POST', credentials: 'same-origin' });
      if (res.ok) { setWatching(true); setContentTab('fsdiff'); fetchDiff(); }
    } catch {}
  };
  const doUnwatch = async () => {
    try {
      await fetch(`/sensor/api/forensic/watch/${pNS}/${pName}`, { method: 'DELETE', credentials: 'same-origin' });
      setWatching(false);
    } catch {}
  };

  const doUpperDir = async () => {
    setUpperLoading(true);
    try {
      const res = await fetch(`/sensor/api/forensic/tar/${pNS}/${pName}`, { credentials: 'same-origin' });
      if (!res.ok) { alert('Upper dir failed: ' + res.status); return; }
      const blob = await res.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href = url; a.download = `upperdir-${pName}-${Date.now()}.tar.gz`;
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
    } catch(e) { alert('Error: ' + e.message); }
    finally { setUpperLoading(false); }
  };

  const podEvents = useMemo(() => {
    const now = Date.now();
    const windowMs = windowH * 60 * 60 * 1000;
    const binary = allEvents.filter(e => {
      if (e.pod !== pName || e.namespace !== pNS) return false;
      if (now - new Date(e.ts).getTime() > windowMs) return false;
      return true;
    });
    const seen = new Set(binary.map(e => e.id).filter(Boolean));
    const watch = watchEvents.filter(e => {
      if (e.id && seen.has(e.id)) return false;
      if (now - new Date(e.ts).getTime() > windowMs) return false;
      return true;
    });
    return [...binary, ...watch];
  }, [allEvents, pName, pNS, windowH, watchEvents]);

  const containers = useMemo(() => {
    const fromSpec   = podContainers(pod);
    const fromEvents = [...new Set(
      podEvents.map(e => e.container).filter(Boolean)
        .map(c => c.includes(':') ? c.split(':')[0] : c)
    )];
    return [...new Set([...fromSpec, ...fromEvents])];
  }, [pod, podEvents]);

  useEffect(() => {
    if (containers.length > 0 && !activeContainer) setActiveContainer(containers[0]);
  }, [containers, activeContainer]);

  const baseContainer = (c) => (c && c.includes(':') ? c.split(':')[0] : c);

  const containerHasAlert = (c) =>
    podEvents.some(e => baseContainer(e.container) === c && (getSev(e.syscall, e.execpath, e.process) === 'critical' || getSev(e.syscall, e.execpath, e.process) === 'high'));

  const toggleSort = (col) => {
    if (col === sortCol) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortCol(col); setSortDir(col === 'ts' ? 'desc' : 'asc'); }
  };
  const sortVal = (e) => {
    switch (sortCol) {
      case 'sev':       return SEV_RANK[getSev(e.syscall, e.execpath, e.process)] ?? 0;
      case 'syscall':   return e.syscall || '';
      case 'cmdline':   return e.cmdline || '';
      case 'process':   return e.process || '';
      case 'container': return e.containerId || '';
      case 'pid':       return e.pid ?? 0;
      default:          return new Date(e.ts).getTime() || 0;
    }
  };

  const visibleEvents = useMemo(() => {
    return podEvents
      .filter(e => {
        if (activeContainer && e.container && baseContainer(e.container) !== activeContainer) return false;
        if (filterSev.size > 0 && !filterSev.has(getSev(e.syscall, e.execpath, e.process))) return false;
        if (filterBins.size > 0) {
          const bin = (e.execpath || e.process || '').toLowerCase();
          if (![...filterBins].some(b => bin.includes(b.toLowerCase()))) return false;
        }
        return true;
      })
      .sort((a, b) => {
        const va = sortVal(a), vb = sortVal(b);
        const cmp = (typeof va === 'number' && typeof vb === 'number')
          ? va - vb : String(va).localeCompare(String(vb));
        return sortDir === 'asc' ? cmp : -cmp;
      });
  }, [podEvents, activeContainer, filterSev, filterBins, getSev, sortCol, sortDir]);

  useEffect(() => { setPage(1); }, [visibleEvents.length]);

  const pagedEvents = useMemo(() => {
    const tp = Math.max(1, Math.ceil(visibleEvents.length / pageSize));
    const cp = Math.min(page, tp);
    return visibleEvents.slice((cp - 1) * pageSize, cp * pageSize);
  }, [visibleEvents, page, pageSize]);

  const critical = visibleEvents.filter(e => getSev(e.syscall, e.execpath, e.process) === 'critical').length;
  const high     = visibleEvents.filter(e => getSev(e.syscall, e.execpath, e.process) === 'high').length;
  const medium   = visibleEvents.filter(e => getSev(e.syscall, e.execpath, e.process) === 'medium').length;
  const procs    = new Set(visibleEvents.map(e => e.process).filter(Boolean)).size;

  const doLogs = async (h) => {
    const hours = h || logsHours;
    setLogsOpen(false); setLogsError(null); setLogsLoading(true);
    const sinceSeconds = hours * 3600;
    const safeContainer = activeContainer?.includes(':') ? activeContainer.split(':')[0] : activeContainer;
    const qs       = safeContainer ? `&container=${encodeURIComponent(safeContainer)}` : '';
    const base     = `/sensor/api/pods/${pNS}/${pName}/logs?sinceSeconds=${sinceSeconds}${qs}`;
    const prevBase = `/sensor/api/pods/${pNS}/${pName}/logs?previous=true&sinceSeconds=${sinceSeconds}${qs}`;
    try {
      const [curRes, prevRes] = await Promise.all([
        fetch(base,     { credentials: 'same-origin' }).catch(() => null),
        fetch(prevBase, { credentials: 'same-origin' }).catch(() => null),
      ]);
      const parseLines = (json, isPrev) => {
        if (!json) return [];

        if (typeof json.logs === 'string') {
          return json.logs.split('\n').filter(l => l.trim()).map(l => ({
            timestamp: l.match(/^\d{4}-\d{2}-\d{2}T[\d:.]+Z/)?.[0] || null,
            pod: json.pod, namespace: json.namespace, container: json.container,
            containerId: isPrev ? 'previous' : 'current',
            log: l.replace(/\x1b\[[0-9;]*m/g, '').trim(),
          }));
        }

        if (Array.isArray(json.lines)) {
          return json.lines
            .filter(x => x && typeof x.log === 'string' && x.log.trim())
            .map(x => ({
              timestamp: x.timestamp || null,
              pod: json.pod, namespace: json.namespace, container: json.container,
              containerId: isPrev ? 'previous' : 'current',
              log: String(x.log).replace(/\x1b\[[0-9;]*m/g, '').trim(),
            }));
        }

        return [];
      };
      const curJson  = curRes?.ok  ? await curRes.json().catch(() => null)  : null;
      const prevJson = prevRes?.ok ? await prevRes.json().catch(() => null) : null;
      if (!curJson && !prevJson) { setLogsError('Sensor недоступен или под не найден'); return; }
      const lines = [...(prevJson ? parseLines(prevJson, true) : []), ...(curJson ? parseLines(curJson, false) : [])];
      const blob  = new Blob([JSON.stringify(lines, null, 2)], { type: 'application/json' });
      const url   = URL.createObjectURL(blob);
      const a     = document.createElement('a');
      a.href = url; a.download = `logs-${pName}-${activeContainer || 'all'}-${hours}h.json`;
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
    } catch(err) { setLogsError(`Ошибка загрузки: ${err.message}`); }
    finally { setLogsLoading(false); }
  };

  return (
    <div className="fns-detail">
      {}
      <div className="fns-pod-hdr">
        <div className="fns-pod-hdr-left">
          <div className="fns-pod-ns">{pNS} /</div>
          <div className="fns-pod-name-row">
            <span className="fns-pod-name">{pName}</span>
            <span className="fns-pod-badge">RUNNING</span>
            {!watching
              ? <button className="fns-watch-btn" onClick={doWatch}>Watch</button>
              : <button className="fns-watch-btn fns-watch-btn--active" onClick={doUnwatch}>
                  ⚠ Anomaly Watch <span className="fns-watch-x">✕</span>
                </button>
            }
          </div>
          {containers.length > 1 && (
            <div className="fns-cs">
              <span className="fns-cs-label">Container:</span>
              <div className="fns-cs-pills">
                {containers.map(c => (
                  <div key={c}
                    className={`fns-cs-pill ${containerHasAlert(c) ? 'fns-cs-pill--alert' : ''} ${c === activeContainer ? 'fns-cs-pill--active' : ''}`}
                    onClick={() => setActiveContainer(c)}>
                    {containerHasAlert(c) && <span className="fns-cs-dot" />}
                    {c}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
        <div className="fns-pod-hdr-right">
          <div className="fns-snap-wrap" ref={logsWrapRef}>
            <button className="fns-btn" disabled={logsLoading}
              onClick={() => { setLogsOpen(o => !o); setLogsError(null); }}>
              {logsLoading ? '⏳ Загрузка…' : `⬇ Logs · ${logsHours}h`}
              {!logsLoading && <span className="fns-arrow">▾</span>}
            </button>
            {logsError && <div className="fns-snap-error">{logsError}</div>}
            {logsOpen && (
              <div className="fns-snap-menu">
                <div className="fns-snap-pod">logs · {pName.slice(0, 28)}</div>
                {[1, 3, 6, 12, 24].map(h => (
                  <div key={h} className={`fns-snap-opt ${h === logsHours ? 'fns-snap-opt--active' : ''}`}
                    onClick={() => { setLogsHours(h); doLogs(h); }}>Last {h} hour{h > 1 ? 's' : ''}</div>
                ))}
              </div>
            )}
          </div>
          <button className="fns-btn fns-btn--upper" disabled={upperLoading} onClick={doUpperDir}>
            {upperLoading ? '⏳…' : '↓ Upper Dir'}
          </button>
        </div>
      </div>

      {}
      <div className="fns-content">
        {}
        <div className="fns-content-tabs">
          <button className={`fns-ctab${contentTab==='syscalls'?' active':''}`}
            onClick={() => setContentTab('syscalls')}>Binary Calls</button>
          <button className={`fns-ctab${contentTab==='fsdiff'?' active':''}`}
            onClick={() => { setContentTab('fsdiff'); if (watching) fetchDiff(); }}>
            FS Diff {watching && <span className="fns-ctab-dot"/>}
            {diff.length > 0 && <span className="fns-ctab-cnt">{diff.length}</span>}
          </button>
          <button className={`fns-ctab${contentTab==='watch-syscall'?' active':''}`}
            onClick={() => setContentTab('watch-syscall')}>
            Syscall Watch
          </button>
          <button className={`fns-ctab${contentTab==='watch-lsm'?' active':''}`}
            onClick={() => setContentTab('watch-lsm')}>
            LSM Watch
          </button>
          <button className={`fns-ctab${contentTab==='watch-tracepoint'?' active':''}`}
            onClick={() => setContentTab('watch-tracepoint')}>
            Tracepoint Watch
          </button>
        </div>

        {contentTab === 'fsdiff' && (
          <div className="fns-fsdiff">
            {!watching && diff.length === 0 && (
              <div className="fns-empty">Нажми Watch чтобы начать отслеживать изменения файловой системы</div>
            )}
            {watching && diff.length === 0 && (
              <div className="fns-empty">
                {diffLoading ? '⏳ Загрузка…' : 'Изменений пока нет — проверяется каждые 2 мин'}
              </div>
            )}
            {diff.length > 0 && (
              <>
                <div className="fns-fsdiff-hdr">
                  <span>{diff.length} изменений</span>
                  <button className="fns-btn" onClick={fetchDiff} disabled={diffLoading}>
                    {diffLoading ? '⏳' : '↻ Обновить'}
                  </button>
                </div>
                <div className="fns-fsdiff-list">
                  <div className="fns-fsdiff-row fns-fsdiff-row--hdr">
                    <span>Op</span><span>Path</span><span>Size</span><span>Modified</span>
                  </div>
                  {diff.map((e, i) => (
                    <div key={i} className={`fns-fsdiff-row fns-fsdiff-row--${e.op}`}>
                      <span className={`fns-fsdiff-op fns-fsdiff-op--${e.op}`}>{e.op}</span>
                      <span className="fns-fsdiff-path" title={e.path}>{e.path}</span>
                      <span className="fns-fsdiff-size">{e.size > 0 ? `${(e.size/1024).toFixed(1)}KB` : '—'}</span>
                      <span className="fns-fsdiff-time">{e.mtime ? new Date(e.mtime).toLocaleTimeString() : '—'}</span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        )}

        {contentTab === 'watch-syscall' && (
          <WatchPicker title="Syscall Watch" captureHint="Captured events appear in the Binary Calls tab"
            max={3} groups={SYSCALL_GROUPS} selected={watchedSyscalls.filter(n => SYSCALL_NAME_SET.has(n))}
            noStore={watchNoStore} onToggle={(n) => toggleWatch(n, SYSCALL_NAME_SET, 3)} />
        )}
        {contentTab === 'watch-lsm' && (
          <WatchPicker title="LSM Watch" captureHint="Captured events appear in the Binary Calls tab"
            max={5} groups={LSM_GROUPS_UI} selected={watchedSyscalls.filter(n => LSM_NAME_SET.has(n))}
            noStore={watchNoStore} onToggle={(n) => toggleWatch(n, LSM_NAME_SET, 5)} />
        )}
        {contentTab === 'watch-tracepoint' && (
          <WatchPicker title="Tracepoint Watch" captureHint="Captured events appear in the Binary Calls tab"
            max={5} groups={TP_GROUPS_UI} selected={watchedSyscalls.filter(n => TP_NAME_SET.has(n))}
            noStore={watchNoStore} onToggle={(n) => toggleWatch(n, TP_NAME_SET, 5)} />
        )}

        {contentTab === 'syscalls' && <>
        <div className="fns-toolbar">
          <span className="fns-toolbar-label">Window:</span>
          <div className="fns-pills">
            {[1, 6, 12, 24].map(h => (
              <div key={h} className={`fns-pill ${windowH === h ? 'fns-pill--active' : ''}`}
                onClick={() => setWindowH(h)}>{h}h</div>
            ))}
          </div>
        </div>

        <div className="fns-stats">
          <div className="fns-stat fns-stat--red"><div className="fns-stat-lbl">Critical</div><div className="fns-stat-val">{critical}</div><div className="fns-stat-sub">events</div></div>
          <div className="fns-stat fns-stat--orange"><div className="fns-stat-lbl">High</div><div className="fns-stat-val">{high}</div><div className="fns-stat-sub">events</div></div>
          <div className="fns-stat fns-stat--yellow"><div className="fns-stat-lbl">Medium</div><div className="fns-stat-val">{medium}</div><div className="fns-stat-sub">events</div></div>
          <div className="fns-stat fns-stat--blue"><div className="fns-stat-lbl">Total</div><div className="fns-stat-val">{visibleEvents.length}</div><div className="fns-stat-sub">last {windowH}h</div></div>
          <div className="fns-stat fns-stat--green"><div className="fns-stat-lbl">Processes</div><div className="fns-stat-val">{procs}</div><div className="fns-stat-sub">unique</div></div>
        </div>

        <div className="fns-timeline">
          <div className="fns-section-hdr">
            <span className="fns-section-title">Activity timeline</span>
            <span className="fns-section-count">{windowH}h window · 5min buckets{activeContainer ? ` · ${activeContainer}` : ''}</span>
          </div>
          <TimelineBars events={visibleEvents} windowH={windowH} />
          <div className="fns-bar-labels">
            <span>{windowH}h ago</span><span>{Math.round(windowH/2)}h ago</span><span>now</span>
          </div>
        </div>

        <div className="fns-filter-row">
          <span className="fns-toolbar-label">Filter:</span>
          <BinaryFilter
            filterSev={filterSev} onSevChange={setFilterSev}
            filterBins={filterBins} onBinsChange={setFilterBins}
          />
        </div>

        <div>
          <div className="fns-section-hdr">
            <span className="fns-section-title">Binary calls</span>
            <span className="fns-section-count">{visibleEvents.length} events{activeContainer ? ` · ${activeContainer}` : ''}</span>
          </div>
          <div className="fns-etable">
            <div className="fns-etable-hdr">
              {FNS_COLUMNS.map(c => (
                <div key={c.key} className="fns-col-head" style={{ cursor: 'pointer', userSelect: 'none' }}
                  onClick={() => toggleSort(c.key)}>
                  {c.label}{sortCol === c.key ? (sortDir === 'asc' ? ' ↑' : ' ↓') : ''}
                </div>
              ))}
            </div>
            {visibleEvents.length === 0
              ? <div className="fns-empty">No events for this window</div>
              : pagedEvents.map(ev => <EventRow key={ev.id} ev={ev} getSev={getSev} />)
            }
          </div>
          <Pager
            total={visibleEvents.length}
            page={page}
            setPage={setPage}
            pageSize={pageSize}
            setPageSize={setPageSize}
          />
        </div>
        </>
        }
      </div>
    </div>
  );
}
