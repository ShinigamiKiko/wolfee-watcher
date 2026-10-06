import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { getCluster } from '../../data/cluster';
import { fetchEvents, fetchGroups, fetchSummary } from './api';
import { PAGE_SIZES, clearResults, loadPageSize, loadResults, savePageSize, saveResults } from './resultStore';
import { useFitToPage } from './useFitToPage';
import { EventDetail, EventTable, Empty, KINDS, fmtDate, normalizeEvent, num } from './shared';

const BLANK = { hours: 24, user: '', ns: '', kind: '', resource: '', ip: '', result: '', danger: false, obj: null };

const objLabel = o => [o.resource, o.ns, o.name || '*'].filter(Boolean).join('/');

function niceMax(v) {
  if (v <= 5) return 5;
  const p = 10 ** Math.floor(Math.log10(v));
  const m = v / p;
  return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * p;
}

function Histogram({ buckets, hours }) {
  const boxRef = useRef(null);
  const [width, setWidth] = useState(640);
  useEffect(() => {
    const measure = () => { if (boxRef.current) setWidth(Math.max(320, boxRef.current.clientWidth)); };
    measure();
    window.addEventListener('resize', measure);
    return () => window.removeEventListener('resize', measure);
  }, []);

  const H = 132, L = 44, B = 20, T = 10;
  const n = buckets.length || 1;
  const plotW = width - L - 6, plotH = H - B - T, bw = plotW / n;
  const max = niceMax(Math.max(1, ...buckets.map(b => b.total)));
  const y = v => T + plotH - (v / max) * plotH;
  const pad = v => String(v).padStart(2, '0');
  const label = i => {
    const d = new Date(buckets[i].start);
    return hours > 48 ? `${pad(d.getMonth() + 1)}-${pad(d.getDate())}` : `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  };
  const ticks = buckets.length ? [...new Set([0, Math.floor(n / 2), n - 1])] : [];

  return (
    <div ref={boxRef}>
      <svg viewBox={`0 0 ${width} ${H}`} width={width} height={H} role="img" aria-label="Events over time">
        <line x1={L} y1={y(0)} x2={width - 6} y2={y(0)} className="al-axis" />
        <line x1={L} y1={y(max)} x2={width - 6} y2={y(max)} className="al-gridline" />
        <text x={L - 6} y={y(max) + 3} textAnchor="end">{num(max)}</text>
        <text x={L - 6} y={y(0) + 3} textAnchor="end">0</text>
        {buckets.map((b, i) => {
          const routine = b.total - b.dangerous;
          const x = L + i * bw + 2, w = Math.max(2, bw - 4);
          return (
            <g key={i}>
              {routine > 0 && <rect x={x} y={y(routine)} width={w} height={y(0) - y(routine)} rx="1.5" className="al-bar"><title>{label(i)}: {routine} routine</title></rect>}
              {b.dangerous > 0 && <rect x={x} y={y(b.total)} width={w} height={y(routine) - y(b.total)} rx="1.5" className="al-bar-danger"><title>{label(i)}: {b.dangerous} dangerous</title></rect>}
            </g>
          );
        })}
        {ticks.map(i => <text key={i} x={L + i * bw + bw / 2} y={H - 5} textAnchor="middle">{label(i)}</text>)}
      </svg>
    </div>
  );
}


const BLOCK = 1000;
const SERVER_PAGE = 500;
const VIEWS = [['events', 'Events'], ['users', 'By user'], ['objects', 'By object']];

const queryParams = f => ({
  hours: f.hours, user: f.user.trim(), ns: f.ns.trim(), kind: f.kind,
  resource: f.resource.trim(), ip: f.ip.trim(), result: f.result, danger: f.danger,
  objResource: f.obj?.resource, objNs: f.obj?.ns, objName: f.obj?.name,
});

async function fetchBlock(view, applied, start) {
  const params = queryParams(applied);
  if (view === 'events') {
    const rows = [];
    let cursor = start;
    do {
      const d = await fetchEvents({ ...params, limit: SERVER_PAGE, ...(cursor || {}) });
      rows.push(...(d.events || []));
      cursor = d.next || null;
    } while (cursor && rows.length < BLOCK);
    return { rows, hasMore: !!cursor, nextStart: cursor };
  }
  const offset = start || 0;
  const d = await fetchGroups({ ...params, by: view === 'users' ? 'user' : 'object', limit: BLOCK, offset });
  const rows = d.groups || [];
  return { rows, hasMore: rows.length === BLOCK, nextStart: offset + BLOCK };
}

export function Investigation({ ruleNames, apiLogConnected, canEdit, retentionHours, preset, onCreateRule, onSilence }) {
  const cluster = getCluster();
  const restored = useRef(preset ? null : loadResults(cluster));
  const initial = restored.current?.applied || { ...BLANK, ...(preset || {}) };
  const [filters, setFilters] = useState(initial);
  const [run, setRun] = useState(() => ({ applied: initial, view: restored.current?.view || 'events', id: restored.current?.id || Date.now() }));
  const [summary, setSummary] = useState({ buckets: [], total: 0 });
  const [block, setBlock] = useState(() => restored.current?.block || null);
  const [starts, setStarts] = useState(() => restored.current?.starts || [null]);
  const [page, setPage] = useState(() => restored.current?.page || 0);
  const [pageSize, setPageSize] = useState(loadPageSize);
  const [selected, setSelected] = useState(null);
  const [state, setState] = useState({ loading: !restored.current, error: '' });
  const loadSeq = useRef(0);
  const winRef = useRef(null);
  const pagerRef = useRef(null);
  const { applied, view } = run;

  const loadBlock = useCallback(async (index, startList, landOnLast) => {
    const seq = ++loadSeq.current;
    setState({ loading: true, error: '' });
    try {
      const got = await fetchBlock(view, applied, startList[index] ?? null);
      if (seq !== loadSeq.current) return;
      const nextStarts = startList.slice(0, index + 1);
      if (got.hasMore) nextStarts[index + 1] = got.nextStart;
      const pages = Math.max(1, Math.ceil(got.rows.length / pageSize));
      setBlock({ index, rows: got.rows, hasMore: got.hasMore });
      setStarts(nextStarts);
      setPage(landOnLast ? pages - 1 : 0);
      setState({ loading: false, error: '' });
    } catch (e) {
      if (seq === loadSeq.current) setState({ loading: false, error: e.message });
    }
  }, [view, applied, pageSize]);

  useEffect(() => {
    if (!preset) return;
    const merged = { ...BLANK, ...preset };
    setFilters(merged);
    setRun({ applied: merged, view: 'events', id: Date.now() });
  }, [preset]);

  useEffect(() => {
    let alive = true;
    fetchSummary({ ...queryParams(applied), buckets: applied.hours <= 6 ? 12 : 24 })
      .then(d => alive && setSummary({ buckets: d.buckets || [], total: d.total || 0 }))
      .catch(() => alive && setSummary({ buckets: [], total: 0 }));
    return () => { alive = false; };
  }, [applied]);

  useEffect(() => {
    if (restored.current && restored.current.id === run.id) {
      restored.current = null;
      return;
    }
    restored.current = null;
    clearResults();
    setBlock(null);
    setSelected(null);
    loadBlock(0, [null], false);
  }, [run]);

  useEffect(() => {
    if (block) saveResults(cluster, { applied, view, id: run.id, block, starts, page });
  }, [cluster, applied, view, run.id, block, starts, page]);

  const rows = block?.rows || [];
  const pages = Math.max(1, Math.ceil(rows.length / pageSize));
  const visibleRaw = useMemo(() => rows.slice(page * pageSize, (page + 1) * pageSize), [rows, page, pageSize]);
  const events = useMemo(() => (view === 'events' ? visibleRaw.map(r => normalizeEvent(r.data, r)) : []), [view, visibleRaw]);
  const offset = (block?.index || 0) * BLOCK + page * pageSize;
  const totalKnown = view === 'events' ? summary.total : (block && !block.hasMore ? block.index * BLOCK + rows.length : null);
  const canPrev = page > 0 || (block?.index || 0) > 0;
  const canNext = page < pages - 1 || !!block?.hasMore;

  const goNext = () => {
    if (page < pages - 1) setPage(page + 1);
    else if (block?.hasMore) loadBlock(block.index + 1, starts, false);
  };
  const goPrev = () => {
    if (page > 0) setPage(page - 1);
    else if (block?.index > 0) loadBlock(block.index - 1, starts, true);
  };
  const changeSize = size => {
    const first = page * pageSize;
    setPageSize(size);
    savePageSize(size);
    setPage(Math.floor(first / size));
  };

  const search = f => setRun(r => ({ applied: f, view: r.view, id: Date.now() }));
  const submit = e => { e.preventDefault(); search(filters); };
  const set = (key, value) => setFilters(prev => ({ ...prev, [key]: value }));
  const clear = () => { setFilters(BLANK); search(BLANK); };
  const switchView = v => { if (v !== view) setRun(r => ({ ...r, view: v, id: Date.now() })); };
  const drill = g => {
    const f = view === 'users' ? { ...applied, user: g.key }
      : g.object ? { ...applied, obj: g.object }
      : { ...applied, resource: g.key.split('/')[0] };
    setFilters(f);
    setRun({ applied: f, view: 'events', id: Date.now() });
  };
  const clearObject = () => { const f = { ...applied, obj: null }; setFilters(f); search(f); };
  const drillUser = user => { const f = { ...filters, user }; setFilters(f); search(f); };
  const copy = () => navigator.clipboard?.writeText(JSON.stringify(events.map(e => e.raw), null, 2)).catch(() => {});

  const ranges = [[1, 'Last hour'], [6, 'Last 6 hours'], [24, 'Last 24 hours'], [72, 'Last 3 days'], [168, 'Last 7 days'], [336, 'Last 14 days']]
    .filter(([h]) => h <= Math.max(24, retentionHours || 24));
  const emptyText = state.loading ? 'Searching…'
    : state.error ? `The search failed: ${state.error}. Try a shorter time range.`
    : 'No events match. Widen the time range or clear a filter.';
  const noun = view === 'events' ? 'events' : view === 'users' ? 'users' : 'objects';
  const range = rows.length
    ? `${num(offset + 1)}–${num(offset + visibleRaw.length)} of ${totalKnown != null ? num(totalKnown) : `${num((block?.index || 0) * BLOCK + rows.length)}+`} ${noun}`
    : `0 ${noun}`;

  const fitStyle = useFitToPage(winRef, pagerRef, [view, !!applied.obj]);

  const pager = (
    <div className="al-pager" ref={pagerRef}>
      <span>{range}{state.loading && rows.length ? ' · loading…' : ''}</span>
      <div>
        <div className="al-seg" role="group" aria-label="Rows per page">
          {PAGE_SIZES.map(n => <button key={n} type="button" aria-pressed={pageSize === n} onClick={() => changeSize(n)}>{n} rows</button>)}
        </div>
        <button className="btn btn-outline al-btn-sm" disabled={!canPrev || state.loading} onClick={goPrev}>Previous</button>
        <button className="btn btn-outline al-btn-sm" disabled={!canNext || state.loading} onClick={goNext}>Next</button>
      </div>
    </div>
  );

  return (
    <div>
      <form className="al-qgrid" onSubmit={submit} id="al-query">
        <label>Time range
          <select className="al-input" value={filters.hours} onChange={e => set('hours', +e.target.value)}>
            {ranges.map(([h, label]) => <option key={h} value={h}>{label}</option>)}
          </select>
        </label>
        <label>User<input className="al-input" value={filters.user} onChange={e => set('user', e.target.value)} placeholder="name or part of it" /></label>
        <label>Namespace<input className="al-input al-mono" value={filters.ns} onChange={e => set('ns', e.target.value)} placeholder="exact name" /></label>
        <label>Action
          <select className="al-input" value={filters.kind} onChange={e => set('kind', e.target.value)}>
            <option value="">Any</option>
            {KINDS.map(k => <option key={k} value={k}>{k}</option>)}
          </select>
        </label>
        <label>Resource<input className="al-input al-mono" value={filters.resource} onChange={e => set('resource', e.target.value)} placeholder="secrets" /></label>
        <label>Source IP<input className="al-input al-mono" value={filters.ip} onChange={e => set('ip', e.target.value)} placeholder="10.20." /></label>
        <label>Result
          <select className="al-input" value={filters.result} onChange={e => set('result', e.target.value)}>
            <option value="">Any</option><option value="allowed">Allowed</option><option value="denied">Denied</option>
          </select>
        </label>
      </form>
      <div className="al-toolbar">
        <button className="btn btn-primary al-btn" type="submit" form="al-query">Search</button>
        <button className="btn btn-outline al-btn" type="button" onClick={clear}>Clear</button>
        <label className="al-check"><input type="checkbox" checked={filters.danger}
          onChange={e => { const f = { ...filters, danger: e.target.checked }; setFilters(f); search(f); }} />Dangerous only</label>
        <div className="al-seg" role="group" aria-label="Group results">
          {VIEWS.map(([id, label]) => (
            <button key={id} aria-pressed={view === id} onClick={() => switchView(id)}>{label}</button>
          ))}
        </div>
        {applied.obj && (
          <button className="al-link al-mono" type="button" onClick={clearObject} title="Remove the object filter">
            Object: {objLabel(applied.obj)} ✕
          </button>
        )}
        {view === 'events' && <button className="btn btn-outline al-btn" type="button" onClick={copy} disabled={!events.length}>Copy page as JSON</button>}
      </div>

      <div className="al-chart">
        <Histogram buckets={summary.buckets} hours={applied.hours} />
        <div className="al-legend">
          <span><i className="al-swatch" />Routine</span>
          <span><i className="al-swatch danger" />Dangerous</span>
          <span>{num(summary.total)} events in the selected range</span>
        </div>
      </div>

      {view === 'events' ? (
        <div className="al-mon">
          <div className="al-winwrap">
            <div className="al-win al-results al-fit" ref={winRef} style={fitStyle} tabIndex={0} aria-label="Search results">
              <EventTable events={events} selectedKey={selected?.key} onSelect={setSelected} withDate
                          ruleNames={ruleNames} emptyText={emptyText} />
            </div>
            {pager}
          </div>
          <EventDetail ev={selected} ruleNames={ruleNames} apiLogConnected={apiLogConnected} canEdit={canEdit}
                       onInvestigate={ev => drillUser(ev.user)} onCreateRule={onCreateRule}
                       onSilence={onSilence} />
        </div>
      ) : (
        <>
          <div className="al-win al-results al-fit" ref={winRef} style={fitStyle} tabIndex={0} aria-label="Grouped results">
            <table className="data-table al-groups">
              <thead>
                <tr>
                  <th>{view === 'users' ? 'User' : 'Object'}</th><th>Events</th><th>Dangerous</th><th>Denied</th>
                  <th>{view === 'users' ? 'Source IPs' : 'Users'}</th><th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {visibleRaw.length === 0 && <tr className="al-norow"><td colSpan={6}><div className="al-blank">{emptyText}</div></td></tr>}
                {visibleRaw.map(g => {
                  const others = g.others?.length ? g.others.slice(0, 3).join(', ') + (g.others.length > 3 ? ` +${g.others.length - 3}` : '') : '';
                  return (
                    <tr key={g.key} tabIndex={0} onClick={() => drill(g)} onKeyDown={e => { if (e.key === 'Enter') drill(g); }}>
                      <td className={`al-clip al-groupkey${view === 'users' ? '' : ' al-mono'}`} title={g.key}>{g.key || <Empty>unknown</Empty>}</td>
                      <td className="al-mono">{num(g.events)}</td>
                      <td className="al-mono">{g.dangerous ? <span className="al-tag al-tag-high">{num(g.dangerous)}</span> : '0'}</td>
                      <td className="al-mono">{num(g.denied)}</td>
                      <td className="al-mono al-clip al-others" title={(g.others || []).join(', ')}>{others || <Empty />}</td>
                      <td className="al-mono">{fmtDate(g.lastSeen)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {pager}
        </>
      )}
    </div>
  );
}
