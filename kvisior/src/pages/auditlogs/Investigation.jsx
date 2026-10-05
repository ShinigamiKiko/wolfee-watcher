import { useCallback, useEffect, useRef, useState } from 'react';
import { fetchEvents, fetchGroups, fetchSummary } from './api';
import { EventDetail, EventTable, Empty, KINDS, fmtDate, normalizeEvent, num } from './shared';

const PAGE = 50;
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

export function Investigation({ ruleNames, apiLogConnected, canEdit, retentionHours, preset, onCreateRule }) {
  const [filters, setFilters] = useState({ ...BLANK, ...(preset || {}) });
  const [applied, setApplied] = useState({ ...BLANK, ...(preset || {}) });
  const [view, setView] = useState('events');
  const [events, setEvents] = useState([]);
  const [groups, setGroups] = useState([]);
  const [summary, setSummary] = useState({ buckets: [], total: 0 });
  const [cursors, setCursors] = useState([null]);
  const [next, setNext] = useState(null);
  const [selected, setSelected] = useState(null);
  const [state, setState] = useState({ loading: true, error: '' });

  useEffect(() => {
    if (!preset) return;
    const merged = { ...BLANK, ...preset };
    setFilters(merged); setApplied(merged); setView('events'); setCursors([null]);
  }, [preset]);

  const params = useCallback(f => ({
    hours: f.hours, user: f.user.trim(), ns: f.ns.trim(), kind: f.kind,
    resource: f.resource.trim(), ip: f.ip.trim(), result: f.result, danger: f.danger,
    objResource: f.obj?.resource, objNs: f.obj?.ns, objName: f.obj?.name,
  }), []);

  useEffect(() => {
    let alive = true;
    fetchSummary({ ...params(applied), buckets: applied.hours <= 6 ? 12 : 24 })
      .then(d => alive && setSummary({ buckets: d.buckets || [], total: d.total || 0 }))
      .catch(() => alive && setSummary({ buckets: [], total: 0 }));
    return () => { alive = false; };
  }, [applied, params]);

  const cursor = cursors[cursors.length - 1];
  useEffect(() => {
    let alive = true;
    setState({ loading: true, error: '' });
    const done = () => alive && setState({ loading: false, error: '' });
    const fail = e => alive && setState({ loading: false, error: e.message });
    if (view === 'events') {
      fetchEvents({ ...params(applied), limit: PAGE, ...(cursor || {}) })
        .then(d => {
          if (!alive) return;
          setEvents((d.events || []).map(r => normalizeEvent(r.data, r)));
          setNext(d.next || null);
        }).then(done).catch(fail);
    } else {
      fetchGroups({ ...params(applied), by: view === 'users' ? 'user' : 'object', limit: 200 })
        .then(d => alive && setGroups(d.groups || [])).then(done).catch(fail);
    }
    return () => { alive = false; };
  }, [applied, view, cursor, params]);

  const apply = f => { setApplied(f); setCursors([null]); setSelected(null); };
  const submit = e => { e.preventDefault(); apply(filters); };
  const set = (key, value) => setFilters(prev => ({ ...prev, [key]: value }));
  const clear = () => { setFilters(BLANK); apply(BLANK); };
  const switchView = v => { setView(v); setCursors([null]); setSelected(null); };
  const drill = g => {
    const f = view === 'users' ? { ...applied, user: g.key }
      : g.object ? { ...applied, obj: g.object }
      : { ...applied, resource: g.key.split('/')[0] };
    setFilters(f); apply(f); setView('events');
  };
  const clearObject = () => { const f = { ...applied, obj: null }; setFilters(f); apply(f); };
  const copy = () => navigator.clipboard?.writeText(JSON.stringify(events.map(e => e.raw), null, 2)).catch(() => {});

  const ranges = [[1, 'Last hour'], [6, 'Last 6 hours'], [24, 'Last 24 hours'], [72, 'Last 3 days'], [168, 'Last 7 days'], [336, 'Last 14 days']]
    .filter(([h]) => h <= Math.max(24, retentionHours || 24));
  const page = cursors.length;
  const emptyText = state.loading ? 'Searching…'
    : state.error ? `The search failed: ${state.error}. Try a shorter time range.`
    : 'No events match. Widen the time range or clear a filter.';

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
          onChange={e => { const f = { ...filters, danger: e.target.checked }; setFilters(f); apply(f); }} />Dangerous only</label>
        <div className="al-seg" role="group" aria-label="Group results">
          {[['events', 'Events'], ['users', 'By user'], ['objects', 'By object']].map(([id, label]) => (
            <button key={id} aria-pressed={view === id} onClick={() => switchView(id)}>{label}</button>
          ))}
        </div>
        {applied.obj && (
          <button className="al-link al-mono" type="button" onClick={clearObject} title="Remove the object filter">
            Object: {objLabel(applied.obj)} ✕
          </button>
        )}
        {view === 'events' && <button className="btn btn-outline al-btn" type="button" onClick={copy}>Copy page as JSON</button>}
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
            <div className="al-scrollx">
              <EventTable events={events} selectedKey={selected?.key} onSelect={setSelected} withDate
                          ruleNames={ruleNames} emptyText={emptyText} />
            </div>
            <div className="al-pager">
              <span>Page {page}{events.length ? `, ${num(events.length)} events shown` : ''}</span>
              <div>
                <button className="btn btn-outline al-btn-sm" disabled={page === 1} onClick={() => setCursors(c => c.slice(0, -1))}>Previous</button>
                <button className="btn btn-outline al-btn-sm" disabled={!next} onClick={() => setCursors(c => [...c, next])}>Next</button>
              </div>
            </div>
          </div>
          <EventDetail ev={selected} ruleNames={ruleNames} apiLogConnected={apiLogConnected} canEdit={canEdit}
                       onInvestigate={ev => drillUser(ev.user, setFilters, apply, filters)} onCreateRule={onCreateRule} />
        </div>
      ) : (
        <div className="al-scrollx">
          <table className="data-table">
            <thead>
              <tr>
                <th>{view === 'users' ? 'User' : 'Object'}</th><th>Events</th><th>Dangerous</th><th>Denied</th>
                <th>{view === 'users' ? 'Source IPs' : 'Users'}</th><th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {groups.length === 0 && <tr className="al-norow"><td colSpan={6}><div className="al-blank">{emptyText}</div></td></tr>}
              {groups.map(g => (
                <tr key={g.key} tabIndex={0} onClick={() => drill(g)} onKeyDown={e => { if (e.key === 'Enter') drill(g); }}>
                  <td className={view === 'users' ? '' : 'al-mono'}>{g.key || <Empty>unknown</Empty>}</td>
                  <td className="al-mono">{num(g.events)}</td>
                  <td className="al-mono">{g.dangerous ? <span className="al-tag al-tag-high">{num(g.dangerous)}</span> : '0'}</td>
                  <td className="al-mono">{num(g.denied)}</td>
                  <td className="al-mono">{g.others?.length ? g.others.slice(0, 3).join(', ') + (g.others.length > 3 ? ` +${g.others.length - 3}` : '') : <Empty />}</td>
                  <td className="al-mono">{fmtDate(g.lastSeen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function drillUser(user, setFilters, apply, filters) {
  const f = { ...filters, user };
  setFilters(f);
  apply(f);
}
