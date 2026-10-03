import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { sseUrl } from '../../data/cluster';
import { fetchEvents, fetchSummary } from './api';
import { EventDetail, EventTable, isDanger, normalizeEvent, num, objText } from './shared';

const WINDOW_SIZES = [100, 200, 500];
const SCROLL_HOLD = 60;

export function Monitoring({ ruleNames, apiLogConnected, canEdit, onInvestigate, onCreateRule, onOlder, onDangerCount }) {
  const [events, setEvents] = useState([]);
  const [pending, setPending] = useState(0);
  const [windowSize, setWindowSize] = useState(200);
  const [paused, setPaused] = useState(false);
  const [dangerOnly, setDangerOnly] = useState(false);
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState(null);
  const [lastHour, setLastHour] = useState(null);
  const [error, setError] = useState('');
  const [loaded, setLoaded] = useState(false);
  const [fresh, setFresh] = useState(() => new Set());

  const boxRef = useRef(null);
  const bufferRef = useRef([]);
  const pausedRef = useRef(false);
  const sizeRef = useRef(windowSize);
  pausedRef.current = paused;
  sizeRef.current = windowSize;

  const flush = useCallback(() => {
    const incoming = bufferRef.current;
    if (!incoming.length) return;
    bufferRef.current = [];
    setPending(0);
    setFresh(new Set(incoming.map(e => e.key)));
    setEvents(prev => {
      const seen = new Set(incoming.map(e => e.uid).filter(Boolean));
      const rest = prev.filter(e => !e.uid || !seen.has(e.uid));
      return [...incoming.slice().reverse(), ...rest].slice(0, sizeRef.current);
    });
  }, []);

  useEffect(() => {
    let alive = true;
    setLoaded(false);
    fetchEvents({ hours: 24, limit: windowSize })
      .then(data => {
        if (!alive) return;
        const rows = (data.events || []).map(r => normalizeEvent(r.data, r));
        setEvents(rows);
        setSelected(prev => prev || rows.find(isDanger) || rows[0] || null);
        setError('');
      })
      .catch(e => alive && setError(e.message))
      .finally(() => alive && setLoaded(true));
    return () => { alive = false; };
  }, [windowSize]);

  useEffect(() => {
    let alive = true;
    const load = () => fetchSummary({ hours: 1, buckets: 1 })
      .then(d => alive && setLastHour(d.total))
      .catch(() => {});
    load();
    const t = setInterval(load, 30000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  useEffect(() => {
    const es = new EventSource(sseUrl('/v1/stream'));
    es.onmessage = msg => {
      let parsed;
      try { parsed = JSON.parse(msg.data); } catch { return; }
      const { type, data } = parsed;
      if (!data) return;
      if (type === 'audit_event') {
        if (pausedRef.current) return;
        bufferRef.current.push(normalizeEvent(data));
        if (bufferRef.current.length > sizeRef.current) bufferRef.current.shift();
        if (boxRef.current && boxRef.current.scrollTop > SCROLL_HOLD) {
          setPending(bufferRef.current.length);
          return;
        }
        flush();
      } else if (type === 'audit_event_update') {
        const patch = ev => {
          if (ev.uid !== data.id) return ev;
          return normalizeEvent({ ...ev.raw, ...data, id: ev.uid }, { id: undefined, ts: ev.ts, origin: 'both', ruleId: data.ruleId || ev.ruleId, sev: data.sev || ev.sev });
        };
        bufferRef.current = bufferRef.current.map(patch);
        setEvents(prev => prev.map(ev => {
          const next = patch(ev);
          return next === ev ? ev : { ...next, key: ev.key };
        }));
        setSelected(prev => (prev && prev.uid === data.id ? { ...patch(prev), key: prev.key } : prev));
      }
    };
    return () => es.close();
  }, [flush]);

  const rows = useMemo(() => {
    const q = search.trim().toLowerCase();
    return events.filter(ev => {
      if (dangerOnly && !isDanger(ev)) return false;
      if (!q) return true;
      const rule = (ev.ruleName || ruleNames[ev.ruleId] || '').toLowerCase();
      return `${ev.kind} ${objText(ev)} ${ev.user} ${ev.ip} ${ev.agent}`.toLowerCase().includes(q) || rule.includes(q);
    });
  }, [events, search, dangerOnly, ruleNames]);

  const danger = useMemo(() => events.filter(isDanger).length, [events]);
  const denied = useMemo(() => events.filter(e => !e.allowed).length, [events]);
  const matched = useMemo(() => {
    const changes = events.filter(e => e.origin !== 'apilog');
    return changes.length ? Math.round(changes.filter(e => e.origin === 'both').length / changes.length * 100) : 0;
  }, [events]);

  useEffect(() => { onDangerCount(danger); }, [danger, onDangerCount]);

  const onScroll = () => {
    if (boxRef.current && boxRef.current.scrollTop <= SCROLL_HOLD) flush();
  };
  const jumpToNew = () => {
    if (boxRef.current) boxRef.current.scrollTop = 0;
    flush();
  };
  const togglePause = () => {
    setPaused(p => {
      if (p) { bufferRef.current = []; setPending(0); }
      return !p;
    });
  };

  const emptyText = !loaded ? 'Loading the latest events…'
    : error ? `Could not load events: ${error}. Check that kvisior can reach the database.`
    : search || dangerOnly ? 'Nothing in the window matches. Clear the search or switch to All events; older events are in Investigation.'
    : 'No audit events yet. They appear here as soon as something changes in the cluster.';

  return (
    <div>
      <div className="al-toolbar">
        <input className="al-input al-search" type="search" placeholder="Search user, object, IP, rule"
               aria-label="Search events in the window" value={search} onChange={e => setSearch(e.target.value)} />
        <div className="al-seg" role="group" aria-label="Show">
          <button aria-pressed={!dangerOnly} onClick={() => setDangerOnly(false)}>All events</button>
          <button aria-pressed={dangerOnly} onClick={() => setDangerOnly(true)}>Dangerous only</button>
        </div>
        <select className="al-input" aria-label="Window size" value={windowSize} onChange={e => setWindowSize(+e.target.value)}>
          {WINDOW_SIZES.map(n => <option key={n} value={n}>Window: {n} events</option>)}
        </select>
        <button className="btn btn-outline al-btn" onClick={togglePause}>{paused ? 'Resume' : 'Pause'}</button>
        <span className={`al-live${paused ? ' paused' : ''}`}><span className="al-pulse" />{paused ? 'Paused, new events are not shown' : 'Live'}</span>
      </div>
      <div className="al-stats">
        <span><b>{lastHour == null ? '—' : num(lastHour)}</b> events in the last hour</span>
        <span><b className={danger ? 'hot' : ''}>{danger}</b> dangerous in window</span>
        <span><b>{denied}</b> denied</span>
        <span>{apiLogConnected ? <><b>{matched}%</b> of changes matched to an API log record</> : 'API log not connected'}</span>
      </div>
      <div className="al-mon">
        <div className="al-winwrap">
          {pending > 0 && (
            <button className="btn btn-primary al-newpill" onClick={jumpToNew}>{pending} new event{pending === 1 ? '' : 's'}</button>
          )}
          <div className="al-win" ref={boxRef} onScroll={onScroll} tabIndex={0} aria-label="Recent audit events">
            <EventTable events={rows} selectedKey={selected?.key} onSelect={setSelected}
                        ruleNames={ruleNames} freshKeys={fresh} emptyText={emptyText} />
          </div>
          <div className="al-winfoot">
            <span>{rows.length === events.length
              ? `Newest ${num(events.length)} events. Older ones leave the window as new ones arrive.`
              : `${num(rows.length)} of ${num(events.length)} events in the window match.`}</span>
            <button className="al-link" onClick={onOlder}>Search older events in Investigation</button>
          </div>
        </div>
        <EventDetail ev={selected} ruleNames={ruleNames} apiLogConnected={apiLogConnected} canEdit={canEdit}
                     onInvestigate={onInvestigate} onCreateRule={onCreateRule} />
      </div>
    </div>
  );
}
