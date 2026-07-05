import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useScanner } from '../../context/ScannerContext';
import { useBridge }  from '../../context/BridgeContext';
import '../../styles/alerts.scss';
import { NETWORK_KINDS, EVIL_KINDS, HONEYPOT_KINDS, KIND_META } from './alertsConstants';

import { kindMeta, relTime, fmtPorts, evtPattern, evtSummary } from './alertsUtils';
import { apiGetSilents, apiPostSilent, apiDeleteSilent, apiSilenceAnomaly, apiUnsilenceAnomaly, apiGetSilentAnomalies, apiIngestAnomaly } from './alertsApi';
import { apiList as apiHoneypotList } from '../honeypot/honeypotApi';
import { RowActions, BucketsPanel, DetailRow, KindReference } from './AlertsUi';
import { AlertDetail } from './AlertDetail';
import { AlertsList } from './AlertsList';

function honeypotTs(ts) {
  if (!ts) return new Date().toISOString();
  return /([zZ]|[+-]\d{2}:?\d{2})$/.test(ts) ? ts : ts + 'Z';
}

export function Alerts() {
  const { results } = useScanner();
  const { honeypotEvents } = useBridge();
  const [events,      setEvents]      = useState([]);
  const [selected,    setSelected]    = useState(null);
  const [kindFilter,  setKindFilter]  = useState('all');
  const [groupFilter, setGroupFilter] = useState('all');
  const [status,      setStatus]      = useState('connecting');
  const [stats,       setStats]       = useState(null);
  const [buckets,     setBuckets]     = useState({ ack: {}, fp: {} });
  const [silentEvents, setSilentEvents] = useState([]);
  const [bucketsOpen, setBucketsOpen] = useState(false);
  const [bucketsTab,  setBucketsTab]  = useState('events');
  const [refOpen,     setRefOpen]     = useState(false);
  const [honeypotIPs, setHoneypotIPs] = useState({});

  const lastIDRef = useRef('0');
  const eventsRef = useRef([]);
  const statsReachableRef = useRef(false);
  const bucketsRef        = useRef(buckets);
  const ingestedRef       = useRef(new Set());

  bucketsRef.current = buckets;

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const items = await apiGetSilents();
        if (!alive) return;
        const ack = {}, fp = {};
        for (const it of items) {
          if (it.type === 'ack') ack[it.key] = { pattern: it.key, summary: it.summary, createdAt: it.created_at, count: 0, lastTs: null };
          if (it.type === 'fp')  fp[it.key]  = { id: it.key,      summary: it.summary, createdAt: it.created_at };
        }
        setBuckets({ ack, fp });
      } catch (e) {
        console.warn('Failed to load silents:', e);
      }
    })();
    return () => { alive = false; };
  }, []);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const data = await apiHoneypotList();
        if (!alive) return;
        const m = {};
        for (const hp of (data.honeypots || [])) {
          if (hp.clusterIP) m[`${hp.namespace}/${hp.name}`] = hp.clusterIP;
        }
        setHoneypotIPs(m);
      } catch (e) {
        console.warn('Failed to load honeypot list:', e);
      }
    };
    load();
    const t = setInterval(load, 30000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  const ackEvent = async (ev) => {
    if (!confirm('Точно ли хотите удалить такие события?\n\nВсе будущие события того же паттерна будут автоматически перемещаться в Silent.')) return;
    const pattern = evtPattern(ev);
    const summary = bucketsRef.current.ack[pattern]?.summary || evtSummary(ev);
    setBuckets(b => ({
      ...b,
      ack: {
        ...b.ack,
        [pattern]: {
          pattern,
          summary,
          createdAt: b.ack[pattern]?.createdAt || new Date().toISOString(),
          lastTs:    ev.ts || new Date().toISOString(),
          count:     (b.ack[pattern]?.count || 0) + 1,
        },
      },
    }));
    setSelected(s => s?.id === ev.id ? null : s);
    try { await apiPostSilent('ack', pattern, summary); }
    catch (e) { console.warn('ack persist failed:', e); }
  };

  const fpEvent = async (ev) => {
    const summary = evtSummary(ev);
    setBuckets(b => ({
      ...b,
      fp: { ...b.fp, [ev.id]: { id: ev.id, summary, createdAt: new Date().toISOString() } },
    }));
    setSelected(s => s?.id === ev.id ? null : s);
    try { await apiPostSilent('fp', String(ev.id), summary); }
    catch (e) { console.warn('fp persist failed:', e); }
  };

  const deleteEvent = async (ev) => {
    setEvents(prev => prev.filter(e => e.id !== ev.id));
    setSelected(s => s?.id === ev.id ? null : s);
    if (ev.id) {
      try { await apiSilenceAnomaly(ev.id); }
      catch (e) { console.warn('anomaly silence failed:', e); }
    }
  };

  const loadSilentEvents = useCallback(async () => {
    try { setSilentEvents(await apiGetSilentAnomalies()); }
    catch (e) { console.warn('load silent events failed:', e); }
  }, []);

  const restoreEvent = async (ev) => {
    setSilentEvents(prev => prev.filter(e => e.id !== ev.id));
    setEvents(prev => [ev, ...prev.filter(e => e.id !== ev.id)]);
    try { await apiUnsilenceAnomaly(ev.id); }
    catch (e) { console.warn('anomaly unsilence failed:', e); }
  };

  const restoreFromBucket = async (kind, key) => {
    setBuckets(b => {
      const next = { ...b, [kind]: { ...b[kind] } };
      delete next[kind][key];
      return next;
    });
    try { await apiDeleteSilent(kind, key); }
    catch (e) { console.warn('silent delete failed:', e); }
  };

  const recordAckMatches = useCallback((incoming) => {
    if (!incoming.length) return;
    const cur = bucketsRef.current.ack;
    if (!Object.keys(cur).length) return;
    let changed = false;
    const nextAck = { ...cur };
    for (const ev of incoming) {
      const p = evtPattern(ev);
      if (nextAck[p]) {
        nextAck[p] = {
          ...nextAck[p],
          count:  (nextAck[p].count || 0) + 1,
          lastTs: ev.ts || new Date().toISOString(),
        };
        changed = true;
      }
    }
    if (changed) setBuckets(b => ({ ...b, ack: nextAck }));
  }, []);

  const honeypotAlerts = useMemo(() => {
    return honeypotEvents.map(ev => ({
      id:            `hp-${ev.honeypotName}-${ev.timestamp}`,
      kind:          'honeypot_probe',
      ts:            honeypotTs(ev.timestamp),
      src_pod:       ev.honeypotName,
      src_namespace: ev.namespace,
      src_ip:        ev.src_ip,
      src_port:      ev.src_port,
      dst_ip:        (ev.dest_ip && ev.dest_ip !== '0.0.0.0') ? ev.dest_ip : '',
      dst_port:      ev.dest_port,
      detail:        `${ev.src_ip || '?'}:${ev.src_port || '?'} → ${ev.server || '?'}:${ev.dest_port || '?'}`,
      _isHoneypot:   true,
      ...ev,
    }));
  }, [honeypotEvents]);

  const digestEvents = useMemo(() => {
    return results
      .filter(r => {
        if (!r.digestChanged) return false;
        const ts = r.digestChangedAt || r.scannedAt;
        if (!ts) return true;
        return Date.now() - new Date(ts).getTime() < 60 * 60 * 1000;
      })
      .map(r => ({
        id:              `digest-${r.name || r.image || r.ref}`,
        kind:            'digest_change',
        ts:              r.digestChangedAt || r.scannedAt || new Date().toISOString(),
        src_pod:         r.name || r.image || '—',
        src_namespace:   r.namespace || '—',
        _currentDigest:  (r.digest        || '').slice(7, 19),
        _previousDigest: (r.previousDigest || '').slice(7, 19),
        _isDigest:       true,
      }));
  }, [results]);

  useEffect(() => {
    for (const ev of [...digestEvents, ...honeypotAlerts]) {
      if (!ev.id || ingestedRef.current.has(ev.id)) continue;
      ingestedRef.current.add(ev.id);
      apiIngestAnomaly(ev).catch(e => {
        ingestedRef.current.delete(ev.id);
        console.warn('ingest failed:', e);
      });
    }
  }, [digestEvents, honeypotAlerts]);

  const mergeEvents = useCallback((incoming) => {
    if (!incoming.length) return;
    recordAckMatches(incoming);
    setEvents(prev => {
      const key  = e => e.id || e.ts;
      const byId = new Map(prev.map(e => [key(e), e]));
      for (const e of incoming) byId.set(key(e), e);
      const all  = [...byId.values()].sort((a, b) => new Date(b.ts) - new Date(a.ts));
      eventsRef.current = all;
      return all.slice(0, 5000);
    });
    const withID = incoming.filter(e => e.id);
    if (withID.length) {
      const maxID = withID.reduce((best, e) => (Number(e.id) > Number(best) ? e.id : best), withID[0].id);
      lastIDRef.current = maxID;
    }
  }, [recordAckMatches]);

  const poll = useCallback(async () => {
    try {
      const res = await fetch(`/anomaly/api/anomalies?since=${lastIDRef.current}&limit=50`, {
        credentials: 'same-origin',
      });
      if (!res.ok) throw new Error(res.status);
      const data = await res.json();
      mergeEvents(data.events || []);
      setStatus(s => s === 'error' ? 'polling' : (s === 'connecting' ? 'polling' : s));
    } catch {
      if (!statsReachableRef.current) setStatus('error');
    }
  }, [mergeEvents]);

  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch('/anomaly/api/stats', { credentials: 'same-origin' });
      if (!res.ok) return;
      const data = await res.json();
      setStats(data);
      statsReachableRef.current = true;
      setStatus(s => s === 'error' ? 'polling' : s);
    } catch {
      statsReachableRef.current = false;
    }
  }, []);

  useEffect(() => {
    poll();
    fetchStats();
    const pollTimer  = setInterval(poll,       5000);
    const statsTimer = setInterval(fetchStats, 30000);
    return () => {
      clearInterval(pollTimer);
      clearInterval(statsTimer);
    };
  }, [poll, fetchStats]);

  useEffect(() => { if (bucketsOpen) loadSilentEvents(); }, [bucketsOpen, loadSilentEvents]);

  const isBucketed = useCallback((ev) => {
    if (!ev) return false;
    if (buckets.fp[ev.id])           return true;
    if (buckets.ack[evtPattern(ev)]) return true;
    return false;
  }, [buckets]);

  const liveEvents   = useMemo(() => events.filter(e => !isBucketed(e)), [events, isBucketed]);

  const networkCount       = liveEvents.filter(e => NETWORK_KINDS.has(e.kind)).length;
  const evilCount          = liveEvents.filter(e => EVIL_KINDS.has(e.kind)).length;
  const digestChangedCount = liveEvents.filter(e => e.kind === 'digest_change').length;
  const honeypotCount      = liveEvents.filter(e => e.kind === 'honeypot_probe').length;

  const bucketBadge =
      silentEvents.length
    + Object.keys(buckets.ack).length
    + Object.keys(buckets.fp).length;

  const resolveHoneypotIP = useCallback((e) => {
    if (e.kind !== 'honeypot_probe') return e;
    const cur = (e.dst_ip && e.dst_ip !== '0.0.0.0') ? e.dst_ip : '';
    const dst_ip = cur || honeypotIPs[`${e.src_namespace}/${e.honeypotName || e.src_pod}`] || '';
    return dst_ip === e.dst_ip ? e : { ...e, dst_ip };
  }, [honeypotIPs]);

  const visible = useMemo(() => {
    let list;
    if (groupFilter === 'images')        list = liveEvents.filter(e => e.kind === 'digest_change');
    else if (groupFilter === 'honeypot') list = liveEvents.filter(e => e.kind === 'honeypot_probe');
    else if (groupFilter === 'all')      list = liveEvents;
    else list = liveEvents.filter(e => {
      if (groupFilter === 'network' && !NETWORK_KINDS.has(e.kind)) return false;
      if (groupFilter === 'evil'    && !EVIL_KINDS.has(e.kind))    return false;
      if (kindFilter !== 'all' && e.kind !== kindFilter)           return false;
      return true;
    });
    return list.map(resolveHoneypotIP);
  }, [liveEvents, groupFilter, kindFilter, resolveHoneypotIP]);

  return (
    <div className="al-page">

      {}
      <div className="al-topbar">
        <div className="al-topbar-left">
          <span className="al-title">Anomaly</span>
          <span className={`al-live-dot al-live-dot--${status}`} />
          <span className="al-live-label">
            {status === 'live'       ? 'Live'
           : status === 'polling'   ? 'Polling'
           : status === 'error'     ? 'Disconnected'
           :                          'Connecting…'}
          </span>
        </div>

        <div className="al-topbar-right">
          {stats && (
            <span className="al-stat-pill">
              <b>{stats.processed?.toLocaleString()}</b> events processed
            </span>
          )}
          <button
            className={`al-pause-btn${refOpen ? ' al-pause-btn--paused' : ''}`}
            onClick={() => { setRefOpen(o => !o); setBucketsOpen(false); }}
            title="Reference: what becomes an anomaly and what triggers it"
          >
            ? Reference
          </button>
          <button
            className={`al-pause-btn${bucketsOpen ? ' al-pause-btn--paused' : ''}`}
            onClick={() => { setBucketsOpen(o => !o); setRefOpen(false); }}
            title="Silent: ACK and FP records"
          >
            Silent{bucketBadge > 0 ? ` · ${bucketBadge}` : ''}
          </button>
        </div>
      </div>

      {}
      <div className="al-counters">
        <div
          className={`al-counter al-counter--total${groupFilter==='all'?' al-counter--active':''}`}
          onClick={() => { setGroupFilter('all'); setKindFilter('all'); }}
        >
          <span className="al-counter-n">{liveEvents.length}</span>
          <span className="al-counter-l">Total Events</span>
        </div>
        <div
          className={`al-counter${groupFilter==='network'?' al-counter--active':''}`}
          onClick={() => { setGroupFilter('network'); setKindFilter('all'); }}
          title="Network syscall anomalies"
        >
          <span className="al-counter-n" style={{ color: networkCount > 0 ? 'var(--warning)' : 'var(--text-muted)' }}>{networkCount}</span>
          <span className="al-counter-l">Network Syscalls</span>
        </div>
        <div
          className={`al-counter${groupFilter==='evil'?' al-counter--active':''}`}
          onClick={() => { setGroupFilter('evil'); setKindFilter('all'); }}
          title="Evil / dangerous syscall anomalies"
        >
          <span className="al-counter-n" style={{ color: evilCount > 0 ? 'var(--danger)' : 'var(--text-muted)' }}>{evilCount}</span>
          <span className="al-counter-l">Evil Syscalls</span>
        </div>
        <div
          className={`al-counter${groupFilter==='images'?' al-counter--active':''}`}
          onClick={() => { setGroupFilter('images'); setKindFilter('all'); }}
          title="Images with digest change in the last hour"
        >
          <span className="al-counter-n" style={{ color: digestChangedCount > 0 ? 'var(--danger)' : 'var(--text-muted)' }}>{digestChangedCount}</span>
          <span className="al-counter-l">Digest Changes</span>
        </div>
        <div
          className={`al-counter${groupFilter==='honeypot'?' al-counter--active':''}`}
          onClick={() => { setGroupFilter('honeypot'); setKindFilter('all'); }}
          title="Honeypot connection attempts"
        >
          <span className="al-counter-n" style={{ color: honeypotCount > 0 ? 'var(--danger)' : 'var(--text-muted)' }}>{honeypotCount}</span>
          <span className="al-counter-l">Honeypot Hits</span>
        </div>
      </div>

      {}
      <div className="al-filters">
        <span className="al-filters-label">Group:</span>
        {[
          { id: 'all',      label: `All (${liveEvents.length})` },
          { id: 'network',  label: `Network Syscalls (${networkCount})` },
          { id: 'evil',     label: `Evil Syscalls (${evilCount})` },
          { id: 'images',   label: `Images (${digestChangedCount})` },
          { id: 'honeypot', label: `Honeypot Hits (${honeypotCount})` },
        ].map(g => (
          <button
            key={g.id}
            className={`al-filter-btn${groupFilter===g.id?' al-filter-btn--active':''}`}
            onClick={() => { setGroupFilter(g.id); setKindFilter('all'); }}
          >
            {g.label}
          </button>
        ))}
        {groupFilter !== 'all' && groupFilter !== 'images' && (
          <>
            <span className="al-filters-sep">·</span>
            <span className="al-filters-label">Kind:</span>
            {['all', ...Object.keys(KIND_META).filter(k => KIND_META[k].group === groupFilter)].map(k => (
              <button
                key={k}
                className={`al-filter-btn${kindFilter===k?' al-filter-btn--active':''}`}
                onClick={() => setKindFilter(k)}
              >
                {k === 'all' ? 'All' : KIND_META[k].label}
              </button>
            ))}
          </>
        )}
      </div>

      {}
      <div className="al-body">

        {}
        <AlertsList
          visible={visible}
          status={status}
          groupFilter={groupFilter}
          selected={selected}
          setSelected={setSelected}
          ackEvent={ackEvent}
          fpEvent={fpEvent}
          deleteEvent={deleteEvent}
        />
        {}
        {refOpen ? (
          <KindReference onClose={() => setRefOpen(false)} />
        ) : bucketsOpen ? (
          <BucketsPanel
            buckets={buckets}
            silentEvents={silentEvents}
            tab={bucketsTab}
            setTab={setBucketsTab}
            onClose={() => setBucketsOpen(false)}
            onRestore={restoreFromBucket}
            onRestoreEvent={restoreEvent}
          />
        ) : (
          <AlertDetail selected={selected} bucketsOpen={bucketsOpen} setSelected={setSelected} />
        )}

      </div>
    </div>
  );
}
