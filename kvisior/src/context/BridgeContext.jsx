import { createContext, useContext, useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { fetchStats, fetchComponents, fetchK8sMetrics, fetchKafkaStats } from '../data/bridge';
import { reconcileRules } from '../data/syscalls';
import { matchAuditEvents } from '../pages/violations/auditMatcher';
import { useApp } from './AppContext';

const BridgeCtx = createContext(null);
export const useBridge = () => useContext(BridgeCtx);

const MAX_EVENTS = 10_000;
const TS_WINDOW  = 60;

function pushCapped(arr, item) {
  const next = [...arr, item];
  return next.length > TS_WINDOW ? next.slice(next.length - TS_WINDOW) : next;
}

export function BridgeProvider({ children }) {
  const { toast } = useApp();
  const [connected,       setConnected]       = useState(false);
  const [events,          setEvents]          = useState([]);
  const [violations,      setViolations]      = useState([]);
  const [auditEvents,     setAuditEvents]     = useState([]);
  const [auditViolations, setAuditViolations] = useState([]);
  const [anomalyEvents,   setAnomalyEvents]   = useState([]);
  const [honeypotEvents,  setHoneypotEvents]  = useState([]);
  const [snapshot,        setSnapshot]        = useState(null);
  const [stats,        setStats]        = useState(null);
  const [components,   setComponents]   = useState([]);
  const [rulesVersion, setRulesVersion] = useState(0);
  const [k8sMetrics,   setK8sMetrics]   = useState(null);
  const [kafkaStats,   setKafkaStats]   = useState(null);
  const [k8sSeries,    setK8sSeries]    = useState({});
  const [kafkaSeries,  setKafkaSeries]  = useState({
    totalLag: [], totalMessages: [], producerBuffered: [],
  });

  const statsRef = useRef(null);
  useEffect(() => { statsRef.current = stats; }, [stats]);

  useEffect(() => {
    let es = null;
    let retryTimer = null;
    let delay = 2_000;
    let alive = true;
    let errorCount = 0;

    const connect = () => {
      if (!alive) return;
      es = new EventSource('/v1/stream');

      es.onopen = () => {
        setConnected(true);
        delay = 2_000;
        errorCount = 0;
      };

      es.onerror = () => {
        setConnected(false);
        es.close();
        errorCount++;
        if (errorCount % 3 === 0) {
          fetch('/auth/me', { credentials: 'same-origin' })
            .then(r => { if (r.status === 401) window.dispatchEvent(new Event('sw-auth-failed')); })
            .catch(() => {});
        }
        if (!alive) return;
        retryTimer = setTimeout(connect, delay);
        delay = Math.min(delay * 2, 30_000);
      };

      es.onmessage = (ev) => {
        let msg;
        try { msg = JSON.parse(ev.data); } catch { return; }
        const { type, data } = msg;
        if (!data) return;

        if (localStorage.getItem('swSseDebug') === '1') {
          console.debug(`[sse] ${type}`, type === 'sensor_snapshot' ? `${ev.data.length}b` : (data.rule || data.id || ''));
        }

        switch (type) {
          case 'tracee_event': {
            const normalized = {
              ...data,
              time:      data.ts ? new Date(data.ts).toLocaleString() : '—',
              pod:       data.pod       || data.container || '—',
              namespace: data.namespace || '—',
              node:      data.node      || '—',
              process:   data.process   || '—',
              execpath:  data.execpath  || '—',
              cmdline:   data.cmdline   || '',
            };
            setEvents(prev => {
              const byId = new Map(prev.map(e => [e.id ?? e.ts, e]));
              byId.set(normalized.id ?? normalized.ts, normalized);
              return [...byId.values()]
                .sort((a, b) => new Date(b.ts) - new Date(a.ts))
                .slice(0, MAX_EVENTS);
            });
            break;
          }

          case 'violation': {
            const raw = typeof data.event === 'object' ? data.event : {};
            const v = {
              ...raw,
              sev:          (data.sev || 'medium').toUpperCase(),
              _matchedRule: { id: data.ruleId, name: data.rule, sev: data.sev },
              _ruleId:      data.ruleId,
              _ruleName:    data.rule,
              _fp:          data.fingerprint || '',
            };
            setViolations(prev => {
              if (v._fp) {
                if (prev.some(x => x._fp === v._fp)) return prev;
              } else if (v.id != null || v.ts != null) {
                const key = `${v.id ?? v.ts}_${v._ruleId ?? ''}`;
                if (prev.some(x => `${x.id ?? x.ts}_${x._ruleId ?? ''}` === key)) return prev;
              }
              return [...prev, v].slice(-5_000);
            });
            break;
          }

          case 'audit_event': {
            if (!data.id) return;
            setAuditEvents(prev => {
              const byId = new Map(prev.map(e => [e.id, e]));
              byId.set(data.id, data);
              return [...byId.values()].slice(-5_000);
            });
            break;
          }

          case 'audit_violation': {
            const v = {
              ...data,
              sev: (data.sev || 'HIGH').toUpperCase(),
              _matchedRule: { id: data.ruleId, name: data.policy, sev: data.sev },
              _ruleId: data.ruleId,
              _ruleName: data.policy,
              _fp: data.fingerprint || '',
            };
            setAuditViolations(prev => {
              if (v._fp) {
                if (prev.some(x => x._fp === v._fp)) return prev;
              }
              return [...prev, v].slice(-5_000);
            });
            break;
          }

          case 'sensor_snapshot':
            setSnapshot(data);
            break;

          case 'anomaly_event': {
            setAnomalyEvents(prev => {
              const key = data.id ?? data.ts;
              if (key != null && prev.some(e => (e.id ?? e.ts) === key)) return prev;
              return [...prev, data].slice(-5_000);
            });
            break;
          }

          case 'honeypot_event': {
            setHoneypotEvents(prev => {
              const exists = prev.some(e =>
                e.honeypotName === data.honeypotName &&
                e.timestamp    === data.timestamp    &&
                e.src_ip       === data.src_ip
              );
              if (exists) return prev;
              return [...prev, data].slice(-1_000);
            });
            const svc  = data.server  || data.dest_port || '?';
            const src  = data.src_ip  || '?';
            toast('error', `Honeypot hit: ${data.honeypotName}`, `${src} → ${svc}`);
            break;
          }

          default:
            break;
        }
      };
    };

    connect();
    return () => {
      alive = false;
      clearTimeout(retryTimer);
      es?.close();
    };
  }, []);

  useEffect(() => {
    const handler = () => setRulesVersion(v => v + 1);
    window.addEventListener('sw-rules-changed', handler);
    return () => window.removeEventListener('sw-rules-changed', handler);
  }, []);

  useEffect(() => {
    let alive = true;
    fetch('/v1/violations?type=syscall&limit=1000', { credentials: 'same-origin' })
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (!alive || !Array.isArray(data?.violations)) return;
        const loaded = data.violations.map(row => {
          const raw = (row.data && typeof row.data === 'object') ? row.data : {};
          return {
            ...raw,
            sev:          (row.sev || 'medium').toUpperCase(),
            _matchedRule: { id: row.ruleId, name: row.ruleName, sev: row.sev },
            _ruleId:      row.ruleId,
            _ruleName:    row.ruleName,
            _fp:          row.fingerprint || '',
          };
        });
        setViolations(prev => {
          const seen = new Set(prev.map(x => x._fp).filter(Boolean));
          const merged = [...prev];
          for (const v of loaded) {
            if (v._fp && seen.has(v._fp)) continue;
            if (v._fp) seen.add(v._fp);
            merged.push(v);
          }
          return merged.slice(-5_000);
        });
      })
      .catch(() => {});
    return () => { alive = false; };
  }, []);

  useEffect(() => {
    let alive = true;
    fetch('/v1/violations?type=audit&limit=1000', { credentials: 'same-origin' })
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (!alive || !Array.isArray(data?.violations)) return;
        const loaded = data.violations.map(row => {
          const raw = (row.data && typeof row.data === 'object') ? row.data : {};
          return {
            _eventId:  raw.id,
            policy:    row.ruleName,
            ruleId:    row.ruleId,
            sev:       (row.sev || 'HIGH').toUpperCase(),
            kind:      raw.kind,
            resource:  raw.resource,
            ns:        row.ns || raw.namespace,
            name:      row.pod || raw.name,
            user:      raw.user,
            timestamp: raw.timestamp || row.ts,
            _matchedRule: { id: row.ruleId, name: row.ruleName, sev: row.sev },
            _ruleId:    row.ruleId,
            _ruleName:  row.ruleName,
            _fp:        row.fingerprint || '',
          };
        });
        setAuditViolations(prev => {
          const seen = new Set(prev.map(x => x._fp).filter(Boolean));
          const merged = [...prev];
          for (const v of loaded) {
            if (v._fp && seen.has(v._fp)) continue;
            if (v._fp) seen.add(v._fp);
            merged.push(v);
          }
          return merged.slice(-5_000);
        });
      })
      .catch(() => {});
    return () => { alive = false; };
  }, []);

  useEffect(() => {
    let prev = null;
    const poll = async () => {
      try {
        const next = await fetchStats();
        const now = Date.now();
        if (prev && next && typeof next.events_total === 'number') {
          const dt = (now - prev.ts) / 1000;
          const dn = next.events_total - prev.events_total;
          if (dt > 0) next.events_per_sec = Math.max(0, dn / dt);
        }
        prev = { events_total: next?.events_total || 0, ts: now };
        setStats(next);
      } catch {}
    };
    poll();
    const t = setInterval(poll, 5_000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    const poll = async () => {
      try {
        const r = await fetchComponents();
        setComponents(Array.isArray(r?.components) ? r.components : []);
      } catch {}
    };
    poll();
    const t = setInterval(poll, 10_000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    const poll = async () => {
      try {
        const data = await fetchK8sMetrics();
        setK8sMetrics(data);
        const ts = data.ts || Math.floor(Date.now() / 1000);
        setK8sSeries(prev => {
          const next = { ...prev };
          let totalCPU = 0, totalMem = 0, totalRst = 0;
          for (const c of (data.components || [])) {
            totalCPU += c.cpu_milli      || 0;
            totalMem += c.mem_bytes      || 0;
            totalRst += c.restarts_total || 0;
            const s = next[c.id] || { cpu: [], mem: [], rst: [] };
            next[c.id] = {
              cpu: pushCapped(s.cpu, { x: ts, y: c.cpu_milli      || 0 }),
              mem: pushCapped(s.mem, { x: ts, y: c.mem_bytes      || 0 }),
              rst: pushCapped(s.rst, { x: ts, y: c.restarts_total || 0 }),
            };
          }
          const ov = next.__overall || { cpu: [], mem: [], rst: [] };
          next.__overall = {
            cpu: pushCapped(ov.cpu, { x: ts, y: totalCPU }),
            mem: pushCapped(ov.mem, { x: ts, y: totalMem }),
            rst: pushCapped(ov.rst, { x: ts, y: totalRst }),
          };
          return next;
        });
      } catch {}
    };
    poll();
    const t = setInterval(poll, 10_000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    const poll = async () => {
      try {
        const data = await fetchKafkaStats();
        setKafkaStats(data);
        const ts = data.ts || Math.floor(Date.now() / 1000);
        const k = data.kafka || {};
        setKafkaSeries(prev => ({
          totalLag:         pushCapped(prev.totalLag,         { x: ts, y: k.total_lag      || 0 }),
          totalMessages:    pushCapped(prev.totalMessages,    { x: ts, y: k.total_messages || 0 }),
          producerBuffered: pushCapped(prev.producerBuffered, { x: ts, y: statsRef.current?.kafka_buffered_records || 0 }),
        }));
      } catch {}
    };
    poll();
    const t = setInterval(poll, 10_000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    const sweep = () => {
      const cutoff = Date.now() - 24 * 60 * 60 * 1000;
      setEvents(prev => prev.filter(e => {
        const t = new Date(e.ts).getTime();
        return Number.isNaN(t) || t > cutoff;
      }));
    };
    const t = setInterval(sweep, 5 * 60 * 1000);
    return () => clearInterval(t);
  }, []);

  const clearTraceeEvents = useCallback(() => {
    setEvents([]);
    setViolations([]);
  }, []);

  const clearAuditEvents = useCallback(() => {
    setAuditEvents([]);
    setAuditViolations([]);
  }, []);

  useEffect(() => {
    reconcileRules().catch(() => {});
  }, []);

  const syscallStats = useMemo(() => {
    const m = {};
    events.forEach(e => { const k = e.syscall || e.name || 'unknown'; m[k] = (m[k] || 0) + 1; });
    return m;
  }, [events]);

  const nsStats = useMemo(() => {
    const m = {};
    events.forEach(e => {
      const k = e.namespace || 'unknown';
      if (!m[k]) m[k] = { ns: k, total: 0, critical: 0, high: 0 };
      m[k].total++;
      if (e.severity === 'critical') m[k].critical++;
      if (e.severity === 'high')     m[k].high++;
    });
    return Object.values(m).sort((a, b) => b.total - a.total);
  }, [events]);

  const nodeStats = useMemo(() => {
    const m = {};
    events.forEach(e => { const k = e.node || 'unknown'; m[k] = (m[k] || 0) + 1; });
    return m;
  }, [events]);

  const ruleHits = useMemo(() => {
    const hits = {};
    violations.forEach(v => {
      if (v._ruleId) hits[v._ruleId] = (hits[v._ruleId] || 0) + 1;
    });
    return hits;
  }, [violations, rulesVersion]);

  const auditHits = useMemo(() => {
    const hits = {};
    auditViolations.forEach(v => {
      if (v._ruleId) hits[v._ruleId] = (hits[v._ruleId] || 0) + 1;
    });
    return hits;
  }, [auditViolations, rulesVersion]);

  const getMatchedRules = useCallback((rawEvent) => {
    const id = rawEvent?.id ?? rawEvent?.ts;
    const matched = violations.filter(v => (v.id ?? v.ts) === id);
    return matched.map(v => v._matchedRule).filter(Boolean);
  }, [violations, rulesVersion]);

  const seenNamespaces = useMemo(() =>
    [...new Set(events.map(e => e.namespace).filter(Boolean))].sort(), [events]);
  const seenPods = useMemo(() =>
    [...new Set(events.map(e => e.pod).filter(Boolean))].sort(), [events]);

  const removeViolation = (fp) => {
    if (fp) setViolations(prev => prev.filter(v => v._fp !== fp));
  };
  const removeAuditViolation = (fp) => {
    if (fp) setAuditViolations(prev => prev.filter(v => v._fp !== fp));
  };

  const allViolations = useMemo(() => [...violations, ...auditViolations], [violations, auditViolations]);

  const counts = useMemo(() => ({
    critical: allViolations.filter(v => v.sev === 'CRITICAL').length,
    high:     allViolations.filter(v => v.sev === 'HIGH').length,
    medium:   allViolations.filter(v => v.sev === 'MEDIUM').length,
    low:      allViolations.filter(v => v.sev === 'LOW').length,
    total:    allViolations.length,
    active:   0,
  }), [allViolations]);

  return (
    <BridgeCtx.Provider value={{
      connected, events, violations, auditViolations, stats, components, counts,
      syscallStats, nsStats, nodeStats,
      ruleHits, auditHits, auditEvents,
      anomalyEvents, honeypotEvents,
      getMatchedRules,
      seenNamespaces, seenPods,
      rulesVersion,
      k8sMetrics, kafkaStats,
      k8sSeries, kafkaSeries,
      clearTraceeEvents, clearAuditEvents,
      removeViolation, removeAuditViolation,
      snapshot,
    }}>
      {children}
    </BridgeCtx.Provider>
  );
}
