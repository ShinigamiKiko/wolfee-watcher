import { useState, useMemo, useEffect, useRef } from 'react';
import '../../styles/forensics/forensics.scss';
import { useBridge } from '../../context/BridgeContext';
import { useSensor }  from '../../context/SensorContext';
import { podName } from '../../utils/format';
import { useSeverityConfig, isForensicEvent } from './forensicsHelpers';
import { SeverityModal } from './SeverityModal';
import { PodDetail }     from './PodDetail';
import { PodList }       from './PodList';
import { NsList }        from './NsList';
import { NETWORK_KINDS } from '../alerts/alertsConstants';

function anomalyToForensic(a) {
  const isNet = NETWORK_KINDS.has(a.kind);
  const dst = a.dst_ip ? `${a.dst_ip}${a.dst_port ? ':' + a.dst_port : ''}` : (a.dst_service || '');
  const cmdline = isNet
    ? `${a.kind} → ${dst || '?'}${a.protocol ? ' ' + a.protocol : ''}`
    : (a.detail || [a.syscall, dst && `→ ${dst}`].filter(Boolean).join(' ') || a.kind);
  return {
    id:        `fanomaly-${a.id}`,
    ts:        a.ts,
    namespace: a.src_namespace,
    pod:       a.src_pod,
    process:   a.src_process,
    node:      a.src_node,
    container: a.src_container,
    syscall:   isNet ? 'network' : (a.syscall || a.kind),
    cmdline,
    _anomaly:  true,
    args: {
      kind: a.kind,
      ...(dst ? { dst } : {}),
      ...(a.detail ? { detail: a.detail } : {}),
      ...(a.baseline_state ? { baseline: a.baseline_state } : {}),
    },
  };
}

function dedupBinary(evts) {
  const seen = new Set();
  const out = [];
  for (const e of evts) {
    const bucket = Math.floor(new Date(e.ts).getTime() / (5 * 60 * 1000));
    const bin = e.execpath || e.process || e.syscall;
    const key = `${bucket}|${e.namespace}|${e.pod}|${bin}|${e.cmdline || ''}`;
    if (!seen.has(key)) { seen.add(key); out.push(e); }
  }
  return out;
}

export function Forensics() {
  const { events } = useBridge();
  const { namespaces, pods }   = useSensor();
  const { config, save, getSev } = useSeverityConfig();

  const [backfill, setBackfill] = useState([]);
  const [anomalies, setAnomalies] = useState([]);
  const fetched = useRef(false);

  useEffect(() => {
    if (fetched.current) return;
    fetched.current = true;
    fetch('/v1/binary-backfill', { credentials: 'same-origin' })
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d?.events) setBackfill(d.events); })
      .catch(() => {});
  }, []);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const res = await fetch('/anomaly/api/anomalies?limit=1000', { credentials: 'same-origin' });
        if (!res.ok) return;
        const d = await res.json();
        if (alive) setAnomalies(d.events || []);
      } catch {}
    };
    load();
    const t = setInterval(load, 10000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  const anomalyEvents = useMemo(
    () => anomalies.filter(a => NETWORK_KINDS.has(a.kind) || a.syscall).map(anomalyToForensic),
    [anomalies],
  );

  const binaryEvents = useMemo(() => {
    const live = events.filter(e => isForensicEvent(e.syscall));
    const liveIds = new Set(live.map(e => e.id).filter(Boolean));
    const merged = [...live, ...backfill.filter(e => !liveIds.has(e.id))];
    return [...dedupBinary(merged), ...anomalyEvents];
  }, [events, backfill, anomalyEvents]);

  const [view,         setView]         = useState('ns');
  const [activeNS,     setActiveNS]     = useState(null);
  const [activePod,    setActivePod]    = useState(null);
  const [sevModalOpen, setSevModalOpen] = useState(false);

  function openNS(ns)   { setActiveNS(ns); setView('pods'); }
  function openPod(pod) { setActivePod(pod); setView('detail'); }
  function goBack(to) {
    setView(to);
    if (to === 'ns')   { setActiveNS(null); setActivePod(null); }
    if (to === 'pods') { setActivePod(null); }
  }

  return (
    <div className="fns-page">
      <div className="fns-breadcrumb">
        <span className={`fns-bc${view === 'ns' ? ' fns-bc--active' : ''}`} onClick={() => goBack('ns')}>Forensics</span>
        {view !== 'ns' && (
          <>
            <span className="fns-bc-sep">›</span>
            <span className={`fns-bc${view === 'pods' ? ' fns-bc--active' : ''}`} onClick={() => goBack('pods')}>{activeNS}</span>
          </>
        )}
        {view === 'detail' && activePod && (
          <>
            <span className="fns-bc-sep">›</span>
            <span className="fns-bc fns-bc--active">
              {podName(activePod).length > 36 ? podName(activePod).slice(0, 36) + '…' : podName(activePod)}
            </span>
          </>
        )}
      </div>

      {view === 'ns'     && <NsList namespaces={namespaces} allEvents={binaryEvents} getSev={getSev} onSelect={openNS} onSeverityOpen={() => setSevModalOpen(true)} />}
      {view === 'pods'   && <PodList ns={activeNS} pods={pods} allEvents={binaryEvents} getSev={getSev} onSelect={openPod} />}
      {view === 'detail' && activePod && <PodDetail pod={activePod} ns={activeNS} allEvents={binaryEvents} getSev={getSev} onBack={() => goBack('pods')} />}

      {sevModalOpen && <SeverityModal config={config} onSave={save} onClose={() => setSevModalOpen(false)} />}
    </div>
  );
}
