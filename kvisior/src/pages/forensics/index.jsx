import { useState, useEffect } from 'react';
import '../../styles/forensics/forensics.scss';
import { useSensor }  from '../../context/SensorContext';
import { podName } from '../../utils/format';
import { useSeverityConfig } from './forensicsHelpers';
import { SeverityModal } from './SeverityModal';
import { PodDetail }     from './PodDetail';
import { PodList }       from './PodList';
import { NsList }        from './NsList';
import { NETWORK_KINDS } from '../alerts/alertsConstants';

function anomalyToForensic(a) {
  const isNet = NETWORK_KINDS.has(a.kind);
  const dst = a.dst_ip ? `${a.dst_ip}${a.dst_port ? ':' + a.dst_port : ''}` : (a.dst_service || '');
  return {
    id: `fanomaly-${a.id}`, ts: a.ts, namespace: a.src_namespace, pod: a.src_pod,
    process: a.src_process, node: a.src_node, container: a.src_container,
    podIP: a.src_ip, podUID: a.src_pod_uid || a.pod_uid || a.podUID,
    syscall: isNet ? 'network' : (a.syscall || a.kind),
    cmdline: isNet ? `${a.kind} → ${dst || '?'}${a.protocol ? ' ' + a.protocol : ''}` : (a.detail || a.kind),
    _anomaly: true,
  };
}

export function Forensics() {
  const { namespaces, pods }   = useSensor();
  const { config, save, getSev } = useSeverityConfig();

  const [anomalies, setAnomalies] = useState([]);
  const [eventSummary, setEventSummary] = useState([]);
  const [activeWatches, setActiveWatches] = useState([]);

  useEffect(() => {
    const load = () => fetch('/v1/forensic-summary', { credentials: 'same-origin' })
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d?.events) setEventSummary(d.events); })
      .catch(() => {});
    load();
    const t = setInterval(load, 30_000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    const load = () => fetch('/anomaly/api/anomalies?limit=1000', { credentials: 'same-origin' })
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d?.events) setAnomalies(d.events); })
      .catch(() => {});
    load();
    const t = setInterval(load, 10_000);
    return () => clearInterval(t);
  }, []);

  const anomalyEvents = anomalies
    .filter(a => NETWORK_KINDS.has(a.kind) || a.syscall)
    .map(anomalyToForensic);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const res = await fetch('/v1/forensic-watches', { credentials: 'same-origin' });
        if (!res.ok) return;
        const data = await res.json();
        if (alive) setActiveWatches(data.watches || []);
      } catch {}
    };
    load();
    const t = setInterval(load, 10000);
    return () => { alive = false; clearInterval(t); };
  }, []);

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

       {view === 'ns'     && <NsList namespaces={namespaces} pods={pods} eventSummary={eventSummary} anomalyEvents={anomalyEvents} activeWatches={activeWatches} getSev={getSev} onSelect={openNS} onSeverityOpen={() => setSevModalOpen(true)} />}
       {view === 'pods'   && <PodList ns={activeNS} pods={pods} eventSummary={eventSummary} anomalyEvents={anomalyEvents} activeWatches={activeWatches} getSev={getSev} onSelect={openPod} />}
      {view === 'detail' && activePod && <PodDetail pod={activePod} ns={activeNS} allEvents={anomalyEvents} activeWatches={activeWatches} getSev={getSev} onBack={() => goBack('pods')} />}

      {sevModalOpen && <SeverityModal config={config} onSave={save} onClose={() => setSevModalOpen(false)} />}
    </div>
  );
}
