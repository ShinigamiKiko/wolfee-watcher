import { useState, useMemo } from 'react';
import { podName, podNS, podContainers, relTime } from '../../utils/format';
import { Icon } from '../../components/Icon';
import { Pager } from '../../components/Pager';
import { usePaged } from '../../hooks/usePaged';

export function PodList({ ns, pods, eventSummary = [], anomalyEvents = [], activeWatches = [], getSev, onSelect }) {
  const [search, setSearch] = useState('');

  const rows = useMemo(() => {
    const byPod = new Map();
    for (const e of eventSummary.filter(e => e.namespace === ns)) {
      if (!e.pod) continue;
      const key = `${e.pod}\0${e.pod_uid || e.container_id || ''}`;
      const list = byPod.get(key);
      if (list) list.push(e); else byPod.set(key, [e]);
    }
    const anomalyByPod = new Map();
    for (const e of anomalyEvents.filter(e => e.namespace === ns)) {
      const key = `${e.pod}\0${e.podUID || e.podIP || ''}`;
      const list = anomalyByPod.get(key) || [];
      list.push(e);
      anomalyByPod.set(key, list);
    }

    const mkRow = (p, pn, gone, podUID = '', containerID = '') => {
      const identity = podUID || containerID;
      const evts = byPod.get(`${pn}\0${identity}`) || byPod.get(`${pn}\0${containerID}`) || [];
      const summaryIP = evts.find(e => e.pod_ip)?.pod_ip || '';
      const rowIP = p?.status?.podIP || p?.status?.podIPs?.[0]?.ip || summaryIP;
      const anomalies = anomalyByPod.get(`${pn}\0${podUID || rowIP}`) || [];
      const critical = evts.filter(e => getSev(e.syscall, e.binary, '') === 'critical')
        .reduce((sum, e) => sum + e.count, 0);
      const eventCount = evts.reduce((sum, e) => sum + e.count, 0) + anomalies.length;
      const lastSeen = evts.reduce((m, e) => Math.max(m, new Date(e.last_ts).getTime()), 0);
      return {
        pod: p,
        name: pn,
        podUID,
        containerID,
        eventCount,
        critical,
        gone,
        lastSeen,
        containers: podContainers(p),
        podIP: rowIP,
        anomalyWatching: activeWatches.some(w => w.namespace === ns && w.pod === pn && w.source === 'anomaly'),
      };
    };

    const live = pods.filter(p => podNS(p) === ns);
    const liveKeys = new Set();
    for (const p of live) {
      const name = podName(p);
      const uid = p?.metadata?.uid || p?.uid || '';
      const containerID = p?.status?.containerStatuses?.[0]?.containerID?.replace(/^\w+:\/\//, '') || '';
      if (uid) liveKeys.add(`${name}\0${uid}`);
      if (containerID) liveKeys.add(`${name}\0${containerID}`);
    }

    const ghosts = [...byPod.keys()]
      .map(key => key.split('\0'))
      .filter(([pn, identity]) => !liveKeys.has(`${pn}\0${identity}`))
      .map(([pn, identity]) => {
        const event = byPod.get(`${pn}\0${identity}`)?.[0];
        const podUID = event?.pod_uid || '';
        const containerID = event?.pod_uid ? '' : (event?.container_id || identity);
        return mkRow({ name: pn, namespace: ns, _gone: true }, pn, true, podUID, containerID);
      });

    return [...live.map(p => mkRow(p, podName(p), false, p?.metadata?.uid || p?.uid || '', p?.status?.containerStatuses?.[0]?.containerID?.replace(/^\w+:\/\//, '') || '')), ...ghosts]
      .filter(r => search === '' || r.name.includes(search))
      .sort((a, b) =>
        a.gone - b.gone ||
        b.critical - a.critical ||
        b.eventCount - a.eventCount);
  }, [ns, pods, eventSummary, anomalyEvents, activeWatches, search, getSev]);

  const { pageItems: pageRows, pager } = usePaged(rows, 'forensics.pods', [ns, search]);
  return (
    <div className="fns-podlist">
      <div className="fns-podlist-hdr">
        <div className="fns-podlist-title">{ns}</div>
      <div className="fns-podlist-count">{rows.length} pods</div>
        <div className="fns-search">
          <span className="fns-search-icon"><Icon name="search" /></span>
          <input placeholder="Search pods…" value={search} onChange={e => setSearch(e.target.value)} />
        </div>
      </div>
      <table className="fns-ptable">
        <thead>
           <tr><th>Pod name</th><th>Pod IP</th><th>Containers</th><th>Events / 24h</th><th>Critical</th></tr>
        </thead>
        <tbody>
          {pageRows.map(r => (
              <tr key={`${ns}/${r.podUID || r.containerID || r.name}`} className={`fns-prow${r.gone ? ' fns-prow--gone' : ''}`} onClick={() => onSelect(r.pod)}>
              <td>
                <div className="fns-pname-wrap">
                  <div className={`fns-sdot fns-sdot--${r.gone ? 'gone' : 'running'}`} />
                   <span className="fns-pname">{r.name}</span>
                   {r.anomalyWatching && <span className="fns-anomaly-dot" title="Anomaly watch active" aria-label="Anomaly watch active" />}
                  {r.gone && (
                    <span className="fns-gone-badge" title={`Last event: ${new Date(r.lastSeen).toLocaleString()}`}>
                      terminated · {relTime(r.lastSeen)}
                    </span>
                  )}
                </div>
              </td>
              <td><span className="fns-pod-ip">{r.podIP || '—'}</span></td>
              <td>
                <div className="fns-cpills">
                  {r.containers.length > 0
                    ? r.containers.map(c => <span key={c} className="fns-cpill">{c}</span>)
                    : <span className="fns-cpill">{r.name.split('-')[0]}</span>
                  }
                </div>
              </td>
              <td>
                <span className={`fns-sc ${r.eventCount > 100 ? 'fns-sc--high' : r.eventCount > 30 ? 'fns-sc--med' : 'fns-sc--low'}`}>
                  {r.eventCount}
                </span>
              </td>
              <td>
                {r.critical > 0
                  ? <span className="fns-crit-badge"><Icon name="alert" /> {r.critical}</span>
                  : <span className="fns-dim">—</span>
                }
              </td>
            </tr>
          ))}
          {rows.length === 0 && <tr><td colSpan={5} className="fns-empty">No pods found</td></tr>}
        </tbody>
      </table>
      {rows.length > 0 && <div className="dw-foot"><Pager {...pager} noun="pods" /></div>}
    </div>
  );
}
