import { podNS } from '../../utils/format';

export function NsList({ namespaces, pods, allEvents, activeWatches, getSev, onSelect, onSeverityOpen }) {
  const SYSTEM_NS = new Set(['kube-system','kube-public','kube-node-lease','calico-system','cilium','cert-manager','monitoring','ingress-nginx']);

  return (
    <div className="fns-nslist">
      <div className="fns-nslist-hdr">
        <div>
          <div className="fns-page-title">Forensics</div>
          <div className="fns-page-sub">Select namespace to explore pod runtime-event history</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="fns-btn" onClick={onSeverityOpen}>⚙ Severity</button>
        </div>
      </div>
      <div className="fns-ns-grid">
        {namespaces.filter(ns => !SYSTEM_NS.has(ns?.metadata?.name || ns?.name || ns)).map(ns => {
          const nsName = ns?.metadata?.name || ns?.name || ns;
          const podCount = pods.filter(p => podNS(p) === nsName).length;
          const cutoff = Date.now() - 24 * 60 * 60 * 1000;
          const evts = allEvents.filter(e => e.namespace === nsName && new Date(e.ts).getTime() >= cutoff);
          const critical = evts.filter(e => getSev(e.syscall, e.execpath, e.process) === 'critical').length;
          const anomalyWatching = activeWatches.some(w => w.namespace === nsName && w.source === 'anomaly');
          return (
            <div key={nsName} className="fns-ns-card" onClick={() => onSelect(nsName)}>
              <div className="fns-ns-icon">⬡</div>
              <div className="fns-ns-info">
                <div className="fns-ns-name">
                  <span>{nsName}</span>
                  {anomalyWatching && <span className="fns-anomaly-dot" title="Anomaly watch active" aria-label="Anomaly watch active" />}
                </div>
                <div className="fns-ns-sub">{podCount} pods</div>
              </div>
              <div className="fns-ns-stats">
                <div className="fns-ns-stat">
                  <div className="fns-ns-stat-val">{evts.length}</div>
                  <div className="fns-ns-stat-lbl">binaries/24h</div>
                </div>
                {critical > 0 && (
                  <div className="fns-ns-stat">
                    <div className="fns-ns-stat-val fns-ns-stat-val--red">{critical}</div>
                    <div className="fns-ns-stat-lbl">critical</div>
                  </div>
                )}
              </div>
              <div className="fns-ns-arrow">›</div>
            </div>
          );
        })}
        {namespaces.length === 0 && (
          <div className="fns-empty">No namespaces — waiting for sensor snapshot…</div>
        )}
      </div>
    </div>
  );
}
