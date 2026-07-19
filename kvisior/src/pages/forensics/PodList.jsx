import { useState, useMemo } from 'react';
import { podName, podNS, podContainers, relTime } from '../../utils/format';

export function PodList({ ns, pods, allEvents, getSev, onSelect }) {
  const [search, setSearch] = useState('');

  const rows = useMemo(() => {
    const cutoff = Date.now() - 24 * 60 * 60 * 1000;
    const recent = allEvents.filter(e => e.namespace === ns && new Date(e.ts).getTime() >= cutoff);

    const byPod = new Map();
    for (const e of recent) {
      if (!e.pod) continue;
      const list = byPod.get(e.pod);
      if (list) list.push(e); else byPod.set(e.pod, [e]);
    }

    const mkRow = (p, pn, gone) => {
      const evts = byPod.get(pn) || [];
      const critical = evts.filter(e => getSev(e.syscall, e.execpath, e.process) === 'critical').length;
      const lastSeen = evts.reduce((m, e) => Math.max(m, new Date(e.ts).getTime()), 0);
      return { pod: p, name: pn, evts, critical, gone, lastSeen, containers: podContainers(p) };
    };

    const live = pods.filter(p => podNS(p) === ns);
    const liveNames = new Set(live.map(podName));

    const ghosts = [...byPod.keys()]
      .filter(pn => !liveNames.has(pn))
      .map(pn => mkRow({ name: pn, namespace: ns, _gone: true }, pn, true));

    return [...live.map(p => mkRow(p, podName(p), false)), ...ghosts]
      .filter(r => search === '' || r.name.includes(search))
      .sort((a, b) =>
        a.gone - b.gone ||
        b.critical - a.critical ||
        b.evts.length - a.evts.length);
  }, [ns, pods, allEvents, search, getSev]);

  return (
    <div className="fns-podlist">
      <div className="fns-podlist-hdr">
        <div className="fns-podlist-title">{ns}</div>
        <div className="fns-podlist-count">{rows.length} pods</div>
        <div className="fns-search">
          <span className="fns-search-icon">⌕</span>
          <input placeholder="Search pods…" value={search} onChange={e => setSearch(e.target.value)} />
        </div>
      </div>
      <table className="fns-ptable">
        <thead>
          <tr><th>Pod name</th><th>Containers</th><th>Binaries / 24h</th><th>Critical</th></tr>
        </thead>
        <tbody>
          {rows.map(r => (
            <tr key={r.name} className={`fns-prow${r.gone ? ' fns-prow--gone' : ''}`} onClick={() => onSelect(r.pod)}>
              <td>
                <div className="fns-pname-wrap">
                  <div className={`fns-sdot fns-sdot--${r.gone ? 'gone' : 'running'}`} />
                  <span className="fns-pname">{r.name}</span>
                  {r.gone && (
                    <span className="fns-gone-badge" title={`Последнее событие: ${new Date(r.lastSeen).toLocaleString('ru-RU')}`}>
                      terminated · {relTime(r.lastSeen)}
                    </span>
                  )}
                </div>
              </td>
              <td>
                <div className="fns-cpills">
                  {r.containers.length > 0
                    ? r.containers.map(c => <span key={c} className="fns-cpill">{c}</span>)
                    : <span className="fns-cpill">{r.name.split('-')[0]}</span>
                  }
                </div>
              </td>
              <td>
                <span className={`fns-sc ${r.evts.length > 100 ? 'fns-sc--high' : r.evts.length > 30 ? 'fns-sc--med' : 'fns-sc--low'}`}>
                  {r.evts.length}
                </span>
              </td>
              <td>
                {r.critical > 0
                  ? <span className="fns-crit-badge">⊗ {r.critical}</span>
                  : <span className="fns-dim">—</span>
                }
              </td>
            </tr>
          ))}
          {rows.length === 0 && <tr><td colSpan={4} className="fns-empty">No pods found</td></tr>}
        </tbody>
      </table>
    </div>
  );
}
