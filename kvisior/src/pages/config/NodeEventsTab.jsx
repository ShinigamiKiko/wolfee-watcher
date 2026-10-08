import { useState, useEffect } from 'react';
import { safeFetch } from './yamlPanelHelpers';
import { Notice } from '../../components/kit';
import { Icon } from '../../components/Icon';

function NodeEventsTab({ item }) {
  const [events,  setEvents]  = useState(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState(null);
  const name = item.raw?.metadata?.name || item.title || '';

  useEffect(() => { setEvents(null); setError(null); }, [name]);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const data = await safeFetch(`/sensor/api/nodes/${name}/events`);
      if (data.error) throw new Error(data.error);
      setEvents(data.events || []);
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  return (
    <>
      <div className="log-tools">
        <button type="button" className="btn btn-primary btn-sm" onClick={load} disabled={loading}>
          {loading ? <><Icon name="loader" /> Loading…</> : events ? <><Icon name="refresh" /> Refresh</> : <><Icon name="play" /> Load Events</>}
        </button>
        {events && <span className="t-xs t-muted">{events.length} events</span>}
      </div>
      {error && <Notice tone="danger" icon="circle-x"><span className="mono t-sm">{error}</span></Notice>}
      {!events && !error && !loading && (
        <div className="empty-state fill-center">
          <Icon name="calendar" size={28} />
          <span>Click <strong className="t-accent">Load Events</strong> to fetch</span>
        </div>
      )}
      {events && events.length === 0 && <div className="empty-state fill-center">No events found for this node</div>}
      {events && events.length > 0 && (
        <div className="events-scroll">
          <table className="data-table data-table--static">
            <thead><tr><th>Time</th><th>Type</th><th>Reason</th><th>Message</th><th className="num">Count</th></tr></thead>
            <tbody>
              {events.map((e, i) => (
                <tr key={i}>
                  <td className="mono t-2xs t-muted">{e.time ? new Date(e.time).toLocaleString() : '—'}</td>
                  <td className={`t-strong ${e.type === 'Warning' ? 't-warning' : 't-ok'}`}>{e.type || '—'}</td>
                  <td className="mono t-xs t-primary">{e.reason || '—'}</td>
                  <td className="t-xs clip clip--md" title={e.message}>{e.message || '—'}</td>
                  <td className="mono num t-muted">{e.count || 1}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

export { NodeEventsTab };
