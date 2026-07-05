import { useState, useEffect } from 'react';
import { ST } from './yamlPanelHelpers';

async function safeFetch(url) {
  const res = await fetch(url, { credentials: 'same-origin' });
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    const preview = text.slice(0, 120).replace(/\s+/g, ' ').trim();
    return { error: `Server returned non-JSON response: ${preview}` };
  }
}

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

  const typeColor = t => t === 'Warning' ? '#fbbf24' : 'var(--accent-3)';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}>
      <div style={{ padding: '10px 0', flexShrink: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
        <button onClick={load} disabled={loading} style={ST.btnLoad}>
          {loading ? '⟳ Loading…' : events ? '↺ Refresh' : '▶ Load Events'}
        </button>
        {events && <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{events.length} events</span>}
      </div>
      {error && <div style={ST.errBox}>✕ {error}</div>}
      {!events && !error && !loading && (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: 'var(--text-muted)', fontSize: 13, flexDirection: 'column', gap: 10 }}>
          <span style={{ fontSize: 32 }}>📅</span>
          <span>Click <strong style={{ color: 'var(--accent)' }}>Load Events</strong> to fetch</span>
        </div>
      )}
      {events && events.length === 0 && (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: 'var(--text-muted)', fontSize: 13 }}>No events found for this node</div>
      )}
      {events && events.length > 0 && (
        <div style={{ flex: 1, overflowY: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['Time','Type','Reason','Message','Count'].map(h => (
                  <th key={h} style={{ textAlign: 'left', padding: '6px 10px', fontSize: 10,
                    fontWeight: 600, letterSpacing: '.07em', textTransform: 'uppercase',
                    color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {events.map((e, i) => (
                <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,.03)' }}>
                  <td style={{ padding: '6px 10px', color: 'var(--text-muted)', whiteSpace: 'nowrap',
                    fontFamily: 'JetBrains Mono,monospace', fontSize: 10 }}>
                    {e.time ? new Date(e.time).toLocaleString() : '—'}
                  </td>
                  <td style={{ padding: '6px 10px', color: typeColor(e.type), fontWeight: 600, whiteSpace: 'nowrap' }}>
                    {e.type || '—'}
                  </td>
                  <td style={{ padding: '6px 10px', color: 'var(--text-primary)', whiteSpace: 'nowrap',
                    fontFamily: 'JetBrains Mono,monospace' }}>{e.reason || '—'}</td>
                  <td style={{ padding: '6px 10px', color: 'var(--text-secondary)', maxWidth: 240,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                    title={e.message}>{e.message || '—'}</td>
                  <td style={{ padding: '6px 10px', color: 'var(--text-muted)',
                    fontFamily: 'JetBrains Mono,monospace', textAlign: 'center' }}>{e.count || 1}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export { NodeEventsTab };
