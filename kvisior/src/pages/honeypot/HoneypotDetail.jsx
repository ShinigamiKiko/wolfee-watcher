import { svcByName, fmtTime } from './honeypotUtils';

export function HoneypotDetail({ selected, selectedEvent, setSelectedEvent, detailTab, setDetailTab, events, loading, hasAlert, deleting, resolveIP, handleDelete, handleHideEvent }) {
  return (
  <div className="hp-detail">
    {!selected && (
      <div className="hp-detail-empty">Select a honeypot to view details</div>
    )}

    {selected && (
      <div className="hp-detail-inner">

        {}
        <div className="hp-detail-header">
          <div>
            <div className="hp-detail-title">
              🍯 {selected.name}
              {hasAlert(selected) && (
                <span className="hp-badge-crit">⚠ Activity detected</span>
              )}
            </div>
            <div className="hp-detail-sub">{selected.namespace} · {selected.clusterIP || '—'}</div>
          </div>
          <button
            className="hp-delete-btn"
            onClick={() => handleDelete(selected)}
            disabled={deleting}
            title="Delete honeypot"
          >
            {deleting ? 'Deleting…' : 'Delete'}
          </button>
        </div>

        {}
        <div className="hp-tabs">
          <button
            className={`hp-tab${detailTab === 'info' ? ' hp-tab--active' : ''}`}
            onClick={() => { setDetailTab('info'); setSelectedEvent(null); }}
          >
            Info
          </button>
          <button
            className={`hp-tab${detailTab === 'events' ? ' hp-tab--active' : ''}`}
            onClick={() => setDetailTab('events')}
          >
            Events
            {events.length > 0 && (
              <span className="hp-alert-badge">{events.length}</span>
            )}
          </button>
        </div>

        {}
        <div className="hp-tab-content">

          {}
          {detailTab === 'info' && (
            <div className="hp-info">
              <div className="hp-section-title">Pod</div>
              <div className="hp-kv-grid">
                <span className="hp-kv-label">Name</span>
                <span className="hp-kv-val">h-{selected.name}</span>
                <span className="hp-kv-label">Namespace</span>
                <span className="hp-kv-val">{selected.namespace}</span>
                <span className="hp-kv-label">ClusterIP</span>
                <span className="hp-kv-val">{selected.clusterIP || '—'}</span>
                <span className="hp-kv-label">Phase</span>
                <span className="hp-kv-val hp-kv-val--ok">{selected.phase || '—'}</span>
                <span className="hp-kv-label">Created</span>
                <span className="hp-kv-val">{fmtTime(selected.createdAt)}</span>
                <span className="hp-kv-label">Image</span>
                <span className="hp-kv-val">localhost/wolfee-watcher/honeypot:latest</span>
              </div>

              <div className="hp-section-title" style={{ marginTop: 20 }}>Service Ports</div>
              <div className="hp-svc-list">
                {(selected.services || []).map(s => {
                  const svc = svcByName(s);
                  return (
                    <div key={s} className="hp-svc-row">
                      <span className="hp-svc-icon">{svc.icon}</span>
                      <span className="hp-svc-name">{svc.label}</span>
                      <span className="hp-svc-port">:{svc.port}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {}
          {detailTab === 'events' && (
            <div className="hp-events-wrap">

              {}
              <div className={`hp-events-list${selectedEvent ? ' hp-events-list--narrow' : ''}`}>
                {loading && (
                  <div className="hp-events-loading">Loading events…</div>
                )}
                {!loading && events.length === 0 && (
                  <div className="hp-events-empty">No events captured yet</div>
                )}
                {!loading && events.length > 0 && (
                  <>
                    <div className="hp-events-header-row">
                      <span>Time</span>
                      <span>Service</span>
                      <span>Src IP</span>
                      <span>Data</span>
                      <span />
                    </div>
                    {events.map((ev, i) => {
                      const isHigh = ev.action !== 'process';
                      return (
                        <div
                          key={ev.id || i}
                          className={`hp-event-row${isHigh ? ' hp-event-row--alert' : ''}${selectedEvent === ev ? ' hp-event-row--selected' : ''}`}
                          onClick={() => setSelectedEvent(selectedEvent === ev ? null : ev)}
                        >
                          <span className="hp-ev-time">{fmtTime(ev.timestamp)}</span>
                          <span className="hp-ev-svc">{ev.server?.replace('_server', '')}</span>
                          <span className="hp-ev-ip">{ev.src_ip}</span>
                          <span className="hp-ev-data">{ev.data || ev.action}</span>
                          {handleHideEvent && (
                            <button
                              className="hp-ev-del"
                              title="Delete event"
                              onClick={(e) => { e.stopPropagation(); handleHideEvent(ev); }}
                            >
                              ✕
                            </button>
                          )}
                        </div>
                      );
                    })}
                  </>
                )}
              </div>

              {}
              {selectedEvent && (
                <div className="hp-event-panel">
                  <div className="hp-event-panel-header">
                    <span>Event Detail</span>
                    <button className="hp-panel-close" onClick={() => setSelectedEvent(null)}>✕</button>
                  </div>
                  <div className="hp-event-panel-body">

                    {}
                    <div className="hp-ep-section">
                      <div className="hp-ep-title">Event</div>
                      <div className="hp-ep-kv">
                        <span className="hp-ep-k">Time</span>
                        <span className="hp-ep-v">{fmtTime(selectedEvent.timestamp)}</span>
                      </div>
                      <div className="hp-ep-kv">
                        <span className="hp-ep-k">Service</span>
                        <span className="hp-ep-v" style={{ color: 'var(--accent-2)' }}>
                          {selectedEvent.server?.replace('_server', '')}
                        </span>
                      </div>
                      <div className="hp-ep-kv">
                        <span className="hp-ep-k">Action</span>
                        <span className="hp-ep-v">{selectedEvent.action}</span>
                      </div>
                      <div className="hp-ep-kv">
                        <span className="hp-ep-k">Src IP</span>
                        <span className="hp-ep-v hp-ep-v--danger">{selectedEvent.src_ip}</span>
                      </div>
                      <div className="hp-ep-kv">
                        <span className="hp-ep-k">Src Port</span>
                        <span className="hp-ep-v">{selectedEvent.src_port || '—'}</span>
                      </div>
                      {selectedEvent.username && (
                        <div className="hp-ep-kv">
                          <span className="hp-ep-k">Username</span>
                          <span className="hp-ep-v hp-ep-v--danger">{selectedEvent.username}</span>
                        </div>
                      )}
                      {selectedEvent.password && (
                        <div className="hp-ep-kv">
                          <span className="hp-ep-k">Password</span>
                          <span className="hp-ep-v hp-ep-v--danger">{selectedEvent.password}</span>
                        </div>
                      )}
                      {selectedEvent.data && (
                        <div className="hp-ep-kv">
                          <span className="hp-ep-k">Data</span>
                          <span className="hp-ep-v">{selectedEvent.data}</span>
                        </div>
                      )}
                    </div>

                    {}
                    <div className="hp-ep-section">
                      <div className="hp-ep-title">Source Pod</div>
                      {(() => {
                        const pod = resolveIP(selectedEvent.src_ip);
                        if (!pod) return (
                          <div className="hp-ep-unresolved">
                            <div style={{ color: 'var(--warning)', fontWeight: 600, marginBottom: 4 }}>
                              ⚠ IP not in cluster snapshot
                            </div>
                            <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.5 }}>
                              {selectedEvent.src_ip} not found in any pod.
                              May be external or pod already deleted.
                            </div>
                          </div>
                        );
                        const dep = pod.metadata?.ownerReferences
                          ?.find(r => r.kind === 'ReplicaSet')?.name
                          ?.replace(/-[a-z0-9]+$/, '') || '—';
                        return (
                          <div className="hp-ep-pod-card">
                            <div className="hp-ep-kv">
                              <span className="hp-ep-k">Pod</span>
                              <span className="hp-ep-v hp-ep-v--danger">{pod.metadata?.name}</span>
                            </div>
                            <div className="hp-ep-kv">
                              <span className="hp-ep-k">Deployment</span>
                              <span className="hp-ep-v">{dep}</span>
                            </div>
                            <div className="hp-ep-kv">
                              <span className="hp-ep-k">Namespace</span>
                              <span className="hp-ep-v">{pod.metadata?.namespace}</span>
                            </div>
                            <div className="hp-ep-kv">
                              <span className="hp-ep-k">Node</span>
                              <span className="hp-ep-v">{pod.spec?.nodeName}</span>
                            </div>
                            <div className="hp-ep-kv">
                              <span className="hp-ep-k">Image</span>
                              <span className="hp-ep-v">{pod.spec?.containers?.[0]?.image}</span>
                            </div>
                          </div>
                        );
                      })()}
                    </div>

                    {}
                    <div className="hp-ep-section">
                      <div className="hp-ep-title">Raw</div>
                      <pre className="hp-ep-raw">
                        {JSON.stringify(selectedEvent, null, 2)}
                      </pre>
                    </div>

                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    )}
  </div>
  );
}
