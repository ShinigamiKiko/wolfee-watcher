import { svcByName, shortImage, fmtTime } from './honeypotUtils';
import { STATE_LABEL } from './honeypotConstants';
import { Icon } from '../../components/Icon';
import { Pager } from '../../components/Pager';
import { usePaged } from '../../hooks/usePaged';

function KV({ k, v, tone }) {
  if (v === undefined || v === null || v === '') return null;
  return (
    <div className="hp-ep-kv">
      <span className="hp-ep-k">{k}</span>
      <span className={`hp-ep-v${tone ? ` hp-ep-v--${tone}` : ''}`}>{v}</span>
    </div>
  );
}

function sourceLabel(ev) {
  const c = ev.client;
  if (c?.src_pod) return { main: c.src_pod, sub: c.src_namespace, linked: true };
  return { main: ev.src_ip, sub: '', linked: false };
}

function ClientCard({ client }) {
  return (
    <div className="hp-ep-pod-card">
      <KV k="Pod" v={client.src_pod} tone="danger" />
      <KV k="Namespace" v={client.src_namespace} />
      <KV k="Workload" v={client.src_deployment} />
      <KV k="Service account" v={client.src_service_account} tone="danger" />
      <KV k="Container" v={client.src_container} />
      <KV k="Node" v={client.src_node} />
      <KV k="Process" v={client.src_process} />
      <KV k="Cmdline" v={client.src_cmdline} />
      <KV k="PID / UID" v={client.src_pid || client.src_uid ? `${client.src_pid || '—'} / ${client.src_uid || '—'}` : ''} />
      <KV k="Seen at" v={client.ts ? fmtTime(client.ts) : ''} />
      <div className="hp-ep-source">Kernel connect() traced by eBPF, matched by source IP and time</div>
    </div>
  );
}

function SnapshotCard({ ip, pod }) {
  if (!pod) return (
    <div className="hp-ep-unresolved">
      <div className="t-warning t-strong mb-4">
        <Icon name="alert" /> No eBPF match, IP not in cluster snapshot
      </div>
      <div className="t-xs t-muted">
        {ip} is not a current pod IP. The client may be outside the cluster, on the host network, or already gone.
      </div>
    </div>
  );
  const dep = pod.metadata?.ownerReferences
    ?.find(r => r.kind === 'ReplicaSet')?.name
    ?.replace(/-[a-z0-9]+$/, '') || pod.metadata?.ownerReferences?.[0]?.name || '—';
  return (
    <div className="hp-ep-pod-card">
      <KV k="Pod" v={pod.metadata?.name} tone="danger" />
      <KV k="Namespace" v={pod.metadata?.namespace} />
      <KV k="Workload" v={dep} />
      <KV k="Service account" v={pod.spec?.serviceAccountName} />
      <KV k="Node" v={pod.spec?.nodeName} />
      <KV k="Image" v={pod.spec?.containers?.[0]?.image} />
      <div className="hp-ep-source">Resolved from the current pod snapshot by IP, no process data</div>
    </div>
  );
}

export function HoneypotDetail({ selected, selectedEvent, setSelectedEvent, detailTab, setDetailTab, events, loading, catalog, hasAlert, deleting, resolveIP, handleDelete, handleHideEvent }) {
  const { pageItems, pager } = usePaged(events, 'honeypot.events', [selected?.name]);
  const svc = svcByName(selected?.service || selected?.services?.[0], catalog);
  const state = STATE_LABEL[selected?.state];
  return (
  <div className="hp-detail">
    {!selected && (
      <div className="hp-detail-empty">Select a honeypot to view details</div>
    )}

    {selected && (
      <div className="hp-detail-inner">

        <div className="hp-detail-header">
          <div>
            <div className="hp-detail-title">
              <Icon name="honeypot" /> {selected.name}
              {hasAlert(selected) && (
                <span className="hp-badge-crit"><Icon name="alert" /> Activity detected</span>
              )}
            </div>
            <div className="hp-detail-sub">
              {selected.legacy ? 'legacy pod' : selected.kind} · {selected.namespace} · {selected.clusterIP || '—'}
            </div>
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

        <div className="hp-tabs" role="tablist">
          <button
            role="tab"
            aria-selected={detailTab === 'info'}
            className={`hp-tab${detailTab === 'info' ? ' hp-tab--active' : ''}`}
            onClick={() => { setDetailTab('info'); setSelectedEvent(null); }}
          >
            Info
          </button>
          <button
            role="tab"
            aria-selected={detailTab === 'events'}
            className={`hp-tab${detailTab === 'events' ? ' hp-tab--active' : ''}`}
            onClick={() => setDetailTab('events')}
          >
            Events
            {events.length > 0 && (
              <span className="hp-alert-badge">{events.length}</span>
            )}
          </button>
        </div>

        <div className="hp-tab-content">

          {detailTab === 'info' && (
            <div className="hp-info">
              <div className="hp-section-title">Workload</div>
              <div className="hp-kv-grid">
                <span className="hp-kv-label">Kind</span>
                <span className="hp-kv-val">{selected.legacy ? 'Pod (legacy)' : selected.kind || '—'}</span>
                <span className="hp-kv-label">Name</span>
                <span className="hp-kv-val">{selected.legacy ? (selected.pods?.[0] || selected.name) : selected.name}</span>
                <span className="hp-kv-label">Namespace</span>
                <span className="hp-kv-val">{selected.namespace}</span>
                <span className="hp-kv-label">State</span>
                <span className={`hp-kv-val${state ? ` hp-kv-val--${state.tone}` : ''}`}>
                  {state ? state.text : '—'}{selected.phase ? ` · ${selected.phase}` : ''}
                </span>
                <span className="hp-kv-label">Pods</span>
                <span className="hp-kv-val">{selected.pods?.length ? selected.pods.join(', ') : '—'}</span>
                <span className="hp-kv-label">Image</span>
                <span className="hp-kv-val">{shortImage(selected.image) || '—'}</span>
                <span className="hp-kv-label">Created</span>
                <span className="hp-kv-val">
                  {fmtTime(selected.createdAt)}{selected.createdBy ? ` by ${selected.createdBy}` : ''}
                </span>
                {selected.id && (
                  <>
                    <span className="hp-kv-label">Registry ID</span>
                    <span className="hp-kv-val">{selected.id}</span>
                  </>
                )}
              </div>

              <div className="hp-section-title mt-24">Service</div>
              <div className="hp-svc-list">
                <div className="hp-svc-row">
                  <span className="hp-svc-icon"><Icon name={svc.icon} /></span>
                  <span className="hp-svc-name">{svc.label}</span>
                  <span className="hp-svc-port">
                    {selected.name}.{selected.namespace}.svc:{selected.port || svc.port}
                  </span>
                </div>
              </div>

              {selected.state === 'missing' && (
                <div className="hp-info-note hp-info-note--danger">
                  The {selected.kind} recorded for this trap no longer exists. Delete it here to clear the registry entry.
                </div>
              )}
              {selected.state === 'replaced' && (
                <div className="hp-info-note hp-info-note--warn">
                  An object named {selected.name} exists, but its UID differs from the one recorded at creation.
                  It is not tracked as a trap.
                </div>
              )}
              {selected.legacy && (
                <div className="hp-info-note">
                  Created by an older operator version as a bare pod. Recreate it to get a realistic workload and client correlation.
                </div>
              )}
            </div>
          )}

          {detailTab === 'events' && (
            <>
            <div className="hp-events-wrap">

              <div className={`hp-events-list dw dw-fill${selectedEvent ? ' hp-events-list--narrow' : ''}`} tabIndex={0} role="region" aria-label="Honeypot events">
                {loading && (
                  <div className="hp-events-loading">Loading events…</div>
                )}
                {!loading && events.length === 0 && (
                  <div className="hp-events-empty">No events captured yet</div>
                )}
                {!loading && events.length > 0 && (
                  <>
                    <div className="hp-events-header-row dw-sticky">
                      <span>Time</span>
                      <span>Service</span>
                      <span>Source</span>
                      <span>Data</span>
                      <span />
                    </div>
                    {pageItems.map((ev, i) => {
                      const isHigh = ev.action !== 'process';
                      const src = sourceLabel(ev);
                      return (
                        <div
                          key={ev.id || i}
                          className={`hp-event-row${isHigh ? ' hp-event-row--alert' : ''}${selectedEvent === ev ? ' hp-event-row--selected' : ''}`}
                          onClick={() => setSelectedEvent(selectedEvent === ev ? null : ev)}
                        >
                          <span className="hp-ev-time">{fmtTime(ev.timestamp)}</span>
                          <span className="hp-ev-svc">{ev.server?.replace('_server', '')}</span>
                          <span className="hp-ev-ip" title={src.linked ? `${src.sub}/${src.main} · ${ev.src_ip}` : ev.src_ip}>
                            {src.linked && <Icon name="link" size={11} />}
                            <span className="hp-ev-src">{src.main}</span>
                          </span>
                          <span className="hp-ev-data">{ev.data || ev.action}</span>
                          {handleHideEvent && (
                            <button
                              className="hp-ev-del"
                              title="Delete event"
                              aria-label="Delete event"
                              onClick={(e) => { e.stopPropagation(); handleHideEvent(ev); }}
                            ><Icon name="x" /></button>
                          )}
                        </div>
                      );
                    })}
                  </>
                )}
              </div>

              {selectedEvent && (
                <div className="hp-event-panel">
                  <div className="hp-event-panel-header">
                    <span>Event Detail</span>
                    <button className="hp-panel-close" onClick={() => setSelectedEvent(null)} aria-label="Close"><Icon name="x" /></button>
                  </div>
                  <div className="hp-event-panel-body">

                    <div className="hp-ep-section">
                      <div className="hp-ep-title">Request</div>
                      <KV k="Time" v={fmtTime(selectedEvent.timestamp)} />
                      <KV k="Service" v={selectedEvent.server?.replace('_server', '')} />
                      <KV k="Action" v={selectedEvent.action} />
                      <KV k="From" v={`${selectedEvent.src_ip || '—'}:${selectedEvent.src_port || '—'}`} tone="danger" />
                      <KV k="To" v={`${selectedEvent.honeypotName || selected.name}${selectedEvent.pod ? ` (${selectedEvent.pod})` : ''}`} />
                      <KV k="Username" v={selectedEvent.username} tone="danger" />
                      <KV k="Password" v={selectedEvent.password} tone="danger" />
                      <KV k="Data" v={selectedEvent.data} />
                    </div>

                    <div className="hp-ep-section">
                      <div className="hp-ep-title">Client</div>
                      {selectedEvent.client
                        ? <ClientCard client={selectedEvent.client} />
                        : <SnapshotCard ip={selectedEvent.src_ip} pod={resolveIP(selectedEvent.src_ip)} />}
                    </div>

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
            {events.length > 0 && <div className="dw-foot"><Pager {...pager} noun="events" /></div>}
            </>
          )}
        </div>
      </div>
    )}
  </div>
  );
}
