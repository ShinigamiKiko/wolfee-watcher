import { useState, useEffect, useCallback, useRef } from 'react';
import { useSensor } from '../../context/SensorContext';
import '../../styles/honeypot.scss';
import { SERVICES, DEFAULT_NS } from './honeypotConstants';
import { apiList, apiCreate, apiDelete, apiEvents, apiPersistedEvents, apiHideEvent, apiHiddenEvents } from './honeypotApi';
import { svcByName, fmtTime } from './honeypotUtils';
import { HoneypotDetail } from './HoneypotDetail';
import { CreateModal } from './CreateModal';

export function Honeypot() {
  const { snapshot } = useSensor();

  const [honeypots,    setHoneypots]    = useState([]);
  const [selected,     setSelected]     = useState(null);
  const [events,       setEvents]       = useState([]);
  const [detailTab,    setDetailTab]    = useState('info');
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [loading,      setLoading]      = useState(false);
  const [error,        setError]        = useState(null);
  const [showModal,    setShowModal]    = useState(false);

  const [formName,     setFormName]     = useState('');
  const [formNs,       setFormNs]       = useState('production');
  const [formSvcs,     setFormSvcs]     = useState(['redis', 'postgres', 'elastic', 'dns']);
  const [creating,     setCreating]     = useState(false);
  const [createErr,    setCreateErr]    = useState(null);
  const [deleting,     setDeleting]     = useState(false);

  const pollRef = useRef(null);
  const selectedRef = useRef(null);

  const loadList = useCallback(async () => {
    try {
      const data = await apiList();
      setHoneypots(data.honeypots || []);
    } catch (e) {
      setError(e.message);
    }
  }, []);

  useEffect(() => {
    loadList();
    pollRef.current = setInterval(loadList, 15_000);
    return () => clearInterval(pollRef.current);
  }, [loadList]);

  useEffect(() => {
    selectedRef.current = selected;
  }, [selected]);

  useEffect(() => {
    const es = new EventSource('/honey/api/honeypots/stream');

    es.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        const { honeypotName, namespace, event } = msg;

        setHoneypots(prev => prev.map(h =>
          h.name === honeypotName && h.namespace === namespace
            ? { ...h, eventCount: (h.eventCount || 0) + 1 }
            : h
        ));

        const cur = selectedRef.current;
        if (cur?.name === honeypotName && cur?.namespace === namespace) {
          setEvents(evs => {
            const exists = evs.some(ev => ev.timestamp === event.timestamp && ev.action === event.action);
            return exists ? evs : [...evs, event];
          });
        }
      } catch {}
    };

    es.onerror = () => {
    };

    return () => es.close();
  }, []);

  const loadEvents = useCallback(async (hp) => {
    if (!hp) return;
    setLoading(true);
    setSelectedEvent(null);
    try {
      const ns = hp.namespace || DEFAULT_NS;
      const [data, persisted, hidden] = await Promise.all([
        apiEvents(hp.name, ns).catch(() => ({ events: [] })),
        apiPersistedEvents(hp.name, ns).catch(() => ({ events: [] })),
        apiHiddenEvents(hp.name, ns).catch(() => ({ ids: [] })),
      ]);
      const hiddenSet = new Set(hidden.ids || []);

      const byId = new Map();
      for (const e of [...(persisted.events || []), ...(data.events || [])]) {
        if (hiddenSet.has(e.id)) continue;
        if (e.id) byId.set(e.id, e);
        else byId.set(`${e.timestamp}\x1f${e.action}\x1f${e.src_ip}`, e);
      }
      const evs = [...byId.values()].sort(
        (a, b) => String(a.timestamp).localeCompare(String(b.timestamp))
      );
      setEvents(evs);
      if (evs.length > 0) {
        setHoneypots(prev => prev.map(h =>
          h.name === hp.name && h.namespace === hp.namespace
            ? { ...h, eventCount: evs.length }
            : h
        ));
      }
    } catch (e) {
      setEvents([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (selected) loadEvents(selected);
  }, [selected, loadEvents]);

  function resolveIP(ip) {
    if (!ip || ip === '0.0.0.0') return null;
    return snapshot?.pods?.find(p => p.status?.podIP === ip) || null;
  }

  async function handleCreate() {
    const name = formName.trim();
    if (!name || formSvcs.length === 0) return;
    if (!/^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(name) || name.length > 40) {
      setCreateErr('Name must be lowercase letters, digits and "-" (max 40 chars), e.g. prod-redis-trap');
      return;
    }
    setCreating(true);
    setCreateErr(null);
    try {
      await apiCreate({ name, namespace: formNs.trim() || DEFAULT_NS, services: formSvcs });
      setShowModal(false);
      setFormName('');
      setFormSvcs(['redis', 'postgres', 'elastic', 'dns']);
      await loadList();
    } catch (e) {
      setCreateErr(e.message);
    } finally {
      setCreating(false);
    }
  }

  async function handleDelete(hp) {
    if (!window.confirm(`Delete honeypot "${hp.name}" in namespace "${hp.namespace}"?\n\nThis will remove the Pod, Service and ConfigMap.`)) return;
    setDeleting(true);
    setError(null);
    try {
      await apiDelete(hp.name, hp.namespace || DEFAULT_NS);
      if (selected?.name === hp.name && selected?.namespace === hp.namespace) setSelected(null);
      await loadList();
    } catch (e) {
      setError(`Delete failed: ${e.message}`);
    } finally {
      setDeleting(false);
    }
  }

  async function handleHideEvent(ev) {
    if (!selected) return;
    const ns = selected.namespace || DEFAULT_NS;
    const prev = events;
    setEvents(evs => evs.filter(e => e !== ev));
    if (selectedEvent === ev) setSelectedEvent(null);
    setHoneypots(hps => hps.map(h =>
      h.name === selected.name && h.namespace === selected.namespace
        ? { ...h, eventCount: Math.max(0, (h.eventCount || 1) - 1) }
        : h
    ));
    try {
      await apiHideEvent(selected.name, ns, ev.id);
    } catch (e) {
      setEvents(prev);
      setError(`Delete event failed: ${e.message}`);
    }
  }

  function toggleSvc(name) {
    setFormSvcs(prev =>
      prev.includes(name) ? prev.filter(s => s !== name) : [...prev, name]
    );
  }

  function selectHp(hp) {
    setSelected(hp);
    setDetailTab('events');
    setSelectedEvent(null);
  }

  function hasAlert(hp) {
    return hp.eventCount > 0;
  }

  return (
    <div className="hp-page">

      {}
      {error && (
        <div className="hp-error-banner">
          <span>⚠ {error}</span>
          <button onClick={() => setError(null)}>✕</button>
        </div>
      )}
      {honeypots.length === 0 && !error && (
        <div className="hp-empty">
          <div className="hp-empty-icon">🍯</div>
          <div className="hp-empty-title">No honeypots deployed</div>
          <div className="hp-empty-sub">
            Deploy fake services inside your cluster to detect lateral movement and unauthorized access.
          </div>
          <button className="hp-btn-primary" onClick={() => setShowModal(true)}>
            + Create Honeypot
          </button>
        </div>
      )}

      {}
      {honeypots.length > 0 && (
        <div className="hp-layout">

          {}
          <div className="hp-list">
            <div className="hp-list-header">
              <span>Honeypots <span className="hp-count">({honeypots.length})</span></span>
              <button className="hp-add-btn" onClick={() => setShowModal(true)}>+</button>
            </div>

            {honeypots.map(hp => (
              <div
                key={`${hp.namespace}/${hp.name}`}
                className={`hp-item${hasAlert(hp) ? ' hp-item--alert' : ''}${selected?.name === hp.name && selected?.namespace === hp.namespace ? ' hp-item--active' : ''}`}
                onClick={() => selectHp(hp)}
              >
                <div className="hp-item-name">
                  <span className={`hp-dot${hasAlert(hp) ? ' hp-dot--alert' : ''}`} />
                  {hp.name}
                  {hasAlert(hp) && <span className="hp-alert-badge">!</span>}
                </div>
                <div className="hp-item-meta">{hp.namespace} · {hp.clusterIP || '—'}</div>
                <div className="hp-item-services">
                  {(hp.services || []).map(s => {
                    const svc = svcByName(s);
                    return (
                      <span key={s} className="hp-svc-badge">
                        {svc.name}:{svc.port}
                      </span>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>

          {}
          <HoneypotDetail
             selected={selected}
             selectedEvent={selectedEvent}
             setSelectedEvent={setSelectedEvent}
             detailTab={detailTab}
             setDetailTab={setDetailTab}
             events={events}
             loading={loading}
             snapshot={snapshot}
             hasAlert={hasAlert}
             deleting={deleting}
             resolveIP={resolveIP}
             handleDelete={handleDelete}
             handleHideEvent={handleHideEvent}
           />
        </div>
      )}

      {}
      <CreateModal
        showModal={showModal} setShowModal={setShowModal}
        formName={formName} setFormName={setFormName}
        formNs={formNs} setFormNs={setFormNs}
        formSvcs={formSvcs} toggleSvc={toggleSvc}
        createErr={createErr} creating={creating} handleCreate={handleCreate}
      />

    </div>
  );
}
