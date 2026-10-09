import { sseUrl } from '../../data/cluster';
import { useState, useEffect, useCallback, useRef } from 'react';
import { useSensor } from '../../context/SensorContext';
import '../../styles/honeypot.scss';
import { DEFAULT_NS, STATE_LABEL } from './honeypotConstants';
import { apiList, apiCreate, apiDelete, apiEvents, apiPersistedEvents, apiHideEvent, apiHiddenEvents } from './honeypotApi';
import { svcByName } from './honeypotUtils';
import { HoneypotDetail } from './HoneypotDetail';
import { CreateModal } from './CreateModal';
import { Icon } from '../../components/Icon';

function kindShort(kind) {
  if (kind === 'StatefulSet') return 'sts';
  if (kind === 'Deployment') return 'deploy';
  return (kind || 'pod').toLowerCase();
}

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

  const [catalog,      setCatalog]      = useState([]);
  const [formSvc,      setFormSvc]      = useState('postgres');
  const [formName,     setFormName]     = useState('postgres');
  const [nameTouched,  setNameTouched]  = useState(false);
  const [formNs,       setFormNs]       = useState('production');
  const [creating,     setCreating]     = useState(false);
  const [createErr,    setCreateErr]    = useState(null);
  const [deleting,     setDeleting]     = useState(false);

  const pollRef = useRef(null);
  const selectedRef = useRef(null);
  const quietRef = useRef(null);
  const loadEventsRef = useRef(null);

  const loadList = useCallback(async () => {
    try {
      const data = await apiList();
      const list = data.honeypots || [];
      setHoneypots(prev => list.map(h => {
        const old = prev.find(p => p.name === h.name && p.namespace === h.namespace);
        return old?.eventCount && !h.eventCount ? { ...h, eventCount: old.eventCount } : h;
      }));
      if (Array.isArray(data.catalog)) setCatalog(data.catalog);
      setSelected(cur => cur ? (list.find(h => h.name === cur.name && h.namespace === cur.namespace) || cur) : cur);
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
    const es = new EventSource(sseUrl('/honey/api/honeypots/stream'));

    es.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        const event = msg.event || msg;
        const honeypotName = msg.honeypotName || event.honeypotName;
        const namespace = msg.namespace || event.namespace;
        if (!honeypotName) return;

        setHoneypots(prev => prev.map(h =>
          h.name === honeypotName && h.namespace === namespace
            ? { ...h, eventCount: (h.eventCount || 0) + 1 }
            : h
        ));

        const cur = selectedRef.current;
        if (cur?.name === honeypotName && cur?.namespace === namespace) {
          setEvents(evs => {
            const exists = evs.some(ev =>
              ev.timestamp === event.timestamp && ev.action === event.action &&
              ev.src_ip === event.src_ip && ev.src_port === event.src_port);
            return exists ? evs : [...evs, event];
          });
          clearTimeout(quietRef.current);
          quietRef.current = setTimeout(() => {
            const now = selectedRef.current;
            if (now?.name === honeypotName && now?.namespace === namespace) loadEventsRef.current?.(now, true);
          }, 5000);
        }
      } catch {}
    };

    es.onerror = () => {
    };

    return () => { es.close(); clearTimeout(quietRef.current); };
  }, []);

  const loadEvents = useCallback(async (hp, quiet = false) => {
    if (!hp) return;
    if (!quiet) {
      setLoading(true);
      setSelectedEvent(null);
    }
    try {
      const ns = hp.namespace || DEFAULT_NS;
      const [data, persisted, hidden] = await Promise.all([
        apiEvents(hp.name, ns).catch(() => ({ events: [] })),
        apiPersistedEvents(hp.name, ns).catch(() => ({ events: [] })),
        apiHiddenEvents(hp.name, ns).catch(() => ({ ids: [] })),
      ]);
      const hiddenSet = new Set(hidden.ids || []);

      const byId = new Map();
      for (const e of [...(data.events || []), ...(persisted.events || [])]) {
        if (hiddenSet.has(e.id)) continue;
        const key = e.id || `${e.timestamp}\x1f${e.action}\x1f${e.src_ip}\x1f${e.src_port}`;
        byId.set(key, { ...(byId.get(key) || {}), ...e });
      }
      const evs = [...byId.values()].sort(
        (a, b) => String(a.timestamp).localeCompare(String(b.timestamp))
      );
      setEvents(evs);
      if (quiet) setSelectedEvent(sel => sel ? (evs.find(e => e.id && e.id === sel.id) || sel) : sel);
      if (evs.length > 0) {
        setHoneypots(prev => prev.map(h =>
          h.name === hp.name && h.namespace === hp.namespace
            ? { ...h, eventCount: evs.length }
            : h
        ));
      }
    } catch (e) {
      if (!quiet) setEvents([]);
    } finally {
      if (!quiet) setLoading(false);
    }
  }, []);
  loadEventsRef.current = loadEvents;

  const selectedKey = selected ? `${selected.namespace}/${selected.name}` : '';
  useEffect(() => {
    if (selectedRef.current) loadEvents(selectedRef.current);
  }, [selectedKey, loadEvents]);

  function resolveIP(ip) {
    if (!ip || ip === '0.0.0.0') return null;
    return snapshot?.pods?.find(p => p.status?.podIP === ip) || null;
  }

  function openCreate() {
    setCreateErr(null);
    setShowModal(true);
  }

  function pickSvc(name) {
    setFormSvc(name);
    if (!nameTouched) setFormName(svcByName(name, catalog).defaultName);
  }

  function editName(v) {
    setNameTouched(v.trim() !== '');
    setFormName(v);
  }

  async function handleCreate() {
    const svc = svcByName(formSvc, catalog);
    const name = formName.trim() || svc.defaultName;
    if (!formSvc) return;
    if (!/^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(name) || name.length > 40) {
      setCreateErr('Name must be lowercase letters, digits and "-" (max 40 chars), e.g. orders-db');
      return;
    }
    setCreating(true);
    setCreateErr(null);
    try {
      const ns = formNs.trim() || DEFAULT_NS;
      await apiCreate({ name, namespace: ns, service: formSvc });
      setShowModal(false);
      setNameTouched(false);
      setFormName(svc.defaultName);
      await loadList();
      setSelected(cur => cur && cur.name === name && cur.namespace === ns ? cur : { name, namespace: ns, services: [formSvc], kind: svc.kind });
      setDetailTab('info');
    } catch (e) {
      setCreateErr(e.message);
    } finally {
      setCreating(false);
    }
  }

  async function handleDelete(hp) {
    const what = hp.legacy ? 'Pod and Service' : `${hp.kind}, Service and NetworkPolicy`;
    if (!window.confirm(`Delete honeypot "${hp.name}" in namespace "${hp.namespace}"?\n\nThis removes the ${what}.`)) return;
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
          <span><Icon name="alert" /> {error}</span>
          <button onClick={() => setError(null)}><Icon name="x" /></button>
        </div>
      )}
      {honeypots.length === 0 && !error && (
        <div className="hp-empty">
          <div className="hp-empty-icon"><Icon name="honeypot" size={28} /></div>
          <div className="hp-empty-title">No honeypots deployed</div>
          <div className="hp-empty-sub">
            Deploy fake services inside your cluster to detect lateral movement and unauthorized access.
          </div>
          <button className="hp-btn-primary" onClick={openCreate}>
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
              <button className="hp-add-btn" onClick={openCreate} aria-label="Create honeypot" title="Create honeypot">+</button>
            </div>

            {honeypots.map(hp => (
              <div
                key={`${hp.namespace}/${hp.name}`}
                className={`hp-item${hasAlert(hp) ? ' hp-item--alert' : ''}${selected?.name === hp.name && selected?.namespace === hp.namespace ? ' hp-item--active' : ''}`}
                onClick={() => selectHp(hp)}
              >
                <div className="hp-item-name">
                  <span className={`hp-dot${hasAlert(hp) ? ' hp-dot--alert' : hp.state && hp.state !== 'ok' ? ' hp-dot--off' : ''}`} />
                  {hp.name}
                  {hasAlert(hp) && <span className="hp-alert-badge">!</span>}
                </div>
                <div className="hp-item-meta">{hp.namespace} · {hp.clusterIP || '—'}</div>
                <div className="hp-item-services">
                  <span className={`hp-kind-badge${hp.legacy ? ' hp-kind-badge--legacy' : ''}`}>
                    {hp.legacy ? 'legacy pod' : kindShort(hp.kind)}
                  </span>
                  {(hp.services || []).map(s => {
                    const svc = svcByName(s, catalog);
                    return (
                      <span key={s} className="hp-svc-badge">
                        {svc.name}:{hp.port || svc.port}
                      </span>
                    );
                  })}
                  {hp.state && hp.state !== 'ok' && STATE_LABEL[hp.state] && (
                    <span className={`hp-state hp-state--${STATE_LABEL[hp.state].tone}`}>{STATE_LABEL[hp.state].text}</span>
                  )}
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
             catalog={catalog}
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
        catalog={catalog}
        formName={formName} setFormName={editName}
        formNs={formNs} setFormNs={setFormNs}
        formSvc={formSvc} pickSvc={pickSvc}
        createErr={createErr} creating={creating} handleCreate={handleCreate}
      />

    </div>
  );
}
