import { kindMeta } from './alertsUtils';
import { fmtPorts } from './alertsUtils';
import { DetailRow } from './AlertsUi';

function shortHash(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, '0');
}

function cleanCred(v) {
  if (v == null) return null;
  const s = String(v);
  if (s === '') return null;
  if (/^[\x20-\x7E]+$/.test(s)) return s;
  const stripped = s.replace(/[\x00-\x1F\x7F�]+/g, '').trim();
  if (stripped.length >= 2 && /^[\x20-\x7E]+$/.test(stripped)) return stripped;
  return `uid:${shortHash(s)}`;
}

function ipOrDash(ip) {
  return (ip && ip !== '0.0.0.0') ? ip : '—';
}

export function AlertDetail({ selected, bucketsOpen, setSelected }) {
  if (!selected || bucketsOpen) return null;
  return (
    <div className="al-detail">
      <div className="al-detail-head">
        <span className="al-detail-kind">{kindMeta(selected.kind).label}</span>
        <button className="al-detail-close" onClick={() => setSelected(null)}>✕</button>
      </div>

      <div className="al-detail-body">

        {selected._isDigest ? (
          <>
            <section className="al-section">
              <div className="al-section-title">Image</div>
              <DetailRow label="Name"      val={selected.src_pod} />
              <DetailRow label="Namespace" val={selected.src_namespace} />
              <DetailRow label="Detected"  val={new Date(selected.ts).toLocaleString()} />
            </section>
            <section className="al-section">
              <div className="al-section-title">Digest</div>
              <DetailRow label="Previous" val={selected._previousDigest ? `${selected._previousDigest}…` : '—'} mono />
              <DetailRow label="Current"  val={selected._currentDigest  ? `${selected._currentDigest}…`  : '—'} mono />
            </section>
          </>
        ) : selected._isHoneypot ? (
          <>
            <section className="al-section">
              <div className="al-section-title">Source (attacker)</div>
              <DetailRow label="IP"   val={selected.src_ip   || '—'} mono />
              <DetailRow label="Port" val={selected.src_port || '—'} />
            </section>
            <section className="al-section">
              <div className="al-section-title">Target (honeypot)</div>
              <DetailRow label="Honeypot"  val={selected.honeypotName || selected.src_pod} />
              <DetailRow label="Namespace" val={selected.src_namespace} />
              <DetailRow label="IP"        val={ipOrDash(selected.dst_ip)} mono />
              <DetailRow label="Port"      val={selected.dst_port || '—'} />
              <DetailRow label="Service"   val={(selected.server || '').replace('_server', '') || '—'} />
            </section>
            {(() => {
              const user = cleanCred(selected.username);
              const pass = cleanCred(selected.password);
              const data = cleanCred(selected.data);
              if (!user && !pass && !data) return null;
              return (
                <section className="al-section">
                  <div className="al-section-title">Captured</div>
                  {user && <DetailRow label="Username" val={user} mono />}
                  {pass && <DetailRow label="Password" val={pass} mono />}
                  {data && <DetailRow label="Data"     val={data} mono />}
                </section>
              );
            })()}
            <section className="al-section">
              <div className="al-section-title">Event</div>
              <DetailRow label="ID"        val={selected.id} mono />
              <DetailRow label="Timestamp" val={new Date(selected.ts).toLocaleString()} />
              <DetailRow label="Kind"      val={selected.kind} mono />
            </section>
          </>
        ) : (
          <>
            <section className="al-section">
              <div className="al-section-title">Source</div>
              <DetailRow label="Namespace"  val={selected.src_namespace} />
              <DetailRow label="Deployment" val={selected.src_deployment} />
              <DetailRow label="Pod"        val={selected.src_pod} />
              {selected.src_ip        && <DetailRow label="Pod IP"    val={selected.src_ip} mono />}
              {selected.src_container && <DetailRow label="Container" val={selected.src_container} />}
              <DetailRow label="Node"       val={selected.src_node} />
              <DetailRow label="Process"    val={selected.src_process} />
            </section>

            <section className="al-section">
              <div className="al-section-title">Destination</div>
              <DetailRow label="IP"       val={selected.dst_ip} />
              <DetailRow label="Port"     val={fmtPorts(selected)} />
              <DetailRow label="Protocol" val={selected.protocol} />
            </section>

            {selected.kind === 'port_scan' && (
              <section className="al-section">
                <div className="al-section-title">Port Scan Detail</div>
                <DetailRow label="Unique ports" val={selected.port_count} />
                <DetailRow label="Window"       val={`${selected.window_sec}s`} />
                <div className="al-ports-wrap">
                  {(selected.scanned_ports || []).map(p => (
                    <span key={p} className="al-port-pill">{p}</span>
                  ))}
                </div>
              </section>
            )}

            {selected.kind === 'suspicious_port' && (
              <section className="al-section">
                <div className="al-section-title">Port Classification</div>
                <DetailRow label="Label" val={selected.port_label} />
              </section>
            )}

            <section className="al-section">
              <div className="al-section-title">Event</div>
              <DetailRow label="ID"        val={selected.id} mono />
              <DetailRow label="Timestamp" val={new Date(selected.ts).toLocaleString()} />
              <DetailRow label="Kind"      val={selected.kind} mono />
              {selected.syscall  && <DetailRow label="Syscall"   val={selected.syscall} mono />}
              {selected.detail   && <DetailRow label="Detail"    val={selected.detail} mono />}
              {selected.baseline_state && <DetailRow label="Baseline" val={selected.baseline_state} />}
            </section>
          </>
        )}

      </div>
    </div>
  );
}
