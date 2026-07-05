import { SEV, sev, STATUS_COLOR } from './auditConstants';

function DetailModal({ item, type, onClose }) {
  if (!item) return null;
  return (
    <div className="au-overlay" onClick={onClose}>
      <div className="au-modal" onClick={e=>e.stopPropagation()}>
        <div className="au-modal__hdr">
          <div className="au-modal__hdr-left">
            {type==='bench' && <>
              <code className="au-modal__id">{item.number}</code>
              <span style={{color:STATUS_COLOR[item.status],fontSize:11,fontWeight:700}}>{item.status}</span>
            </>}
            {type==='hunter' && item.id && <>
              <code className="au-modal__id">{item.id}</code>
              {item.severity && (
                <span className="au-modal__sev" style={{color:sev(item.severity).color,background:sev(item.severity).bg,border:`1px solid ${sev(item.severity).border}`}}>
                  {item.severity.toUpperCase()}
                </span>
              )}
            </>}
          </div>
          <button className="au-modal__x" onClick={onClose}>✕</button>
        </div>

        <div className="au-modal__title">
          {type==='bench' ? item.desc : item.vulnerability}
        </div>

        <div className="au-modal__body">
          {type==='bench' && <>
            {item.actual       && <F label="Actual value"><pre>{item.actual}</pre></F>}
            {item.expected     && <F label="Expected"><pre>{item.expected}</pre></F>}
            {item.reason       && <F label="Reason"><p>{item.reason}</p></F>}
            {item.remediation  && <F label="🔧 Remediation" hl><p>{item.remediation}</p></F>}
          </>}
          {type==='hunter' && <>
            {item.category     && <F label="Category"><code>{item.category}</code></F>}
            {item.hunter       && <F label="Hunter module"><code>{item.hunter}</code></F>}
            {item.location     && <F label="Location"><code>{item.location}</code></F>}
            {item.mitre        && <F label="MITRE ATT&CK"><code>{item.mitre}</code></F>}
            {(item.avd_description||item.description) && (
              <F label={item.avd_description?'📖 Description (AVD)':'📖 Description'}>
                <p>{item.avd_description||item.description}</p>
              </F>
            )}
            {item.avd_impact   && <F label="⚡ Impact"><p>{item.avd_impact}</p></F>}
            {item.evidence     && <F label="Evidence"><pre>{item.evidence}</pre></F>}
            {item.avd_remediation && <F label="🔧 Remediation (AVD)" hl><p>{item.avd_remediation}</p></F>}
            {item.avd_link     && <F label="AVD Reference"><a href={item.avd_link} target="_blank" rel="noreferrer">{item.avd_link}</a></F>}
          </>}
        </div>
      </div>
    </div>
  );
}

function F({ label, hl, children }) {
  return (
    <div className={`au-field${hl?' au-field--hl':''}`}>
      <div className="au-field__label">{label}</div>
      {children}
    </div>
  );
}


export { DetailModal, F };
