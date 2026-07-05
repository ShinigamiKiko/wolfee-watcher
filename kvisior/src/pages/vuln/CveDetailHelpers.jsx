import { SevBadge } from '../../components/ui';
import { sevColor, epssLabel } from '../../data/scanner';

function TabButton({ active, disabled, onClick, children }) {
  return (
    <button
      onClick={disabled ? undefined : onClick}
      disabled={disabled}
      style={{
        background:    'none',
        border:        'none',
        borderBottom:  active ? '2px solid var(--accent)' : '2px solid transparent',
        padding:       '8px 14px',
        marginBottom:  -1,
        color:         disabled ? 'var(--text-muted)' : (active ? 'var(--text-primary)' : 'var(--text-secondary)'),
        opacity:       disabled ? .45 : 1,
        cursor:        disabled ? 'not-allowed' : 'pointer',
        fontSize:      12,
        fontWeight:    active ? 600 : 500,
        letterSpacing: '.02em',
        userSelect:    'none',
      }}
    >{children}</button>
  );
}

function FstecPanel({ item, kv, showMore, setShowMore }) {
  const d = item.bduDetail;
  return (
    <div style={{ flex:1, overflowY:'auto', padding:'14px 16px', userSelect:'text' }}>
      {}
      <div style={{ display:'flex', gap:6, marginBottom:14, flexWrap:'wrap' }}>
        <span style={{
          fontSize:11, padding:'2px 8px', borderRadius:4,
          background:'rgba(239,68,68,.15)', color:'var(--danger)',
          fontFamily:'JetBrains Mono,monospace', fontWeight:700,
        }}>{item.bduId || 'БДУ'}</span>
        {item.bduSeverity && /^(critical|high|medium|low)$/i.test(item.bduSeverity) && (
          <span style={{
            fontSize:11, padding:'2px 8px', borderRadius:4,
            background:'rgba(255,255,255,.06)',
            color: FSTEC_SEV_COLOR[item.bduSeverity.toLowerCase()] || 'var(--text-secondary)',
            fontWeight:700, textTransform:'capitalize',
          }}>{item.bduSeverity}</span>
        )}
        {d?.exploitStatus && /существует/i.test(d.exploitStatus) && (
          <span style={{
            fontSize:11, padding:'2px 8px', borderRadius:4,
            background:'rgba(239,68,68,.15)', color:'var(--danger)', fontWeight:600,
          }}>💥 PoC</span>
        )}
        {d?.fixStatus && (
          <span style={{
            fontSize:11, padding:'2px 8px', borderRadius:4,
            background: d.fixStatus === 'Уязвимость устранена' ? 'rgba(16,185,129,.12)' : 'rgba(255,255,255,.06)',
            color:      d.fixStatus === 'Уязвимость устранена' ? 'var(--accent-3)' : 'var(--text-muted)',
          }}>{d.fixStatus}</span>
        )}
      </div>

      {!d && (
        <div style={{ fontSize:12, color:'var(--text-muted)', lineHeight:1.6, padding:'8px 12px', background:'var(--bg-elevated)', border:'1px solid var(--border)', borderRadius:8 }}>
          CVE найден в БДУ ФСТЭК, но детальная карточка не собрана на бэкенде
          (вероятно, выставлен <code style={{ color:'var(--text-secondary)' }}>BDU_NO_DETAIL</code>).
          Полная информация доступна на bdu.fstec.ru.
        </div>
      )}

      {d && (
        <>
          {}
          <div style={{ marginBottom:12 }}>
            {kv('БДУ ID',
              <span style={{ fontFamily:'JetBrains Mono,monospace', fontSize:11, color:'var(--danger)' }}>{d.identifier}</span>
            )}
            {d.vulStatus && kv('Статус', <span style={{ fontSize:11 }}>{d.vulStatus}</span>)}
            {d.exploitStatus && kv('Эксплуатация', <span style={{ fontSize:11 }}>{d.exploitStatus}</span>)}
            {d.fixStatus && kv('Исправление', <span style={{ fontSize:11 }}>{d.fixStatus}</span>)}
            {d.vulClass && kv('Класс', <span style={{ fontSize:11 }}>{d.vulClass}</span>)}
            {d.vulElimination && kv('Способ устранения', <span style={{ fontSize:11 }}>{d.vulElimination}</span>)}
            {(d.cwes?.length > 0) && kv('CWE',
              <span style={{ fontSize:11, lineHeight:1.6 }}>
                {d.cwes.map((cwe, i) => (
                  <span key={cwe.id}>
                    <span style={{ fontFamily:'JetBrains Mono,monospace' }}>{cwe.id}</span>
                    {cwe.name && <span style={{ color:'var(--text-muted)' }}> — {cwe.name}</span>}
                    {i < d.cwes.length - 1 ? '; ' : ''}
                  </span>
                ))}
              </span>
            )}
            {d.identifyDate    && kv('Выявлена',     <span style={{ fontSize:11 }}>{d.identifyDate}</span>)}
            {d.publicationDate && kv('Опубликована', <span style={{ fontSize:11 }}>{d.publicationDate}</span>)}
            {d.lastUpdDate     && kv('Обновлена',    <span style={{ fontSize:11 }}>{d.lastUpdDate}</span>)}
            {(d.cvss3Vector || d.cvss3Score > 0) && kv('CVSS 3 Vector',
              <CvssVectorValue vector={d.cvss3Vector} score={d.cvss3Score} />
            )}
            {(d.cvss2Vector || d.cvss2Score > 0) && kv('CVSS 2 Vector',
              <CvssVectorValue vector={d.cvss2Vector} score={d.cvss2Score} />
            )}
            {(d.cvss4Vector || d.cvss4Score > 0) && kv('CVSS 4 Vector',
              <CvssVectorValue vector={d.cvss4Vector} score={d.cvss4Score} />
            )}
          </div>

          {}
          {d.solution && (
            <div style={{ marginTop:8, marginBottom:12 }}>
              <div style={{ fontSize:11, textTransform:'uppercase', letterSpacing:'.07em', color:'var(--accent-3)', marginBottom:6, fontWeight:600 }}>
                Рекомендации ФСТЭК
              </div>
              <div style={{
                fontSize:    12,
                color:       'var(--text-secondary)',
                lineHeight:  1.6,
                whiteSpace:  'pre-wrap',
                padding:     '10px 12px',
                background:  'rgba(16,185,129,.06)',
                border:      '1px solid rgba(16,185,129,.18)',
                borderRadius: 8,
              }}>{linkifyURLs(d.solution)}</div>
            </div>
          )}

          {}
          {d.software?.length > 0 && (
            <div style={{ marginTop:8, marginBottom:12 }}>
              <div style={{ fontSize:11, textTransform:'uppercase', letterSpacing:'.07em', color:'var(--text-muted)', marginBottom:6 }}>Уязвимое ПО</div>
              <div>
                {d.software.map((s, i) => (
                  <SoftwareRow key={i} sw={s} />
                ))}
              </div>
            </div>
          )}

          {}
          {d.environments?.length > 0 && (
            <div style={{ marginTop:8, marginBottom:12 }}>
              <div style={{ fontSize:11, textTransform:'uppercase', letterSpacing:'.07em', color:'var(--text-muted)', marginBottom:6 }}>Среда функционирования</div>
              <div>
                {d.environments.map((e, i) => (
                  <SoftwareRow key={i} sw={e} />
                ))}
              </div>
            </div>
          )}

          {}
          {d.sources?.length > 0 && (
            <div style={{ marginTop:8, marginBottom:12 }}>
              <div style={{ fontSize:11, textTransform:'uppercase', letterSpacing:'.07em', color:'var(--text-muted)', marginBottom:6 }}>Источники</div>
              {d.sources.map((s, i) => (
                <a key={i} href={s} target="_blank" rel="noreferrer"
                  style={{ display:'block', fontSize:11, color:'var(--accent)', marginBottom:3, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                  {s}
                </a>
              ))}
            </div>
          )}

          {}
          {(d.description || d.name) && (
            <div style={{ marginTop:14 }}>
              <div style={{ fontSize:11, textTransform:'uppercase', letterSpacing:'.07em', color:'var(--text-muted)', marginBottom:6 }}>Description</div>
              <div style={{ fontSize:12, color:'var(--text-secondary)', lineHeight:1.6, whiteSpace:'pre-wrap' }}>
                {d.description || d.name}
              </div>
            </div>
          )}

          {}
          {hasShouldFields(d) && (
            <button
              onClick={() => setShowMore(s => !s)}
              style={{
                marginTop:    8,
                background:   'none',
                border:       '1px solid var(--border)',
                borderRadius: 6,
                padding:      '5px 10px',
                fontSize:     11,
                color:        'var(--text-secondary)',
                cursor:       'pointer',
              }}
            >{showMore ? '▾ Скрыть' : '▸ Ещё…'}</button>
          )}

          {showMore && (
            <div style={{ marginTop:10 }}>
              {d.slOperProcs?.length > 0 && kv('Способ эксплуатации',
                <span style={{ fontSize:11 }}>{d.slOperProcs.join(', ')}</span>
              )}
              {d.otherIds?.length > 0 && kv('Другие ID',
                <span style={{ fontSize:11, lineHeight:1.6 }}>
                  {d.otherIds.map((o, i) => (
                    <span key={i}>
                      {o.type && <span style={{ color:'var(--text-muted)' }}>{o.type}: </span>}
                      <span style={{ fontFamily:'JetBrains Mono,monospace' }}>{o.value}</span>
                      {i < d.otherIds.length - 1 ? '; ' : ''}
                    </span>
                  ))}
                </span>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}

function CvssVectorValue({ vector, score }) {
  return (
    <span style={{ fontFamily:'JetBrains Mono,monospace', fontSize:9, wordBreak:'break-all', color:'var(--text-muted)' }}>
      {vector}
      {score > 0 && (
        <span style={{ color:'var(--text-secondary)', fontWeight:700, marginLeft:vector ? 6 : 0, fontSize:11 }}>
          {score.toFixed(1)}
        </span>
      )}
    </span>
  );
}

function SoftwareRow({ sw }) {
  const parts = [];
  if (sw.vendor)  parts.push(sw.vendor);
  if (sw.name)    parts.push(sw.name);
  if (sw.version) parts.push(sw.version);
  if (sw.platform) parts.push(`(${sw.platform})`);
  return (
    <div style={{ fontSize:11, color:'var(--text-secondary)', padding:'4px 8px', background:'rgba(255,255,255,.03)', border:'1px solid rgba(255,255,255,.05)', borderRadius:6, marginBottom:4, fontFamily:'JetBrains Mono,monospace', wordBreak:'break-word' }}>
      {parts.join(' ')}
      {sw.types?.length > 0 && (
        <span style={{ color:'var(--text-muted)', marginLeft:6 }}>· {sw.types.join(', ')}</span>
      )}
    </div>
  );
}

function hasShouldFields(d) {
  return !!(d && (
    (d.slOperProcs && d.slOperProcs.length) ||
    (d.otherIds && d.otherIds.length)
  ));
}

function linkifyURLs(text) {
  if (!text) return null;
  const parts = text.split(/(https?:\/\/[^\s)<>"']+)/g);
  return parts.map((p, i) => {
    if (/^https?:\/\//.test(p)) {
      return <a key={i} href={p} target="_blank" rel="noreferrer" style={{ color:'var(--accent)', wordBreak:'break-all' }}>{p}</a>;
    }
    return <span key={i}>{p}</span>;
  });
}

export { TabButton, FstecPanel, CvssVectorValue, SoftwareRow, hasShouldFields, linkifyURLs };
