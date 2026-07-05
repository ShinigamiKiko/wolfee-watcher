import { useScanner } from '../../context/ScannerContext';
import { SevBadge }   from '../../components/ui';

const fmtLayer = (raw = '') => raw
  .replace(/^\/bin\/sh -c #\(nop\)\s+/, '')
  .replace(/^\/bin\/sh -c\s+/, 'RUN ')
  .trim() || raw;

function buildRegex(pattern) {
  try {
    return new RegExp(`(${pattern})`, 'gi');
  } catch {
    return new RegExp(`(${pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
  }
}

function highlight(text, matchRe) {
  if (!matchRe) return <span>{text}</span>;
  matchRe.lastIndex = 0;
  const parts = [];
  let last = 0, m;
  while ((m = matchRe.exec(text)) !== null) {
    if (m.index > last) parts.push(<span key={last}>{text.slice(last, m.index)}</span>);
    parts.push(
      <mark key={m.index} style={{ background: 'rgba(245,158,11,.35)', color: 'var(--warning)', borderRadius: 3, padding: '0 2px', fontWeight: 700 }}>
        {m[0]}
      </mark>
    );
    last = m.index + m[0].length;
    if (m[0].length === 0) { matchRe.lastIndex++; break; }
  }
  if (last < text.length) parts.push(<span key={last}>{text.slice(last)}</span>);
  return parts.length ? parts : <span>{text}</span>;
}

export function BuildDetail({ v, onClose }) {
  if (!v) return null;

  const { histories } = useScanner();
  const hist    = histories.find(h => h.image === v.image);
  const matchRe = v.instruction ? buildRegex(v.instruction) : null;
  const layers  = hist?.layers || [];

  return (
    <div className="detail-panel open">
      <div className="detail-panel-inner">
        <div className="dp-header">
          <div style={{ minWidth: 0 }}>
            <div className="dp-title">{v.policy}</div>
            <div className="dp-meta" style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 11 }}>{v.image}</div>
          </div>
          <button className="dp-close" onClick={onClose}>✕</button>
        </div>

        <div style={{ marginBottom: 12 }}><SevBadge sev={v.sev} /></div>

        <div style={{ padding: '9px 12px', background: 'rgba(245,158,11,.07)', border: '1px solid rgba(245,158,11,.2)',
          borderRadius: 8, marginBottom: 16, fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
          <span style={{ color: 'var(--warning)', fontWeight: 600, marginRight: 6 }}>⚠</span>
          {v.detail}
        </div>

        <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '.09em', textTransform: 'uppercase',
          color: 'var(--text-muted)', marginBottom: 8, borderBottom: '1px solid var(--border)', paddingBottom: 4 }}>
          Dockerfile
          {hist?.status === 'unavailable' && <span style={{ color: 'var(--danger)', marginLeft: 8, textTransform: 'none', fontWeight: 400, fontSize: 10 }}>{hist.error}</span>}
          {(!hist || hist.status === 'fetching') && <span style={{ color: 'var(--text-muted)', marginLeft: 8, textTransform: 'none', fontWeight: 400, fontSize: 10 }}>loading…</span>}
        </div>

        {layers.length > 0 ? (
          <div style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 11, lineHeight: 1.75,
            background: 'var(--bg-base)', borderRadius: 8, border: '1px solid var(--border)',
            overflow: 'auto', maxHeight: 400, padding: '8px 0' }}>
            {layers.map((l, i) => {
              const instruction = fmtLayer(l.created_by);
              if (!instruction || instruction === 'nop') return null;
              const isEmpty = l.empty_layer;
              const isMatch = !isEmpty && matchRe && (() => { matchRe.lastIndex = 0; return matchRe.test(l.created_by || ''); })();
              return (
                <div key={i} style={{ display: 'flex', borderLeft: isMatch ? '2px solid var(--warning)' : '2px solid transparent', padding: '0 10px 0 8px', opacity: isEmpty ? 0.45 : 1 }}>
                  <span style={{ color: 'var(--text-muted)', userSelect: 'none', marginRight: 14, minWidth: 22, textAlign: 'right', flexShrink: 0, opacity: .4, fontSize: 10 }}>
                    {i + 1}
                  </span>
                  <span style={{ color: isEmpty ? 'var(--text-muted)' : 'var(--text-secondary)', whiteSpace: 'pre-wrap', wordBreak: 'break-all', flex: 1 }}>
                    {isMatch ? highlight(instruction, matchRe) : instruction}
                  </span>
                </div>
              );
            })}
          </div>
        ) : hist?.status === 'done' ? (
          <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>No layers found.</div>
        ) : null}

        <div style={{ marginTop: 12, display: 'flex', flexDirection: 'column', gap: 4 }}>
          <div className="dp-kv"><span>Pattern</span><code style={{ fontSize: 11 }}>{v.instruction || '—'}</code></div>
          <div className="dp-kv"><span>Action</span><span>{v.action || 'alert'}</span></div>
          {v.namespace && <div className="dp-kv"><span>Namespace</span><span>{v.namespace}</span></div>}
        </div>
      </div>
    </div>
  );
}
