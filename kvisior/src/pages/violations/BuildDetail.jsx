import { useScanner } from '../../context/ScannerContext';
import { SevBadge }   from '../../components/ui';
import { SidePanel, DetailSection, KV, Notice } from '../../components/kit';

const fmtLayer = (raw = '') => raw
  .replace(/^\/bin\/sh -c #\(nop\)\s+/, '')
  .replace(/^\/bin\/sh -c\s+/, 'RUN ')
  .trim() || raw;

function highlight(text, query) {
  if (!query) return text;
  const lowerText = text.toLowerCase();
  const lowerQuery = query.toLowerCase();
  const parts = [];
  let offset = 0;
  let index;
  while ((index = lowerText.indexOf(lowerQuery, offset)) !== -1) {
    if (index > offset) parts.push(<span key={offset}>{text.slice(offset, index)}</span>);
    parts.push(<mark key={index} className="hit">{text.slice(index, index + query.length)}</mark>);
    offset = index + query.length;
  }
  if (offset < text.length) parts.push(<span key={offset}>{text.slice(offset)}</span>);
  return parts.length ? parts : text;
}

export function BuildDetail({ v, onClose }) {
  const { histories } = useScanner();
  if (!v) return null;

  const hist      = histories.find(h => h.image === v.image);
  const matchText = v.instruction?.trim().slice(0, 256) || '';
  const layers    = hist?.layers || [];

  const status = hist?.status === 'unavailable'
    ? <span className="t-danger t-xs">{hist.error}</span>
    : (!hist || hist.status === 'fetching') ? <span className="t-muted t-xs">loading…</span> : null;

  return (
    <SidePanel title={v.policy} meta={<span className="mono">{v.image}</span>} onClose={onClose} actions={<SevBadge sev={v.sev} />}>
      <Notice tone="warning">{v.detail}</Notice>

      <DetailSection title="Dockerfile" aside={status}>
        {layers.length > 0 ? (
          <ol className="layers">
            {layers.map((l, i) => {
              const instruction = fmtLayer(l.created_by);
              if (!instruction || instruction === 'nop') return null;
              const isEmpty = l.empty_layer;
              const isMatch = !isEmpty && matchText && instruction.toLowerCase().includes(matchText.toLowerCase());
              return (
                <li key={i} className={isMatch ? 'match' : isEmpty ? 'empty' : undefined}>
                  <span className="layers-n">{i + 1}</span>
                  <span className="layers-text">{isMatch ? highlight(instruction, matchText) : instruction}</span>
                </li>
              );
            })}
          </ol>
        ) : hist?.status === 'done' ? (
          <div className="t-sm t-muted">No layers found.</div>
        ) : null}
      </DetailSection>

      <DetailSection>
        <KV items={[
          ['Pattern', <code className="inline">{v.instruction || '—'}</code>],
          ['Action', v.action || 'alert'],
          v.namespace && ['Namespace', v.namespace],
        ]} />
      </DetailSection>
    </SidePanel>
  );
}
