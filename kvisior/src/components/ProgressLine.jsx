import { Icon } from './Icon';

const KIND = {
  ok:   { icon: 'check',   color: 'var(--accent-3)' },
  fail: { icon: 'x',       color: 'var(--danger)' },
  warn: { icon: 'alert',   color: 'var(--warning)' },
};

export function ProgressLine({ line, compact }) {
  const k = KIND[line?.kind];
  return (
    <div className={`progress-line${compact ? ' progress-line--compact' : ''}`} style={{ color: k ? k.color : 'var(--text-secondary)' }}>
      {k && <Icon name={k.icon} />}
      <span>{line?.text ?? String(line ?? '')}</span>
    </div>
  );
}
