import { Icon } from './Icon';

const ICON = { ok: 'check', fail: 'x', warn: 'alert' };

export function ProgressLine({ line, compact }) {
  const kind = ICON[line?.kind] ? line.kind : null;
  return (
    <div className={`progress-line${compact ? ' progress-line--compact' : ''}${kind ? ` progress-line--${kind}` : ' t-secondary'}`}>
      {kind && <Icon name={ICON[kind]} />}
      <span>{line?.text ?? String(line ?? '')}</span>
    </div>
  );
}
