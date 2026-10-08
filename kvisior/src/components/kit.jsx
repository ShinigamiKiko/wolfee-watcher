import { Icon } from './Icon';

export const cx = (...parts) => parts.filter(Boolean).join(' ');

const SEV_TONE = { CRITICAL: 'danger', HIGH: 'warning', MEDIUM: 'info', LOW: 'ok' };

export const sevTone = sev => SEV_TONE[String(sev || '').toUpperCase()];

const STAT_TONE = { danger: 'danger', warning: 'warn', ok: 'success', accent: 'info' };

export function Stat({ label, value, sub, tone, onClick, active, title }) {
  const body = (
    <>
      <div className="stat-label">{label}</div>
      <div className={cx('stat-value', STAT_TONE[tone])}>{value}</div>
      {sub != null && <div className="stat-delta">{sub}</div>}
    </>
  );
  if (onClick) {
    return <button type="button" className={cx('stat-card', active && 'active')} aria-pressed={active} title={title} onClick={onClick}>{body}</button>;
  }
  return <div className="stat-card" title={title}>{body}</div>;
}

export function Crumbs({ items, meta }) {
  return (
    <div className="crumbs">
      {items.map((it, i) => {
        const last = i === items.length - 1;
        return (
          <span key={i} className="row row--tight">
            {last || !it.onClick
              ? <span className="crumbs-current">{it.label}</span>
              : <button type="button" className="crumbs-link" onClick={it.onClick}>{it.label}</button>}
            {!last && <span className="crumbs-sep" aria-hidden="true">›</span>}
          </span>
        );
      })}
      {meta && <span className="crumbs-meta">{meta}</span>}
    </div>
  );
}

export function SortTh({ col, label, sort, dir, onSort, title }) {
  const on = sort === col;
  return (
    <th className="th-sort" title={title} aria-sort={on ? (dir === 'desc' ? 'descending' : 'ascending') : undefined}>
      <button type="button" className="th-sort-btn" aria-sort={on ? dir : undefined} onClick={() => onSort(col)}>
        {label}<Icon name={on ? (dir === 'desc' ? 'chevron-down' : 'chevron-up') : 'sort'} />
      </button>
    </th>
  );
}

export function Score({ label, value, className }) {
  return (
    <div className="score">
      <div className="score-label">{label}</div>
      <div className={cx('score-value', className)}>{value}</div>
    </div>
  );
}

export function PageHeader({ title, subtitle, actions, children, className }) {
  return (
    <div className={cx('page-header', className)}>
      <div className="page-heading">
        <div className="page-title">{title}</div>
        {subtitle && <div className="page-subtitle">{subtitle}</div>}
      </div>
      {children}
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  );
}

export function Toolbar({ children, className }) {
  return <div className={cx('toolbar', className)}>{children}</div>;
}

export function SearchInput({ value, onChange, placeholder = 'Search…', label, className, width, size }) {
  return (
    <span className="input-wrap">
      <Icon name="search" />
      <input
        className={cx('input', 'input--search', size === 'sm' && 'input--sm', className)}
        style={width ? { width } : undefined}
        type="search"
        value={value}
        placeholder={placeholder}
        aria-label={label || placeholder}
        onChange={e => onChange(e.target.value)}
      />
    </span>
  );
}

export function Select({ value, onChange, options, label, className, children }) {
  return (
    <select className={cx('input', className)} value={value} aria-label={label} onChange={e => onChange(e.target.value)}>
      {options
        ? options.map(o => {
            const opt = typeof o === 'object' ? o : { value: o, label: o };
            return <option key={opt.value} value={opt.value}>{opt.label}</option>;
          })
        : children}
    </select>
  );
}

export function Seg({ options, value, onChange, label, className }) {
  return (
    <div className={cx('seg', className)} role="group" aria-label={label}>
      {options.map(o => {
        const opt = typeof o === 'object' ? o : { value: o, label: o };
        return (
          <button key={opt.value} type="button" aria-pressed={value === opt.value} disabled={opt.disabled}
            title={opt.title} onClick={() => onChange(opt.value)}>
            {opt.icon && <Icon name={opt.icon} />}{opt.label}
          </button>
        );
      })}
    </div>
  );
}

export function Chip({ pressed, onClick, children, title, disabled }) {
  return (
    <button type="button" className="chip" aria-pressed={!!pressed} onClick={onClick} title={title} disabled={disabled}>
      {children}
    </button>
  );
}

export function Tag({ tone, mono, outline, children, title, className }) {
  return (
    <span className={cx('tag', tone && `tag--${tone}`, mono && 'tag--mono', outline && 'tag--outline', className)} title={title}>
      {children}
    </span>
  );
}

export function Badge({ tone, children, title }) {
  return <span className={cx('badge', tone && `badge--${tone}`)} title={title}>{children}</span>;
}

const KIND_TONE = {
  Deployment: 'accent', StatefulSet: 'violet', DaemonSet: 'ok', ReplicaSet: 'accent', Job: 'warning', CronJob: 'warning', Pod: 'accent',
  ClusterRole: 'violet', Role: 'accent', ClusterRoleBinding: 'danger', RoleBinding: 'warning',
};

export function KindBadge({ kind }) {
  return <Badge tone={KIND_TONE[kind] || 'accent'}>{kind}</Badge>;
}

export function Pane({ title, sub, tools, footer, flush, className, bodyClassName, children }) {
  return (
    <section className={cx('pane', className)}>
      {(title || tools) && (
        <div className={cx('pane-head', flush && 'pane-head--flush')}>
          <div className="grow">
            {title && <div className="pane-title">{title}</div>}
            {sub && <div className="pane-sub">{sub}</div>}
          </div>
          {tools && <div className="pane-tools">{tools}</div>}
        </div>
      )}
      {children != null && <div className={cx('pane-body', bodyClassName)}>{children}</div>}
      {footer && <div className="pane-foot">{footer}</div>}
    </section>
  );
}

export function SectionLabel({ children, className }) {
  return <div className={cx('section-label', className)}>{children}</div>;
}

export function KV({ items, compact, className }) {
  return (
    <dl className={cx('kv', compact && 'kv--compact', className)}>
      {items.filter(Boolean).map(([k, v], i) => (
        <div key={typeof k === 'string' ? k : i}>
          <dt>{k}</dt>
          <dd>{v ?? '—'}</dd>
        </div>
      ))}
    </dl>
  );
}

export function CodeBlock({ children, wrap, tall, className }) {
  return <pre className={cx('code-block', wrap && 'code-block--wrap', tall && 'code-block--tall', className)}>{children}</pre>;
}

const NOTICE_ICON = { warning: 'alert', danger: 'alert', ok: 'circle-check' };

export function Notice({ tone, icon, children, className }) {
  const name = icon === false ? null : icon || NOTICE_ICON[tone] || 'info';
  return (
    <div className={cx('notice', tone && `notice--${tone}`, className)} role={tone === 'danger' ? 'alert' : undefined}>
      {name && <Icon name={name} />}
      <div className="grow">{children}</div>
    </div>
  );
}

export function Field({ label, hint, error, htmlFor, children, className }) {
  return (
    <div className={cx('field', className)}>
      {label && <label className="field-label" htmlFor={htmlFor}>{label}</label>}
      {children}
      {hint && !error && <div className="field-hint">{hint}</div>}
      {error && <div className="field-error">{error}</div>}
    </div>
  );
}

export function Switch({ checked, onChange, label, disabled }) {
  return (
    <button type="button" role="switch" className="switch" aria-checked={!!checked} aria-label={label}
      disabled={disabled} onClick={() => onChange(!checked)} />
  );
}

export function EmptyRow({ cols, children }) {
  return (
    <tr className="empty-row">
      <td colSpan={cols}>{children}</td>
    </tr>
  );
}

export function Meter({ value, max = 100, color, label, showValue = true }) {
  const pct = max > 0 ? Math.max(0, Math.min(100, (value / max) * 100)) : 0;
  return (
    <div className="meter" role="meter" aria-valuenow={value} aria-valuemin={0} aria-valuemax={max} aria-label={label}>
      <div className="meter-track"><div className="meter-fill" style={{ width: `${pct}%`, background: color }} /></div>
      {showValue && <span className="meter-value">{Math.round(pct)}%</span>}
    </div>
  );
}

export function Metrics({ items, cols, className }) {
  return (
    <div className={cx('metrics', cols && cols !== 4 && `metrics--${cols}`, className)}>
      {items.filter(Boolean).map(it => (
        <div key={it.label} className="metric">
          <div className="metric-label">{it.label}</div>
          {it.value !== undefined && <div className={cx('metric-value', it.tone && `t-${it.tone}`)}>{it.value}</div>}
          {it.children}
          {it.sub != null && <div className="metric-sub">{it.sub}</div>}
        </div>
      ))}
    </div>
  );
}
