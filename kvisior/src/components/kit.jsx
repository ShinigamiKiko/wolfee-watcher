import { useEffect, useRef, useState } from 'react';
import { Icon } from './Icon';

export const cx = (...parts) => parts.filter(Boolean).join(' ');

const SEV_TONE = { CRITICAL: 'danger', HIGH: 'orange', MEDIUM: 'warning', LOW: 'low' };

export const sevTone = sev => SEV_TONE[String(sev || '').toUpperCase()];

const STAT_TONE = { danger: 'danger', warning: 'warn', ok: 'success', accent: 'info' };

export function Stat({ label, value, sub, tone, icon, onClick, active, title }) {
  const body = (
    <>
      <div className="stat-top">
        <div className="stat-label">{label}</div>
        {icon && <span className="stat-icon"><Icon name={icon} /></span>}
      </div>
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
        {title && <h2 className="sr-only">{title}</h2>}
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
  if (children == null || children === '') return null;
  return <span className={cx('badge', tone && `badge--${tone}`)} title={title}>{children}</span>;
}

const KIND_TONE = {
  Deployment: 'accent', StatefulSet: 'violet', DaemonSet: 'ok', ReplicaSet: 'accent', Job: 'warning', CronJob: 'warning', Pod: 'accent',
  ClusterRole: 'violet', Role: 'accent', ClusterRoleBinding: 'danger', RoleBinding: 'warning',
};

const ACTION_TONE = {
  create: 'ok', update: 'accent', patch: 'accent', delete: 'warning', deletecollection: 'warning',
  exec: 'danger', attach: 'danger', portforward: 'danger', get: 'violet', list: 'violet', watch: 'violet',
};

export const actionTone = kind => ACTION_TONE[String(kind || '').toLowerCase().replace(/[^a-z]/g, '')];

export function ActionBadge({ kind }) {
  return <Badge tone={actionTone(kind)}>{kind || '—'}</Badge>;
}

export function KindBadge({ kind }) {
  return <Badge tone={KIND_TONE[kind] || 'accent'}>{kind}</Badge>;
}

export function Pane({ title, sub, icon, accent, tools, footer, flush, className, bodyClassName, children }) {
  return (
    <section className={cx('pane', accent && `pane--${accent === true ? 'accent' : accent}`, className)}>
      {(title || tools) && (
        <div className={cx('pane-head', flush && 'pane-head--flush')}>
          {icon && <span className={cx('pane-icon', accent === 'danger' && 'pane-icon--danger')}><Icon name={icon} /></span>}
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

export function SidePanel({ title, meta, onClose, actions, tools, tabs, label, width, fill, children }) {
  return (
    <aside className={cx('detail-panel open', width && `detail-panel--${width}`, fill && 'detail-panel--fill')} aria-label={label || (typeof title === 'string' ? title : undefined)}>
      <div className="detail-panel-inner">
        <div className="dp-header">
          <div className="grow">
            <div className="dp-title">{title}</div>
            {meta && <div className="dp-meta">{meta}</div>}
          </div>
          {tools && <div className="row shrink-0">{tools}</div>}
          <button type="button" className="dp-close" aria-label="Close" onClick={onClose}><Icon name="x" /></button>
        </div>
        {actions && <div className="dp-actions">{actions}</div>}
        {tabs && <div className="subtabs dp-tabs" role="tablist">{tabs}</div>}
        {children}
      </div>
    </aside>
  );
}

export function DetailSection({ title, aside, children, className }) {
  return (
    <section className={cx('dp-sec', className)}>
      {title && <div className="section-label row row--between">{title}{aside}</div>}
      {children}
    </section>
  );
}

export function SubTabs({ tabs, active, onChange }) {
  return tabs.map(t => {
    const opt = typeof t === 'object' ? t : { id: t, label: t };
    return (
      <button key={opt.id} type="button" role="tab" aria-selected={active === opt.id} disabled={opt.disabled}
        className={cx('subtab', active === opt.id && 'active')} onClick={() => onChange(opt.id)}>
        {opt.label}
      </button>
    );
  });
}

export function SelectMenu({ value, options, onChange, label, placeholder, size }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  useEffect(() => {
    if (!open) return undefined;
    const away = e => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    const esc = e => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('mousedown', away);
    document.addEventListener('keydown', esc);
    return () => { document.removeEventListener('mousedown', away); document.removeEventListener('keydown', esc); };
  }, [open]);
  const opts = options.map(o => (typeof o === 'object' ? o : { value: o, label: o }));
  const current = opts.find(o => o.value === value);
  return (
    <div ref={ref} className="menu-select">
      <button type="button" className={cx('btn btn-outline', size === 'sm' && 'btn-sm', current && current.value !== opts[0]?.value && 'is-set')}
        aria-haspopup="listbox" aria-expanded={open} aria-label={label} onClick={() => setOpen(o => !o)}>
        <span className="clip">{current ? current.label : placeholder}</span>
        <Icon name="chevron-down" className={open ? 'rot-180' : undefined} />
      </button>
      {open && (
        <div className="menu" role="listbox" aria-label={label}>
          {opts.map(o => (
            <button key={o.value} type="button" role="option" aria-selected={o.value === value} className="menu-item"
              onClick={() => { onChange(o.value); setOpen(false); }}>
              <span className="clip">{o.label}</span>
              {o.value === value && <Icon name="check" />}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

const RING_TONE = { ok: 'var(--accent-3)', warning: 'var(--warning)', danger: 'var(--danger)', accent: '#3b82f6' };

export function Ring({ pct, tone = 'accent', size = 58 }) {
  const r = (size - 10) / 2;
  const c = 2 * Math.PI * r;
  const v = Math.max(0, Math.min(100, pct || 0));
  return (
    <div className="ring" style={{ width: size, height: size }} role="img" aria-label={`${v}%`}>
      <svg viewBox={`0 0 ${size} ${size}`} width={size} height={size} aria-hidden="true">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--bg-inset)" strokeWidth="5" />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={RING_TONE[tone] || tone} strokeWidth="5"
          strokeLinecap="round" strokeDasharray={`${(c * v) / 100} ${c}`} />
      </svg>
      <span>{v}%</span>
    </div>
  );
}

export function SevBar({ counts }) {
  const total = counts.reduce((a, [, n]) => a + n, 0);
  return (
    <>
      <div className="sevbar" role="img" aria-label={counts.map(([k, n]) => `${k} ${n}`).join(', ')}>
        {total > 0 && counts.map(([k, n, color]) => n > 0 && <i key={k} style={{ width: `${(n / total) * 100}%`, background: color }} />)}
      </div>
      <div className="legend">
        {counts.map(([k, n, color]) => <span key={k} style={{ '--c': color }}>{k} {n.toLocaleString()}</span>)}
      </div>
    </>
  );
}
