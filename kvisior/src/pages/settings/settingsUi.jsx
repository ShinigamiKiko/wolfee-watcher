import { useId, useState } from 'react';
import { Field as KitField, Tag, EmptyRow, cx } from '../../components/kit';
import { Icon } from '../../components/Icon';

export const RoleBadge = ({ role }) => (
  <Tag tone={role === 'admin' ? 'accent' : 'violet'} className="t-upper">{role}</Tag>
);

export const PermissionDeniedHint = ({ msg }) => <div className="field-hint mt-8">{msg}</div>;

export function Field({ label, value, onChange, type = 'text', options, span }) {
  return (
    <KitField label={label} className={span ? 'span-2' : undefined}>
      {type === 'select' ? (
        <select value={value || ''} onChange={e => onChange(e.target.value)} className="input input--block">
          {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
      ) : (
        <input type={type} value={value || ''} onChange={e => onChange(e.target.value)} className="input input--block" />
      )}
    </KitField>
  );
}

export function SettingsSection({ title, desc, action, readOnlyText, canCreate, error, children }) {
  return (
    <section className="pane settings-section">
      <div className="pane-head">
        <div className="grow">
          <div className="pane-title">{title}</div>
          {desc && <div className="pane-sub">{desc}</div>}
        </div>
        {canCreate === false
          ? <span className="t-xs t-muted">{readOnlyText}</span>
          : action}
      </div>
      <div className="pane-body">
        {error && <div className="field-error mb-12">Error: {error}</div>}
        {children}
      </div>
    </section>
  );
}

export function EditorBox({ title, onSave, onCancel, saveLabel = 'Save', children }) {
  return (
    <div className="item-card mb-16">
      <div className="t-sm t-strong t-primary mb-12">{title}</div>
      <div className="fields fields--2">{children}</div>
      <div className="row">
        <button type="button" className="btn btn-primary" onClick={onSave}>{saveLabel}</button>
        <button type="button" className="btn btn-ghost" onClick={onCancel}>Cancel</button>
      </div>
    </div>
  );
}

export function ListState({ items, cols, empty }) {
  if (items == null) return <EmptyRow cols={cols}>Loading…</EmptyRow>;
  if (items.length === 0) return <EmptyRow cols={cols}>{empty}</EmptyRow>;
  return null;
}

export function SettingsGroup({ title, desc, children }) {
  return (
    <section className="set-group">
      <div className="set-group-head">
        <h3 className="set-group-title">{title}</h3>
        {desc && <p className="set-group-desc">{desc}</p>}
      </div>
      <div className="set-list">{children}</div>
    </section>
  );
}

export function SettingsRow({ icon, title, desc, summary, status, tone, defaultOpen = false, children }) {
  const [open, setOpen] = useState(defaultOpen);
  const id = useId();
  return (
    <div className={cx('set-row', open && 'set-row--open')}>
      <button type="button" className="set-row-head" aria-expanded={open} aria-controls={id} onClick={() => setOpen(o => !o)}>
        <span className={cx('set-row-icon', tone === 'muted' && 'set-row-icon--muted')}><Icon name={icon} /></span>
        <span className="set-row-text">
          <span className="set-row-title">{title}</span>
          {desc && <span className="set-row-desc">{desc}</span>}
        </span>
        <span className="set-row-summary">{summary}</span>
        <span className="set-row-status">{status && <span className={cx('status-pill', tone && `status-pill--${tone}`)}>{status}</span>}</span>
        <Icon name="chevron-down" className="set-row-chev" />
      </button>
      {open && <div className="set-row-body" id={id}>{children}</div>}
    </div>
  );
}

export function SettingsActions({ children, aside }) {
  return (
    <div className="set-actions">
      {aside && <div className="set-actions-aside">{aside}</div>}
      <div className="set-actions-main">{children}</div>
    </div>
  );
}

export function SettingsToggle({ label, hint, children }) {
  return (
    <div className="set-toggle">
      {children}
      <div className="grow">
        <div className="set-toggle-label">{label}</div>
        {hint && <div className="set-toggle-hint">{hint}</div>}
      </div>
    </div>
  );
}
