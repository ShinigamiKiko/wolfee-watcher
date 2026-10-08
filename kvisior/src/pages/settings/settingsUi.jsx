import { Field as KitField, Tag, EmptyRow } from '../../components/kit';

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
