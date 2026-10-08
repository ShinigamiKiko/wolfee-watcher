import { Icon } from './Icon';

export function SevBadge({ sev }) {
  if (!sev) return null;
  return <span className={`sev sev-${sev.toLowerCase()}`}>{sev}</span>;
}

export function StatusDot({ type, label }) {
  return <span className={`status-dot status-${type}`}>{label}</span>;
}

export function Tabs({ tabs, active, onSwitch }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map(t => (
        <button key={t.id} type="button" role="tab" aria-selected={active === t.id}
          className={`tab${active === t.id ? ' active' : ''}`} onClick={() => onSwitch(t.id)}>
          {t.label}
          {t.count != null && <span className={`tab-count${t.hot ? ' hot' : ''}`}>{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function FilterDropdown({ label, id, children }) {
  const toggle = () => {
    const el = document.getElementById(id);
    if (el) el.classList.toggle('open');
  };
  return (
    <div className="filter-dd">
      <button type="button" className="btn btn-outline btn-dd" onClick={toggle}>
        {label} <Icon name="chevron-down" />
      </button>
      <div className="filter-dd-menu" id={id}>
        {children}
      </div>
    </div>
  );
}
