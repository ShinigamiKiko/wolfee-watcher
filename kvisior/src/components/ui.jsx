export function SevBadge({ sev }) {
  if (!sev) return null;
  return <span className={`sev sev-${sev.toLowerCase()}`}>{sev}</span>;
}

export function StatusDot({ type, label }) {
  return <span className={`status-dot status-${type}`}>{label}</span>;
}

function StatCard({ label, value, variant, delta, deltaDir }) {
  return (
    <div className="stat-card">
      <div className="stat-label">{label}</div>
      <div className={`stat-value ${variant || ''}`}>{value}</div>
      {delta && <div className={`stat-delta ${deltaDir || ''}`}>{delta}</div>}
    </div>
  );
}

function StatsGrid({ children, cols }) {
  return (
    <div className="stats-grid" style={cols ? {gridTemplateColumns:`repeat(${cols},1fr)`} : undefined}>
      {children}
    </div>
  );
}

function Card({ children, style, className }) {
  return <div className={`card ${className||''}`} style={style}>{children}</div>;
}

function CardHeader({ title, children }) {
  return (
    <div className="card-header">
      <div className="card-title">{title}</div>
      {children}
    </div>
  );
}

export function Tabs({ tabs, active, onSwitch }) {
  return (
    <div className="tabs">
      {tabs.map(t => (
        <div key={t.id} className={`tab${active === t.id ? ' active' : ''}`} onClick={() => onSwitch(t.id)}>
          {t.label}
        </div>
      ))}
    </div>
  );
}

function ComplianceBar({ label, pct, color, delay }) {
  return (
    <div className="compliance-item">
      <div className="compliance-header">
        <span className="compliance-name">{label}</span>
        <span className="compliance-pct">{pct}%</span>
      </div>
      <div className="compliance-bar">
        <div className="compliance-fill" style={{width:`${pct}%`,background:color,animationDelay:`${delay||0}s`}} />
      </div>
    </div>
  );
}

function DPBlock({ title, children }) {
  return (
    <div className="dp-block">
      {title && <div className="dp-section" style={{margin:'0 0 10px'}}>{title}</div>}
      {children}
    </div>
  );
}

function KVRow({ k, v }) {
  return (
    <div className="dp-kv">
      <span>{k}</span>
      <span>{v ?? '—'}</span>
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
      <button className="btn btn-outline" style={{fontSize:12,whiteSpace:'nowrap'}} onClick={toggle}>
        {label} ▾
      </button>
      <div className="filter-dd-menu" id={id}>
        {children}
      </div>
    </div>
  );
}
