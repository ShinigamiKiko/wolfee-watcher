export const RoleBadge = ({ role }) => {
  const isAdmin = role === 'admin';
  const bg = isAdmin ? 'rgba(0,200,255,.12)' : 'rgba(124,58,237,.12)';
  const fg = isAdmin ? 'var(--accent)' : '#a78bfa';
  return <span style={{fontSize:11,padding:'2px 8px',borderRadius:5,background:bg,color:fg,textTransform:'uppercase',letterSpacing:'.04em'}}>{role}</span>;
};

export const PermissionDeniedHint = ({ msg }) => (
  <div style={{fontSize:11,color:'var(--text-muted)',marginTop:6}}>{msg}</div>
);

export function Field({ label, value, onChange, type = 'text', options }) {
  return (
    <div>
      <label style={{display:'block',fontSize:11,textTransform:'uppercase',letterSpacing:'.07em',color:'var(--text-muted)',marginBottom:6}}>{label}</label>
      {type === 'select' ? (
        <select value={value || ''} onChange={e => onChange(e.target.value)} className="form-select">
          {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
      ) : (
        <input type={type} value={value || ''} onChange={e => onChange(e.target.value)} className="form-input" />
      )}
    </div>
  );
}
