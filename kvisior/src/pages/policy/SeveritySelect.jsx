import { useState } from 'react';

function SeveritySelect({ value, onChange }) {
  return (
    <div className="cpol-field">
      <label className="cpol-label">Severity</label>
      <select className="cpol-select" value={value} onChange={e => onChange(e.target.value)}>
        {['Critical', 'High', 'Medium', 'Low'].map(s => (
          <option key={s} value={s}>{s.toUpperCase()}</option>
        ))}
      </select>
    </div>
  );
}


export { SeveritySelect };
