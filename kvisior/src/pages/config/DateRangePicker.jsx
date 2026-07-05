import { useState } from 'react';
import { ST } from './yamlPanelHelpers';

function DateRangePicker({ fromVal, toVal, onFromChange, onToChange }) {
  return (
    <div style={{ display: 'flex', alignItems: 'flex-end', gap: 8, flexShrink: 0 }}>
      <div>
        <span style={ST.dtLabel}>From</span>
        <input type="datetime-local" value={fromVal} onChange={e => onFromChange(e.target.value)}
          style={ST.dtInput} />
      </div>
      <div style={{ color: 'var(--text-muted)', fontSize: 14, paddingBottom: 4 }}>→</div>
      <div>
        <span style={ST.dtLabel}>To</span>
        <input type="datetime-local" value={toVal} onChange={e => onToChange(e.target.value)}
          style={ST.dtInput} />
      </div>
      {(fromVal || toVal) && (
        <button onClick={() => { onFromChange(''); onToChange(''); }}
          style={{ ...ST.btnCopy, paddingBottom: 4, fontSize: 11, alignSelf: 'flex-end' }}
          title="Clear range">✕</button>
      )}
    </div>
  );
}

function applyToFilter(lines, toVal) {
  if (!toVal) return lines;
  const toTs = new Date(toVal).getTime();
  return lines.filter(line => {
    const m = line.match(/(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})/);
    if (!m) return true;
    return new Date(m[1]).getTime() <= toTs;
  });
}

export { DateRangePicker, applyToFilter };