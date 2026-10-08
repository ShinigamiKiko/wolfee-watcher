import { Icon } from '../../components/Icon';

function DateRangePicker({ fromVal, toVal, onFromChange, onToChange }) {
  return (
    <div className="dt-range">
      <div className="dt-field">
        <label htmlFor="log-from">From</label>
        <input id="log-from" className="input" type="datetime-local" value={fromVal} onChange={e => onFromChange(e.target.value)} />
      </div>
      <span className="dt-arrow" aria-hidden="true">→</span>
      <div className="dt-field">
        <label htmlFor="log-to">To</label>
        <input id="log-to" className="input" type="datetime-local" value={toVal} onChange={e => onToChange(e.target.value)} />
      </div>
      {(fromVal || toVal) && (
        <button type="button" className="btn-icon" title="Clear range" aria-label="Clear range"
          onClick={() => { onFromChange(''); onToChange(''); }}><Icon name="x" /></button>
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
