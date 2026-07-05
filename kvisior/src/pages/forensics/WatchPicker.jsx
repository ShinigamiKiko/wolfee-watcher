export function WatchPicker({ title, captureHint, groups, selected, max = 3, noStore, onToggle }) {
  if (noStore) {
    return <div className="fns-empty" style={{ marginTop: 32 }}>{title} requires PostgreSQL</div>;
  }
  return (
    <div className="fns-syscall-watch">
      <div className="fns-syscall-watch-hdr">
        <span className="fns-section-title">{title}</span>
        <span className="fns-section-count">
          {captureHint} · {selected.length}/{max} selected
        </span>
      </div>

      {groups.map(group => (
        <div key={group.label} className="fns-syscall-group">
          <div className="fns-syscall-group-label">{group.label}</div>
          <div className="fns-syscall-chips">
            {group.items.map(({ name, desc }) => {
              const on       = selected.includes(name);
              const disabled = !on && selected.length >= max;
              return (
                <div
                  key={name}
                  className={`fns-syscall-chip${on ? ' fns-syscall-chip--on' : ''}${disabled ? ' fns-syscall-chip--disabled' : ''}`}
                  onClick={() => !disabled && onToggle(name)}
                  title={disabled ? `Max ${max} selected — deselect one first` : desc}
                >
                  {name}
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}
