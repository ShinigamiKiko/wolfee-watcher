
export function DetailPanel({ open, width = 520, onClose, title, sub, children, headerExtra }) {
  return (
    <div
      className="detail-panel-wrap"
      style={{ width: open ? width : 0 }}
    >
      <div className="detail-panel-inner" style={{ width }}>
        <div className="detail-panel-card">
          <div className="detail-panel-header">
            <div style={{ minWidth: 0 }}>
              <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                {title}
              </div>
              {sub && (
                <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 3 }}>
                  {sub}
                </div>
              )}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
              {headerExtra}
              <button className="dp-close" onClick={onClose}>✕</button>
            </div>
          </div>
          <div className="detail-panel-body">
            {children}
          </div>
        </div>
      </div>
    </div>
  );
}
