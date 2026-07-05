export function EmptyState({ icon, title, sub, action }) {
  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center',
      justifyContent: 'center', padding: '60px 20px', gap: 10,
      color: 'var(--text-muted)',
    }}>
      <span style={{ fontSize: 32 }}>{icon}</span>
      <div style={{ fontSize: 14, color: 'var(--text-secondary)', fontWeight: 500 }}>{title}</div>
      <div style={{ fontSize: 12, textAlign: 'center', maxWidth: 340, lineHeight: 1.6 }}>{sub}</div>
      {action}
    </div>
  );
}
