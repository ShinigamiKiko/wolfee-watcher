export function SilentFpButtons({ onSilent, onFp }) {
  const btn = {
    fontSize: 10, fontWeight: 600, padding: '2px 7px', borderRadius: 4,
    border: '1px solid', cursor: 'pointer', background: 'transparent',
    transition: 'all .12s', marginRight: 4,
  };
  return (
    <>
      <button title="Silent — suppress all violations for this category until manually removed"
        style={{ ...btn, color: 'var(--warning)', borderColor: 'rgba(251,191,36,.35)' }}
        onMouseEnter={e => e.currentTarget.style.background = 'rgba(251,191,36,.1)'}
        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
        onClick={e => { e.stopPropagation(); onSilent(); }}>
        Silent
      </button>
      <button title="FP — mark as false positive, hides this single instance for 7 days"
        style={{ ...btn, color: 'var(--text-muted)', borderColor: 'rgba(100,116,139,.35)' }}
        onMouseEnter={e => e.currentTarget.style.background = 'rgba(100,116,139,.1)'}
        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
        onClick={e => { e.stopPropagation(); onFp(); }}>
        FP
      </button>
    </>
  );
}
