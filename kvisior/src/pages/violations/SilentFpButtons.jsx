export function SilentFpButtons({ onSilent, onFp }) {
  return (
    <>
      <button title="Silent — suppress all violations for this category until manually removed"
        className="btn btn-xs btn-ghost btn-tone-warning"
        onClick={e => { e.stopPropagation(); onSilent(); }}>
        Silent
      </button>
      <button title="FP — mark as false positive, hides this single instance for 7 days"
        className="btn btn-xs btn-ghost btn-tone-muted"
        onClick={e => { e.stopPropagation(); onFp(); }}>
        FP
      </button>
    </>
  );
}
