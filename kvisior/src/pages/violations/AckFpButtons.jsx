export function AckFpButtons({ onAck, onFp }) {
  return (
    <>
      <button title="ACK — suppress all violations for this resource+policy for 24h"
        className="btn btn-xs btn-ghost btn-tone-warning"
        onClick={e=>{e.stopPropagation();onAck();}}>
        ACK
      </button>
      <button title="FP — mark as false positive, remove this single row"
        className="btn btn-xs btn-ghost btn-tone-muted"
        onClick={e=>{e.stopPropagation();onFp();}}>
        FP
      </button>
    </>
  );
}

