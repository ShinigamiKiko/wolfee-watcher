export const PAGE_SIZES = [50, 100, 150];

const num = n => Number(n).toLocaleString();

export function Pager({ total, page, pageSize, onPage, onPageSize, noun = 'rows', range, canPrev, canNext, onPrev, onNext, busy }) {
  const pages = Math.max(1, Math.ceil((total || 0) / pageSize));
  const prevOk = canPrev ?? page > 1;
  const nextOk = canNext ?? page < pages;
  const text = range ?? (total
    ? `${num((page - 1) * pageSize + 1)}–${num(Math.min(page * pageSize, total))} of ${num(total)} ${noun}`
    : `0 ${noun}`);
  return (
    <div className="pager">
      <span className="pager__range">{text}{busy ? ' · loading…' : ''}</span>
      <div className="pager__controls">
        <div className="pager__sizes" role="group" aria-label="Rows per page">
          {PAGE_SIZES.map(n => (
            <button key={n} type="button" aria-pressed={pageSize === n} onClick={() => onPageSize(n)}>{n} rows</button>
          ))}
        </div>
        {range == null && pages > 1 && <span className="pager__pos">{page} / {pages}</span>}
        <button type="button" className="btn btn-outline btn-sm" disabled={!prevOk || busy}
          onClick={() => (onPrev ? onPrev() : onPage(page - 1))}>Previous</button>
        <button type="button" className="btn btn-outline btn-sm" disabled={!nextOk || busy}
          onClick={() => (onNext ? onNext() : onPage(page + 1))}>Next</button>
      </div>
    </div>
  );
}
