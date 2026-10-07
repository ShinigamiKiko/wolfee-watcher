import { Pager as SharedPager } from '../../components/Pager';

export function Pager({ total, pageSize, page, setPage, setPageSize }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <div className="dw-foot">
      <SharedPager total={total} pageSize={pageSize} page={Math.min(page, pages)}
        onPage={setPage} onPageSize={n => { setPageSize(n); setPage(1); }} />
    </div>
  );
}
