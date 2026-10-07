import { Pager as SharedPager } from '../../components/Pager';

function Pager({ total, page, setPage, pageSize, setPageSize }) {
  if (!total) return null;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <SharedPager total={total} pageSize={pageSize} page={Math.min(page, pages)} noun="events"
      onPage={setPage} onPageSize={n => { setPageSize(n); setPage(1); }} />
  );
}

export { Pager };
