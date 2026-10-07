import { useEffect, useMemo, useState } from 'react';
import { PAGE_SIZES } from '../components/Pager';

const storageKey = key => `kvisior.pageSize.${key}`;

function loadSize(key) {
  try {
    const n = Number(localStorage.getItem(storageKey(key)));
    return PAGE_SIZES.includes(n) ? n : PAGE_SIZES[0];
  } catch {
    return PAGE_SIZES[0];
  }
}

export function usePageSize(key) {
  const [pageSize, setPageSize] = useState(() => loadSize(key));
  const change = n => {
    setPageSize(n);
    try { localStorage.setItem(storageKey(key), String(n)); } catch {}
  };
  return [pageSize, change];
}

export function usePaged(items, key, resetDeps = []) {
  const [pageSize, setPageSize] = usePageSize(key);
  const [page, setPage] = useState(1);
  const list = items || [];
  const total = list.length;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const current = Math.min(page, pages);

  useEffect(() => { setPage(1); }, resetDeps);

  const pageItems = useMemo(
    () => list.slice((current - 1) * pageSize, current * pageSize),
    [list, current, pageSize],
  );

  return {
    pageItems,
    offset: (current - 1) * pageSize,
    pager: {
      total,
      page: current,
      pageSize,
      onPage: setPage,
      onPageSize: n => { setPageSize(n); setPage(1); },
    },
  };
}
