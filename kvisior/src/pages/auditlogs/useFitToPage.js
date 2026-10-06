import { useLayoutEffect, useState } from 'react';

const MIN_WINDOW = 200;

export function useFitToPage(winRef, belowRef, deps) {
  const [height, setHeight] = useState(null);
  useLayoutEffect(() => {
    const win = winRef.current;
    const page = win?.closest('.page');
    if (!win || !page) return undefined;
    const fit = () => {
      const pageBox = page.getBoundingClientRect();
      const top = win.getBoundingClientRect().top - pageBox.top + page.scrollTop;
      const bottom = parseFloat(getComputedStyle(page).paddingBottom) || 0;
      const below = belowRef?.current?.offsetHeight || 0;
      setHeight(Math.max(MIN_WINDOW, Math.floor(page.clientHeight - top - below - bottom)));
    };
    fit();
    const observer = typeof ResizeObserver === 'function' ? new ResizeObserver(fit) : null;
    if (observer) {
      observer.observe(page);
      for (const child of page.children) observer.observe(child);
    }
    window.addEventListener('resize', fit);
    return () => {
      observer?.disconnect();
      window.removeEventListener('resize', fit);
    };
  }, deps);
  return height ? { height } : undefined;
}
