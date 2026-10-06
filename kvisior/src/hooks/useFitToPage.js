import { useLayoutEffect, useState } from 'react';

const MIN_WINDOW = 200;

export function windowCap() {
  return Math.min(600, Math.max(340, Math.round(window.innerHeight * 0.58)));
}

function scrollParent(el) {
  for (let node = el?.parentElement; node && node !== document.body; node = node.parentElement) {
    const { overflowY } = getComputedStyle(node);
    if (overflowY === 'auto' || overflowY === 'scroll' || node.classList.contains('page')) return node;
  }
  return null;
}

export function useFitToPage(winRef, belowRef, deps) {
  const [height, setHeight] = useState(null);
  useLayoutEffect(() => {
    const win = winRef.current;
    const host = scrollParent(win);
    if (!win || !host) return undefined;
    const fit = () => {
      const hostBox = host.getBoundingClientRect();
      const top = win.getBoundingClientRect().top - hostBox.top + host.scrollTop;
      const bottom = parseFloat(getComputedStyle(host).paddingBottom) || 0;
      const below = belowRef?.current?.offsetHeight || 0;
      const available = Math.floor(host.clientHeight - top - below - bottom);
      setHeight(Math.max(MIN_WINDOW, Math.min(windowCap(), available)));
    };
    fit();
    const frame = requestAnimationFrame(fit);
    const observer = typeof ResizeObserver === 'function' ? new ResizeObserver(fit) : null;
    if (observer) {
      observer.observe(host);
      for (const child of host.children) observer.observe(child);
    }
    window.addEventListener('resize', fit);
    return () => {
      cancelAnimationFrame(frame);
      observer?.disconnect();
      window.removeEventListener('resize', fit);
    };
  }, deps);
  return height ? { height } : undefined;
}
