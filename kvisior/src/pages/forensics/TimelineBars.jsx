import { useMemo } from 'react';

export function TimelineBars({ events, windowH }) {
  const buckets = useMemo(() => {
    const now = Date.now();
    const windowMs = windowH * 60 * 60 * 1000;
    const bucketMs = windowMs / 60;
    const arr = Array(60).fill(0);
    events.forEach(e => {
      const age = now - new Date(e.ts).getTime();
      if (age < 0 || age > windowMs) return;
      const idx = Math.min(59, Math.floor((windowMs - age) / bucketMs));
      arr[idx]++;
    });
    return arr;
  }, [events, windowH]);

  const max = Math.max(1, ...buckets);

  return (
    <div className="fns-bars">
      {buckets.map((v, i) => {
        const pct = (v / max) * 100;
        const cls = pct === 0 ? 'quiet' : pct < 30 ? 'low' : pct < 60 ? 'med' : pct < 85 ? 'high' : 'spike';
        return <div key={i} className={`fns-bar fns-bar--${cls}`} style={{ height: `${Math.max(pct, 2)}%` }} />;
      })}
    </div>
  );
}
