import { useCallback, useEffect, useRef, useState } from 'react';
import { Icon } from './Icon';

const clampX = (x, w) => Math.max(0, Math.min(window.innerWidth - Math.min(w, window.innerWidth), x));
const clampY = y => Math.max(0, Math.min(window.innerHeight - 40, y));

export function FloatingWindow({ open, resetKey, title, badges, tabs, onClose, width = 480, height = 560, minWidth = 320, minHeight = 280, label, children }) {
  const [pos, setPos] = useState(null);
  const [size, setSize] = useState({ w: width, h: height });
  const drag = useRef(null);

  useEffect(() => {
    if (!open) return;
    const w = Math.min(width, window.innerWidth - 16);
    const h = Math.min(height, window.innerHeight - 16);
    setSize({ w, h });
    setPos({ x: Math.max(8, window.innerWidth - w - 32), y: Math.max(8, (window.innerHeight - h) / 2) });
  }, [open, resetKey, width, height]);

  useEffect(() => {
    if (!open) return undefined;
    const onKey = e => { if (e.key === 'Escape') onClose?.(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  const track = useCallback((e, apply) => {
    if (e.button !== 0) return;
    e.preventDefault();
    drag.current = { sx: e.clientX, sy: e.clientY, pos, size };
    const move = ev => apply(ev.clientX - drag.current.sx, ev.clientY - drag.current.sy, drag.current);
    const up = () => {
      drag.current = null;
      window.removeEventListener('mousemove', move);
      window.removeEventListener('mouseup', up);
    };
    window.addEventListener('mousemove', move);
    window.addEventListener('mouseup', up);
  }, [pos, size]);

  const onMove = e => track(e, (dx, dy, s) => setPos({ x: clampX(s.pos.x + dx, s.size.w), y: clampY(s.pos.y + dy) }));
  const onResize = e => {
    e.stopPropagation();
    track(e, (dx, dy, s) => setSize({ w: Math.max(minWidth, s.size.w + dx), h: Math.max(minHeight, s.size.h + dy) }));
  };

  if (!open || !pos) return null;

  return (
    <div className="fwin" role="dialog" aria-label={label || (typeof title === 'string' ? title : undefined)}
      style={{ left: pos.x, top: pos.y, width: size.w, height: size.h }}>
      <div className="fwin-head" onMouseDown={onMove}>
        <span className="fwin-grip" aria-hidden="true" />
        <div className="fwin-title">{title}</div>
        {badges}
        <button type="button" className="btn-icon btn-icon--sm fwin-close" aria-label="Close" onMouseDown={e => e.stopPropagation()} onClick={onClose}>
          <Icon name="x" />
        </button>
      </div>
      {tabs && <div className="fwin-tabs subtabs" onMouseDown={e => e.stopPropagation()}>{tabs}</div>}
      <div className="fwin-body">{children}</div>
      <div className="fwin-resize" onMouseDown={onResize} aria-hidden="true" />
    </div>
  );
}
