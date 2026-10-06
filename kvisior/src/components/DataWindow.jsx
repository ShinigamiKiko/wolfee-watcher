import { useRef } from 'react';
import { useFitToPage } from '../hooks/useFitToPage';

export function DataWindow({ label, footer, deps = [], className = '', children }) {
  const winRef = useRef(null);
  const footRef = useRef(null);
  const style = useFitToPage(winRef, footRef, deps);
  return (
    <>
      <div ref={winRef} className={`dw${className ? ` ${className}` : ''}`} style={style} tabIndex={0} role="region" aria-label={label}>
        {children}
      </div>
      {footer && <div ref={footRef} className="dw-foot">{footer}</div>}
    </>
  );
}
