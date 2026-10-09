import { useRef } from 'react';
import { useFitToPage } from '../hooks/useFitToPage';

export function DataWindow({ label, footer, deps = [], className = '', fit = true, children }) {
  const winRef = useRef(null);
  const footRef = useRef(null);
  const style = useFitToPage(winRef, footRef, deps);
  return (
    <>
      <div ref={winRef} className={`dw${fit ? '' : ' dw-fill'}${className ? ` ${className}` : ''}`} style={fit ? style : undefined} tabIndex={0} role="region" aria-label={label}>
        {children}
      </div>
      {footer && <div ref={footRef} className="dw-foot">{footer}</div>}
    </>
  );
}
