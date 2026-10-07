import { useApp } from '../context/AppContext';
import { Icon } from './Icon';

const ICONS = { success: 'circle-check', error: 'circle-x', warn: 'alert', info: 'info' };

export function ToastStack() {
  const { toasts, dismissToast } = useApp();
  return (
    <div id="toast-stack">
      {toasts.map(t => (
        <div key={t.id} className={`toast ${t.type}`}>
          <span className="toast-icon"><Icon name={ICONS[t.type] || 'info'} size={16} /></span>
          <div className="toast-body">
            <div className="toast-title">{t.title}</div>
            {t.sub && <div className="toast-sub">{t.sub}</div>}
          </div>
          <button className="toast-close" onClick={() => dismissToast(t.id)}><Icon name="x" /></button>
        </div>
      ))}
    </div>
  );
}
