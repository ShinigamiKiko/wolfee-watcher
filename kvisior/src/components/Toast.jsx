import { useApp } from '../context/AppContext';

const ICONS = { success:'✅', error:'❌', warn:'⚠️', info:'ℹ️' };

export function ToastStack() {
  const { toasts, dismissToast } = useApp();
  return (
    <div id="toast-stack">
      {toasts.map(t => (
        <div key={t.id} className={`toast ${t.type}`}>
          <span className="toast-icon">{ICONS[t.type] || 'ℹ️'}</span>
          <div className="toast-body">
            <div className="toast-title">{t.title}</div>
            {t.sub && <div className="toast-sub">{t.sub}</div>}
          </div>
          <button className="toast-close" onClick={() => dismissToast(t.id)}>✕</button>
        </div>
      ))}
    </div>
  );
}
