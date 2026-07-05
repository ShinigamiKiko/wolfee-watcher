import { createContext, useContext, useState, useCallback } from 'react';

const AppCtx = createContext(null);
export const useApp = () => useContext(AppCtx);

export function AppProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const [modal, setModal] = useState(null);

  const toast = useCallback((type, title, sub, duration = 4000) => {
    const id = Date.now() + Math.random();
    setToasts(prev => [...prev, { id, type, title, sub }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), duration);
  }, []);

  const dismissToast = useCallback((id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const showModal = useCallback((content) => setModal(content), []);
  const closeModal = useCallback(() => setModal(null), []);

  return (
    <AppCtx.Provider value={{ toasts, dismissToast, toast, modal, showModal, closeModal }}>
      {children}
    </AppCtx.Provider>
  );
}
