import { useApp } from '../context/AppContext';

export function Modal() {
  const { modal, closeModal } = useApp();
  if (!modal) return null;
  return (
    <div className="modal-backdrop" onClick={e => e.target === e.currentTarget && closeModal()}>
      {modal}
    </div>
  );
}
