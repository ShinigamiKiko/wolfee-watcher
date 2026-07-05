import { Navigate, useLocation } from 'react-router-dom';
import { usePerms } from '../context/PermissionsContext';

export function RequireAuth({ children }) {
  const { authenticated, loading } = usePerms();
  const location = useLocation();

  if (loading) {
    return <div style={{minHeight:'100vh',background:'var(--bg-base)'}} />;
  }
  if (!authenticated) {
    return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  }
  return children;
}
