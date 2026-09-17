import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { getCluster, setCluster, listClusters } from '../data/cluster';

const Ctx = createContext(null);

export function ClusterProvider({ children }) {
  const [clusters, setClusters] = useState([]);
  const [local, setLocal] = useState('default');
  const [current, setCurrent] = useState(getCluster());
  const [error, setError] = useState(null);

  const reload = useCallback(async () => {
    try {
      const { clusters: rows, local: localID } = await listClusters();
      setClusters(rows);
      setLocal(localID);
      setError(null);
      if (!rows.some(c => c.id === getCluster())) {
        const fallback = rows.find(c => c.id === localID) || rows[0];
        if (fallback) {
          setCluster(fallback.id);
          setCurrent(fallback.id);
        }
      }
    } catch (e) {
      setError(e.message);
    }
  }, []);

  useEffect(() => { reload(); }, [reload]);

  const select = useCallback((id) => {
    setCluster(id);
    setCurrent(id);
  }, []);

  return (
    <Ctx.Provider value={{ clusters, current, local, error, select, reload }}>
      {children}
    </Ctx.Provider>
  );
}

export function useClusters() {
  const v = useContext(Ctx);
  if (!v) throw new Error('useClusters must be used inside ClusterProvider');
  return v;
}
