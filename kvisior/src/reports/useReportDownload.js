import { useCallback, useRef, useState } from 'react';
import { useApp } from '../context/AppContext';
import { usePerms } from '../context/PermissionsContext';
import { getCluster } from '../data/cluster';

export function useReportDownload() {
  const { toast } = useApp();
  const { me } = usePerms() || {};
  const [busy, setBusy] = useState(null);
  const lock = useRef(false);

  const download = useCallback(async (key, build) => {
    if (lock.current) return;
    lock.current = true;
    setBusy(key);
    try {
      const name = await build({ cluster: getCluster(), user: me?.username || me?.full_name || '' });
      toast('success', 'Report downloaded', name);
    } catch (e) {
      toast('error', 'Report failed', e?.message || String(e));
    } finally {
      lock.current = false;
      setBusy(null);
    }
  }, [me, toast]);

  return { busy, download };
}
