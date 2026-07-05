
import { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import {
  listImages, getResults, getHistories, triggerScan, stopScan as apiStopScan, subscribeScanStream,
  scannerHealth, sortByRisk, getSchedule, saveSchedule,
} from '../data/scanner';

const ScannerCtx = createContext(null);
export const useScanner = () => useContext(ScannerCtx);

export function ScannerProvider({ children }) {
  const [clusterImages, setClusterImages] = useState([]);
  const [results, setResults]             = useState([]);
  const [summary, setSummary]             = useState(null);
  const [histories, setHistories]         = useState([]);
  const [scanning, setScanning]           = useState(false);
  const [progress, setProgress]           = useState([]);
  const [agentOnline, setAgentOnline]     = useState(false);
  const [agentInfo, setAgentInfo]       = useState(null);
  const [schedule, setSchedule]         = useState(null);
  const unsubRef = useRef(null);
  const scanStartedAtRef = useRef(0);
  const finalizeScanRef = useRef(null);

  useEffect(() => {
    let cancelled = false;
    const check = async () => {
      const h = await scannerHealth().catch(() => null);
      if (cancelled) return;
      setAgentOnline(!!h?.status);
      if (h) {
        setAgentInfo(h);
        if (h.schedule) setSchedule(h.schedule);
        if (h.scanning === false &&
            scanStartedAtRef.current > 0 &&
            Date.now() - scanStartedAtRef.current > 5000) {
          finalizeScanRef.current?.();
        }
      }
    };
    check();
    const intervalMs = scanning ? 5_000 : 30_000;
    const t = setInterval(check, intervalMs);
    return () => { cancelled = true; clearInterval(t); };
  }, [scanning]);

  const refreshImages = useCallback(async () => {
    try {
      const data = await listImages();
      setClusterImages(data.images || []);
    } catch (e) {
      console.warn('[scanner] listImages:', e);
    }
  }, []);

  useEffect(() => {
    refreshImages();
    const t = setInterval(refreshImages, 60_000);
    return () => clearInterval(t);
  }, [refreshImages]);

  const refreshResults = useCallback(async () => {
    try {
      const data = await getResults();
      setResults(data.results || []);
      setSummary(data.summary || null);
    } catch (e) {
      console.warn('[scanner] getResults:', e);
    }
  }, []);

  useEffect(() => {
    refreshResults();
    const t = setInterval(refreshResults, 30_000);
    return () => clearInterval(t);
  }, [refreshResults]);

  const refreshHistories = useCallback(async () => {
    try {
      const data = await getHistories();
      setHistories(data.histories || []);
    } catch (e) {
      console.warn('[scanner] getHistories:', e);
    }
  }, []);

  useEffect(() => {
    refreshHistories();
    const t = setInterval(refreshHistories, 15 * 60 * 1000);
    return () => clearInterval(t);
  }, [refreshHistories]);

  const finalizeScan = useCallback(() => {
    scanStartedAtRef.current = 0;
    setScanning(false);
    if (unsubRef.current) { unsubRef.current(); unsubRef.current = null; }
    refreshResults();
  }, [refreshResults]);
  finalizeScanRef.current = finalizeScan;

  const startScan = useCallback(async (images = []) => {
    if (scanning) return;
    scanStartedAtRef.current = Date.now();
    setScanning(true);
    setProgress(['Connecting to scanner…']);
    if (unsubRef.current) unsubRef.current();

    try {
      const resp = await triggerScan(images);
      if (resp.queued === 0) {
        setProgress([`⚠ ${resp.message || 'No images found in cluster'}`]);
        scanStartedAtRef.current = 0;
        setScanning(false);
        return;
      }
      setProgress([`Queued ${resp.queued} images for scanning…`]);
    } catch (e) {
      setProgress(prev => [...prev, `Error: ${e.message}`]);
      scanStartedAtRef.current = 0;
      setScanning(false);
      return;
    }

    unsubRef.current = subscribeScanStream((ev) => {
      switch (ev.type) {
        case 'start':
        case 'progress':
          setProgress(prev => [...prev.slice(-99), ev.message]);
          break;
        case 'result':
          if (ev.result) {
            setResults(prev => {
              const idx = prev.findIndex(r => r.image === ev.result.image);
              if (idx >= 0) {
                const next = [...prev];
                next[idx] = ev.result;
                return next;
              }
              return [...prev, ev.result];
            });
            setProgress(prev => [
              ...prev.slice(-99),
              `✓ ${ev.result.image}: ${ev.result.summary?.total ?? 0} CVEs (${ev.result.summary?.critical ?? 0} critical)`,
            ]);
          }
          break;
        case 'done':
          setProgress(prev => [...prev.slice(-99), `✓ ${ev.message}`]);
          finalizeScan();
          break;
        case 'error':
          setProgress(prev => [...prev.slice(-99), `✗ ${ev.image}: ${ev.message}`]);
          break;
      }
    });
  }, [scanning, finalizeScan]);

  const stopScan = useCallback(async () => {
    if (!scanning) return;
    try {
      const resp = await apiStopScan();
      setProgress(prev => [...prev.slice(-99), '⏹ Stop requested…']);
      if (resp && resp.stopped === false) {
        setProgress(prev => [...prev.slice(-99), 'Backend was already idle — clearing UI state.']);
        finalizeScan();
      }
    } catch (e) {
      setProgress(prev => [...prev.slice(-99), `Error stopping: ${e.message}`]);
      const h = await scannerHealth().catch(() => null);
      if (h && h.scanning === false) finalizeScan();
    }
  }, [scanning, finalizeScan]);

  const allCVEs = results.flatMap(r =>
    (r.cves || []).map(c => ({ ...c, _image: r.image, _imageName: r.name, _imageTag: r.tag }))
  );
  const sortedCVEs = sortByRisk(allCVEs);

  const updateSchedule = async (sched) => {
    const saved = await saveSchedule(sched);
    setSchedule(saved);
    return saved;
  };

  return (
    <ScannerCtx.Provider value={{
      clusterImages,
      results,
      summary,
      histories,
      allCVEs: sortedCVEs,
      scanning,
      progress,
      agentOnline,
      agentInfo,
      startScan,
      stopScan,
      refreshImages,
      refreshResults,
      schedule,
      updateSchedule,
    }}>
      {children}
    </ScannerCtx.Provider>
  );
}
