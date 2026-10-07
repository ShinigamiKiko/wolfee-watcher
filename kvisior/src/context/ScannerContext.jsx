
import { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import {
  listImages, getResults, getHistories, triggerScan, stopScan as apiStopScan, subscribeScanStream,
  scannerHealth, sortByRisk, getSchedule, saveSchedule,
} from '../data/scanner';

const line = (kind, text) => ({ kind, text });

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
  const [scanErrors, setScanErrors]     = useState([]);
  const unsubRef = useRef(null);
  const scanStartedAtRef = useRef(0);
  const scanningRef = useRef(false);
  const sawBackendScanRef = useRef(false);
  const finalizeScanRef = useRef(null);
  const adoptScanRef = useRef(null);

  useEffect(() => {
    let cancelled = false;
    const check = async () => {
      const h = await scannerHealth().catch(() => null);
      if (cancelled) return;
      setAgentOnline(!!h?.status);
      if (!h) return;

      setAgentInfo(h);
      if (h.schedule) setSchedule(h.schedule);

      if (h.scanning === true) {
        sawBackendScanRef.current = true;
        if (!scanningRef.current) adoptScanRef.current?.();
        return;
      }

      if (h.scanning === false && scanningRef.current && scanStartedAtRef.current > 0) {
        const elapsed = Date.now() - scanStartedAtRef.current;
        if (sawBackendScanRef.current || elapsed > 30_000) finalizeScanRef.current?.();
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
    sawBackendScanRef.current = false;
    scanningRef.current = false;
    setScanning(false);
    if (unsubRef.current) { unsubRef.current(); unsubRef.current = null; }
    refreshResults();
  }, [refreshResults]);
  finalizeScanRef.current = finalizeScan;

  const subscribe = useCallback(() => {
    if (unsubRef.current) unsubRef.current();
    unsubRef.current = subscribeScanStream((ev) => {
      switch (ev.type) {
        case 'start':
        case 'progress':
          setProgress(prev => [...prev.slice(-99), line('info', ev.message)]);
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
              line('ok', `${ev.result.image}: ${ev.result.summary?.total ?? 0} CVEs (${ev.result.summary?.critical ?? 0} critical)`),
            ]);
          }
          break;
        case 'done':
          setProgress(prev => [...prev.slice(-99), line('ok', ev.message)]);
          finalizeScan();
          break;
        case 'error':
          setProgress(prev => [...prev.slice(-99), line('fail', `${ev.image}: ${ev.message}`)]);
          setScanErrors(prev => [...prev.slice(-99), { image: ev.image, message: ev.message }]);
          break;
      }
    }, (error) => {
      setProgress(prev => [...prev.slice(-99), line('fail', error.message)]);
      setScanErrors(prev => [...prev.slice(-99), { image: 'scanner', message: error.message }]);
    });
  }, [finalizeScan]);

  const adoptScan = useCallback(() => {
    scanningRef.current = true;
    scanStartedAtRef.current = Date.now();
    sawBackendScanRef.current = true;
    setScanning(true);
    setScanErrors([]);
    setProgress(prev => (prev.length ? prev : [line('info', 'Scan already running — attaching to progress stream…')]));
    subscribe();
  }, [subscribe]);
  adoptScanRef.current = adoptScan;

  const startScan = useCallback(async (images = []) => {
    if (scanningRef.current) return { ok: false, reason: 'busy', message: 'A scan is already running' };

    setProgress([line('info', 'Connecting to scanner…')]);
    setScanErrors([]);

    let resp;
    try {
      resp = await triggerScan(images);
    } catch (e) {
      const message = e?.message || 'Scanner request failed';
      setProgress([line('fail', message)]);
      return { ok: false, reason: 'error', message };
    }

    if (!resp || (!resp.queued && !resp.scanning)) {
      const message = resp?.message || 'No images found in cluster';
      setProgress([line('warn', message)]);
      return { ok: false, reason: 'empty', message };
    }

    scanningRef.current = true;
    scanStartedAtRef.current = Date.now();
    sawBackendScanRef.current = !!resp.scanning;
    setScanning(true);
    setProgress([line('info', resp.queued
      ? `Queued ${resp.queued} images for scanning…`
      : 'Attaching to a scan already in progress…')]);
    subscribe();
    return { ok: true, queued: resp.queued || 0 };
  }, [subscribe]);

  const stopScan = useCallback(async () => {
    if (!scanningRef.current) return { ok: false, message: 'No scan is running' };
    try {
      const resp = await apiStopScan();
      setProgress(prev => [...prev.slice(-99), line('info', 'Stop requested…')]);
      if (resp && resp.stopped === false) {
        setProgress(prev => [...prev.slice(-99), line('info', 'Backend was already idle — clearing UI state.')]);
        finalizeScan();
      }
      return { ok: true };
    } catch (e) {
      const message = e?.message || 'Stop request failed';
      setProgress(prev => [...prev.slice(-99), line('fail', `Error stopping: ${message}`)]);
      const h = await scannerHealth().catch(() => null);
      if (h && h.scanning === false) finalizeScan();
      return { ok: false, message };
    }
  }, [finalizeScan]);

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
      scanErrors,
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
