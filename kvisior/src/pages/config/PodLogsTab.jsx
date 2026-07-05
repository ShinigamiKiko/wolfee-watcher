import { useState, useRef, useEffect } from 'react';
import { getContainers, colorizeLog, ST } from './yamlPanelHelpers';
import { DateRangePicker, applyToFilter } from './DateRangePicker';

async function safeFetch(url) {
  const res = await fetch(url, { credentials: 'same-origin' });
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    const preview = text.slice(0, 120).replace(/\s+/g, ' ').trim();
    return { error: `Server returned non-JSON response: ${preview}` };
  }
}

function EmptyLogState() {
  return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
      color: 'var(--text-muted)', fontSize: 13, flexDirection: 'column', gap: 10 }}>
      <span style={{ fontSize: 32 }}>📋</span>
      <span>Set a time range and click <strong style={{ color: 'var(--accent)' }}>Load Logs</strong></span>
    </div>
  );
}

function PodLogsTab({ item }) {
  const [lines,       setLines]       = useState([]);
  const [loading,     setLoading]     = useState(false);
  const [pulling,     setPulling]     = useState(false);
  const [error,       setError]       = useState(null);
  const [container,   setContainer]   = useState('');
  const [fromVal,     setFromVal]     = useState('');
  const [toVal,       setToVal]       = useState('');
  const [lastFetchAt, setLastFetchAt] = useState(null);
  const [newCount,    setNewCount]    = useState(0);
  const [copied,      setCopied]      = useState(false);
  const bottomRef = useRef(null);

  const ns         = item.raw?.metadata?.namespace || '';
  const name       = item.raw?.metadata?.name || item.title || '';
  const containers = getContainers(item.raw);

  useEffect(() => {
    setLines([]); setError(null); setLoading(false);
    setLastFetchAt(null); setNewCount(0);
    setContainer(containers[0] || '');
    setFromVal(''); setToVal('');
  }, [name, ns]);

  const buildUrl = (since = null) => {
    const p = new URLSearchParams();
    if (container) p.set('container', container);
    if (since) {
      p.set('sinceTime', since);
    } else if (fromVal) {
      p.set('sinceTime', new Date(fromVal).toISOString());
    } else if (toVal) {
      p.set('tail', 'all');
    } else {
      p.set('tail', '500');
    }
    return `/sensor/api/pods/${ns}/${name}/logs?${p}`;
  };

  const scrollBottom = () =>
    setTimeout(() => bottomRef.current?.scrollIntoView({ behavior: 'smooth' }), 50);

  const loadLogs = async () => {
    setLoading(true); setError(null); setLines([]); setNewCount(0);
    try {
      const data = await safeFetch(buildUrl());
      if (data.error) throw new Error(data.error);
      setLines(data.logs ? data.logs.split('\n') : []);
      setLastFetchAt(data.fetchedAt);
      scrollBottom();
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  const pullNew = async () => {
    if (!lastFetchAt) return;
    setPulling(true); setError(null); setNewCount(0);
    try {
      const data = await safeFetch(buildUrl(lastFetchAt));
      if (data.error) throw new Error(data.error);
      const nl = data.logs ? data.logs.split('\n').filter(Boolean) : [];
      if (nl.length) { setLines(prev => [...prev, ...nl]); setNewCount(nl.length); scrollBottom(); }
      setLastFetchAt(data.fetchedAt);
    } catch (e) { setError(e.message); }
    finally { setPulling(false); }
  };

  const copy = () => {
    navigator.clipboard?.writeText(visibleLines.join('\n'));
    setCopied(true); setTimeout(() => setCopied(false), 1500);
  };

  const visibleLines = applyToFilter(lines, toVal);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0, gap: 0 }}>
      {}
      {containers.length > 1 && (
        <div style={{ paddingTop: 8, paddingBottom: 4, flexShrink: 0 }}>
          <select value={container} onChange={e => setContainer(e.target.value)}
            style={{ ...ST.dtInput, fontSize: 12 }}>
            {containers.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>
      )}

      {}
      <div style={{ display: 'flex', alignItems: 'flex-end', gap: 8,
        padding: '8px 0 10px', flexWrap: 'wrap', flexShrink: 0 }}>
        <DateRangePicker fromVal={fromVal} toVal={toVal}
          onFromChange={setFromVal} onToChange={setToVal} />

        <div style={{ display: 'flex', gap: 7, alignItems: 'center', flexWrap: 'wrap' }}>
          <button onClick={loadLogs} disabled={loading} style={ST.btnLoad}>
            {loading ? '⟳ Loading…' : '▶ Load Logs'}
          </button>
          {lastFetchAt && (
            <button onClick={pullNew} disabled={pulling} style={ST.btnPull}>
              {pulling ? '⟳ Pulling…' : '⬇ Pull New'}
            </button>
          )}
          {lines.length > 0 && (
            <button onClick={copy} style={ST.btnCopy}>
              {copied ? '✓ Copied' : '⎘ Copy'}
            </button>
          )}
          {lines.length > 0 && (
            <span style={{ fontSize: 11, color: 'var(--text-muted)', display: 'flex', gap: 6, alignItems: 'center' }}>
              {newCount > 0 && <span style={{ color: 'var(--accent-3)', fontWeight: 600 }}>+{newCount} new</span>}
              {toVal && visibleLines.length !== lines.length
                ? <span>{visibleLines.length} <span style={{ color: 'var(--text-muted)' }}>/ {lines.length} lines</span></span>
                : <span>{lines.length} lines</span>
              }
            </span>
          )}
        </div>
      </div>

      {error && <div style={ST.errBox}>✕ {error}</div>}
      {!lines.length && !error && !loading && <EmptyLogState />}
      {lines.length > 0 && (
        <div style={ST.logBox}>
          {colorizeLog(visibleLines.join('\n'))}
          <div ref={bottomRef} />
        </div>
      )}
    </div>
  );
}

export { PodLogsTab };
