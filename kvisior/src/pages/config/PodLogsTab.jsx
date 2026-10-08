import { useState, useRef, useEffect } from 'react';
import { getContainers, colorizeLog, safeFetch } from './yamlPanelHelpers';
import { Notice } from '../../components/kit';
import { DateRangePicker, applyToFilter } from './DateRangePicker';
import { Icon } from '../../components/Icon';

function EmptyLogState() {
  return (
    <div className="empty-state fill-center">
      <Icon name="clipboard" size={28} />
      <span>Set a time range and click <strong className="t-accent">Load Logs</strong></span>
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
    <>
      <div className="log-tools">
        {containers.length > 1 && (
          <select className="input input--sm" aria-label="Container" value={container} onChange={e => setContainer(e.target.value)}>
            {containers.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
        )}
        <DateRangePicker fromVal={fromVal} toVal={toVal} onFromChange={setFromVal} onToChange={setToVal} />
        <button type="button" className="btn btn-primary btn-sm" onClick={loadLogs} disabled={loading}>
          {loading ? <><Icon name="loader" /> Loading…</> : <><Icon name="play" /> Load Logs</>}
        </button>
        {lastFetchAt && (
          <button type="button" className="btn btn-outline btn-sm" onClick={pullNew} disabled={pulling}>
            {pulling ? <><Icon name="loader" /> Pulling…</> : <><Icon name="download" /> Pull New</>}
          </button>
        )}
        {lines.length > 0 && (
          <button type="button" className="btn btn-outline btn-sm" onClick={copy}>
            {copied ? <><Icon name="check" /> Copied</> : <><Icon name="copy" /> Copy</>}
          </button>
        )}
        {lines.length > 0 && (
          <span className="row t-xs t-muted">
            {newCount > 0 && <span className="t-ok t-strong">+{newCount} new</span>}
            {toVal && visibleLines.length !== lines.length
              ? <span>{visibleLines.length} / {lines.length} lines</span>
              : <span>{lines.length} lines</span>}
          </span>
        )}
      </div>

      {error && <Notice tone="danger" icon="circle-x"><span className="mono t-sm">{error}</span></Notice>}
      {!lines.length && !error && !loading && <EmptyLogState />}
      {lines.length > 0 && (
        <div className="log-box">
          {colorizeLog(visibleLines.join('\n'))}
          <div ref={bottomRef} />
        </div>
      )}
    </>
  );
}

export { PodLogsTab };
