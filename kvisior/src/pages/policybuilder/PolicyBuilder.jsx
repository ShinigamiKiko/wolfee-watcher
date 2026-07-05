import { useState, useMemo, useEffect, useCallback } from 'react';
import { useBridge } from '../../context/BridgeContext';
import { Sparkline } from '../../components/Sparkline';
import { EmptyState } from '../../components/EmptyState';
import { relTime } from '../../utils/format';
import { aggregateProbes, fmtNum, riskColor } from './probesData';
import { CONTAINER_PATH_PRESETS, SCOPE_FIELDS, genPolicyYaml } from './policyFilters';
import '../../styles/probes.scss';
import '../../styles/policybuilder.scss';

function loadState(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    if (raw) return { ...fallback, ...JSON.parse(raw) };
  } catch { }
  return fallback;
}

function FilterRow({ row, onChange, onRemove }) {
  return (
    <div className="pb-frow">
      <input
        className="pb-finput"
        value={row.value}
        placeholder={`args.${row.key}=…`}
        onChange={e => onChange(e.target.value)}
      />
      <button className="pb-frow-btn danger" title="Remove" onClick={onRemove}>✕</button>
    </div>
  );
}

function PathPicker({ onApply, onClose }) {
  const [value, setValue] = useState('');
  const v = value.trim();
  return (
    <div className="pb-preset-menu pb-picker">
      <div className="pb-picker-hint">
        Click a preset to fill the field below, edit it if needed, then press <b>Add path</b>.
      </div>
      {CONTAINER_PATH_PRESETS.map(grp => (
        <div key={grp.group} className="pb-preset-grp">
          <div className="pb-preset-grp-label">{grp.group}</div>
          {grp.paths.map(p => (
            <button key={p.value} type="button"
              className={`pb-preset-item${value === p.value ? ' sel' : ''}`}
              title={p.desc}
              onClick={() => setValue(p.value)}>
              {p.value}
            </button>
          ))}
        </div>
      ))}
      <input className="pb-picker-custom" autoFocus
        placeholder="path — pick a preset above or type your own…"
        value={value}
        onChange={e => setValue(e.target.value)}
        onKeyDown={e => { if (e.key === 'Enter' && v) onApply(v); }} />
      <div className="pb-picker-foot">
        <button type="button" className="pb-frow-btn" onClick={onClose}>Cancel</button>
        <button type="button" className="pb-picker-ok" disabled={!v}
          onClick={() => onApply(v)}>Add path</button>
      </div>
    </div>
  );
}

function AddPicker({ catalog, hits, included, onAdd, onClose }) {
  const [q, setQ] = useState('');
  const [group, setGroup] = useState('all');
  const groups = useMemo(() => ['all', ...new Set(catalog.map(c => c.group))], [catalog]);

  const list = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const rows = catalog.filter(c => {
      if (group !== 'all' && c.group !== group) return false;
      if (!needle) return true;
      return c.name.toLowerCase().includes(needle) || c.desc.toLowerCase().includes(needle);
    });
    return rows.slice().sort((a, b) => {
      const aa = hits.get(a.name)?.active ? 1 : 0;
      const bb = hits.get(b.name)?.active ? 1 : 0;
      if (aa !== bb) return bb - aa;
      return a.name.localeCompare(b.name);
    });
  }, [catalog, hits, q, group]);

  return (
    <div className="pb-add-menu" onClick={e => e.stopPropagation()}>
      <div className="pb-add-tools">
        <input className="pb-add-search" autoFocus placeholder="Search hook or description…"
          value={q} onChange={e => setQ(e.target.value)} />
        <select className="probes-select" value={group} onChange={e => setGroup(e.target.value)}>
          {groups.map(g => <option key={g} value={g}>{g === 'all' ? 'All groups' : g}</option>)}
        </select>
      </div>
      <div className="pb-add-list">
        {list.map(c => {
          const h = hits.get(c.name);
          const added = included.has(c.name);
          const hasPath = (c.args || []).some(a => a.kind === 'path');
          const state = added ? 'in policy' : h?.active ? 'active' : h?.count ? 'idle' : 'add +';
          return (
            <button key={c.name} type="button"
              className={`pb-add-row${added ? ' added' : ''}`}
              disabled={added}
              title={added ? 'Already in policy' : c.desc}
              onClick={() => onAdd(c.name)}>
              <span className={`status-dot ${h?.active ? 'status-active' : h?.count ? 'status-warn' : 'probes-never'}`} />
              <span className="pb-add-name">{c.name}</span>
              {hasPath && <span className="pb-add-path-tag" title="Supports file-path filters">path</span>}
              <span className={`sev sev-${c.risk || 'low'}`}>{c.group}</span>
              <span className="pb-add-state">{state}</span>
            </button>
          );
        })}
        {list.length === 0 && <div className="pb-add-empty">No hooks match.</div>}
      </div>
      <div className="pb-add-foot">
        <span className="pb-add-hint">{included.size} in policy</span>
        <button type="button" className="pb-frow-btn" onClick={onClose}>Done</button>
      </div>
    </div>
  );
}

function EventCard({
  event, rows, hit, expanded, onToggle, onRemove,
  pickerFor, setPickerFor, addPathValue, addRow, updateRowAt, removeRowAt, renderExtra,
}) {
  const pathArgs  = event.args.filter(a => a.kind === 'path');
  const otherArgs = event.args.filter(a => a.kind !== 'path');
  const pathKeys  = new Set(pathArgs.map(a => a.key));
  const pathCount = rows.filter(r => pathKeys.has(r.key) && (r.value || '').trim() !== '').length;
  const statusCls = hit?.active ? 'status-active' : hit?.count ? 'status-warn' : 'probes-never';
  const rowsFor = key => rows.map((r, i) => ({ r, i })).filter(x => x.r.key === key);
  const metaLabel = pathArgs.length === 0
    ? 'no path arg'
    : pathCount ? `${pathCount} path${pathCount > 1 ? 's' : ''}` : 'all paths';

  return (
    <div className={`pb-card${expanded ? ' open' : ''}`}>
      <div className="pb-card-head" onClick={onToggle}>
        <span className="pb-card-caret">{expanded ? '▾' : '▸'}</span>
        <span className={`status-dot ${statusCls}`} />
        <span className="pb-card-name">{event.name}</span>
        <span className={`sev sev-${event.risk || 'low'}`}>{event.group}</span>
        <span className="pb-card-meta">{metaLabel}</span>
        <span className="pb-card-spark">
          {hit?.windowCount
            ? <Sparkline points={hit.spark} width={90} height={22} color={riskColor(event.risk || 'low')} />
            : null}
        </span>
        <button className="pb-card-remove" title="Remove from policy"
          onClick={e => { e.stopPropagation(); onRemove(); }}>✕</button>
      </div>

      {expanded && (
        <div className="pb-card-body">
          <p className="pb-card-desc">{event.desc}</p>
          {renderExtra && renderExtra(event)}

          <div className="probes-dp-section">
            <div className="probes-dp-section-title">Watch file paths</div>
            {pathArgs.length === 0
              ? <div className="pb-arg-empty">This hook has no file-path argument — it is added unfiltered (every event of this type within scope).</div>
              : <p className="pb-hint">Press <b>+ Add path</b>, pick a preset (or type your own), adjust it, then add. Each path becomes <code>args.&lt;key&gt;=path</code>; with no paths the hook matches everything.</p>}
            {pathArgs.map(arg => {
              const list = rowsFor(arg.key);
              const pk = `${event.name}::${arg.key}`;
              return (
                <div className="pb-arg" key={arg.key}>
                  <div className="pb-arg-head">
                    <span className="pb-arg-key">args.{arg.key}</span>
                    <span className="pb-arg-kind">{arg.label || 'path'}</span>
                    <span className="pb-preset-wrap" style={{ marginLeft: 'auto' }}>
                      <button className="pb-arg-add pb-arg-add-path" title="Choose a path to watch"
                        onClick={() => setPickerFor(p => p === pk ? null : pk)}>+ Add path</button>
                      {pickerFor === pk && (
                        <PathPicker
                          onApply={v => { addPathValue(event.name, arg.key, v); setPickerFor(null); }}
                          onClose={() => setPickerFor(null)} />
                      )}
                    </span>
                  </div>
                  {list.length === 0
                    ? <div className="pb-arg-empty">no path filter — matches all paths; press + Add path to choose which to watch</div>
                    : <div className="pb-chips">
                        {list.map(({ r, i }) => (
                          <span className="pb-path-chip" key={i} title={`args.${arg.key}=${r.value}`}>
                            {r.value}
                            <button type="button" className="pb-chip-x" title="Remove"
                              onClick={() => removeRowAt(event.name, i)}>✕</button>
                          </span>
                        ))}
                      </div>}
                </div>
              );
            })}
          </div>

          {otherArgs.length > 0 && (
            <details className="pb-more">
              <summary>Other arguments ({otherArgs.length})</summary>
              <div className="pb-more-body">
                {otherArgs.map(arg => {
                  const list = rowsFor(arg.key);
                  return (
                    <div className="pb-arg" key={arg.key}>
                      <div className="pb-arg-head">
                        <span className="pb-arg-key">args.{arg.key}</span>
                        <span className="pb-arg-kind">{arg.kind}{arg.label ? ` · ${arg.label}` : ''}</span>
                        <button className="pb-arg-add" onClick={() => addRow(event.name, arg.key)}>+ value</button>
                      </div>
                      {list.length === 0
                        ? <div className="pb-arg-empty">no filter — matches all</div>
                        : list.map(({ r, i }) => (
                          <FilterRow key={i} row={r}
                            onChange={nv => updateRowAt(event.name, i, nv)}
                            onRemove={() => removeRowAt(event.name, i)} />
                        ))}
                    </div>
                  );
                })}
              </div>
            </details>
          )}

          <div className="probes-dp-section pb-card-live">
            <div className="probes-dp-section-title">Live activity</div>
            {hitLine(hit)}
          </div>
        </div>
      )}
    </div>
  );
}

export function PolicyBuilder({ title, catalog, storageKey, renderExtra }) {
  const { events, connected } = useBridge();

  const init = loadState(storageKey, { included: [], filters: {}, scope: { container: true } });
  const [included, setIncluded] = useState(() => new Set(init.included));
  const [filters,  setFilters]  = useState(init.filters);
  const [scope,    setScope]    = useState(init.scope);

  const [showAdd,  setShowAdd]  = useState(false);
  const [expanded, setExpanded] = useState(() => new Set());
  const [pickerFor, setPickerFor] = useState(null);
  const [showYaml, setShowYaml] = useState(false);
  const [copied,   setCopied]   = useState(false);

  useEffect(() => {
    const payload = JSON.stringify({ included: [...included], filters, scope });
    try { localStorage.setItem(storageKey, payload); } catch { }
  }, [included, filters, scope, storageKey]);

  const hits = useMemo(() => {
    const m = new Map(aggregateProbes(events).map(p => [p.name, p]));
    return m;
  }, [events]);

  const includedList = useMemo(
    () => catalog.filter(c => included.has(c.name)), [catalog, included]);

  const addEvent = useCallback((name) => {
    setIncluded(prev => {
      if (prev.has(name)) return prev;
      const next = new Set(prev); next.add(name); return next;
    });
    setExpanded(prev => { const n = new Set(prev); n.add(name); return n; });
  }, []);

  const removeEvent = useCallback((name) => {
    setIncluded(prev => { const n = new Set(prev); n.delete(name); return n; });
    setPickerFor(p => (p && p.startsWith(`${name}::`)) ? null : p);
  }, []);

  const toggleExpand = useCallback((name) => {
    setExpanded(prev => {
      const n = new Set(prev);
      n.has(name) ? n.delete(name) : n.add(name);
      return n;
    });
  }, []);

  const addRow = (name, key) =>
    setFilters(prev => ({ ...prev, [name]: [...(prev[name] || []), { key, value: '' }] }));

  const updateRowAt = (name, idx, newVal) =>
    setFilters(prev => {
      const rows = [...(prev[name] || [])];
      if (rows[idx]) rows[idx] = { ...rows[idx], value: newVal };
      return { ...prev, [name]: rows };
    });

  const removeRowAt = (name, idx) =>
    setFilters(prev => ({ ...prev, [name]: (prev[name] || []).filter((_, i) => i !== idx) }));

  const addPathValue = (name, key, value) =>
    setFilters(prev => {
      const rows = prev[name] || [];
      if (rows.some(r => r.key === key && r.value === value)) return prev;
      return { ...prev, [name]: [...rows, { key, value }] };
    });

  const includedEvents = useMemo(() =>
    includedList.map(c => ({ name: c.name, filters: filters[c.name] || [] })),
    [includedList, filters]);

  const yaml = useMemo(() => genPolicyYaml(title, includedEvents, scope), [title, includedEvents, scope]);

  const copyYaml = async () => {
    try { await navigator.clipboard.writeText(yaml); setCopied(true); setTimeout(() => setCopied(false), 1500); }
    catch { }
  };

  return (
    <div className="probes-page pb-page">
      <div className="probes-header pb-header-min">
        <div className="probes-title-row">
          <div className="probes-title">{title}</div>
          <div className={`probes-conn ${connected ? 'ok' : 'down'}`}>
            <span className="dot" /> {connected ? 'bridge live' : 'bridge offline'}
          </div>
        </div>
      </div>

      <div className="probes-body">
        <div className="pb-canvas">
          <div className="probes-toolbar pb-canvas-toolbar">
            <div className="pb-canvas-title">
              Hooks in policy <span className="pb-canvas-count">{included.size}</span>
            </div>
            <div className="pb-canvas-actions">
              {included.size > 0 && (
                <button className="probes-toggle" onClick={() => setIncluded(new Set())}>Clear all</button>
              )}
              <button className="pb-export-btn" onClick={() => setShowYaml(true)}>
                Export policy YAML →
              </button>
              <div className="pb-add-wrap">
                <button className="pb-add-btn" title="Add a hook to the policy"
                  onClick={() => setShowAdd(s => !s)}>+ Add hook</button>
                {showAdd && (
                  <>
                    <div className="pb-add-backdrop" onClick={() => setShowAdd(false)} />
                    <AddPicker
                      catalog={catalog} hits={hits} included={included}
                      onAdd={addEvent}
                      onClose={() => setShowAdd(false)} />
                  </>
                )}
              </div>
            </div>
          </div>

          <div className="pb-cards-wrap">
            {includedList.length === 0 ? (
              <EmptyState icon="➕"
                title="No hooks in this policy yet"
                sub="Press “+ Add hook” (top right) to add the hooks you want to watch, then restrict each one to the file paths that matter. Nothing is collected until you add it." />
            ) : (
              <div className="pb-cards">
                {includedList.map(c => (
                  <EventCard key={c.name}
                    event={c}
                    rows={filters[c.name] || []}
                    hit={hits.get(c.name)}
                    expanded={expanded.has(c.name)}
                    onToggle={() => toggleExpand(c.name)}
                    onRemove={() => removeEvent(c.name)}
                    pickerFor={pickerFor}
                    setPickerFor={setPickerFor}
                    addPathValue={addPathValue}
                    addRow={addRow}
                    updateRowAt={updateRowAt}
                    removeRowAt={removeRowAt}
                    renderExtra={renderExtra} />
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {showYaml && (
        <div className="pb-yaml-overlay" onClick={() => setShowYaml(false)}>
          <div className="pb-yaml-card" onClick={e => e.stopPropagation()}>
            <div className="pb-yaml-head">
              <span>{title} — Tracee policy ({included.size} events)</span>
              <div className="pb-yaml-actions">
                <button className="pb-export-btn" onClick={copyYaml}>{copied ? 'Copied ✓' : 'Copy'}</button>
                <button className="probes-dp-close" onClick={() => setShowYaml(false)}>✕</button>
              </div>
            </div>
            <div className="pb-scope pb-yaml-scope">
              <span className="pb-scope-label">Scope</span>
              <label className="pb-scope-chk">
                <input type="checkbox" checked={scope.container !== false}
                  onChange={e => setScope(s => ({ ...s, container: e.target.checked }))} />
                container
              </label>
              {SCOPE_FIELDS.filter(f => f.kind !== 'flag').map(f => (
                <span className="pb-scope-field" key={f.key}>
                  <span className="pb-scope-key">{f.label}</span>
                  <input className="pb-scope-input" placeholder={f.hint}
                    value={scope[f.key] || ''}
                    onChange={e => setScope(s => ({ ...s, [f.key]: e.target.value }))} />
                </span>
              ))}
            </div>
            <pre className="pb-yaml-body">{yaml}</pre>
          </div>
        </div>
      )}
    </div>
  );
}

function hitLine(h) {
  if (!h || !h.count) return <div className="probes-dp-empty">Not seen in the current stream window.</div>;
  return (
    <div className="pb-hits">
      <span><b>{fmtNum(h.count)}</b> hits</span>
      <span><b>{fmtNum(h.windowCount)}</b> last hour</span>
      <span><b>{h.nsCount}</b> ns</span>
      <span><b>{h.podCount}</b> pods</span>
      <span>last {h.lastSeen ? relTime(h.lastSeen) : '—'}</span>
    </div>
  );
}
