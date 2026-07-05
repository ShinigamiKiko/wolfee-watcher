import { useState, useRef, useEffect } from 'react';
import { toYaml } from './yamlUtils';
import { isPod, isNode } from './yamlPanelHelpers';
import { PodLogsTab }   from './PodLogsTab';
import { NodeEventsTab } from './NodeEventsTab';

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

export function YamlPanel({ item, onClose }) {
  const [activeTab, setActiveTab] = useState('manifest');
  const [copied,    setCopied]    = useState(false);

  useEffect(() => { setActiveTab('manifest'); }, [item?.title]);

  if (!item) return null;

  const yaml    = item.raw ? toYaml(item.raw) : null;
  const _isPod  = isPod(item);
  const _isNode = isNode(item);

  const tabs = _isPod  ? ['manifest', 'logs']
             : _isNode ? ['manifest', 'events']
             :           ['manifest'];

  const tabLabel = t => ({ manifest: '📄 Manifest', logs: '📋 Logs', events: '📅 Events' }[t] || t);

  const copy = () => { navigator.clipboard?.writeText(yaml || ''); setCopied(true); setTimeout(() => setCopied(false), 1500); };

  return (
    <div className="detail-panel open" style={{ width: 580, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
      <div style={{ display: 'flex', flexDirection: 'column', height: '100%', padding: '16px 16px 0' }}>

        {}
        <div style={{ display: 'flex', justifyContent: 'space-between',
          alignItems: 'flex-start', marginBottom: 10, flexShrink: 0 }}>
          <div style={{ minWidth: 0, flex: 1, marginRight: 8 }}>
            <div style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 13, fontWeight: 600,
              color: 'var(--text-primary)', wordBreak: 'break-all' }}>{item.title}</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{item.sub}</div>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0 }}>
            {activeTab === 'manifest' && yaml && (
              <button onClick={copy} style={{ fontSize: 11, padding: '3px 10px', borderRadius: 5,
                cursor: 'pointer', background: 'var(--bg-elevated)', border: '1px solid var(--border)',
                color: copied ? 'var(--accent-3)' : 'var(--text-muted)' }}>
                {copied ? '✓ Copied' : 'Copy YAML'}
              </button>
            )}
            <button className="dp-close" onClick={onClose}>✕</button>
          </div>
        </div>

        {}
        {tabs.length > 1 && (
          <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', marginBottom: 12, flexShrink: 0 }}>
            {tabs.map(t => (
              <button key={t} onClick={() => setActiveTab(t)}
                style={{ padding: '7px 16px', fontSize: 12, fontWeight: 500, cursor: 'pointer',
                  background: 'none', border: 'none', outline: 'none',
                  color: t === activeTab ? 'var(--accent)' : 'var(--text-muted)',
                  borderBottom: `2px solid ${t === activeTab ? 'var(--accent)' : 'transparent'}`,
                  marginBottom: -1, transition: 'all .15s' }}>
                {tabLabel(t)}
              </button>
            ))}
          </div>
        )}

        {}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, paddingBottom: 16, overflow: 'hidden' }}>
          {activeTab === 'manifest' && (
            yaml
              ? <pre style={{ flex: 1, overflowY: 'auto', overflowX: 'auto', fontSize: 11,
                  lineHeight: 1.65, color: 'var(--text-primary)', fontFamily: 'JetBrains Mono,monospace',
                  background: 'var(--bg-card)', borderRadius: 8, padding: 12, margin: 0, whiteSpace: 'pre' }}>
                  {yaml}
                </pre>
              : <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>No YAML available</div>
          )}
          {activeTab === 'logs'    && _isPod  && <PodLogsTab    item={item} />}
          {activeTab === 'events'  && _isNode && <NodeEventsTab  item={item} />}
        </div>
      </div>
    </div>
  );
}
