import { useState, useMemo } from 'react';
import { SevBadge } from '../../components/ui';
import { SYSCALL_BY_NAME, matchesRule } from '../../data/syscalls';

export function SyscallDetail({ v, onClose, onFp, onResolve, getMatchedRules, rulesVersion }) {
  const [tab, setTab] = useState('violation');

  const matchedPolicies = useMemo(() => {
    if (!v || !getMatchedRules) return [];
    return getMatchedRules(v._raw || v);
  }, [v, getMatchedRules, rulesVersion]);

  if (!v) return null;

  const syscallMeta = SYSCALL_BY_NAME?.[v.syscall] || null;
  const isRoot      = v.uid === 0;
  const isCrit      = v.sev === 'CRITICAL';

  const kv = (k, val) => (
    <div className="dp-kv" key={k}>
      <span>{k}</span>
      <span style={{ textAlign: 'right', maxWidth: '60%', wordBreak: 'break-all' }}>{val ?? '—'}</span>
    </div>
  );

  const block = (title, children) => (
    <div style={{ marginBottom: 16 }}>
      <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '.09em', textTransform: 'uppercase',
        color: 'var(--text-muted)', marginBottom: 8, borderBottom: '1px solid var(--border)', paddingBottom: 4 }}>
        {title}
      </div>
      {children}
    </div>
  );

  return (
    <div className="detail-panel open">
      <div className="detail-panel-inner">
        <div className="dp-header">
          <div style={{ minWidth: 0 }}>
            <div className="dp-title" style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 13 }}>{v.syscall}</div>
            <div className="dp-meta">{v.namespace} · {v.node}</div>
          </div>
          <button className="dp-close" onClick={onClose}>✕</button>
        </div>

        <div style={{ display: 'flex', gap: 8, marginBottom: 16, alignItems: 'center', flexWrap: 'wrap' }}>
          <SevBadge sev={v.sev} />
          <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono,monospace' }}>{v.category}</span>
          <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
            <button className="btn btn-outline" style={{ fontSize: 11, padding: '3px 9px', color: 'var(--text-muted)', borderColor: 'rgba(100,116,139,.35)' }}
              onClick={() => onFp?.()}>🚩 FalsePos</button>
            <button className="btn btn-outline" style={{ fontSize: 11, padding: '3px 9px', color: 'var(--danger)', borderColor: 'rgba(239,68,68,.35)' }}
              onClick={() => onResolve?.()}>✓ Resolve</button>
          </div>
        </div>

        <div className="tabs" style={{ marginBottom: 16 }}>
          {['violation', 'deployment', 'policy'].map(t => (
            <div key={t} className={`tab${tab === t ? ' active' : ''}`} onClick={() => setTab(t)}
              style={{ textTransform: 'capitalize', fontSize: 12 }}>{t}</div>
          ))}
        </div>

        {tab === 'violation' && <>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 12 }}>
            Syscall <span style={{ fontFamily: 'JetBrains Mono,monospace', color: 'var(--accent)' }}>{v.syscall}</span>
            {syscallMeta && <> — {syscallMeta.desc}</>}
            {v.pod && v.pod !== '—' && <> in pod <strong style={{ color: 'var(--text-primary)' }}>{v.pod}</strong></>}.
          </div>
          {matchedPolicies.length > 0 && (
            <div style={{ fontSize: 12, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ color: 'var(--text-muted)' }}>Rule:</span>
              <span style={{ color: 'var(--accent)', fontFamily: 'JetBrains Mono,monospace', fontWeight: 500 }}>
                {matchedPolicies[0].name}
              </span>
              {matchedPolicies.length > 1 && (
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>+{matchedPolicies.length - 1} more</span>
              )}
            </div>
          )}
          {block('Event Details', <>
            {kv('Syscall',   v.syscall)}
            {kv('Severity',  v._matchedRule?.sev || v.sev)}
            {kv('Policy',    v._matchedRule?.name || '—')}
            {kv('Pod',       v.pod !== '—' ? v.pod : (v._raw?.pod || '—'))}
            {kv('Namespace', v.namespace !== '—' ? v.namespace : (v._raw?.namespace || '—'))}
            {kv('Node',      v.node !== '—' ? v.node : (v._raw?.node || '—'))}
            {kv('Process',   v.process !== '—' ? v.process : (v._raw?.process || '—'))}
            {kv('PID', v.pid)}{kv('UID', v.uid)}
          </>)}
          {block('Time', <>{kv('First seen', v.firstSeen)}{kv('Last seen', v.lastSeen)}</>)}
        </>}

        {tab === 'deployment' && <>
          {block('Workload', (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 10 }}>
              {[['Pod', v.pod], ['Namespace', v.namespace], ['Node', v.node], ['Cluster', v.cluster]].map(([k, val]) => (
                <div key={k} style={{ background: 'var(--bg-elevated)', borderRadius: 8, padding: '8px 10px' }}>
                  <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '.07em', color: 'var(--text-muted)', marginBottom: 3 }}>{k}</div>
                  <div style={{ fontSize: 12, color: 'var(--text-primary)', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{val || '—'}</div>
                </div>
              ))}
            </div>
          ))}
          {block('Container', <>{kv('Image', v.image)}{kv('Container', v.container)}{kv('Process', v.process !== '—' ? v.process : (v._raw?.process || '—'))}{kv('Cmdline', v.cmdline !== '—' ? v.cmdline : (v._raw?.cmdline || '—'))}</>)}
          {block('Security Context', <>{kv('Running as root', isRoot ? '⚠ Yes' : 'No')}{kv('Syscall risk', syscallMeta?.sev || v.severity || '—')}{kv('UID', v.uid)}{kv('PID', v.pid)}</>)}
        </>}

        {tab === 'policy' && <>
          {matchedPolicies.length > 0
            ? block('Matched Policies', matchedPolicies.map(p => (
                <div key={p.id} style={{ padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,.04)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                    <span style={{ fontSize: 13, color: 'var(--text-primary)', fontWeight: 500 }}>{p.name}</span>
                    <SevBadge sev={p.sev} />
                  </div>
                  <div style={{ display: 'flex', gap: 12, fontSize: 11, color: 'var(--text-muted)' }}>
                    {p.syscall && p.syscall !== '*' && <span>syscall: <code style={{ color: 'var(--accent)' }}>{p.syscall}</code></span>}
                    {p.processFilter && <span>binary: <code style={{ color: 'var(--accent)' }}>{p.processFilter}</code></span>}
                    {p.namespace && <span>ns: <code style={{ color: 'var(--accent)' }}>{p.namespace}</code></span>}
                    {p.action && <span>action: <code style={{ color: 'var(--warning)' }}>{p.action}</code></span>}
                  </div>
                </div>
              )))
            : <div style={{ fontSize: 13, color: 'var(--text-muted)', padding: '12px 0' }}>No policy rules matched this event.</div>
          }
          {syscallMeta && block('Syscall Reference', <>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 8 }}>{syscallMeta.desc}</div>
            {kv('Category', syscallMeta.cat)}{kv('Default severity', syscallMeta.sev)}
          </>)}
          {block('Rationale',   <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{v.rationale}</div>)}
          {block('Remediation', <div style={{ fontSize: 12, color: 'var(--accent-3)',       lineHeight: 1.6, whiteSpace: 'pre-line' }}>{v.remediation}</div>)}
        </>}
      </div>
    </div>
  );
}
