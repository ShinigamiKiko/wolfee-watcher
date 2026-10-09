import { useState, useMemo } from 'react';
import { SevBadge } from '../../components/ui';
import { SYSCALL_BY_NAME } from '../../data/syscalls';
import { SidePanel, DetailSection, SubTabs, KV, Score, Notice } from '../../components/kit';
import { originOf, containerIdOf } from '../../utils/origin';
import { Icon } from '../../components/Icon';

const pick = (v, key) => (v[key] && v[key] !== '—' ? v[key] : (v._raw?.[key] || '—'));

export function SyscallDetail({ v, onClose, onFp, onResolve, getMatchedRules, rulesVersion }) {
  const [tab, setTab] = useState('violation');

  const matchedPolicies = useMemo(() => {
    if (!v || !getMatchedRules) return [];
    return getMatchedRules(v._raw || v);
  }, [v, getMatchedRules, rulesVersion]);

  if (!v) return null;

  const syscallMeta = SYSCALL_BY_NAME?.[v.syscall] || null;
  const isRoot = v.uid === 0;
  const origin = originOf(v);
  const containerId = containerIdOf(v);
  const originText = origin ? `${origin.label}${origin.shortId ? ` · ${origin.shortId}` : ''}` : null;

  return (
    <SidePanel
      title={<span className="mono">{v.syscall}</span>}
      meta={`${origin ? origin.title : v.namespace} · ${v.node}`}
      onClose={onClose}
      actions={<>
        <SevBadge sev={v.sev} />
        {v.category && <span className="mono t-xs t-muted">{v.category}</span>}
        <span className="grow" />
        <button type="button" className="btn btn-outline btn-sm btn-tone-muted" onClick={() => onFp?.()}><Icon name="flag" /> FalsePos</button>
        <button type="button" className="btn btn-outline btn-sm btn-tone-danger" onClick={() => onResolve?.()}><Icon name="check" /> Resolve</button>
      </>}
      tabs={<SubTabs tabs={[{ id: 'violation', label: 'Violation' }, { id: 'deployment', label: 'Deployment' }, { id: 'policy', label: 'Policy' }]} active={tab} onChange={setTab} />}
    >
      {tab === 'violation' && <>
        {origin && (
          <Notice icon="info">
            <div className="t-strong">{origin.title}{origin.shortId && <span className="mono t-muted"> · {origin.shortId}</span>}</div>
            <div className="t-sm t-secondary mt-4">{origin.hint}</div>
          </Notice>
        )}
        <div className="dp-lead">
          Syscall <span className="mono t-accent">{v.syscall}</span>
          {syscallMeta && <> — {syscallMeta.desc}</>}
          {v.pod && v.pod !== '—' && <> in pod <strong>{v.pod}</strong></>}.
        </div>
        {matchedPolicies.length > 0 && (
          <div className="row t-sm mb-12">
            <span className="t-muted">Rule:</span>
            <span className="mono t-accent t-medium">{matchedPolicies[0].name}</span>
            {matchedPolicies.length > 1 && <span className="t-xs t-muted">+{matchedPolicies.length - 1} more</span>}
          </div>
        )}
        <DetailSection title="Event details">
          <KV items={[
            ['Syscall', v.syscall],
            ['Severity', v._matchedRule?.sev || v.sev],
            ['Policy', v._matchedRule?.name || '—'],
            ['Pod', originText || pick(v, 'pod')],
            ['Namespace', origin ? 'not in Kubernetes' : pick(v, 'namespace')],
            ['Node', pick(v, 'node')],
            containerId ? ['Container ID', <span className="mono" title={containerId}>{containerId.slice(0, 12)}</span>] : null,
            ['Process', pick(v, 'process')],
            ['PID', v.pid],
            ['UID', v.uid],
          ]} />
        </DetailSection>
        <DetailSection title="Time">
          <KV items={[['First seen', v.firstSeen], ['Last seen', v.lastSeen]]} />
        </DetailSection>
      </>}

      {tab === 'deployment' && <>
        <DetailSection title="Workload">
          <div className="score-grid score-grid--2">
            {[['Pod', originText || v.pod], ['Namespace', origin ? 'not in Kubernetes' : v.namespace], ['Node', v.node], ['Cluster', v.cluster]].map(([k, val]) => (
              <Score key={k} label={k} value={<span className="clip">{val || '—'}</span>} className="t-sm t-medium" />
            ))}
          </div>
        </DetailSection>
        <DetailSection title="Container">
          <KV items={[['Image', v.image], ['Container', v.container], ['Process', pick(v, 'process')], ['Cmdline', pick(v, 'cmdline')]]} />
        </DetailSection>
        <DetailSection title="Security context">
          <KV items={[
            ['Running as root', isRoot ? <span className="t-warning"><Icon name="alert" /> Yes</span> : 'No'],
            ['Syscall risk', syscallMeta?.sev || v.severity || '—'],
            ['UID', v.uid],
            ['PID', v.pid],
          ]} />
        </DetailSection>
      </>}

      {tab === 'policy' && <>
        <DetailSection title="Matched policies">
          {matchedPolicies.length > 0
            ? matchedPolicies.map(p => (
                <div key={p.id} className="item-card">
                  <div className="row row--between mb-4">
                    <span className="t-md t-medium t-primary">{p.name}</span>
                    <SevBadge sev={p.sev} />
                  </div>
                  <div className="row row--wrap row--loose t-xs t-muted">
                    {p.syscall && p.syscall !== '*' && <span>syscall: <code className="inline t-accent">{p.syscall}</code></span>}
                    {p.processFilter && <span>binary: <code className="inline t-accent">{p.processFilter}</code></span>}
                    {p.namespace && <span>ns: <code className="inline t-accent">{p.namespace}</code></span>}
                    {p.action && <span>action: <code className="inline t-warning">{p.action}</code></span>}
                  </div>
                </div>
              ))
            : <div className="t-sm t-muted">No policy rules matched this event.</div>}
        </DetailSection>
        {syscallMeta && (
          <DetailSection title="Syscall reference">
            <div className="prose mb-8">{syscallMeta.desc}</div>
            <KV items={[['Category', syscallMeta.cat], ['Default severity', syscallMeta.sev]]} />
          </DetailSection>
        )}
        {v.rationale && <DetailSection title="Rationale"><div className="prose">{v.rationale}</div></DetailSection>}
        {v.remediation && <DetailSection title="Remediation"><div className="prose t-ok">{v.remediation}</div></DetailSection>}
      </>}
    </SidePanel>
  );
}
