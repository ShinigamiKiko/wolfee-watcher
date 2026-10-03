import { useCallback, useEffect, useMemo, useState } from 'react';
import { usePerms } from '../../context/PermissionsContext';
import { fetchRules, fetchSources } from './api';
import { Monitoring } from './Monitoring';
import { Investigation } from './Investigation';
import { Rules } from './Rules';
import { RESOURCES } from './shared';

const TABS = [['monitoring', 'Monitoring'], ['investigation', 'Investigation'], ['rules', 'Rules']];

export function AuditLogs() {
  const { isAdmin } = usePerms();
  const [tab, setTab] = useState('monitoring');
  const [rules, setRules] = useState([]);
  const [stats, setStats] = useState({});
  const [builtinMissing, setBuiltinMissing] = useState(0);
  const [rulesError, setRulesError] = useState('');
  const [sources, setSources] = useState(null);
  const [danger, setDanger] = useState(0);
  const [preset, setPreset] = useState(null);
  const [draft, setDraft] = useState(null);

  const reloadRules = useCallback(async () => {
    try {
      const data = await fetchRules();
      setRules(data.rules || []);
      setStats(data.stats || {});
      setBuiltinMissing(data.builtinMissing || 0);
      setRulesError('');
    } catch (e) {
      setRulesError(e.message);
    }
  }, []);

  useEffect(() => { reloadRules(); }, [reloadRules]);

  useEffect(() => {
    let alive = true;
    const load = () => fetchSources().then(d => alive && setSources(d)).catch(() => alive && setSources({ sources: [], failed: true }));
    load();
    const t = setInterval(load, 30000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  const ruleNames = useMemo(() => Object.fromEntries(rules.map(r => [r.id, r.name])), [rules]);
  const origins = useMemo(() => new Set((sources?.sources || []).map(s => s.origin)), [sources]);
  const apiLogConnected = origins.has('both') || origins.has('apilog');
  const admissionSeen = origins.has('admission') || origins.has('both');

  const investigate = useCallback(ev => { setPreset({ user: ev.user, hours: 24 }); setTab('investigation'); }, []);
  const createFromEvent = useCallback(ev => {
    setDraft({
      name: `${ev.kind} ${ev.resource}${ev.ns ? ' in ' + ev.ns : ''}`,
      spec: {
        kinds: [ev.kind],
        resources: RESOURCES.includes(ev.resource) ? [ev.resource] : [],
        ns: ev.ns || '',
        subject: (ev.user || '').startsWith('system:') ? 'sa' : 'people',
      },
    });
    setTab('rules');
  }, []);
  const clearDraft = useCallback(() => setDraft(null), []);

  return (
    <div className="page active al-page">
      <div className="page-header al-header">
        <div className="page-title">Audit logs</div>
        <div className="al-sources">
          <span className="al-source">
            <span className={`al-dot${admissionSeen ? '' : ' off'}`} />
            <span><b>Admission webhook</b> {sources == null ? 'checking' : admissionSeen ? 'receiving' : 'no events in the last hour'}</span>
          </span>
          <span className="al-source">
            <span className={`al-dot${apiLogConnected ? '' : ' off'}`} />
            <span><b>kube-apiserver log</b> {sources == null ? 'checking' : apiLogConnected ? 'receiving' : 'not connected'}</span>
          </span>
        </div>
      </div>

      {sources != null && !apiLogConnected && (
        <div className="al-notice">
          <p>No kube-apiserver audit log records arrived in the last hour, so source IP and client are empty and read actions (<code>get</code>, <code>list</code>) are not visible. Changes still arrive through the admission webhook. To connect the log, start kube-apiserver with <code>--audit-log-path</code> and <code>--audit-policy-file</code> and set <code>sentryAudit.auditLog.enabled</code> in the chart.</p>
        </div>
      )}

      <div className="tabs" role="tablist" aria-label="Audit logs">
        {TABS.map(([id, label]) => (
          <div key={id} role="tab" tabIndex={0} aria-selected={tab === id}
               className={`tab${tab === id ? ' active' : ''}`}
               onClick={() => setTab(id)} onKeyDown={e => { if (e.key === 'Enter') setTab(id); }}>
            {label}
            {id === 'monitoring' && danger > 0 && <span className="al-count hot">{danger}</span>}
            {id === 'rules' && rules.length > 0 && <span className="al-count">{rules.length}</span>}
          </div>
        ))}
      </div>

      {tab === 'monitoring' && (
        <Monitoring ruleNames={ruleNames} apiLogConnected={apiLogConnected} canEdit={isAdmin}
                    onInvestigate={investigate} onCreateRule={createFromEvent}
                    onOlder={() => setTab('investigation')} onDangerCount={setDanger} />
      )}
      {tab === 'investigation' && (
        <Investigation ruleNames={ruleNames} apiLogConnected={apiLogConnected} canEdit={isAdmin}
                       retentionHours={sources?.retentionHours} preset={preset} onCreateRule={createFromEvent} />
      )}
      {tab === 'rules' && (
        <Rules rules={rules} stats={stats} builtinMissing={builtinMissing} canEdit={isAdmin}
               draft={draft} onDraftUsed={clearDraft} reload={reloadRules} loadError={rulesError} />
      )}
    </div>
  );
}
