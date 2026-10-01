import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApp } from '../../context/AppContext';
import { getCluster } from '../../data/cluster';
import { createRule, deleteRule, patchRule, restoreRules, updateRule } from './api';
import { KINDS, READ_KINDS, RESOURCES, SEVERITIES, fmtDate, num } from './shared';

const BLANK_SPEC = {
  kinds: [], resources: [], ns: '', nsExclude: '', objName: '', subject: 'any', users: '', usersExclude: '',
  ipMode: 'any', ipList: '', result: 'any', cmd: '', alertEvery: 'each', thN: 3, thMin: 10, clusters: [],
};
const blankRule = () => ({ name: '', severity: 'high', enabled: true, alert: false, spec: { ...BLANK_SPEC } });

export function describeRule(r) {
  const s = r.spec || {};
  const parts = [`${(s.kinds || []).join(', ')} ${s.resources?.length ? s.resources.join(', ') : 'any resource'}`];
  if (s.ns && s.ns !== '*') parts.push(`in ${s.ns}`);
  if (s.nsExclude) parts.push(`except ${s.nsExclude}`);
  if (s.objName) parts.push(`named ${s.objName}`);
  if (s.subject === 'people') parts.push('by people');
  if (s.subject === 'sa') parts.push('by service accounts');
  if (s.users) parts.push(`user ${s.users}`);
  if (s.usersExclude) parts.push(`not ${s.usersExclude}`);
  if (s.ipMode === 'in') parts.push(`from ${s.ipList}`);
  if (s.ipMode === 'notin') parts.push(`not from ${s.ipList}`);
  if (s.result && s.result !== 'any') parts.push(`${s.result} only`);
  if (s.cmd) parts.push(`command has ${s.cmd}`);
  if (r.alert && s.alertEvery === 'threshold') parts.push(`alert after ${s.thN} in ${s.thMin} min`);
  if (s.clusters?.length) parts.push(`cluster ${s.clusters.join(', ')}`);
  return parts.join('; ');
}

function Switch({ checked, onChange, label, disabled }) {
  return <button type="button" role="switch" aria-checked={checked} aria-label={label} disabled={disabled}
                 className="al-switch" onClick={() => onChange(!checked)} />;
}

function Chips({ options, selected, onToggle, label }) {
  return (
    <div className="al-chips" role="group" aria-label={label}>
      {options.map(o => (
        <button key={o} type="button" className="al-chip" aria-pressed={selected.includes(o)} onClick={() => onToggle(o)}>{o}</button>
      ))}
    </div>
  );
}

function RuleForm({ initial, editing, onSave, onCancel }) {
  const [rule, setRule] = useState(initial);
  const [errors, setErrors] = useState({});
  const [saving, setSaving] = useState(false);
  const nameRef = useRef(null);
  const cluster = getCluster();

  useEffect(() => { setRule(initial); setErrors({}); nameRef.current?.focus(); }, [initial]);

  const spec = rule.spec;
  const setSpec = (key, value) => setRule(r => ({ ...r, spec: { ...r.spec, [key]: value } }));
  const toggle = (key, value) => setSpec(key, spec[key].includes(value) ? spec[key].filter(v => v !== value) : [...spec[key], value]);
  const needsLog = spec.ipMode !== 'any' || (spec.kinds.length > 0 && spec.kinds.every(k => READ_KINDS.includes(k)));
  const repeat = rule.alert && spec.alertEvery === 'threshold';
  const thisClusterOnly = spec.clusters.length > 0;

  const submit = async e => {
    e.preventDefault();
    const found = {};
    if (!rule.name.trim()) found.name = 'Enter a name for the rule.';
    if (!spec.kinds.length) found.kinds = 'Pick at least one action.';
    if (spec.ipMode !== 'any' && !spec.ipList.trim()) found.ip = 'Enter at least one address or network.';
    setErrors(found);
    if (Object.keys(found).length) return;
    setSaving(true);
    try {
      await onSave({
        ...rule,
        name: rule.name.trim(),
        spec: { ...spec, ns: spec.ns.trim() || '*', cmd: spec.kinds.includes('exec') ? spec.cmd : '', thN: +spec.thN || 3, thMin: +spec.thMin || 10 },
      });
    } catch (err) {
      setErrors({ save: err.message });
    } finally {
      setSaving(false);
    }
  };

  return (
    <form className="al-form" onSubmit={submit} noValidate>
      <h2>{editing ? `Edit rule: ${initial.name}` : 'New audit rule'}</h2>
      <fieldset>
        <legend>What happened</legend>
        <div className="al-grid">
          <label>Name
            <input ref={nameRef} className={`al-input${errors.name ? ' invalid' : ''}`} maxLength={120} value={rule.name}
                   onChange={e => setRule(r => ({ ...r, name: e.target.value }))} placeholder="Exec into payment pods" />
            {errors.name && <span className="al-err">{errors.name}</span>}
          </label>
        </div>
        <div className="al-sublabel">Actions</div>
        <Chips options={KINDS} selected={spec.kinds} onToggle={v => toggle('kinds', v)} label="Actions" />
        {errors.kinds && <span className="al-err">{errors.kinds}</span>}
        <div className="al-sublabel">Resources <span className="al-dim">(none selected means any)</span></div>
        <Chips options={RESOURCES} selected={spec.resources} onToggle={v => toggle('resources', v)} label="Resources" />
        {spec.kinds.includes('exec') && (
          <div className="al-grid al-gap">
            <label>Command contains
              <input className="al-input al-mono" value={spec.cmd} onChange={e => setSpec('cmd', e.target.value)} placeholder="/bin/sh" />
            </label>
          </div>
        )}
      </fieldset>
      <fieldset>
        <legend>Where</legend>
        <div className="al-grid">
          <label>Namespaces<input className="al-input al-mono" value={spec.ns === '*' ? '' : spec.ns} onChange={e => setSpec('ns', e.target.value)} placeholder="prod-*, staging" /></label>
          <label>Except namespaces<input className="al-input al-mono" value={spec.nsExclude} onChange={e => setSpec('nsExclude', e.target.value)} placeholder="kube-system" /></label>
          <label>Object name<input className="al-input al-mono" value={spec.objName} onChange={e => setSpec('objName', e.target.value)} placeholder="*-db" /></label>
          <label>Clusters
            <select className="al-input" value={thisClusterOnly ? 'one' : 'all'} onChange={e => setSpec('clusters', e.target.value === 'one' ? [cluster] : [])}>
              <option value="all">All clusters</option>
              <option value="one">{thisClusterOnly ? spec.clusters.join(', ') : `Only ${cluster}`}</option>
            </select>
          </label>
        </div>
      </fieldset>
      <fieldset>
        <legend>Who and from where</legend>
        <div className="al-grid">
          <label>Who
            <select className="al-input" value={spec.subject} onChange={e => setSpec('subject', e.target.value)}>
              <option value="any">Anyone</option><option value="people">People only</option><option value="sa">Service accounts only</option>
            </select>
          </label>
          <label>Only these users<input className="al-input al-mono" value={spec.users} onChange={e => setSpec('users', e.target.value)} placeholder="a.sokolov, system:serviceaccount:ci:*" /></label>
          <label>Except users<input className="al-input al-mono" value={spec.usersExclude} onChange={e => setSpec('usersExclude', e.target.value)} placeholder="system:serviceaccount:argocd:*" /></label>
          <label>Source IP
            <select className="al-input" value={spec.ipMode} onChange={e => setSpec('ipMode', e.target.value)}>
              <option value="any">Any address</option><option value="in">Only from</option><option value="notin">Not from</option>
            </select>
          </label>
          {spec.ipMode !== 'any' && (
            <label>Addresses
              <input className={`al-input al-mono${errors.ip ? ' invalid' : ''}`} value={spec.ipList} onChange={e => setSpec('ipList', e.target.value)} placeholder="10.20.0.0/16, 10.42.*" />
              {errors.ip && <span className="al-err">{errors.ip}</span>}
            </label>
          )}
          <label>Result
            <select className="al-input" value={spec.result} onChange={e => setSpec('result', e.target.value)}>
              <option value="any">Allowed or denied</option><option value="allowed">Allowed only</option><option value="denied">Denied only</option>
            </select>
          </label>
        </div>
        {needsLog && <p className="al-hint al-gap">Read actions and source IP come only from the kube-apiserver log. On a cluster without it this rule cannot match.</p>}
      </fieldset>
      <fieldset>
        <legend>Response</legend>
        <div className="al-grid">
          <label>Severity
            <select className="al-input" value={rule.severity} onChange={e => setRule(r => ({ ...r, severity: e.target.value }))}>
              {SEVERITIES.map(s => <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>)}
            </select>
          </label>
          {rule.alert && (
            <label>Raise an alert
              <select className="al-input" value={spec.alertEvery} onChange={e => setSpec('alertEvery', e.target.value)}>
                <option value="each">Every time</option><option value="threshold">Only after repeats</option>
              </select>
            </label>
          )}
          {repeat && <label>Times<input className="al-input al-mono" type="number" min="2" max="1000" value={spec.thN} onChange={e => setSpec('thN', e.target.value)} /></label>}
          {repeat && <label>Within, minutes<input className="al-input al-mono" type="number" min="1" max="1440" value={spec.thMin} onChange={e => setSpec('thMin', e.target.value)} /></label>}
        </div>
        <div className="al-checks">
          <label className="al-check"><input type="checkbox" checked={rule.enabled} onChange={e => setRule(r => ({ ...r, enabled: e.target.checked }))} />Report in Violations and highlight in Monitoring</label>
          <label className="al-check"><input type="checkbox" checked={rule.alert} onChange={e => setRule(r => ({ ...r, alert: e.target.checked }))} />Send to Alert Log</label>
        </div>
        <p className="al-hint al-gap">Alerts appear in Alert Log next to runtime, anomaly and honeypot alerts and go out through the integrations configured for it.</p>
      </fieldset>
      {errors.save && <p className="al-err">Could not save the rule: {errors.save}</p>}
      <div className="al-actions">
        <button className="btn btn-primary al-btn" type="submit" disabled={saving}>{editing ? 'Save changes' : 'Save rule'}</button>
        <button className="btn btn-outline al-btn" type="button" onClick={onCancel}>Cancel</button>
      </div>
    </form>
  );
}

export function Rules({ rules, stats, builtinMissing, canEdit, draft, onDraftUsed, reload, loadError }) {
  const { toast } = useApp();
  const navigate = useNavigate();
  const [search, setSearch] = useState('');
  const [group, setGroup] = useState('');
  const [form, setForm] = useState(null);
  const [confirm, setConfirm] = useState(null);

  useEffect(() => {
    if (!draft) return;
    setForm({ editing: false, rule: { ...blankRule(), ...draft, spec: { ...BLANK_SPEC, ...draft.spec } } });
    onDraftUsed();
  }, [draft, onDraftUsed]);

  const groups = useMemo(() => [...new Set(rules.map(r => r.group))], [rules]);
  const rows = useMemo(() => {
    const q = search.trim().toLowerCase();
    return rules.filter(r => (!group || r.group === group) && (!q || `${r.name} ${describeRule(r)}`.toLowerCase().includes(q)));
  }, [rules, search, group]);

  const run = async (action, done) => {
    try {
      await action();
      await reload();
      if (done) toast('success', done);
    } catch (e) {
      toast('error', 'The change was not saved', e.status === 403 ? 'Only administrators can change audit rules.' : e.message);
    }
  };
  const save = async rule => {
    if (form.editing) await updateRule(rule.id, rule); else await createRule(rule);
    await reload();
    toast('success', form.editing ? `Rule "${rule.name}" updated` : `Rule "${rule.name}" saved`, 'Every kvisior picks it up within 15 seconds.');
    setForm(null);
  };

  const enabled = rules.filter(r => r.enabled).length;
  const alerting = rules.filter(r => r.alert).length;

  return (
    <div>
      <div className="al-toolbar">
        <input className="al-input al-search" type="search" placeholder="Search rules" aria-label="Search rules" value={search} onChange={e => setSearch(e.target.value)} />
        <select className="al-input" aria-label="Group" value={group} onChange={e => setGroup(e.target.value)}>
          <option value="">All groups</option>
          {groups.map(g => <option key={g} value={g}>{g}</option>)}
        </select>
        {canEdit && <button className="btn btn-primary al-btn" onClick={() => setForm({ editing: false, rule: blankRule() })}>Add rule</button>}
        {canEdit && builtinMissing > 0 && (
          <button className="btn btn-outline al-btn" onClick={() => run(restoreRules, 'Built-in rules restored')}>Restore {builtinMissing} built-in rule{builtinMissing === 1 ? '' : 's'}</button>
        )}
      </div>
      <p className="al-hint al-note">
        {rules.length} rules: {enabled} report violations, {alerting} send alerts to{' '}
        <button className="al-link" onClick={() => navigate('/alertlog')}>Alert Log</button>. Rules are stored in the database and apply to every cluster unless a rule names one.
        {!canEdit && ' Only administrators can change them.'}
      </p>
      {loadError && <p className="al-err">Could not load the rules: {loadError}</p>}
      {form && <RuleForm initial={form.rule} editing={form.editing} onSave={save} onCancel={() => setForm(null)} />}
      <div className="al-scrollx">
        <table className="data-table al-rules">
          <thead><tr><th>Enabled</th><th>Alert</th><th>Rule</th><th>Severity</th><th>Violations</th><th>Last seen</th><th /></tr></thead>
          <tbody>
            {rows.length === 0 && <tr className="al-norow"><td colSpan={7}><div className="al-blank">No rules match. Clear the search, or add a rule for the action you want to watch.</div></td></tr>}
            {rows.map(r => {
              const st = stats[r.id];
              return (
                <tr key={r.id}>
                  <td><Switch checked={r.enabled} disabled={!canEdit} label={`Report ${r.name} in Violations`}
                              onChange={v => run(() => patchRule(r.id, { enabled: v }))} /></td>
                  <td><Switch checked={r.alert} disabled={!canEdit} label={`Send ${r.name} to Alert Log`}
                              onChange={v => run(() => patchRule(r.id, { alert: v }), v ? `"${r.name}" now sends alerts to Alert Log` : `"${r.name}" no longer sends alerts`)} /></td>
                  <td className="al-rulecell">
                    <div>{r.name}<span className="al-tag al-tag-origin">{r.origin === 'builtin' ? r.group : 'Custom'}</span></div>
                    <div className="al-mono al-ruledesc">{describeRule(r)}</div>
                  </td>
                  <td><span className={`al-tag al-tag-${r.severity}`}>{r.severity}</span></td>
                  <td className="al-mono">{st ? num(st.violations) : '0'}</td>
                  <td className="al-mono">{st?.lastSeen ? fmtDate(st.lastSeen) : <span className="al-empty">never</span>}</td>
                  <td>
                    {canEdit && (
                      <div className="al-rowactions">
                        {confirm === r.id ? (
                          <>
                            <button className="btn btn-danger al-btn-sm" onClick={() => { setConfirm(null); run(() => deleteRule(r.id), `Rule "${r.name}" deleted`); }}>Delete rule</button>
                            <button className="btn btn-outline al-btn-sm" onClick={() => setConfirm(null)}>Keep</button>
                          </>
                        ) : (
                          <>
                            <button className="btn btn-outline al-btn-sm" onClick={() => setForm({ editing: true, rule: { ...r, spec: { ...BLANK_SPEC, ...r.spec } } })}>Edit</button>
                            <button className="btn btn-outline al-btn-sm" onClick={() => setConfirm(r.id)}>Delete</button>
                          </>
                        )}
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
