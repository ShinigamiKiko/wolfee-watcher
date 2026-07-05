import { useState } from 'react';
import { SYSCALLS, PATH_PRESETS, PROT_PRESETS, SOCKET_PRESETS, DUP_PRESETS, CAT_LABEL } from '../../data/syscalls';
import { TRACEPOINT_EVENT_NAMES } from '../../data/tracepoints';

const TRACEPOINT_SET = new Set(TRACEPOINT_EVENT_NAMES);
import { BuildPolicyForm }  from './BuildPolicyForm';
import { DeployPolicyForm } from './DeployPolicyForm';
import { AuditPolicyForm }  from './AuditPolicyForm';
import { LsmPolicyForm }    from './LsmPolicyForm';
import { TracepointPolicyForm } from './TracepointPolicyForm';
import { SeveritySelect }     from './SeveritySelect';
import { RuntimePolicyForm } from './RuntimePolicyForm';

const SYSCALLS_BY_CAT = SYSCALLS.reduce((m, s) => {
  (m[s.cat] = m[s.cat] || []).push(s);
  return m;
}, {});
const CAT_ORDER = ['process', 'security', 'memory', 'escape', 'privesc', 'filesystem', 'network'];

export function PolicyModal({ initial, onSave, onClose }) {
  const isEdit = !!initial;

  const initialTab = (() => {
    if (initial?.detType === 'Build')      return 'Build';
    if (initial?.detType === 'Deploy')     return 'Deploy';
    if (initial?.detType === 'Audit')      return 'Audit';
    if (initial?.detType === 'LSM')        return 'LSM';
    if (initial?.detType === 'Tracepoint') return 'Tracepoint';
    return 'Runtime';
  })();
  const [outerTab,   setOuterTab]   = useState(initialTab);

  const [name,       setName]       = useState(initial?.name || '');
  const [sev,        setSev]        = useState(() => {
    const raw = initial?.sev || 'High';
    return raw.charAt(0).toUpperCase() + raw.slice(1).toLowerCase();
  });
  const [nameEdited, setNameEdited] = useState(!!initial?.name);

  const [detType,    setDetType]    = useState(initial?.detType || (initial?.processFilter ? 'Binary' : 'Syscall'));
  const [syscall,    setSyscall]    = useState(initial?.syscall       || '');
  const [binary,     setBinary]     = useState(initial?.processFilter || '');
  const [pathFilter, setPathFilter] = useState(initial?.pathFilter    || '');
  const [ns,         setNs]         = useState(initial?.namespace     || '');
  const [alertOnly,  setAlertOnly]  = useState(initial?.alertOnly ?? false);

  const selectedSyscall = SYSCALLS.find(s => s.name === syscall);
  const paramType = selectedSyscall?.paramType;

  const autoName = detType === 'Binary'
    ? (binary.trim() ? `Binary: ${binary.trim()}${pathFilter.trim() ? ' ' + pathFilter.trim() : ''}` : '')
    : (syscall ? `${TRACEPOINT_SET.has(syscall) ? 'Tracepoint' : 'Syscall'}: ${syscall}${pathFilter ? ' ' + pathFilter : ''}` : '');

  const effectiveName = nameEdited ? name : autoName;
  const canSaveRuntime = effectiveName.trim() && (detType === 'Syscall' ? !!syscall : !!binary.trim());

  const buildRuntimeRule = (enabled) => ({
    id:            initial?.id || `rule-${Date.now()}`,
    name:          effectiveName.trim(),
    sev:           sev.toUpperCase(),
    detType,
    category:      '*',
    syscall:       detType === 'Syscall' ? syscall : '*',
    processFilter: detType === 'Binary'  ? binary.trim() : '',
    pathFilter:    pathFilter.trim(),
    namespace:     ns.trim(),
    podPattern:    '',
    alertOnly,
    enabled,
  });

  const handleSyscallSelect = (n) => {
    setSyscall(prev => prev === n ? '' : n);
    setPathFilter('');
  };

  const nameField = (placeholder = 'Policy name (auto-filled)') => (
    <div className="cpol-field">
      <label className="cpol-label">Name</label>
      <input className="cpol-input"
        value={nameEdited ? name : (outerTab === 'Runtime' ? effectiveName : name)}
        onChange={e => { setName(e.target.value); setNameEdited(true); }}
        onFocus={() => { if (!nameEdited && outerTab === 'Runtime' && effectiveName) setName(effectiveName); }}
        placeholder={placeholder} />
    </div>
  );

  return (
    <div className="cpol-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="cpol-modal">
        <div className="cpol-hdr">
          <div className="cpol-tabs">
            {['Runtime', 'Build', 'Deploy', 'Audit', 'LSM', 'Tracepoint'].map(t => (
              <div key={t} className={`cpol-tab${outerTab === t ? ' active' : ''}`}
                onClick={() => setOuterTab(t)}>{t}</div>
            ))}
          </div>
        </div>

        <div className="cpol-body">
          {outerTab === 'Runtime' && <RuntimePolicyForm
            detType={detType} setDetType={setDetType}
            syscall={syscall} setSyscall={setSyscall}
            binary={binary} setBinary={setBinary}
            pathFilter={pathFilter} setPathFilter={setPathFilter}
            ns={ns} setNs={setNs}
            alertOnly={alertOnly} setAlertOnly={setAlertOnly}
            sev={sev} setSev={setSev}
            name={name} setName={setName}
            nameEdited={nameEdited} setNameEdited={setNameEdited}
            effectiveName={effectiveName} canSaveRuntime={canSaveRuntime}
            onSave={rule => { onSave(rule); onClose(); }}
          />}
          {outerTab === 'Build' && <>
            {nameField('e.g. No latest tag in production')}
            <SeveritySelect value={sev} onChange={setSev} />
            <BuildPolicyForm name={name} sev={sev} onSave={onSave} onClose={onClose} initial={initial} />
          </>}
          {outerTab === 'Deploy' && <>
            {nameField('e.g. No privileged containers')}
            <SeveritySelect value={sev} onChange={setSev} />
            <DeployPolicyForm name={name} sev={sev} onSave={onSave} onClose={onClose} initial={initial} />
          </>}
          {outerTab === 'Audit' && <>
            {nameField('e.g. RBAC hardening')}
            <SeveritySelect value={sev} onChange={setSev} />
            <AuditPolicyForm name={name} sev={sev} onSave={onSave} onClose={onClose} initial={initial} />
          </>}
          {outerTab === 'LSM' && <>
            {nameField('e.g. Watch /etc/shadow opens')}
            <SeveritySelect value={sev} onChange={setSev} />
            <LsmPolicyForm name={name} sev={sev} onSave={onSave} onClose={onClose} initial={initial} />
          </>}
          {outerTab === 'Tracepoint' && <>
            {nameField('e.g. Kernel module load')}
            <SeveritySelect value={sev} onChange={setSev} />
            <TracepointPolicyForm name={name} sev={sev} onSave={onSave} onClose={onClose} initial={initial} />
          </>}
        </div>

        {outerTab === 'Runtime' && (
          <div className="cpol-footer">
            <button className="cpol-btn" onClick={onClose}>Cancel</button>
            <button className="cpol-btn"
              onClick={() => { if (canSaveRuntime) { onSave(buildRuntimeRule(false)); onClose(); } }}
              disabled={!canSaveRuntime}>Save draft</button>
            <button className="cpol-btn primary"
              onClick={() => { if (canSaveRuntime) { onSave(buildRuntimeRule(true)); onClose(); } }}
              disabled={!canSaveRuntime}>
              {isEdit ? 'Save changes' : 'Create & Enable'}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
