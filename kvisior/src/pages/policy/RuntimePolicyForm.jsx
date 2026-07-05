import { SeveritySelect } from './SeveritySelect';
import { SYSCALLS, PATH_PRESETS, PROT_PRESETS, SOCKET_PRESETS, DUP_PRESETS, CAT_LABEL } from '../../data/syscalls';
import { TRACEPOINT_EVENTS } from '../../data/tracepoints';

const SYSCALLS_BY_CAT = SYSCALLS.reduce((m, s) => {
  (m[s.cat] = m[s.cat] || []).push(s);
  return m;
}, {});
const CAT_ORDER = ['process', 'security', 'memory', 'escape', 'privesc', 'filesystem', 'network'];

export function RuntimePolicyForm({
  detType, setDetType, syscall, setSyscall,
  pathFilter, setPathFilter,
  binary, setBinary,
  ns, setNs,
  alertOnly, setAlertOnly,
  sev, setSev,
  name, setName,
  nameEdited, setNameEdited,
  effectiveName, canSaveRuntime,
  onSave,
}) {
  const selectedSyscall = SYSCALLS.find(s => s.name === syscall)
    || TRACEPOINT_EVENTS.find(t => t.name === syscall);
  const paramType = selectedSyscall?.paramType;

  const handleSyscallSelect = (n) => {
    setSyscall(prev => prev === n ? '' : n);
    setPathFilter('');
  };

  return (
    <>
      {}
      <div className="cpol-field">
        <label className="cpol-label">Name</label>
        <input className="cpol-input"
          value={nameEdited ? name : effectiveName}
          onChange={e => { setName(e.target.value); setNameEdited(true); }}
          onFocus={() => { if (!nameEdited && effectiveName) setName(effectiveName); }}
          placeholder="Policy name (auto-filled)" />
      </div>

      <SeveritySelect value={sev} onChange={setSev} />

      {}
      <div className="cpol-field">
        <label className="cpol-label">Detection type</label>
        <div className="cpol-toggle">
          {['Syscall', 'Binary'].map(t => (
            <button key={t} className={`cpol-toggle-btn${detType === t ? ' active' : ''}`}
              onClick={() => setDetType(t)}>{t}</button>
          ))}
        </div>
      </div>

      {}
      {detType === 'Syscall' && (
        <div className="cpol-field">
          <label className="cpol-label">Syscall</label>
          {CAT_ORDER.map(cat => {
            const group = SYSCALLS_BY_CAT[cat];
            if (!group?.length) return null;
            return (
              <div key={cat} style={{ marginBottom: 10 }}>
                <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.08em',
                  textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 5 }}>
                  {CAT_LABEL[cat] || cat}
                </div>
                <div className="cpol-syscall-grid">
                  {group.map(s => (
                    <div key={s.name}
                      className={`cpol-syscall-chip${syscall === s.name ? ' sel' : ''}`}
                      title={s.desc}
                      onClick={() => handleSyscallSelect(s.name)}>
                      {s.name}
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
          {}
          <div style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.08em',
              textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 5 }}>
              Kernel Tracepoints
            </div>
            <div className="cpol-syscall-grid">
              {TRACEPOINT_EVENTS.map(t => (
                <div key={t.name}
                  className={`cpol-syscall-chip${syscall === t.name ? ' sel' : ''}`}
                  title={t.desc}
                  onClick={() => handleSyscallSelect(t.name)}>
                  {t.name}
                </div>
              ))}
            </div>
          </div>
          {syscall && (
            <div className="cpol-hint" style={{ marginTop: 6 }}>
              <code>{syscall}</code> — {selectedSyscall?.desc}
            </div>
          )}
        </div>
      )}

      {}
      {detType === 'Binary' && <>
        <div className="cpol-field">
          <label className="cpol-label">Binary name</label>
          <div className="cpol-input-pre">
            <span className="cpol-input-pre-sym">$</span>
            <input value={binary} onChange={e => setBinary(e.target.value)}
              placeholder="e.g. cat" autoFocus />
          </div>
          <div className="cpol-hint">Matches binary name: <code>cat</code> → triggers on <code>/bin/cat</code>, <code>/usr/bin/cat</code></div>
        </div>
        <div className="cpol-field">
          <label className="cpol-label">
            Arguments
            <span style={{ fontWeight: 400, textTransform: 'none', letterSpacing: 0,
              marginLeft: 8, fontSize: 11, color: 'var(--text-muted)' }}>— optional path filter</span>
          </label>
          <input className="cpol-input" value={pathFilter} onChange={e => setPathFilter(e.target.value)}
            placeholder="e.g. /etc/passwd"
            style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 13 }} />
          <div className="cpol-hint">Empty = alert on any invocation</div>
        </div>
      </>}

      {}
      {detType === 'Syscall' && syscall && (
        <div className="cpol-field">
          <label className="cpol-label">
            {paramType === 'path'  ? 'Path filter' :
             paramType === 'prot'  ? 'Memory protection' :
             paramType === 'newfd' ? 'Target file descriptor' : 'Argument filter'}
            <span style={{ fontWeight: 400, textTransform: 'none', letterSpacing: 0,
              marginLeft: 8, fontSize: 11, color: 'var(--text-muted)' }}>— empty = any</span>
          </label>

          {paramType === 'path' && <>
            <div className="cpol-syscall-grid" style={{ marginBottom: 8 }}>
              {PATH_PRESETS.map(p => (
                <div key={p.value}
                  className={`cpol-syscall-chip${pathFilter === p.value ? ' sel' : ''}`}
                  title={p.desc}
                  onClick={() => setPathFilter(prev => prev === p.value ? '' : p.value)}>
                  {p.label}
                </div>
              ))}
            </div>
            <input className="cpol-input" value={pathFilter}
              onChange={e => setPathFilter(e.target.value)}
              placeholder="or type custom path…"
              style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 13 }} />
            <div className="cpol-hint">Matches <code>pathname</code> argument — substring match</div>
          </>}

          {paramType === 'prot' && <>
            <div className="cpol-syscall-grid" style={{ marginBottom: 8 }}>
              {PROT_PRESETS.map(p => {
                const selected = pathFilter.split(',').map(v => v.trim()).includes(p.value);
                return (
                  <div key={p.value}
                    className={`cpol-syscall-chip${selected ? ' sel' : ''}`}
                    title={p.desc}
                    onClick={() => {
                      const vals = pathFilter ? pathFilter.split(',').map(v => v.trim()).filter(Boolean) : [];
                      const idx = vals.indexOf(p.value);
                      if (idx >= 0) vals.splice(idx, 1); else vals.push(p.value);
                      setPathFilter(vals.join(','));
                    }}>
                    {p.label}
                  </div>
                );
              })}
            </div>
            <div className="cpol-hint">
              {pathFilter
                ? <><code>args.prot ∈ {'{' + pathFilter + '}'}</code></>
                : 'No filter — catch any prot that passed Tracee filter (6 or 7)'}
            </div>
          </>}

          {paramType === 'socket' && <>
            <div className="cpol-syscall-grid" style={{ marginBottom: 8 }}>
              {SOCKET_PRESETS.map(p => {
                const selected = pathFilter.split(',').map(v => v.trim()).includes(p.value);
                return (
                  <div key={p.value}
                    className={`cpol-syscall-chip${selected ? ' sel' : ''}`}
                    title={p.desc}
                    onClick={() => {
                      const vals = pathFilter ? pathFilter.split(',').map(v => v.trim()).filter(Boolean) : [];
                      const idx = vals.indexOf(p.value);
                      if (idx >= 0) vals.splice(idx, 1); else vals.push(p.value);
                      setPathFilter(vals.join(','));
                    }}>
                    {p.label}
                  </div>
                );
              })}
            </div>
            <div className="cpol-hint">
              {pathFilter
                ? <><code>args.domain ∈ {'{' + pathFilter + '}'}</code></>
                : 'No filter — catch any socket domain. Select to narrow.'}
            </div>
          </>}

          {paramType === 'newfd' && <>
            <div className="cpol-syscall-grid" style={{ marginBottom: 8 }}>
              {DUP_PRESETS.map(p => {
                const selected = pathFilter.split(',').map(v => v.trim()).includes(p.value);
                return (
                  <div key={p.value}
                    className={`cpol-syscall-chip${selected ? ' sel' : ''}`}
                    title={p.desc}
                    onClick={() => {
                      const vals = pathFilter ? pathFilter.split(',').map(v => v.trim()).filter(Boolean) : [];
                      const idx = vals.indexOf(p.value);
                      if (idx >= 0) vals.splice(idx, 1); else vals.push(p.value);
                      setPathFilter(vals.join(','));
                    }}>
                    {p.label}
                  </div>
                );
              })}
            </div>
            <div className="cpol-hint">
              {pathFilter
                ? <><code>args.newfd ∈ {'{' + pathFilter + '}'}</code> — tracee captures only newfd≤2 (reverse shell)</>
                : 'No filter — catch all dup2/dup3 (newfd 0/1/2). Select to narrow.'}
            </div>
          </>}

          {!paramType && <>
            <input className="cpol-input" value={pathFilter}
              onChange={e => setPathFilter(e.target.value)}
              placeholder={
                syscall === 'connect' ? 'e.g. 1.2.3.4 or :443' :
                syscall === 'execve' || syscall === 'execveat' ? 'e.g. /bin/sh' :
                'e.g. /etc/passwd'}
              style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 13 }} />
            <div className="cpol-hint">Substring match against syscall arguments</div>
          </>}
        </div>
      )}

      {}
      <div className="cpol-field">
        <label className="cpol-label">
          Namespace
          <span style={{ fontWeight: 400, textTransform: 'none', letterSpacing: 0,
            marginLeft: 8, fontSize: 11, color: 'var(--text-muted)' }}>— optional, substring</span>
        </label>
        <input className="cpol-input" value={ns} onChange={e => setNs(e.target.value)}
          placeholder="e.g. production" />
      </div>

      {}
      <div className="cpol-field">
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', userSelect: 'none' }}>
          <input type="checkbox" checked={alertOnly} onChange={e => setAlertOnly(e.target.checked)}
            style={{ width: 15, height: 15, accentColor: 'var(--accent)', cursor: 'pointer' }} />
          <span className="cpol-label" style={{ margin: 0 }}>Alert</span>
        </label>
      </div>
    </>
  );
}
