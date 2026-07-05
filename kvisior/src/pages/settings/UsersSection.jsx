import { useCallback, useEffect, useState } from 'react';
import { usePerms } from '../../context/PermissionsContext';
import { useApp } from '../../context/AppContext';
import { apiJSON } from './settingsApi';
import { RoleBadge, Field, btnGhost, btnDanger, PermissionDeniedHint } from './settingsUi';
import { ROLE_OPTIONS } from './settingsConstants';

const inputStyle = {
  width: '100%', boxSizing: 'border-box',
  background: 'var(--bg-base)', border: '1px solid var(--border)',
  borderRadius: 8, padding: '9px 12px', fontSize: 13,
  color: 'var(--text-primary)', outline: 'none', fontFamily: 'DM Sans,sans-serif',
};

function ResetPasswordDialog({ user, onClose, onSuccess }) {
  const [np,   setNp]   = useState('');
  const [conf, setConf] = useState('');
  const [busy, setBusy] = useState(false);
  const [err,  setErr]  = useState(null);

  const submit = async (e) => {
    e?.preventDefault?.();
    if (np.length < 8)  { setErr('Minimum 8 characters'); return; }
    if (np !== conf)    { setErr('Passwords do not match'); return; }
    setBusy(true); setErr(null);
    try {
      await apiJSON(`/api/users/${user.id}/password`, {
        method: 'POST',
        body: JSON.stringify({ new: np }),
      });
      onSuccess(user.username);
    } catch (e) {
      setErr(String(e.message || e));
      setBusy(false);
    }
  };

  return (
    <div className="modal">
      <div className="modal-header">
        <span className="modal-title">Reset password — {user.username}</span>
        <button className="modal-close" onClick={onClose}>✕</button>
      </div>
      <form onSubmit={submit} className="modal-body" style={{display:'flex',flexDirection:'column',gap:14}}>
        <div>
          <label style={{display:'block',fontSize:11,textTransform:'uppercase',letterSpacing:'.07em',color:'var(--text-muted)',marginBottom:6}}>New password</label>
          <input type="password" autoFocus autoComplete="new-password" value={np} onChange={e => setNp(e.target.value)} disabled={busy} style={inputStyle} />
        </div>
        <div>
          <label style={{display:'block',fontSize:11,textTransform:'uppercase',letterSpacing:'.07em',color:'var(--text-muted)',marginBottom:6}}>Confirm password</label>
          <input type="password" autoComplete="new-password" value={conf} onChange={e => setConf(e.target.value)} disabled={busy} style={inputStyle} />
        </div>
        {err && (
          <div style={{fontSize:12,padding:'8px 10px',borderRadius:6,background:'rgba(239,68,68,.1)',border:'1px solid rgba(239,68,68,.3)',color:'var(--danger)'}}>
            {err}
          </div>
        )}
        <div className="modal-footer">
          <button type="button" onClick={onClose} style={btnGhost}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={busy}>{busy ? 'Saving…' : 'Reset password'}</button>
        </div>
      </form>
    </div>
  );
}

export function UsersSection({ toast }) {
  const { can, me, reload: reloadPerms } = usePerms();
  const { showModal, closeModal } = useApp();
  const [users, setUsers]   = useState(null);
  const [groups, setGroups] = useState([]);
  const [error, setError]   = useState(null);
  const [editing, setEditing] = useState(null);

  const reload = useCallback(async () => {
    try {
      const body = await apiJSON('/api/users');
      setUsers(body.items || []);
      try {
        const g = await apiJSON('/api/groups');
        setGroups(g.items || []);
      } catch { }
      setError(null);
    } catch (e) { setError(String(e.message || e)); }
  }, []);
  useEffect(() => { reload(); }, [reload]);

  const startCreate = () => setEditing({ username: '', email: '', full_name: '', group_id: '', role: 'ro', password: '' });
  const startEdit   = (u) => setEditing({ id: u.id, username: u.username, email: u.email,
    full_name: u.full_name, group_id: u.group_id, role: u.role });

  const save = async () => {
    if (!editing.username.trim()) { toast('error', 'Username required', ''); return; }
    if (!editing.id) {
      if (!editing.password || editing.password.length < 8) {
        toast('error', 'Password required', 'New users need a password of at least 8 characters');
        return;
      }
    }
    try {
      if (editing.id) {
        await apiJSON(`/api/users/${editing.id}`, {
          method: 'PUT',
          body: JSON.stringify({
            email: editing.email,
            full_name: editing.full_name,
            group_id: editing.group_id,
            role: editing.role,
          }),
        });
        toast('success', 'User updated', editing.username);
      } else {
        await apiJSON('/api/users', { method: 'POST', body: JSON.stringify(editing) });
        toast('success', 'User created', editing.username);
      }
      setEditing(null);
      reload();
      if (me && editing.username === me.username) reloadPerms();
    } catch (e) { toast('error', 'Save failed', String(e.message || e)); }
  };

  const resetPassword = (u) => {
    showModal(
      <ResetPasswordDialog
        user={u}
        onClose={closeModal}
        onSuccess={(username) => { closeModal(); toast('success', 'Password reset', username); }}
      />
    );
  };

  const remove = async (u) => {
    if (!window.confirm(`Delete user "${u.username}"?`)) return;
    try {
      await apiJSON(`/api/users/${u.id}`, { method: 'DELETE' });
      toast('warn', 'User removed', u.username);
      reload();
    } catch (e) { toast('error', 'Delete failed', String(e.message || e)); }
  };

  return (
    <div className="card" style={{padding:24,border:'none'}}>
      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:16}}>
        <div>
          <div style={{fontSize:14,fontWeight:600,color:'var(--text-primary)',marginBottom:3}}>User Permissions</div>
          <div style={{fontSize:12,color:'var(--text-muted)'}}>
            Effective role wins between the user's own role and the group role. Admin can do everything;
            Read-Only can only view — no create, edit or delete.
          </div>
        </div>
        {can('users.create') ? (
          <button className="btn btn-primary" onClick={startCreate}>+ New user</button>
        ) : (
          <span style={{fontSize:11,color:'var(--text-muted)'}}>Read-only — cannot create users</span>
        )}
      </div>

      {error && <div style={{fontSize:12,color:'var(--danger)',marginBottom:10}}>Error: {error}</div>}

      {editing && (
        <div style={{padding:14,border:'1px solid var(--border)',borderRadius:8,marginBottom:16,background:'var(--bg-elevated)'}}>
          <div style={{fontSize:12,fontWeight:600,marginBottom:10}}>{editing.id ? 'Edit user' : 'New user'}</div>
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}>
            {!editing.id && (
              <Field label="Username *" value={editing.username}
                onChange={v => setEditing(e => ({...e, username: v}))} />
            )}
            <Field label="Full name" value={editing.full_name}
              onChange={v => setEditing(e => ({...e, full_name: v}))} />
            <Field label="Email" value={editing.email}
              onChange={v => setEditing(e => ({...e, email: v}))} />
            <Field label="Role" type="select" value={editing.role} options={ROLE_OPTIONS}
              onChange={v => setEditing(e => ({...e, role: v}))} />
            <Field label="Group" type="select" value={editing.group_id || ''}
              options={[{value: '', label: '— No group —'}, ...groups.map(g => ({value: g.id, label: `${g.name} (${g.role})`}))]}
              onChange={v => setEditing(e => ({...e, group_id: v}))} />
            {!editing.id && (
              <Field label="Initial password *" type="password" value={editing.password || ''}
                onChange={v => setEditing(e => ({...e, password: v}))} />
            )}
          </div>
          <div style={{display:'flex',gap:8,marginTop:12}}>
            <button className="btn btn-primary" onClick={save}>Save</button>
            <button onClick={() => setEditing(null)} style={btnGhost}>Cancel</button>
          </div>
        </div>
      )}

      <div className="table-wrap">
        <table className="data-table">
          <thead><tr><th>Username</th><th>Full name</th><th>Email</th><th>Group</th><th>Role</th><th>Effective</th><th/></tr></thead>
          <tbody>
            {users == null && <tr><td colSpan={7} style={{padding:14,fontSize:12,color:'var(--text-muted)'}}>Loading…</td></tr>}
            {users != null && users.length === 0 && <tr><td colSpan={7} style={{padding:14,fontSize:12,color:'var(--text-muted)'}}>No users yet</td></tr>}
            {(users || []).map(u => (
              <tr key={u.id}>
                <td className="td-primary mono" style={{fontSize:12}}>{u.username}</td>
                <td style={{fontSize:12,color:'var(--text-muted)'}}>{u.full_name || '—'}</td>
                <td style={{fontSize:12,color:'var(--text-muted)'}}>{u.email || '—'}</td>
                <td style={{fontSize:12,color:'var(--text-muted)'}}>{u.group_name || '—'}</td>
                <td><RoleBadge role={u.role}/></td>
                <td><RoleBadge role={u.effective_role}/></td>
                <td style={{display:'flex',gap:6}}>
                  {can('users.write') && <button onClick={() => startEdit(u)} style={btnGhost}>Edit</button>}
                  {can('users.write') && <button onClick={() => resetPassword(u)} style={btnGhost}>Reset password</button>}
                  {can('users.delete') && <button onClick={() => remove(u)} style={btnDanger}>Remove</button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {me && (
        <PermissionDeniedHint msg={`Signed in as "${me.username}" with effective role "${me.effective_role}".`} />
      )}
    </div>
  );
}
