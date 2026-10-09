import { useCallback, useEffect, useState } from 'react';
import { usePerms } from '../../context/PermissionsContext';
import { useApp } from '../../context/AppContext';
import { apiJSON } from './settingsApi';
import { RoleBadge, Field, PermissionDeniedHint, SettingsSection, EditorBox, ListState } from './settingsUi';
import { Field as KitField, Notice } from '../../components/kit';
import { ROLE_OPTIONS } from './settingsConstants';
import { Icon } from '../../components/Icon';

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
    <div className="modal modal--sm" role="dialog" aria-modal="true" aria-labelledby="reset-pw-title">
      <div className="modal-header">
        <span className="modal-title" id="reset-pw-title">Reset password — {user.username}</span>
        <button type="button" className="modal-close" aria-label="Close" onClick={onClose}><Icon name="x" /></button>
      </div>
      <form onSubmit={submit} className="modal-body">
        <KitField label="New password" htmlFor="reset-pw-new">
          <input id="reset-pw-new" type="password" autoFocus autoComplete="new-password" value={np} onChange={e => setNp(e.target.value)} disabled={busy} className="input input--block" />
        </KitField>
        <KitField label="Confirm password" htmlFor="reset-pw-confirm">
          <input id="reset-pw-confirm" type="password" autoComplete="new-password" value={conf} onChange={e => setConf(e.target.value)} disabled={busy} className="input input--block" />
        </KitField>
        {err && <Notice tone="danger" className="mb-0">{err}</Notice>}
        <div className="modal-footer">
          <button type="button" onClick={onClose} className="btn btn-ghost">Cancel</button>
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
    <SettingsSection
      title="User Permissions"
      desc="Effective role wins between the user's own role and the group role. Admin can do everything; Read-Only can only view — no create, edit or delete."
      canCreate={can('users.create')}
      readOnlyText="Read-only — cannot create users"
      action={<button type="button" className="btn btn-primary" onClick={startCreate}>+ New user</button>}
      error={error}
    >
      {editing && (
        <EditorBox title={editing.id ? 'Edit user' : 'New user'} onSave={save} onCancel={() => setEditing(null)}>
          {!editing.id && <Field label="Username *" value={editing.username} onChange={v => setEditing(e => ({ ...e, username: v }))} />}
          <Field label="Full name" value={editing.full_name} onChange={v => setEditing(e => ({ ...e, full_name: v }))} />
          <Field label="Email" value={editing.email} onChange={v => setEditing(e => ({ ...e, email: v }))} />
          <Field label="Role" type="select" value={editing.role} options={ROLE_OPTIONS} onChange={v => setEditing(e => ({ ...e, role: v }))} />
          <Field label="Group" type="select" value={editing.group_id || ''}
            options={[{ value: '', label: '— No group —' }, ...groups.map(g => ({ value: g.id, label: `${g.name} (${g.role})` }))]}
            onChange={v => setEditing(e => ({ ...e, group_id: v }))} />
          {!editing.id && <Field label="Initial password *" type="password" value={editing.password || ''} onChange={v => setEditing(e => ({ ...e, password: v }))} />}
        </EditorBox>
      )}

      <div className="table-wrap">
        <table className="data-table data-table--static">
          <thead><tr><th>Username</th><th>Full name</th><th>Email</th><th>Group</th><th>Role</th><th>Effective</th><th aria-label="Actions" /></tr></thead>
          <tbody>
            <ListState items={users} cols={7} empty="No users yet" />
            {(users || []).map(u => (
              <tr key={u.id}>
                <td className="td-primary mono t-sm">{u.username}</td>
                <td className="t-sm t-muted wrap">{u.full_name || '—'}</td>
                <td className="t-sm t-muted">{u.email || '—'}</td>
                <td className="t-sm t-muted wrap">{u.group_name || '—'}</td>
                <td><RoleBadge role={u.role} /></td>
                <td><RoleBadge role={u.effective_role} /></td>
                <td className="row-actions-cell">
                  <span className="row-actions">
                    {can('users.write') && <button type="button" onClick={() => startEdit(u)} className="btn btn-ghost btn-sm">Edit</button>}
                    {can('users.write') && <button type="button" onClick={() => resetPassword(u)} className="btn btn-ghost btn-sm btn-square" title="Reset password" aria-label={`Reset password for ${u.username}`}><Icon name="lock" /></button>}
                    {can('users.delete') && <button type="button" onClick={() => remove(u)} className="btn btn-ghost btn-sm btn-square btn-tone-danger" title="Remove" aria-label={`Remove ${u.username}`}><Icon name="x" /></button>}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {me && <PermissionDeniedHint msg={`Signed in as "${me.username}" with effective role "${me.effective_role}".`} />}
    </SettingsSection>
  );
}
