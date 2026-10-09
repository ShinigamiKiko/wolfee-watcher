import { useCallback, useEffect, useState } from 'react';
import { usePerms } from '../../context/PermissionsContext';
import { Icon } from '../../components/Icon';
import { apiJSON, formatDate } from './settingsApi';
import { RoleBadge, Field, SettingsSection, EditorBox, ListState } from './settingsUi';
import { ROLE_OPTIONS } from './settingsConstants';

export function GroupSection({ toast }) {
  const { can } = usePerms();
  const [groups, setGroups] = useState(null);
  const [error, setError]   = useState(null);
  const [editing, setEditing] = useState(null);

  const reload = useCallback(async () => {
    try {
      const body = await apiJSON('/api/groups');
      setGroups(body.items || []);
      setError(null);
    } catch (e) { setError(String(e.message || e)); }
  }, []);
  useEffect(() => { reload(); }, [reload]);

  const startCreate = () => setEditing({ name: '', description: '', role: 'ro' });
  const startEdit   = (g) => setEditing({ id: g.id, name: g.name, description: g.description, role: g.role });

  const save = async () => {
    if (!editing.name.trim()) { toast('error', 'Name required', ''); return; }
    try {
      if (editing.id) {
        await apiJSON(`/api/groups/${editing.id}`, { method: 'PUT', body: JSON.stringify(editing) });
        toast('success', 'Group updated', editing.name);
      } else {
        await apiJSON('/api/groups', { method: 'POST', body: JSON.stringify(editing) });
        toast('success', 'Group created', editing.name);
      }
      setEditing(null);
      reload();
    } catch (e) { toast('error', 'Save failed', String(e.message || e)); }
  };

  const remove = async (g) => {
    if (!window.confirm(`Delete group "${g.name}"?`)) return;
    try {
      await apiJSON(`/api/groups/${g.id}`, { method: 'DELETE' });
      toast('warn', 'Group removed', g.name);
      reload();
    } catch (e) { toast('error', 'Delete failed', String(e.message || e)); }
  };

  return (
    <SettingsSection
      title="Groups"
      desc="Bundle users and assign shared roles."
      canCreate={can('groups.create')}
      readOnlyText="Read-only — cannot create groups"
      action={<button type="button" className="btn btn-primary" onClick={startCreate}>+ New group</button>}
      error={error}
    >
      {editing && (
        <EditorBox title={editing.id ? 'Edit group' : 'New group'} onSave={save} onCancel={() => setEditing(null)}>
          <Field label="Name *" value={editing.name} onChange={v => setEditing(e => ({ ...e, name: v }))} />
          <Field label="Role" type="select" value={editing.role} options={ROLE_OPTIONS} onChange={v => setEditing(e => ({ ...e, role: v }))} />
          <Field span label="Description" value={editing.description} onChange={v => setEditing(e => ({ ...e, description: v }))} />
        </EditorBox>
      )}

      <div className="table-wrap">
        <table className="data-table data-table--static">
          <thead><tr><th>Name</th><th>Description</th><th>Members</th><th>Role</th><th>Created</th><th aria-label="Actions" /></tr></thead>
          <tbody>
            <ListState items={groups} cols={6} empty="No groups yet" />
            {(groups || []).map(g => (
              <tr key={g.id}>
                <td className="td-primary mono t-sm">{g.name}</td>
                <td className="t-sm t-muted wrap">{g.description || '—'}</td>
                <td className="t-sm t-muted">{g.member_count}</td>
                <td><RoleBadge role={g.role} /></td>
                <td className="t-sm t-muted">{formatDate(g.created_at)}</td>
                <td className="row-actions-cell">
                  <span className="row-actions">
                    {can('groups.write') && <button type="button" onClick={() => startEdit(g)} className="btn btn-ghost btn-sm">Edit</button>}
                    {can('groups.delete') && <button type="button" onClick={() => remove(g)} className="btn btn-ghost btn-sm btn-square btn-tone-danger" title="Remove" aria-label={`Remove ${g.name}`}><Icon name="x" /></button>}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </SettingsSection>
  );
}
