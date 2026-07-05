import { useCallback, useEffect, useState } from 'react';
import { usePerms } from '../../context/PermissionsContext';
import { apiJSON, formatDate } from './settingsApi';
import { RoleBadge, Field, btnGhost, btnDanger } from './settingsUi';
import { ROLE_OPTIONS } from './settingsConstants';

function GroupEditor({ editing, setEditing, onSave, onCancel }) {
  return (
    <div style={{padding:14,border:'1px solid var(--border)',borderRadius:8,marginBottom:16,background:'var(--bg-elevated)'}}>
      <div style={{fontSize:12,fontWeight:600,marginBottom:10,color:'var(--text-primary)'}}>
        {editing.id ? 'Edit group' : 'New group'}
      </div>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}>
        <Field label="Name *" value={editing.name} onChange={v => setEditing(e => ({...e, name: v}))} />
        <Field label="Role" type="select" value={editing.role} options={ROLE_OPTIONS}
          onChange={v => setEditing(e => ({...e, role: v}))} />
        <div style={{gridColumn:'span 2'}}>
          <Field label="Description" value={editing.description}
            onChange={v => setEditing(e => ({...e, description: v}))} />
        </div>
      </div>
      <div style={{display:'flex',gap:8,marginTop:12}}>
        <button className="btn btn-primary" onClick={onSave}>Save</button>
        <button onClick={onCancel} style={btnGhost}>Cancel</button>
      </div>
    </div>
  );
}

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
    <div className="card" style={{padding:24,border:'none'}}>
      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:16}}>
        <div>
          <div style={{fontSize:14,fontWeight:600,color:'var(--text-primary)',marginBottom:3}}>Groups</div>
          <div style={{fontSize:12,color:'var(--text-muted)'}}>Bundle users and assign shared roles.</div>
        </div>
        {can('groups.create') ? (
          <button className="btn btn-primary" onClick={startCreate}>+ New group</button>
        ) : (
          <span style={{fontSize:11,color:'var(--text-muted)'}}>Read-only — cannot create groups</span>
        )}
      </div>

      {error && <div style={{fontSize:12,color:'var(--danger)',marginBottom:10}}>Error: {error}</div>}

      {editing && (
        <GroupEditor
          editing={editing}
          setEditing={setEditing}
          onSave={save}
          onCancel={() => setEditing(null)}
        />
      )}

      <div className="table-wrap">
        <table className="data-table">
          <thead><tr><th>Name</th><th>Description</th><th>Members</th><th>Role</th><th>Created</th><th/></tr></thead>
          <tbody>
            {groups == null && <tr><td colSpan={6} style={{padding:14,fontSize:12,color:'var(--text-muted)'}}>Loading…</td></tr>}
            {groups != null && groups.length === 0 && <tr><td colSpan={6} style={{padding:14,fontSize:12,color:'var(--text-muted)'}}>No groups yet</td></tr>}
            {(groups || []).map(g => (
              <tr key={g.id}>
                <td className="td-primary mono" style={{fontSize:12}}>{g.name}</td>
                <td style={{fontSize:12,color:'var(--text-muted)',maxWidth:280}}>{g.description || '—'}</td>
                <td style={{fontSize:12,color:'var(--text-muted)'}}>{g.member_count}</td>
                <td><RoleBadge role={g.role}/></td>
                <td style={{fontSize:12,color:'var(--text-muted)'}}>{formatDate(g.created_at)}</td>
                <td style={{display:'flex',gap:6}}>
                  {can('groups.write') && (
                    <button onClick={() => startEdit(g)} style={btnGhost}>Edit</button>
                  )}
                  {can('groups.delete') && (
                    <button onClick={() => remove(g)} style={btnDanger}>Remove</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
