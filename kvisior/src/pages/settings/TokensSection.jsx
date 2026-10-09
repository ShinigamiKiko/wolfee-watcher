import { useCallback, useEffect, useState } from 'react';
import { usePerms } from '../../context/PermissionsContext';
import { Icon } from '../../components/Icon';
import { apiJSON, formatDate } from './settingsApi';
import { RoleBadge, Field, SettingsSection, EditorBox, ListState } from './settingsUi';
import { Notice } from '../../components/kit';
import { ROLE_OPTIONS, TOKEN_TTL_OPTIONS } from './settingsConstants';

export function TokensSection({ toast }) {
  const { can } = usePerms();
  const [tokens, setTokens] = useState(null);
  const [users, setUsers]   = useState([]);
  const [error, setError]   = useState(null);
  const [creating, setCreating] = useState(null);
  const [revealed, setRevealed] = useState(null);

  const reload = useCallback(async () => {
    try {
      const body = await apiJSON('/api/tokens');
      setTokens(body.items || []);
      try {
        const u = await apiJSON('/api/users');
        setUsers(u.items || []);
      } catch { }
      setError(null);
    } catch (e) { setError(String(e.message || e)); }
  }, []);
  useEffect(() => { reload(); }, [reload]);

  const startCreate = () => setCreating({ name: '', role: 'ro', user_id: '', expires_in: '8760h' });

  const save = async () => {
    if (!creating.name.trim()) { toast('error', 'Name required', ''); return; }
    try {
      const body = await apiJSON('/api/tokens', { method: 'POST', body: JSON.stringify(creating) });
      setRevealed({ name: creating.name, plaintext: body.plaintext });
      setCreating(null);
      toast('success', 'Token created', 'Copy it now — it won\'t be shown again');
      reload();
    } catch (e) { toast('error', 'Create failed', String(e.message || e)); }
  };

  const revoke = async (t) => {
    if (!window.confirm(`Revoke token "${t.name}"?`)) return;
    try {
      await apiJSON(`/api/tokens/${t.id}`, { method: 'DELETE' });
      toast('warn', 'Token revoked', t.name);
      reload();
    } catch (e) { toast('error', 'Revoke failed', String(e.message || e)); }
  };

  return (
    <SettingsSection
      title="API Tokens"
      desc="Tokens allow programmatic access to the wolfee-watcher API."
      canCreate={can('tokens.create')}
      readOnlyText="Read-only — cannot create tokens"
      action={<button type="button" className="btn btn-primary" onClick={startCreate}>+ Generate token</button>}
      error={error}
    >
      {creating && (
        <EditorBox title="New API token" saveLabel="Generate" onSave={save} onCancel={() => setCreating(null)}>
          <Field label="Name *" value={creating.name} onChange={v => setCreating(c => ({ ...c, name: v }))} />
          <Field label="Role" type="select" value={creating.role} options={ROLE_OPTIONS} onChange={v => setCreating(c => ({ ...c, role: v }))} />
          <Field label="Owner" type="select" value={creating.user_id}
            options={[{ value: '', label: '— No owner —' }, ...users.map(u => ({ value: u.id, label: u.username }))]}
            onChange={v => setCreating(c => ({ ...c, user_id: v }))} />
          <Field label="Expires" type="select" value={creating.expires_in} options={TOKEN_TTL_OPTIONS} onChange={v => setCreating(c => ({ ...c, expires_in: v }))} />
        </EditorBox>
      )}

      {revealed && (
        <Notice tone="ok" icon="check">
          <div className="t-strong t-ok mb-4">Token "{revealed.name}" generated</div>
          <div className="t-xs t-secondary mb-8">Copy it now. The plaintext is not stored and will not be shown again.</div>
          <div className="secret-box">{revealed.plaintext}</div>
          <div className="row mt-8">
            <button type="button" onClick={() => navigator.clipboard.writeText(revealed.plaintext)} className="btn btn-ghost btn-sm">Copy to clipboard</button>
            <button type="button" onClick={() => setRevealed(null)} className="btn btn-ghost btn-sm">Dismiss</button>
          </div>
        </Notice>
      )}

      <div className="table-wrap">
        <table className="data-table data-table--static">
          <thead><tr><th>Name</th><th>Role</th><th>Owner</th><th>Created</th><th>Expires</th><th>Status</th><th aria-label="Actions" /></tr></thead>
          <tbody>
            <ListState items={tokens} cols={7} empty="No tokens yet" />
            {(tokens || []).map(t => {
              const expired = t.expires_at && new Date(t.expires_at) < new Date();
              return (
                <tr key={t.id}>
                  <td className="td-primary mono t-sm">{t.name}</td>
                  <td><RoleBadge role={t.role} /></td>
                  <td className="t-sm t-muted">{t.username || '—'}</td>
                  <td className="t-sm t-muted">{formatDate(t.created_at)}</td>
                  <td className="t-sm t-muted">{t.expires_at ? formatDate(t.expires_at) : 'Never'}</td>
                  <td><span className={`status-dot ${expired ? 'status-warn' : 'status-active'}`}>{expired ? 'Expired' : 'Active'}</span></td>
                  <td className="row-actions-cell">
                    {can('tokens.delete') && <button type="button" onClick={() => revoke(t)} className="btn btn-ghost btn-sm btn-square btn-tone-danger" title="Revoke" aria-label={`Revoke ${t.name}`}><Icon name="x" /></button>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </SettingsSection>
  );
}
