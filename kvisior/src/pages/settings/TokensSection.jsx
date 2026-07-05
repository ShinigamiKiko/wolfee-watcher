import { useCallback, useEffect, useState } from 'react';
import { usePerms } from '../../context/PermissionsContext';
import { apiJSON, formatDate } from './settingsApi';
import { RoleBadge, Field, btnGhost, btnDanger } from './settingsUi';
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
    <div className="card" style={{padding:24,border:'none'}}>
      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:16}}>
        <div>
          <div style={{fontSize:14,fontWeight:600,color:'var(--text-primary)',marginBottom:3}}>API Tokens</div>
          <div style={{fontSize:12,color:'var(--text-muted)'}}>Tokens allow programmatic access to the Wolf Vision API.</div>
        </div>
        {can('tokens.create') ? (
          <button className="btn btn-primary" onClick={startCreate}>+ Generate token</button>
        ) : (
          <span style={{fontSize:11,color:'var(--text-muted)'}}>Read-only — cannot create tokens</span>
        )}
      </div>

      {error && <div style={{fontSize:12,color:'var(--danger)',marginBottom:10}}>Error: {error}</div>}

      {creating && (
        <div style={{padding:14,border:'1px solid var(--border)',borderRadius:8,marginBottom:16,background:'var(--bg-elevated)'}}>
          <div style={{fontSize:12,fontWeight:600,marginBottom:10}}>New API token</div>
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}>
            <Field label="Name *" value={creating.name} onChange={v => setCreating(c => ({...c, name: v}))} />
            <Field label="Role" type="select" value={creating.role} options={ROLE_OPTIONS}
              onChange={v => setCreating(c => ({...c, role: v}))} />
            <Field label="Owner" type="select" value={creating.user_id}
              options={[{value: '', label: '— No owner —'}, ...users.map(u => ({value: u.id, label: u.username}))]}
              onChange={v => setCreating(c => ({...c, user_id: v}))} />
            <Field label="Expires" type="select" value={creating.expires_in} options={TOKEN_TTL_OPTIONS}
              onChange={v => setCreating(c => ({...c, expires_in: v}))} />
          </div>
          <div style={{display:'flex',gap:8,marginTop:12}}>
            <button className="btn btn-primary" onClick={save}>Generate</button>
            <button onClick={() => setCreating(null)} style={btnGhost}>Cancel</button>
          </div>
        </div>
      )}

      {revealed && (
        <div style={{padding:14,border:'1px solid var(--accent-3)',borderRadius:8,marginBottom:16,background:'rgba(34,197,94,.08)'}}>
          <div style={{fontSize:12,fontWeight:600,marginBottom:6,color:'var(--accent-3)'}}>Token "{revealed.name}" generated</div>
          <div style={{fontSize:11,color:'var(--text-muted)',marginBottom:8}}>Copy it now. The plaintext is not stored and will not be shown again.</div>
          <div className="mono" style={{fontSize:12,padding:'8px 10px',background:'var(--bg-base)',borderRadius:6,wordBreak:'break-all',color:'var(--text-primary)'}}>{revealed.plaintext}</div>
          <button onClick={() => { navigator.clipboard.writeText(revealed.plaintext); }} style={{...btnGhost, marginTop:8}}>Copy to clipboard</button>
          <button onClick={() => setRevealed(null)} style={{...btnGhost, marginTop:8, marginLeft:6}}>Dismiss</button>
        </div>
      )}

      <div className="table-wrap">
        <table className="data-table">
          <thead><tr><th>Name</th><th>Role</th><th>Owner</th><th>Created</th><th>Expires</th><th>Status</th><th/></tr></thead>
          <tbody>
            {tokens == null && <tr><td colSpan={7} style={{padding:14,fontSize:12,color:'var(--text-muted)'}}>Loading…</td></tr>}
            {tokens != null && tokens.length === 0 && <tr><td colSpan={7} style={{padding:14,fontSize:12,color:'var(--text-muted)'}}>No tokens yet</td></tr>}
            {(tokens || []).map(t => {
              const expired = t.expires_at && new Date(t.expires_at) < new Date();
              return (
                <tr key={t.id}>
                  <td className="td-primary mono" style={{fontSize:12}}>{t.name}</td>
                  <td><RoleBadge role={t.role}/></td>
                  <td style={{fontSize:12,color:'var(--text-muted)'}}>{t.username || '—'}</td>
                  <td style={{fontSize:12,color:'var(--text-muted)'}}>{formatDate(t.created_at)}</td>
                  <td style={{fontSize:12,color:'var(--text-muted)'}}>{t.expires_at ? formatDate(t.expires_at) : 'Never'}</td>
                  <td>
                    <span className={`status-dot ${expired ? 'status-warn' : 'status-active'}`}>
                      {expired ? 'Expired' : 'Active'}
                    </span>
                  </td>
                  <td>
                    {can('tokens.delete') && (
                      <button onClick={() => revoke(t)} style={btnDanger}>Revoke</button>
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
