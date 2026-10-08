import { useEffect, useState, useCallback } from 'react';
import { useApp } from '../context/AppContext';
import { usePerms } from '../context/PermissionsContext';
import { apiJSON, formatDate } from './settings/settingsApi';
import { RoleBadge, Field, SettingsSection, EditorBox } from './settings/settingsUi';
import { PageHeader, KV, Notice, Meter, Field as KitField, EmptyRow } from '../components/kit';

const TOKEN_TTL_OPTIONS = [
  { value: '',       label: 'Never expires' },
  { value: '720h',   label: '30 days' },
  { value: '2160h',  label: '90 days' },
  { value: '8760h',  label: '1 year' },
];

export function MyProfile() {
  const { toast } = useApp();
  const { me, can, role } = usePerms();
  const [cur,  setCur]    = useState('');
  const [np,   setNp]     = useState('');
  const [conf, setConf]   = useState('');
  const [savingPw, setSavingPw] = useState(false);

  const [tokens, setTokens]   = useState([]);
  const [tokError, setTokError] = useState(null);
  const [creating, setCreating] = useState(null);
  const [revealed, setRevealed] = useState(null);

  const reloadTokens = useCallback(async () => {
    try {
      const body = await apiJSON('/api/tokens');
      const mine = (body.items || []).filter(t => t.user_id === me?.id || (!t.user_id && me?.username === 'admin'));
      setTokens(mine);
      setTokError(null);
    } catch (e) { setTokError(String(e.message || e)); }
  }, [me]);

  useEffect(() => { reloadTokens(); }, [reloadTokens]);

  const strength = np.length === 0 ? 0 : np.length < 8 ? 1 : np.length < 12 ? 2 : 3;
  const strengthColor = ['', 'var(--danger)', 'var(--warning)', 'var(--ok-text)'][strength];
  const strengthTone = ['', 't-danger', 't-warning', 't-ok'][strength];
  const strengthLabel = ['','Weak','Fair','Strong'][strength];

  const savePassword = async () => {
    if (!cur||!np||!conf) { toast('error','Missing fields','Fill in all password fields'); return; }
    if (np.length < 8) { toast('error','Too short','Minimum 8 characters'); return; }
    if (np !== conf) { toast('error','Mismatch','Passwords do not match'); return; }
    setSavingPw(true);
    try {
      await apiJSON('/api/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({ current: cur, new: np }),
      });
      setCur(''); setNp(''); setConf('');
      toast('success','Password updated','Your password has been changed');
    } catch (e) {
      toast('error','Update failed', String(e.message || e));
    } finally {
      setSavingPw(false);
    }
  };

  const startCreate = () => setCreating({ name: '', role: role === 'admin' ? 'admin' : 'ro', expires_in: '8760h' });
  const generate = async () => {
    if (!creating.name.trim()) { toast('error', 'Name required', ''); return; }
    try {
      const body = await apiJSON('/api/tokens', {
        method: 'POST',
        body: JSON.stringify({
          name: creating.name,
          role: creating.role,
          expires_in: creating.expires_in,
          user_id: me?.id || '',
        }),
      });
      setRevealed({ name: creating.name, plaintext: body.plaintext });
      setCreating(null);
      toast('success', 'Token created', 'Copy it now — it won\'t be shown again');
      reloadTokens();
    } catch (e) { toast('error', 'Create failed', String(e.message || e)); }
  };

  const revoke = async (t) => {
    if (!window.confirm(`Revoke token "${t.name}"?`)) return;
    try {
      await apiJSON(`/api/tokens/${t.id}`, { method: 'DELETE' });
      toast('warn', 'Token revoked', t.name);
      reloadTokens();
    } catch (e) { toast('error', 'Revoke failed', String(e.message || e)); }
  };

  const initials = (me?.full_name || me?.username || 'U').split(/\s+/).map(s => s[0]).join('').slice(0,2).toUpperCase();

  const passwords = [['Current Password', cur, setCur, 'current-password'], ['New Password', np, setNp, 'new-password'], ['Confirm New Password', conf, setConf, 'new-password']];

  return (
    <div className="page active" id="page-profile">
      <PageHeader title="My Profile" subtitle="Account details and security settings" />

      <div className="grid-2 profile-grid">
        <section className="pane">
          <div className="pane-body">
            <div className="row row--loose mb-16">
              <div className="avatar avatar--lg">{initials}</div>
              <div>
                <div className="t-lg t-strong t-primary">{me?.full_name || me?.username || 'Unknown user'}</div>
                <div className="t-sm t-muted mt-4">{me?.email || '—'}</div>
              </div>
            </div>
            <KV items={[
              ['Username', me?.username || '—'],
              ['Group', me?.group_name || '—'],
              ['Direct role', me?.role ? <RoleBadge role={me.role} /> : '—'],
              ['Effective role', me?.effective_role ? <RoleBadge role={me.effective_role} /> : '—'],
            ]} />
          </div>
        </section>

        <section className="pane">
          <div className="pane-head">
            <div className="grow">
              <div className="pane-title">Change Password</div>
              <div className="pane-sub">Passwords must be at least 8 characters.</div>
            </div>
          </div>
          <div className="pane-body">
            {passwords.map(([label, val, setter, auto]) => (
              <KitField key={label} label={label} htmlFor={`pw-${label}`}>
                <input id={`pw-${label}`} type="password" autoComplete={auto} placeholder="••••••••" className="input input--block"
                  value={val} onChange={e => setter(e.target.value)} />
                {label === 'New Password' && np.length > 0 && (
                  <div className="row">
                    <div className="grow"><Meter value={strength} max={3} color={strengthColor} showValue={false} label="Password strength" /></div>
                    <span className={`t-2xs ${strengthTone}`}>{strengthLabel}</span>
                  </div>
                )}
              </KitField>
            ))}
            <button type="button" className="btn btn-primary" onClick={savePassword} disabled={savingPw}>{savingPw ? 'Saving…' : 'Save password'}</button>
          </div>
        </section>

        <div className="span-2">
          <SettingsSection
            title="API Tokens"
            desc="Tokens you've created. Plaintext is shown once on creation."
            canCreate={can('tokens.create')}
            readOnlyText="Read-only — cannot create tokens"
            action={<button type="button" className="btn btn-primary" onClick={startCreate}>+ Generate token</button>}
            error={tokError}
          >
            {creating && (
              <EditorBox title="New API token" saveLabel="Generate" onSave={generate} onCancel={() => setCreating(null)}>
                <Field label="Name *" value={creating.name} onChange={v => setCreating(c => ({ ...c, name: v }))} />
                <Field label="Role" type="select" value={creating.role} onChange={v => setCreating(c => ({ ...c, role: v }))}
                  options={[{ value: 'admin', label: 'Admin' }, { value: 'ro', label: 'Read-Only' }]} />
                <Field label="Expires" type="select" value={creating.expires_in} options={TOKEN_TTL_OPTIONS} onChange={v => setCreating(c => ({ ...c, expires_in: v }))} />
              </EditorBox>
            )}

            {revealed && (
              <Notice tone="ok" icon="check">
                <div className="t-strong t-ok mb-4">Token "{revealed.name}" generated</div>
                <div className="t-xs t-secondary mb-8">Copy it now — the plaintext is not stored.</div>
                <div className="secret-box">{revealed.plaintext}</div>
                <div className="row mt-8">
                  <button type="button" onClick={() => navigator.clipboard.writeText(revealed.plaintext)} className="btn btn-ghost btn-sm">Copy</button>
                  <button type="button" onClick={() => setRevealed(null)} className="btn btn-ghost btn-sm">Dismiss</button>
                </div>
              </Notice>
            )}

            <div className="table-wrap">
              <table className="data-table data-table--static">
                <thead><tr><th>Name</th><th>Role</th><th>Created</th><th>Expiration</th><th>Status</th><th aria-label="Actions" /></tr></thead>
                <tbody>
                  {tokens.length === 0 && <EmptyRow cols={6}>No tokens yet</EmptyRow>}
                  {tokens.map(t => {
                    const expired = t.expires_at && new Date(t.expires_at) < new Date();
                    return (
                      <tr key={t.id}>
                        <td className="td-primary mono t-sm">{t.name}</td>
                        <td><RoleBadge role={t.role} /></td>
                        <td className="t-sm t-muted">{formatDate(t.created_at)}</td>
                        <td className="t-sm t-muted">{t.expires_at ? formatDate(t.expires_at) : 'Never'}</td>
                        <td><span className={`status-dot ${expired ? 'status-warn' : 'status-active'}`}>{expired ? 'Expired' : 'Active'}</span></td>
                        <td className="row-actions-cell">
                          {can('tokens.delete') && <button type="button" onClick={() => revoke(t)} className="btn btn-ghost btn-sm btn-tone-danger">Revoke</button>}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </SettingsSection>
        </div>
      </div>
    </div>
  );
}
