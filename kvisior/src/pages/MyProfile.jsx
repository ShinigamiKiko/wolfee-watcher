import { useEffect, useState, useCallback } from 'react';
import { useApp } from '../context/AppContext';
import { usePerms } from '../context/PermissionsContext';
import { apiJSON, formatDate } from './settings/settingsApi';

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
  const strengthColor = ['','var(--danger)','var(--warning)','var(--accent-3)'][strength];
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

  return (
    <div className="page active" id="page-profile">
      <div className="page-header">
        <div>
          <div className="page-title">My Profile</div>
          <div className="page-subtitle">Account details and security settings</div>
        </div>
      </div>

      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:20,maxWidth:960}}>

        <div className="card" style={{padding:24,border:'none'}}>
          <div style={{display:'flex',alignItems:'center',gap:16,marginBottom:24}}>
            <div style={{width:56,height:56,borderRadius:'50%',background:'linear-gradient(135deg,var(--accent),var(--accent-2))',display:'flex',alignItems:'center',justifyContent:'center',fontSize:20,fontWeight:700,color:'#fff',flexShrink:0}}>{initials}</div>
            <div>
              <div style={{fontSize:16,fontWeight:600,color:'var(--text-primary)'}}>{me?.full_name || me?.username || 'Unknown user'}</div>
              <div style={{fontSize:12,color:'var(--text-muted)',marginTop:2}}>{me?.email || '—'}</div>
            </div>
          </div>
          <div style={{display:'flex',flexDirection:'column',gap:14}}>
            <Pair k="Username" v={me?.username || '—'} />
            <Pair k="Group" v={me?.group_name || '—'} />
            <Pair k="Direct role" v={me?.role || '—'} />
            <Pair k="Effective role" v={me?.effective_role || '—'} />
          </div>
        </div>

        <div className="card" style={{padding:24,border:'none'}}>
          <div style={{fontSize:14,fontWeight:600,color:'var(--text-primary)',marginBottom:6}}>Change Password</div>
          <div style={{fontSize:12,color:'var(--text-muted)',marginBottom:20}}>Passwords must be at least 8 characters.</div>
          <div style={{display:'flex',flexDirection:'column',gap:14}}>
            {[['Current Password',cur,setCur],['New Password',np,setNp],['Confirm New Password',conf,setConf]].map(([label,val,setter])=>(
              <div key={label}>
                <label style={{display:'block',fontSize:11,textTransform:'uppercase',letterSpacing:'.07em',color:'var(--text-muted)',marginBottom:6}}>{label}</label>
                <input type="password" placeholder="••••••••" value={val} onChange={e=>setter(e.target.value)}
                  style={{width:'100%',background:'var(--bg-elevated)',border:'1px solid var(--border)',borderRadius:8,padding:'9px 12px',fontSize:13,color:'var(--text-primary)',outline:'none',fontFamily:'DM Sans,sans-serif'}} />
                {label==='New Password' && np.length>0 && (
                  <div style={{marginTop:6}}>
                    <div style={{height:3,borderRadius:2,background:'var(--bg-base)',overflow:'hidden'}}>
                      <div style={{height:'100%',width:`${strength*33}%`,background:strengthColor,borderRadius:2,transition:'all .3s'}} />
                    </div>
                    <div style={{fontSize:10,color:strengthColor,marginTop:4}}>{strengthLabel}</div>
                  </div>
                )}
              </div>
            ))}
            <button className="btn btn-primary" style={{alignSelf:'flex-start',marginTop:4}} onClick={savePassword} disabled={savingPw}>{savingPw ? 'Saving…' : 'Save password'}</button>
          </div>
        </div>

        <div className="card" style={{padding:24,gridColumn:'span 2',border:'none'}}>
          <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:16}}>
            <div>
              <div style={{fontSize:14,fontWeight:600,color:'var(--text-primary)',marginBottom:3}}>API Tokens</div>
              <div style={{fontSize:12,color:'var(--text-muted)'}}>Tokens you've created. Plaintext is shown once on creation.</div>
            </div>
            {can('tokens.create') ? (
              <button className="btn btn-primary" onClick={startCreate}>+ Generate token</button>
            ) : (
              <span style={{fontSize:11,color:'var(--text-muted)'}}>Read-only — cannot create tokens</span>
            )}
          </div>

          {tokError && <div style={{fontSize:12,color:'var(--danger)',marginBottom:10}}>Error: {tokError}</div>}

          {creating && (
            <div style={{padding:14,border:'1px solid var(--border)',borderRadius:8,marginBottom:16,background:'var(--bg-elevated)'}}>
              <div style={{display:'grid',gridTemplateColumns:'1fr 1fr 1fr',gap:10}}>
                <div>
                  <label style={{display:'block',fontSize:11,textTransform:'uppercase',letterSpacing:'.07em',color:'var(--text-muted)',marginBottom:6}}>Name *</label>
                  <input value={creating.name} onChange={e => setCreating(c => ({...c, name: e.target.value}))}
                    style={{width:'100%',background:'var(--bg-elevated)',border:'1px solid var(--border)',borderRadius:8,padding:'9px 12px',fontSize:13,color:'var(--text-primary)',outline:'none',fontFamily:'DM Sans,sans-serif'}} />
                </div>
                <div>
                  <label style={{display:'block',fontSize:11,textTransform:'uppercase',letterSpacing:'.07em',color:'var(--text-muted)',marginBottom:6}}>Role</label>
                  <select value={creating.role} onChange={e => setCreating(c => ({...c, role: e.target.value}))}
                    style={{width:'100%',background:'var(--bg-elevated)',border:'1px solid var(--border)',borderRadius:8,padding:'9px 12px',fontSize:13,color:'var(--text-primary)',outline:'none',fontFamily:'DM Sans,sans-serif'}}>
                    <option value="admin">Admin</option>
                    <option value="ro">Read-Only</option>
                  </select>
                </div>
                <div>
                  <label style={{display:'block',fontSize:11,textTransform:'uppercase',letterSpacing:'.07em',color:'var(--text-muted)',marginBottom:6}}>Expires</label>
                  <select value={creating.expires_in} onChange={e => setCreating(c => ({...c, expires_in: e.target.value}))}
                    style={{width:'100%',background:'var(--bg-elevated)',border:'1px solid var(--border)',borderRadius:8,padding:'9px 12px',fontSize:13,color:'var(--text-primary)',outline:'none',fontFamily:'DM Sans,sans-serif'}}>
                    {TOKEN_TTL_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </div>
              </div>
              <div style={{display:'flex',gap:8,marginTop:12}}>
                <button className="btn btn-primary" onClick={generate}>Generate</button>
                <button onClick={() => setCreating(null)} style={{fontSize:11,padding:'4px 10px',background:'transparent',border:'1px solid var(--border)',borderRadius:5,color:'var(--text-primary)',cursor:'pointer'}}>Cancel</button>
              </div>
            </div>
          )}

          {revealed && (
            <div style={{padding:14,border:'1px solid var(--accent-3)',borderRadius:8,marginBottom:16,background:'rgba(34,197,94,.08)'}}>
              <div style={{fontSize:12,fontWeight:600,marginBottom:6,color:'var(--accent-3)'}}>Token "{revealed.name}" generated</div>
              <div style={{fontSize:11,color:'var(--text-muted)',marginBottom:8}}>Copy it now — the plaintext is not stored.</div>
              <div className="mono" style={{fontSize:12,padding:'8px 10px',background:'var(--bg-base)',borderRadius:6,wordBreak:'break-all',color:'var(--text-primary)'}}>{revealed.plaintext}</div>
              <button onClick={() => navigator.clipboard.writeText(revealed.plaintext)} style={{fontSize:11,padding:'4px 10px',background:'transparent',border:'1px solid var(--border)',borderRadius:5,color:'var(--text-primary)',cursor:'pointer',marginTop:8}}>Copy</button>
              <button onClick={() => setRevealed(null)} style={{fontSize:11,padding:'4px 10px',background:'transparent',border:'1px solid var(--border)',borderRadius:5,color:'var(--text-primary)',cursor:'pointer',marginTop:8,marginLeft:6}}>Dismiss</button>
            </div>
          )}

          <div className="table-wrap">
            <table className="data-table">
              <thead><tr><th>Name</th><th>Role</th><th>Created</th><th>Expiration</th><th>Status</th><th/></tr></thead>
              <tbody>
                {tokens.length === 0 && <tr><td colSpan={6} style={{padding:14,fontSize:12,color:'var(--text-muted)'}}>No tokens yet</td></tr>}
                {tokens.map(t => {
                  const expired = t.expires_at && new Date(t.expires_at) < new Date();
                  return (
                    <tr key={t.id}>
                      <td className="td-primary mono" style={{fontSize:12}}>{t.name}</td>
                      <td><span style={{fontSize:11,padding:'2px 8px',borderRadius:5,background:'rgba(124,58,237,.12)',color:'#a78bfa'}}>{t.role}</span></td>
                      <td style={{fontSize:12,color:'var(--text-muted)'}}>{formatDate(t.created_at)}</td>
                      <td style={{fontSize:12,color:'var(--text-muted)'}}>{t.expires_at ? formatDate(t.expires_at) : 'Never'}</td>
                      <td><span className={`status-dot ${expired ? 'status-warn' : 'status-active'}`}>{expired ? 'Expired' : 'Active'}</span></td>
                      <td>
                        {can('tokens.delete') && (
                          <button onClick={() => revoke(t)} style={{fontSize:11,padding:'3px 8px',background:'transparent',border:'1px solid var(--border)',borderRadius:5,color:'var(--danger)',cursor:'pointer'}}>Revoke</button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

function Pair({ k, v }) {
  return (
    <div>
      <div style={{fontSize:10,textTransform:'uppercase',letterSpacing:'.07em',color:'var(--text-muted)',marginBottom:4}}>{k}</div>
      <div style={{fontSize:13,color:'var(--text-primary)',fontWeight:500}}>{v}</div>
    </div>
  );
}
