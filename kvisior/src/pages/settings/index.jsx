import { useState } from 'react';
import { useApp } from '../../context/AppContext';
import { SECTIONS } from './settingsConstants';
import { GroupSection } from './GroupSection';
import { TokensSection } from './TokensSection';
import { UsersSection } from './UsersSection';
import { IntegrationsSection } from './IntegrationsSection';

export function Settings() {
  const { toast } = useApp();
  const [active, setActive] = useState('group');

  return (
    <div className="page active" id="page-settings">
      <div className="page-header">
        <div>
          <div className="page-title">Settings</div>
          <div className="page-subtitle">Workspace configuration</div>
        </div>
      </div>

      <div style={{display:'grid',gridTemplateColumns:'220px 1fr',gap:20,maxWidth:1200}}>
        <div className="card" style={{padding:8,border:'none',alignSelf:'start'}}>
          <ul style={{listStyle:'none',padding:0,margin:0}}>
            {SECTIONS.map(s => {
              const isActive = s.id === active;
              return (
                <li key={s.id}
                  onClick={() => setActive(s.id)}
                  style={{
                    padding:'10px 12px',
                    borderRadius:6,
                    cursor:'pointer',
                    fontSize:13,
                    fontWeight: isActive ? 600 : 500,
                    color: isActive ? 'var(--accent)' : 'var(--text-primary)',
                    background: isActive ? 'rgba(0,200,255,.08)' : 'transparent',
                    marginBottom:2,
                  }}>
                  <div>{s.label}</div>
                  <div style={{fontSize:11,color:'var(--text-muted)',fontWeight:400,marginTop:2}}>{s.desc}</div>
                </li>
              );
            })}
          </ul>
        </div>

        <div>
          {active === 'group'        && <GroupSection toast={toast} />}
          {active === 'tokens'       && <TokensSection toast={toast} />}
          {active === 'users'        && <UsersSection toast={toast} />}
          {active === 'integrations' && <IntegrationsSection toast={toast} />}
        </div>
      </div>
    </div>
  );
}
