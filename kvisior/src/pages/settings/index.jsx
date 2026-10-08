import { useState } from 'react';
import { useApp } from '../../context/AppContext';
import { SECTIONS } from './settingsConstants';
import { GroupSection } from './GroupSection';
import { TokensSection } from './TokensSection';
import { UsersSection } from './UsersSection';
import { IntegrationsSection } from './IntegrationsSection';
import { PageHeader } from '../../components/kit';

export function Settings() {
  const { toast } = useApp();
  const [active, setActive] = useState('group');

  return (
    <div className="page active" id="page-settings">
      <PageHeader title="Settings" subtitle="Workspace configuration" />

      <div className="nav-layout">
        <nav className="side-nav" aria-label="Settings sections">
          {SECTIONS.map(s => (
            <button key={s.id} type="button" aria-current={s.id === active} onClick={() => setActive(s.id)}>
              <div>{s.label}</div>
              <div className="side-nav-desc">{s.desc}</div>
            </button>
          ))}
        </nav>

        <div className="grow">
          {active === 'group'        && <GroupSection toast={toast} />}
          {active === 'tokens'       && <TokensSection toast={toast} />}
          {active === 'users'        && <UsersSection toast={toast} />}
          {active === 'integrations' && <IntegrationsSection toast={toast} />}
        </div>
      </div>
    </div>
  );
}
