import { useState } from 'react';
import { EvilComponents } from './systemhealth/EvilComponents';
import { EvilStats }      from './systemhealth/EvilStats';
import { EvilKafka }      from './systemhealth/EvilKafka';

const TABS = [
  { id: 'components', label: 'EvilComponents' },
  { id: 'stats',      label: 'EvilStats' },
  { id: 'kafka',      label: 'EvilKafka' },
];

function TabBar({ active, onChange }) {
  return (
    <div style={{ display: 'flex', gap: 2, borderBottom: '1px solid var(--border)', marginBottom: 20 }}>
      {TABS.map(t => (
        <button
          key={t.id}
          onClick={() => onChange(t.id)}
          style={{
            background: 'none',
            border: 'none',
            borderBottom: active === t.id ? '2px solid var(--accent)' : '2px solid transparent',
            color: active === t.id ? 'var(--accent)' : 'var(--text-muted)',
            padding: '8px 18px',
            fontSize: 13,
            fontWeight: active === t.id ? 600 : 400,
            cursor: 'pointer',
            fontFamily: 'DM Sans, sans-serif',
            transition: 'color .15s, border-color .15s',
            marginBottom: -1,
          }}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function SystemHealth() {
  const [tab, setTab] = useState('components');

  return (
    <div className="page active" id="page-syshealth">
      <div className="page-header">
        <div>
          <div className="page-title">System Health</div>
          <div className="page-subtitle">Platform component health, K8s metrics and Kafka internals</div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <span className="live-dot">Live</span>
        </div>
      </div>

      <TabBar active={tab} onChange={setTab} />

      {tab === 'components' && <EvilComponents />}
      {tab === 'stats'      && <EvilStats />}
      {tab === 'kafka'      && <EvilKafka />}
    </div>
  );
}
