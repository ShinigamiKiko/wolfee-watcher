import { useState } from 'react';
import { Tabs } from '../components/ui';
import { PageHeader } from '../components/kit';
import { EvilComponents } from './systemhealth/EvilComponents';
import { EvilStats }      from './systemhealth/EvilStats';
import { EvilKafka }      from './systemhealth/EvilKafka';
import '../styles/systemhealth.scss';

const TABS = [
  { id: 'components', label: 'EvilComponents' },
  { id: 'stats',      label: 'EvilStats' },
  { id: 'kafka',      label: 'EvilKafka' },
];

export function SystemHealth() {
  const [tab, setTab] = useState('components');

  return (
    <div className="page active" id="page-syshealth">
      <PageHeader
        title="System Health"
        subtitle="Platform component health, K8s metrics and Kafka internals"
        actions={<span className="live-dot">Live</span>}
      />

      <Tabs tabs={TABS} active={tab} onSwitch={setTab} />

      {tab === 'components' && <EvilComponents />}
      {tab === 'stats'      && <EvilStats />}
      {tab === 'kafka'      && <EvilKafka />}
    </div>
  );
}
