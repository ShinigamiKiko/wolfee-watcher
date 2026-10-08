import { useState, useEffect } from 'react';
import { toYaml } from './yamlUtils';
import { isPod, isNode } from './yamlPanelHelpers';
import { PodLogsTab }   from './PodLogsTab';
import { NodeEventsTab } from './NodeEventsTab';
import { SidePanel, SubTabs, CodeBlock } from '../../components/kit';
import { Icon } from '../../components/Icon';

const TAB_ICON = { manifest: 'file', logs: 'clipboard', events: 'calendar' };

export function YamlPanel({ item, onClose }) {
  const [activeTab, setActiveTab] = useState('manifest');
  const [copied,    setCopied]    = useState(false);

  useEffect(() => { setActiveTab('manifest'); }, [item?.title]);

  if (!item) return null;

  const yaml    = item.raw ? toYaml(item.raw) : null;
  const _isPod  = isPod(item);
  const _isNode = isNode(item);
  const tabs = _isPod ? ['manifest', 'logs'] : _isNode ? ['manifest', 'events'] : ['manifest'];

  const copy = () => { navigator.clipboard?.writeText(yaml || ''); setCopied(true); setTimeout(() => setCopied(false), 1500); };

  return (
    <SidePanel
      fill
      title={<span className="mono">{item.title}</span>}
      meta={item.sub}
      onClose={onClose}
      tools={activeTab === 'manifest' && yaml && (
        <button type="button" className="btn btn-outline btn-sm" onClick={copy}>
          {copied ? <><Icon name="check" /> Copied</> : <><Icon name="copy" /> Copy YAML</>}
        </button>
      )}
      tabs={tabs.length > 1 && (
        <SubTabs active={activeTab} onChange={setActiveTab}
          tabs={tabs.map(t => ({ id: t, label: <span className="ic-label"><Icon name={TAB_ICON[t]} />{t[0].toUpperCase() + t.slice(1)}</span> }))} />
      )}
    >
      <div className="dp-fill">
        {activeTab === 'manifest' && (yaml
          ? <CodeBlock className="yaml-pre">{yaml}</CodeBlock>
          : <div className="t-md t-muted">No YAML available</div>)}
        {activeTab === 'logs'   && _isPod  && <PodLogsTab item={item} />}
        {activeTab === 'events' && _isNode && <NodeEventsTab item={item} />}
      </div>
    </SidePanel>
  );
}
