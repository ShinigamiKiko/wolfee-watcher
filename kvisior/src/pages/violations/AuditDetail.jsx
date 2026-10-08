import { SevBadge } from '../../components/ui';
import { SidePanel, DetailSection, KV, Badge, ActionBadge, actionTone } from '../../components/kit';
import { Icon } from '../../components/Icon';

const KIND_ICON = {
  exec:        'terminal',
  attach:      'plug',
  portforward: 'link',
  create:      'plus',
  update:      'edit',
  delete:      'trash',
};

const NOTICE_TONE = { danger: 'notice--danger', warning: 'notice--warning', ok: 'notice--ok' };

export function AuditDetail({ v, onClose }) {
  if (!v) return null;

  const ts = v.timestamp ? new Date(v.timestamp).toLocaleString() : '—';
  const opt = (label, val) => (val ? [label, val] : null);

  return (
    <SidePanel
      title={<span className="row"><Icon name={KIND_ICON[v.kind] || 'help'} /> {v.policy}</span>}
      meta={`${v.kind} · ${v.webhookType || v.resource} · ${v.ns}`}
      onClose={onClose}
      actions={<><SevBadge sev={v.sev} /><ActionBadge kind={v.kind} /><Badge>{v.check}</Badge></>}
    >
      <div className={`notice ${NOTICE_TONE[actionTone(v.kind)] || ''} dp-lead`}>
        <div>
          <strong>{v.user || 'unknown'}</strong>
          {v.serviceAccount ? <> (<strong>{v.serviceAccount}</strong>)</> : null}
          {v.groups?.length ? <span className="t-muted"> [{v.groups.join(', ')}]</span> : null}
          {' performed '}
          <strong>{v.kind}</strong>
          {v.webhookType ? <> on <strong>{v.webhookType}</strong></> : v.resource ? <> on <strong>{v.resource}</strong></> : null}
          {v.name ? <> · <code className="inline">{v.name}</code></> : null}
          {v.ns ? <> in <strong>{v.ns}</strong></> : null}
        </div>
      </div>

      {(v.commands?.length || v.container) && (
        <DetailSection title="Exec details">
          <KV items={[opt('Container', v.container), opt('Command', v.commands?.join(' '))]} />
        </DetailSection>
      )}

      {v.ports?.length > 0 && (
        <DetailSection title="Port forward">
          <KV items={[['Ports', v.ports.join(', ')]]} />
        </DetailSection>
      )}

      <DetailSection title="Event details">
        <KV items={[
          ['Time', ts],
          opt('User', v.user),
          opt('ServiceAccount', v.serviceAccount),
          opt('Groups', v.groups?.join(', ')),
          opt('Source IPs', v.sourceIPs?.join(', ')),
          opt('Client', v.userAgent),
          opt('Occurrences', v.hits > 1 ? String(v.hits) : ''),
          opt('Resource', v.resource),
          opt('Webhook type', v.webhookType),
          opt('Name', v.name),
          opt('Namespace', v.ns),
          opt('UID', v.uid),
          opt('Resource version', v.resourceVersion),
          opt('Source', v.source),
          opt('Policy', v.policy),
          ['Action', v.action || 'alert'],
        ]} />
      </DetailSection>
    </SidePanel>
  );
}
