import { SevBadge } from '../../components/ui';
import { SidePanel, DetailSection, KV, Notice } from '../../components/kit';

export function DeployDetail({ v, onClose }) {
  if (!v) return null;

  return (
    <SidePanel title={v.policy} meta={`${v.workload} · ${v.ns}`} onClose={onClose} actions={<SevBadge sev={v.sev} />}>
      <Notice tone="danger" icon="alert">{v.detail}</Notice>
      <DetailSection title="Workload details">
        <KV items={[
          ['Workload',  v.workload],
          ['Kind',      v.kind],
          ['Namespace', v.ns],
          ['Policy',    v.policy],
          ['Check',     v.check],
          ['Action',    v.action || 'alert'],
        ]} />
      </DetailSection>
    </SidePanel>
  );
}
