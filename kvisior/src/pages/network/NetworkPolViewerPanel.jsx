import { PolViewer } from './NetworkPolViewer';
import { FloatingWindow } from '../../components/FloatingWindow';

export function PolViewerPanel({ pol, onClose }) {
  return (
    <FloatingWindow open={!!pol} resetKey={pol?.metadata?.uid || pol?.metadata?.name} onClose={onClose}
      width={480} height={560} minWidth={360} minHeight={300}
      title={<span className="mono">{pol?.metadata?.name}</span>} label={`Network policy ${pol?.metadata?.name || ''}`}>
      <div className="fwin-flush">
        <PolViewer pol={pol} />
      </div>
    </FloatingWindow>
  );
}
