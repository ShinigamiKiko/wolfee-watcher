import { SevBadge } from '../../components/ui';
import { FloatingWindow } from '../../components/FloatingWindow';
import { Tag, SectionLabel, Notice, Score, sevTone, cx } from '../../components/kit';
import { epssTone } from '../../data/scanner';
import { RiskBox, PocLinks } from './CveDetail';

export function SbomDetail({ pkg, onClose }) {
  const cves = pkg?.cves || [];
  const hasCrit = cves.some(c => (c.severity || '').toUpperCase() === 'CRITICAL');
  const hasHigh = cves.some(c => (c.severity || '').toUpperCase() === 'HIGH');
  const topSev = hasCrit ? 'CRITICAL' : hasHigh ? 'HIGH' : cves.length > 0 ? 'MEDIUM' : null;

  return (
    <FloatingWindow
      open={!!pkg}
      resetKey={pkg && `${pkg.name}@${pkg.version}`}
      onClose={onClose}
      width={480}
      height={580}
      minWidth={340}
      minHeight={300}
      label={pkg ? `Package ${pkg.name}` : undefined}
      title={pkg?.name}
      badges={topSev && <SevBadge sev={topSev} />}
    >
      {pkg && (
        <>
          <div className="mono t-sm t-muted mb-16">
            {pkg.version} · {pkg.type}{pkg.license ? ` · ${pkg.license}` : ''}
          </div>

          <SectionLabel>CVEs ({cves.length})</SectionLabel>
          {cves.length === 0 && <div className="t-sm t-muted">No known vulnerabilities</div>}
          {cves.map(c => {
            const tone = sevTone(c.severity);
            const eTone = epssTone(c.epssScore);
            return (
              <div key={c.id} className="item-card">
                <div className="row row--between mb-8">
                  <span className="row row--tight">
                    <span className="mono t-xs t-strong t-primary">{c.id}</span>
                    {c.inKev && <Tag tone="danger">KEV</Tag>}
                    {c.pocs?.length > 0 && <Tag tone="warning">PoC</Tag>}
                  </span>
                  <SevBadge sev={(c.severity || '').toUpperCase()} />
                </div>

                {(c.title || c.description) && (
                  <div className="t-xs t-secondary mb-8">
                    {c.title || (c.description?.length > 120 ? c.description.slice(0, 120) + '…' : c.description)}
                  </div>
                )}

                {c.riskScore > 0 && <RiskBox inset score={c.riskScore} label={c.riskLabel} />}

                <div className="score-grid">
                  <Score label="CVSS v3" value={c.cvssV3Score ? c.cvssV3Score.toFixed(1) : '—'} className={tone && `t-${tone}`} />
                  <Score label="EPSS" value={c.epssScore ? (c.epssScore * 100).toFixed(2) + '%' : '—'} className={eTone ? `t-${eTone}` : 't-secondary'} />
                  <Score label="Fix" value={c.hasFix ? (c.fixedIn || 'Available') : 'None'} className={cx('t-xs', c.hasFix ? 't-ok' : 't-muted')} />
                </div>

                {c.hasFix && (
                  <Notice tone="ok" icon="check" className="mt-8 mb-0 fix-box">Fix available — upgrade to <strong>{c.fixedIn}</strong></Notice>
                )}

                {c.pocs?.length > 0 && <div className="mt-8"><PocLinks pocs={c.pocs} /></div>}
              </div>
            );
          })}

          <div className="block">
            <SectionLabel>Lib uses — appears in {pkg.images.length} {pkg.images.length === 1 ? 'image' : 'images'}</SectionLabel>
            {pkg.images.map(img => (
              <div key={img} className="item-card">
                <div className="t-sm t-medium t-primary">{img.split(':')[0]}</div>
                <div className="mono t-2xs t-muted mt-4 break">{img}</div>
              </div>
            ))}
          </div>
        </>
      )}
    </FloatingWindow>
  );
}
