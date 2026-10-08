import { useState, useEffect } from 'react';
import { SevBadge } from '../../components/ui';
import { FloatingWindow } from '../../components/FloatingWindow';
import { KV, Tag, SectionLabel, Notice, Meter, sevTone, cx } from '../../components/kit';
import { epssLabel, epssTone } from '../../data/scanner';
import { FstecPanel, CvssVectorValue } from './CveDetailHelpers';
import { Icon } from '../../components/Icon';

const VEX_LABEL = {
  fixed:               { icon: 'circle-check', text: 'Fixed',               tone: 'ok' },
  not_fixed:           { icon: 'circle-x',     text: 'Not Fixed',           tone: 'danger' },
  wont_fix:            { icon: 'alert',        text: "Won't Fix",           tone: 'warning' },
  under_investigation: { icon: 'search',       text: 'Under Investigation', tone: 'violet' },
  unknown:             { icon: 'help',         text: 'Unknown',             tone: 'muted' },
};

const TONE_COLOR = { danger: 'var(--danger)', warning: 'var(--warning)', info: 'var(--info)', ok: 'var(--ok-text)' };

export function RiskBox({ score, label, inset, note }) {
  const tone = sevTone(label);
  return (
    <div className={cx('risk-box', inset && 'risk-box--inset')}>
      <div className="row row--between mb-4">
        <span className="t-xs t-muted">Risk Score</span>
        <span className={cx('mono t-sm t-strong', tone && `t-${tone}`)}>{score}/100 · {label}</span>
      </div>
      <Meter value={score} color={TONE_COLOR[tone]} label="Risk score" showValue={false} />
      {note && <div className="t-2xs t-muted mt-4">{note}</div>}
    </div>
  );
}

export function PocLinks({ pocs }) {
  return pocs.map((p, i) => (
    <a key={i} className="poc-link" href={p.url} target="_blank" rel="noreferrer">
      <span><Icon name="code" /> {p.name}</span>
      {p.stars > 0 && <span><Icon name="star" /> {p.stars}</span>}
    </a>
  ));
}

export function CveDetail({ item, onClose }) {
  const [tab, setTab] = useState('nvd');
  const [showMore, setShowMore] = useState(false);

  useEffect(() => {
    if (item) { setTab('nvd'); setShowMore(false); }
  }, [item?.id]);

  const open = !!item && !item._isScanResult;
  const c = item || {};
  const epss = c.epssScore > 0 ? epssLabel(c.epssScore) : null;
  const eTone = epssTone(c.epssScore);
  const vex = VEX_LABEL[c.vexStatus] || VEX_LABEL.unknown;
  const hasFstec = !!(c.bduDetail || c.bduId);
  const tone = sevTone(c.severity);
  const mono = v => <span className="mono t-xs">{v}</span>;

  return (
    <FloatingWindow
      open={open}
      resetKey={c.id}
      onClose={onClose}
      label={`CVE ${c.id}`}
      title={<span className="mono">{c.id}</span>}
      badges={<SevBadge sev={c.severity?.toUpperCase()} />}
      tabs={<>
        <button type="button" className={cx('subtab', tab === 'nvd' && 'active')} onClick={() => setTab('nvd')}>NVD</button>
        <button type="button" className={cx('subtab', tab === 'fstec' && 'active')} disabled={!hasFstec}
          title={hasFstec ? undefined : 'Not listed in the FSTEC BDU'} onClick={() => setTab('fstec')}>FSTEC</button>
      </>}
    >
      {tab === 'nvd' && (
        <>
          <div className="t-sm t-muted mb-12">{c.pkgName} {c.pkgVersion}</div>

          <div className="row row--wrap mb-12">
            {c.cvssV3Score > 0 && <Tag tone={tone} mono>CVSS {c.cvssV3Score.toFixed(1)}</Tag>}
            {epss && <Tag tone={eTone} mono>EPSS {epss.text}</Tag>}
            {c.inKev && <Tag tone="danger"><Icon name="flame" /> CISA KEV</Tag>}
            {c.pocs?.length > 0 && <Tag tone="warning"><Icon name="code" /> PoC ({c.pocs.length})</Tag>}
          </div>

          {c.riskScore > 0 && <RiskBox score={c.riskScore} label={c.riskLabel} note="60% CVSS · 40% EPSS weighted score" />}

          {c.title && <div className="prose mb-12">{c.title}</div>}

          <KV compact items={[
            ['Package', mono(c.pkgName)],
            ['Installed', mono(c.pkgVersion)],
            c.fixedIn && ['Fixed in', <span className="mono t-xs t-ok">{c.fixedIn}</span>],
            c.pkgType && ['Type', c.pkgType],
            c.cwes?.length > 0 && ['CWE', c.cwes.join(', ')],
            c.publishedDate && ['Published', c.publishedDate],
            c._imageName && ['Image', mono(`${c._imageName}:${c._imageTag || ''}`)],
            ['VEX / Fix State', <span className={`t-${vex.tone}`}><Icon name={vex.icon} /> {vex.text}{c.vexSource && <span className="t-muted"> ({c.vexSource})</span>}</span>],
            (c.cvssV3Vector || c.cvssV3Score > 0) && ['CVSS v3 Vector', <CvssVectorValue vector={c.cvssV3Vector} score={c.cvssV3Score} />],
            (c.cvssV2Vector || c.cvssV2Score > 0) && ['CVSS v2 Vector', <CvssVectorValue vector={c.cvssV2Vector} score={c.cvssV2Score} />],
            (c.cvssV4Vector || c.cvssV4Score > 0) && ['CVSS v4 Vector', <CvssVectorValue vector={c.cvssV4Vector} score={c.cvssV4Score} />],
            c.epssScore > 0 && ['EPSS', <span>
              <span className={cx('mono t-strong', eTone && `t-${eTone}`)}>{(c.epssScore * 100).toFixed(3)}%</span>
              {c.epssPercentile > 0 && <span className="t-muted"> ({Math.round(c.epssPercentile * 100)}th percentile)</span>}
            </span>],
            ['CISA KEV', c.inKev
              ? <span className="t-danger t-strong"><Icon name="flame" /> Actively exploited</span>
              : <span className="t-muted">Not listed</span>],
          ]} />

          {c.hasFix && (
            <Notice tone="ok" icon="check" className="mt-12 fix-box">Fix available — upgrade to <strong>{c.fixedIn}</strong></Notice>
          )}

          {c.pocs?.length > 0 && (
            <div className="block">
              <SectionLabel className="t-warning"><Icon name="code" /> Public PoC Exploits ({c.pocs.length})</SectionLabel>
              <PocLinks pocs={c.pocs} />
            </div>
          )}

          {c.description && (
            <div className="block">
              <SectionLabel>Description</SectionLabel>
              <div className="prose">{c.description}</div>
            </div>
          )}

          {c.references?.length > 0 && (
            <div className="block">
              <SectionLabel>References</SectionLabel>
              <div className="link-list">
                {c.references.slice(0, 6).map((ref, i) => <a key={i} href={ref} target="_blank" rel="noreferrer">{ref}</a>)}
              </div>
            </div>
          )}
        </>
      )}

      {tab === 'fstec' && <FstecPanel item={c} showMore={showMore} setShowMore={setShowMore} />}
    </FloatingWindow>
  );
}
