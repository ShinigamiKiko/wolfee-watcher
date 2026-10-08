import { KV, Tag, SectionLabel, Notice, sevTone } from '../../components/kit';
import { Icon } from '../../components/Icon';

const FIXED = 'Уязвимость устранена';

function FstecPanel({ item, showMore, setShowMore }) {
  const d = item.bduDetail;
  const bduSev = /^(critical|high|medium|low)$/i.test(item.bduSeverity || '') ? item.bduSeverity : null;
  return (
    <>
      <div className="row row--wrap mb-12">
        <Tag tone="danger" mono>{item.bduId || 'BDU'}</Tag>
        {bduSev && <Tag tone={sevTone(bduSev)}>{bduSev}</Tag>}
        {d?.exploitStatus && /существует/i.test(d.exploitStatus) && <Tag tone="danger"><Icon name="code" /> PoC</Tag>}
        {d?.fixStatus && <Tag tone={d.fixStatus === FIXED ? 'ok' : undefined}>{d.fixStatus}</Tag>}
      </div>

      {!d && (
        <Notice icon={false}>
          The CVE is listed in the FSTEC BDU, but the backend did not collect its detail card
          (most likely <code className="inline">BDU_NO_DETAIL</code> is set). Full details are available at bdu.fstec.ru.
        </Notice>
      )}

      {d && (
        <>
          <KV compact items={[
            ['BDU ID', <span className="mono t-danger">{d.identifier}</span>],
            d.vulStatus && ['Status', d.vulStatus],
            d.exploitStatus && ['Exploitation', d.exploitStatus],
            d.fixStatus && ['Fix', d.fixStatus],
            d.vulClass && ['Class', d.vulClass],
            d.vulElimination && ['Remediation', d.vulElimination],
            d.cwes?.length > 0 && ['CWE', d.cwes.map((cwe, i) => (
              <span key={cwe.id}>
                <span className="mono">{cwe.id}</span>
                {cwe.name && <span className="t-muted"> — {cwe.name}</span>}
                {i < d.cwes.length - 1 ? '; ' : ''}
              </span>
            ))],
            d.identifyDate && ['Identified', d.identifyDate],
            d.publicationDate && ['Published', d.publicationDate],
            d.lastUpdDate && ['Updated', d.lastUpdDate],
            (d.cvss3Vector || d.cvss3Score > 0) && ['CVSS 3 Vector', <CvssVectorValue vector={d.cvss3Vector} score={d.cvss3Score} />],
            (d.cvss2Vector || d.cvss2Score > 0) && ['CVSS 2 Vector', <CvssVectorValue vector={d.cvss2Vector} score={d.cvss2Score} />],
            (d.cvss4Vector || d.cvss4Score > 0) && ['CVSS 4 Vector', <CvssVectorValue vector={d.cvss4Vector} score={d.cvss4Score} />],
          ]} />

          {d.solution && (
            <div className="block">
              <SectionLabel>FSTEC recommendations</SectionLabel>
              <Notice tone="ok" icon={false}><div className="prose">{linkifyURLs(d.solution)}</div></Notice>
            </div>
          )}

          {d.software?.length > 0 && (
            <div className="block">
              <SectionLabel>Affected software</SectionLabel>
              {d.software.map((s, i) => <SoftwareRow key={i} sw={s} />)}
            </div>
          )}

          {d.environments?.length > 0 && (
            <div className="block">
              <SectionLabel>Operating environment</SectionLabel>
              {d.environments.map((e, i) => <SoftwareRow key={i} sw={e} />)}
            </div>
          )}

          {d.sources?.length > 0 && (
            <div className="block">
              <SectionLabel>Sources</SectionLabel>
              <div className="link-list">
                {d.sources.map((s, i) => <a key={i} href={s} target="_blank" rel="noreferrer">{s}</a>)}
              </div>
            </div>
          )}

          {(d.description || d.name) && (
            <div className="block">
              <SectionLabel>Description</SectionLabel>
              <div className="prose">{d.description || d.name}</div>
            </div>
          )}

          {hasShouldFields(d) && (
            <button type="button" className="btn btn-outline btn-sm mt-12" aria-expanded={showMore} onClick={() => setShowMore(s => !s)}>
              <Icon name={showMore ? 'chevron-down' : 'chevron-right'} /> {showMore ? 'Show less' : 'More…'}
            </button>
          )}

          {showMore && (
            <KV compact className="mt-12" items={[
              d.slOperProcs?.length > 0 && ['Exploitation method', d.slOperProcs.join(', ')],
              d.otherIds?.length > 0 && ['Other IDs', d.otherIds.map((o, i) => (
                <span key={i}>
                  {o.type && <span className="t-muted">{o.type}: </span>}
                  <span className="mono">{o.value}</span>
                  {i < d.otherIds.length - 1 ? '; ' : ''}
                </span>
              ))],
            ]} />
          )}
        </>
      )}
    </>
  );
}

function CvssVectorValue({ vector, score }) {
  return (
    <span className="cvss-vector">
      {vector}
      {score > 0 && <b>{score.toFixed(1)}</b>}
    </span>
  );
}

function SoftwareRow({ sw }) {
  const parts = [sw.vendor, sw.name, sw.version, sw.platform && `(${sw.platform})`].filter(Boolean);
  return (
    <div className="sw-row">
      {parts.join(' ')}
      {sw.types?.length > 0 && <span className="t-muted"> · {sw.types.join(', ')}</span>}
    </div>
  );
}

function hasShouldFields(d) {
  return !!(d && ((d.slOperProcs && d.slOperProcs.length) || (d.otherIds && d.otherIds.length)));
}

function linkifyURLs(text) {
  if (!text) return null;
  const parts = text.split(/(https?:\/\/[^\s)<>"']+)/g);
  return parts.map((p, i) => (/^https?:\/\//.test(p)
    ? <a key={i} href={p} target="_blank" rel="noreferrer" className="break">{p}</a>
    : <span key={i}>{p}</span>));
}

export { FstecPanel, CvssVectorValue, SoftwareRow, hasShouldFields, linkifyURLs };
