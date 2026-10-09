import { Report, TONE, fmtDate } from './pdfKit';

const SEV_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
const sevTone = s => TONE[String(s || '').toLowerCase()] || TONE.unknown;

function imageRef(r) {
  const name = r.name || r.image || '';
  return r.tag && !name.endsWith(`:${r.tag}`) ? `${name}:${r.tag}` : name;
}

export async function vulnReport({ results, cves, summary, cluster, user }) {
  const ok = results.filter(r => !(r.status === 'error' || r.error));
  const failed = results.filter(r => r.status === 'error' || r.error);
  const s = summary || {};

  const r = await Report.create({
    title: 'Vulnerability Report',
    subtitle: `Container images running in the cluster: ${ok.length} scanned${failed.length ? `, ${failed.length} failed` : ''}, ${cves.length} findings.`,
    cluster, user, fileBase: 'vulnerabilities', orientation: 'landscape',
  });

  r.tiles([
    { label: 'Critical', value: s.critical || 0, color: TONE.critical },
    { label: 'High', value: s.high || 0, color: TONE.high },
    { label: 'Medium', value: s.medium || 0, color: TONE.medium },
    { label: 'Low', value: s.low || 0, color: TONE.low },
    { label: 'Fixable', value: s.fixable || 0, color: TONE.pass },
    { label: 'CISA KEV', value: s.inKev || 0, color: TONE.critical },
  ]);

  const images = [...ok].sort((a, b) =>
    (b.summary?.critical || 0) - (a.summary?.critical || 0) ||
    (b.summary?.high || 0) - (a.summary?.high || 0) ||
    (b.summary?.total || 0) - (a.summary?.total || 0));

  r.heading('Images', 'Ordered by critical, then high findings.');
  if (images.length) {
    r.table({
      head: ['Image', 'Critical', 'High', 'Medium', 'Low', 'Total', 'Scanned'],
      body: images.map(i => [
        imageRef(i),
        i.summary?.critical || 0, i.summary?.high || 0, i.summary?.medium || 0, i.summary?.low || 0,
        i.summary?.total || 0, fmtDate(i.scannedAt),
      ]),
      columnStyles: {
        1: { cellWidth: 52, halign: 'right' }, 2: { cellWidth: 44, halign: 'right' },
        3: { cellWidth: 52, halign: 'right' }, 4: { cellWidth: 40, halign: 'right' },
        5: { cellWidth: 44, halign: 'right' }, 6: { cellWidth: 104 },
      },
      tone: (row, col) => {
        if (col === 1 && row[1] > 0) return TONE.critical;
        if (col === 2 && row[2] > 0) return TONE.high;
        return null;
      },
    });
  } else {
    r.note('No scanned images.');
  }

  if (failed.length) {
    r.heading('Images that failed to scan');
    r.table({
      head: ['Image', 'Error'],
      body: failed.map(i => [imageRef(i), String(i.error || i.status || 'error')]),
      columnStyles: { 0: { cellWidth: 200 } },
    });
  }

  const kev = cves.filter(c => c.inKev);
  if (kev.length) {
    r.heading('Actively exploited (CISA KEV)', 'Patch these first: CISA has confirmed exploitation in the wild.');
    r.table({
      head: ['CVE', 'Severity', 'Package', 'Installed', 'Fixed in', 'Image'],
      body: kev.map(c => [c.id, String(c.severity || 'UNKNOWN').toUpperCase(), c.pkgName || '', c.pkgVersion || '', c.fixedIn || '—',
        c._imageName ? `${c._imageName}${c._imageTag ? `:${c._imageTag}` : ''}` : '']),
      columnStyles: { 0: { cellWidth: 92 }, 1: { cellWidth: 62 } },
      tone: (row, col) => (col === 1 ? sevTone(row[1]) : null),
    });
  }

  const sorted = [...cves].sort((a, b) =>
    (SEV_RANK[String(a.severity).toUpperCase()] ?? 5) - (SEV_RANK[String(b.severity).toUpperCase()] ?? 5) ||
    (b.cvssV3Score || 0) - (a.cvssV3Score || 0));
  r.heading('All findings', 'Ordered by severity, then CVSS v3 score.');
  if (sorted.length) {
    r.table({
      head: ['CVE', 'BDU', 'Severity', 'CVSS', 'EPSS', 'KEV', 'Package', 'Installed', 'Fixed in', 'Image'],
      body: sorted.map(c => [
        c.id,
        c.bduId || '—',
        String(c.severity || 'UNKNOWN').toUpperCase(),
        c.cvssV3Score > 0 ? c.cvssV3Score.toFixed(1) : '—',
        c.epssScore > 0 ? `${(c.epssScore * 100).toFixed(2)}%` : '—',
        c.inKev ? 'yes' : '',
        c.pkgName || '',
        c.pkgVersion || '',
        c.fixedIn || (c.hasFix ? 'yes' : '—'),
        c._imageName ? `${c._imageName}${c._imageTag ? `:${c._imageTag}` : ''}` : '',
      ]),
      columnStyles: {
        0: { cellWidth: 92 }, 1: { cellWidth: 92 }, 2: { cellWidth: 62 }, 3: { cellWidth: 36, halign: 'right' },
        4: { cellWidth: 46, halign: 'right' }, 5: { cellWidth: 30 },
      },
      tone: (row, col) => {
        if (col === 2) return sevTone(row[2]);
        if (col === 5 && row[5]) return TONE.critical;
        return null;
      },
    });
  } else {
    r.note('No vulnerabilities found.');
  }

  return r.save();
}
