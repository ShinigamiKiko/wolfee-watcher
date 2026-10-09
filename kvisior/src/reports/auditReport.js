import { Report, TONE, fmtDate } from './pdfKit';

const STATUS_TONE = { PASS: TONE.pass, FAIL: TONE.fail, WARN: TONE.warn, INFO: TONE.info };
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

export async function benchReport({ run, cluster, user }) {
  const controls = Array.isArray(run.data?.controls) ? run.data.controls : [];
  const totals = run.data?.totals || {};
  const total = (totals.pass || 0) + (totals.fail || 0) + (totals.warn || 0) + (totals.info || 0);
  const score = total ? Math.round((totals.pass || 0) / total * 100) : 0;

  const r = await Report.create({
    title: 'CIS Kubernetes Benchmark',
    subtitle: `kube-bench run "${run.name}" started ${fmtDate(run.startedAt)}`,
    cluster, user, fileBase: 'kube-bench',
  });

  r.tiles([
    { label: 'Pass rate', value: `${score}%`, color: score >= 80 ? TONE.pass : score >= 50 ? TONE.warn : TONE.fail },
    { label: 'Pass', value: totals.pass || 0, color: TONE.pass },
    { label: 'Fail', value: totals.fail || 0, color: TONE.fail },
    { label: 'Warn', value: totals.warn || 0, color: TONE.warn },
    { label: 'Info', value: totals.info || 0, color: TONE.info },
  ]);

  const actionable = [];
  controls.forEach(c => (c.tests || []).forEach(t => {
    if (t.status === 'FAIL' || t.status === 'WARN') actionable.push({ c, t });
  }));
  actionable.sort((a, b) => (a.t.status === b.t.status ? 0 : a.t.status === 'FAIL' ? -1 : 1));

  r.heading('Checks that need action', `${actionable.length} failed or warning checks, failures first.`);
  if (actionable.length) {
    r.table({
      head: ['Check', 'Status', 'Description', 'Remediation'],
      body: actionable.map(({ t }) => [t.number, t.status, t.desc || '', t.remediation || '—']),
      columnStyles: { 0: { cellWidth: 42 }, 1: { cellWidth: 40 }, 2: { cellWidth: 170 } },
      tone: (row, col) => (col === 1 ? STATUS_TONE[row[1]] : null),
    });
  } else {
    r.note('No failed or warning checks.');
  }

  r.heading('All checks by section');
  controls.forEach(c => {
    const tests = c.tests || [];
    r.subheading(`${c.id}  ${c.text || ''}${c.node_type ? `  ·  ${c.node_type}` : ''}  —  ${c.pass || 0} pass, ${c.fail || 0} fail, ${c.warn || 0} warn`);
    r.table({
      head: ['Check', 'Status', 'Description'],
      body: tests.map(t => [t.number, t.status, t.desc || '']),
      columnStyles: { 0: { cellWidth: 42 }, 1: { cellWidth: 40 } },
      tone: (row, col) => (col === 1 ? STATUS_TONE[row[1]] : null),
    });
  });

  const details = actionable.filter(({ t }) => t.actual || t.expected || t.reason);
  if (details.length) {
    r.heading('Evidence for failed and warning checks');
    details.forEach(({ t }) => {
      r.subheading(`${t.number}  ${t.desc || ''}`, STATUS_TONE[t.status]);
      r.paragraph(t.reason, { label: 'Reason' });
      r.paragraph(t.actual, { label: 'Actual value', mono: true });
      r.paragraph(t.expected, { label: 'Expected', mono: true });
    });
  }

  return r.save();
}

export async function hunterReport({ run, cluster, user }) {
  const nodes = Array.isArray(run.data?.nodes) ? run.data.nodes : [];
  const services = Array.isArray(run.data?.services) ? run.data.services : [];
  const vulns = (Array.isArray(run.data?.vulnerabilities) ? run.data.vulnerabilities : [])
    .filter(Boolean)
    .sort((a, b) => (SEV_RANK[a.severity] ?? 4) - (SEV_RANK[b.severity] ?? 4));
  const totals = run.data?.totals || {};
  const tone = s => TONE[s] || TONE.unknown;

  const r = await Report.create({
    title: 'Kubernetes Penetration Test',
    subtitle: `kube-hunter run "${run.name}" started ${fmtDate(run.startedAt)}`,
    cluster, user, fileBase: 'kube-hunter',
  });

  r.tiles([
    { label: 'Findings', value: vulns.length, color: vulns.length ? TONE.fail : TONE.pass },
    { label: 'Critical', value: totals.critical || 0, color: TONE.critical },
    { label: 'High', value: totals.high || 0, color: TONE.high },
    { label: 'Medium', value: totals.medium || 0, color: TONE.medium },
    { label: 'Low', value: totals.low || 0, color: TONE.low },
  ]);

  if (nodes.length || services.length) {
    r.heading('Attack surface discovered');
    if (nodes.length) {
      r.subheading('Nodes');
      r.table({ head: ['Type', 'Location'], body: nodes.map(n => [n.type || 'node', n.location || '']), columnStyles: { 0: { cellWidth: 120 } } });
    }
    if (services.length) {
      r.subheading('Services');
      r.table({ head: ['Service', 'Location'], body: services.map(s => [s.service || '', s.location || '']), columnStyles: { 0: { cellWidth: 120 } } });
    }
  }

  r.heading('Findings', vulns.length ? 'Ordered by severity.' : undefined);
  if (!vulns.length) {
    r.note('kube-hunter found no vulnerabilities.');
    return r.save();
  }
  r.table({
    head: ['Severity', 'ID', 'Vulnerability', 'Category', 'Location'],
    body: vulns.map(v => [(v.severity || 'n/a').toUpperCase(), v.id || '—', v.vulnerability || '', v.category || '', v.location || '']),
    columnStyles: { 0: { cellWidth: 52 }, 1: { cellWidth: 46 }, 4: { cellWidth: 100 } },
    tone: (row, col) => (col === 0 ? tone(String(row[0]).toLowerCase()) : null),
  });

  r.heading('Finding details');
  vulns.forEach(v => {
    r.subheading(`${(v.severity || 'n/a').toUpperCase()}  ${v.id ? `${v.id}  ` : ''}${v.vulnerability || ''}`, tone(v.severity));
    r.facts([
      ['Category', v.category],
      ['Hunter module', v.hunter],
      ['Location', v.location],
      ['MITRE ATT&CK', v.mitre],
      ['Reference', v.avd_link],
    ]);
    r.paragraph(v.avd_description || v.description, { label: 'Description' });
    r.paragraph(v.avd_impact, { label: 'Impact' });
    r.paragraph(v.evidence, { label: 'Evidence', mono: true });
    r.paragraph(v.avd_remediation, { label: 'Remediation' });
  });

  return r.save();
}
