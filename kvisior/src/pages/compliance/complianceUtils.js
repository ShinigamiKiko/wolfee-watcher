import { CIS }        from './checksCIS';
import { NIST, PCI }  from './checksNIST_PCI';
import { HIPAA }      from './checksHIPAA';
import { FSTEC }      from './checksFSTEC';

const STANDARDS = [
  { id:'CIS',   label:'CIS Kubernetes 1.5', checks: CIS,   color:'var(--accent)' },
  { id:'NIST',  label:'NIST 800-190',       checks: NIST,  color:'var(--accent-2)' },
  { id:'PCI',   label:'PCI DSS',            checks: PCI,   color:'var(--warning)' },
  { id:'HIPAA', label:'HIPAA',              checks: HIPAA, color:'var(--accent-3)' },
  { id:'FSTEC', label:'ФСТЭК 118',          checks: FSTEC, color:'var(--danger)' },
];

function runStandard(std, data) {
  const results = std.checks.map(c => {
    try {
      const r = c.fn(data);
      return { ...c, ...r, score: Math.round(r.passing / r.total * 100) };
    } catch(e) {
      return { ...c, passing:0, total:1, score:0, entities:[], fix:'', err: e.message };
    }
  });
  const overall = results.length
    ? Math.round(results.reduce((s,r)=>s+r.score,0) / results.length)
    : 0;
  return { ...std, results, overall };
}

function scoreColor(n) { return n>=80?'var(--accent-3)':n>=50?'var(--warning)':'var(--danger)'; }

export const REFRESH_MS = 10 * 60 * 1000;

export { STANDARDS, runStandard, scoreColor };
