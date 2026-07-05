import { appDeps, appPods, podContainers, wlContainers, SYS_NS } from './checksCIS';

const allPods = d => d.snap?.pods || [];
const allNamespaces = d => d.snap?.namespaces || [];
const allDaemonSets = d => d.snap?.daemon_sets || [];
const readyNodes = d => (d.snap?.nodes || []).filter(n =>
  (n.status?.conditions || []).some(c => c.type === 'Ready' && c.status === 'True'));

const isPodRunning = p => {
  if (p.status?.phase !== 'Running') return false;
  const cs = p.status?.containerStatuses;
  if (!cs || cs.length === 0) return true;
  return cs.every(c => c.ready === true);
};

const findByName = (items, ...needles) =>
  (items || []).filter(it => {
    const n = (it.metadata?.name || '').toLowerCase();
    return needles.some(s => n.includes(s));
  });

const parseSemver = s => {
  const m = String(s || '').match(/(\d+)\.(\d+)(?:\.(\d+))?/);
  return m ? [+m[1], +m[2], +(m[3] || 0)] : null;
};
const cmpSemver = (a, b) => {
  for (let i = 0; i < 3; i++) if ((a[i]||0) !== (b[i]||0)) return (a[i]||0) - (b[i]||0);
  return 0;
};

export { allPods, allNamespaces, allDaemonSets, readyNodes, isPodRunning, findByName, parseSemver, cmpSemver };
