import { AUDIT_CHECKS } from '../../policy/constants';
import { fpKey } from '../violationsConstants';

const push = (arr, v) => { v._fp = fpKey(v, 'Build'); arr.push(v); };

export function evalBuildViolations(buildPolicies, clusterImages, histories) {
  const histByRef = {};
  histories.forEach(h => { histByRef[h.image] = h; });

  const viols = [];
  for (const policy of buildPolicies) {
    if (policy.enabled === false) continue;

    const nsFilter = policy.namespace?.trim();
    const images   = clusterImages.length > 0
      ? clusterImages
      : Object.keys(histByRef).map(r => ({ ref: r }));

    if (policy.trustedRegistries?.trim()) {
      const trusted = policy.trustedRegistries
        .split(',')
        .map(r => r.trim().toLowerCase())
        .filter(Boolean);

      for (const img of images) {
        const ref = img.ref || img.image || img.name || '';
        if (!ref) continue;
        if (nsFilter) {
          const imgNs = img.namespace || '';
          if (imgNs && imgNs !== nsFilter) continue;
        }
        const refLower = ref.toLowerCase();
        const isTrusted = trusted.some(t => refLower.startsWith(t));
        if (!isTrusted) {
          push(viols, {
            policy: policy.name, sev: policy.sev || 'HIGH', image: ref,
            detail: `Image not from trusted registry. Trusted: ${trusted.join(', ')}`,
            instruction: policy.trustedRegistries, namespace: nsFilter,
            action: policy.action, _policyId: policy.id, _check: 'registry',
            _detectedAt: Date.now(),
          });
        }
      }
    }

    if (!policy.buildInstruction?.trim()) continue;

    const pattern = policy.buildInstruction.trim();

    for (const img of images) {
      const ref  = img.ref || img.image || img.name || '';
      if (!ref) continue;

      const isLocalhost = ref.startsWith('localhost/') || ref.startsWith('localhost:');
      if (isLocalhost) continue;

      const hist = histByRef[ref];

      if (!hist || hist.status === 'pending' || hist.status === 'fetching') continue;

      if (hist.status === 'unavailable') {
        push(viols, {
          policy: policy.name, sev: policy.sev || 'MEDIUM', image: ref,
          detail: `History unavailable: ${hist.error || 'registry unreachable'}`,
          instruction: policy.buildInstruction, namespace: nsFilter,
          action: 'alert', _policyId: policy.id, _pending: true, _check: 'history',
          _detectedAt: Date.now(),
        });
        continue;
      }

      let regex;
      try {
        regex = new RegExp(pattern, 'i');
      } catch {
        regex = new RegExp(pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      }

      const matchedLayer = (hist.layers || []).find(l => regex.test(l.created_by || ''));

      if (matchedLayer) {
        const displayInstr = matchedLayer.created_by
          .replace(/^\/bin\/sh -c #\(nop\)\s+/, '')
          .replace(/^\/bin\/sh -c\s+/, 'RUN ')
          .trim();
        push(viols, {
          policy: policy.name, sev: policy.sev || 'MEDIUM', image: ref,
          detail: `Layer matches: ${displayInstr}`,
          instruction: policy.buildInstruction, namespace: nsFilter,
          action: policy.action, _policyId: policy.id, _check: 'layer',
          _detectedAt: Date.now(),
        });
      }
    }
  }
  return viols;
}
