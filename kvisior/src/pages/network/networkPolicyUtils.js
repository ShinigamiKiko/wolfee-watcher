const SKIP_KEYS = new Set(['managedFields','resourceVersion','uid','selfLink',
  'generation','creationTimestamp','annotations','finalizers','ownerReferences']);

export function cleanObj(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(cleanObj);
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (SKIP_KEYS.has(k)) continue;
    const c = cleanObj(v);
    if (c !== null && c !== undefined) out[k] = c;
  }
  return out;
}

export function toYaml(obj, indent = 0) {
  const p = '  '.repeat(indent);
  if (obj === null || obj === undefined) return '';
  if (typeof obj === 'string')
    return /[:{}[\],#&*?|<>=!%@`"']/.test(obj) ? `"${obj.replace(/"/g,'\\"')}"` : obj;
  if (typeof obj === 'number' || typeof obj === 'boolean') return String(obj);
  if (Array.isArray(obj)) {
    if (!obj.length) return '[]';
    return obj.map(v => typeof v === 'object' && v !== null
      ? `\n${p}- ${toYaml(v, indent+1).trimStart()}`
      : `\n${p}- ${toYaml(v)}`).join('');
  }
  const entries = Object.entries(obj).filter(([,v]) => v !== undefined && v !== null && v !== '');
  if (!entries.length) return '{}';
  return entries.map(([k, v]) => {
    if (Array.isArray(v) && v.length && typeof v[0]==='object')
      return `\n${p}${k}:${toYaml(v, indent+1)}`;
    if (typeof v==='object' && !Array.isArray(v))
      return `\n${p}${k}:\n${p}  ${toYaml(v, indent+1).trimStart()}`;
    return `\n${p}${k}: ${toYaml(v)}`;
  }).join('');
}

export function normalizePolicies(raw = []) {
  return raw.map(np => {
    const meta   = np.metadata || {};
    const spec   = np.spec    || {};
    const podSel = spec.podSelector?.matchLabels || {};
    const types  = spec.policyTypes || ['Ingress'];
    const ingress = [], egress = [];

    const peerLabel = f =>
      f.podSelector       ? Object.entries(f.podSelector.matchLabels||{}).map(([k,v])=>`${k}=${v}`).join(', ')||'any pod'
      : f.namespaceSelector ? 'any namespace'
      : 'anywhere';
    const peerSel = f => f.podSelector?.matchLabels || null;

    if (types.includes('Ingress')) {
      for (const rule of (spec.ingress||[])) {
        const ports = (rule.ports||[]).map(p=>`${p.protocol||'TCP'}:${p.port}`);
        ingress.push({ peers: rule.from ? rule.from.map(peerLabel) : ['anywhere'], peerSels:(rule.from||[]).map(peerSel), ports, effect:'allow' });
      }
      if (!spec.ingress) ingress.push({ peers:['(deny all)'], peerSels:[], ports:[], effect:'deny' });
    }
    if (types.includes('Egress')) {
      for (const rule of (spec.egress||[])) {
        const ports = (rule.ports||[]).map(p=>`${p.protocol||'TCP'}:${p.port}`);
        egress.push({ peers: rule.to ? rule.to.map(peerLabel) : ['anywhere'], peerSels:(rule.to||[]).map(peerSel), ports, effect:'allow' });
      }
      if (!spec.egress) egress.push({ peers:['(deny all)'], peerSels:[], ports:[], effect:'deny' });
    }

    return { name:meta.name, namespace:meta.namespace, podSel, selLabel:meta.name, policyTypes:types, ingress, egress, raw:np };
  });
}

export function buildGraph(policies, services) {
  const svcByLabel = {};
  for (const svc of (services||[])) {
    const sel = svc.spec?.selector||{};
    const app = sel.app || Object.values(sel)[0];
    if (app && svc.spec?.clusterIP && svc.spec.clusterIP !== 'None')
      svcByLabel[app] = { ip:svc.spec.clusterIP, name:svc.metadata?.name, ns:svc.metadata?.namespace };
  }

  const nodes=[], edges=[];
  const SUBJECT_X=340, COL_GAP=280, ROW_H=160;

  policies.forEach((pol, pi) => {
    const sy = 80 + pi * ROW_H;
    const svcInfo = svcByLabel[Object.values(pol.podSel)[0]||''];
    const subjId = `subj:${pol.name}`;
    nodes.push({ id:subjId, label:pol.selLabel, ns:pol.namespace, x:SUBJECT_X, y:sy, kind:'subject', policy:pol, svcInfo });

    pol.ingress.forEach((rule, ri) => rule.peers.forEach((peer, rpi) => {
      const peerId = `peer:in:${pol.name}:${ri}:${rpi}`;
      const peerApp = rule.peerSels[rpi] ? Object.values(rule.peerSels[rpi])[0] : null;
      nodes.push({ id:peerId, label:peerApp||peer, ns:pol.namespace, x:SUBJECT_X-COL_GAP, y:sy+(ri+rpi-(pol.ingress.length-1)/2)*60, kind:'peer', svcInfo:peerApp?svcByLabel[peerApp]:null });
      edges.push({ id:`e:in:${pol.name}:${ri}:${rpi}`, src:peerId, dst:subjId, effect:rule.effect, ports:rule.ports, dir:'ingress', pol });
    }));

    pol.egress.forEach((rule, ri) => rule.peers.forEach((peer, rpi) => {
      const peerId = `peer:out:${pol.name}:${ri}:${rpi}`;
      const peerApp = rule.peerSels[rpi] ? Object.values(rule.peerSels[rpi])[0] : null;
      nodes.push({ id:peerId, label:peerApp||peer, ns:pol.namespace, x:SUBJECT_X+COL_GAP, y:sy+(ri+rpi-(pol.egress.length-1)/2)*60, kind:'peer', svcInfo:peerApp?svcByLabel[peerApp]:null });
      edges.push({ id:`e:out:${pol.name}:${ri}:${rpi}`, src:subjId, dst:peerId, effect:rule.effect, ports:rule.ports, dir:'egress', pol });
    }));
  });

  return { nodes, edges, byId: Object.fromEntries(nodes.map(n=>[n.id,n])) };
}

function parsePorts(str) {
  if (!str.trim()) return undefined;
  return str.split(',').map(s=>s.trim()).filter(Boolean).map(p => {
    const [proto, port] = p.includes('/') ? p.split('/') : ['TCP', p];
    return { protocol: proto.toUpperCase(), port: parseInt(port)||port };
  });
}

function parsePeers(str) {
  if (!str.trim()) return [];
  return str.split(',').map(s=>s.trim()).filter(Boolean).map(peer => ({ podSelector:{ matchLabels:{ app:peer } } }));
}

export function buildFormYaml(form, toYamlFn) {
  const policyTypes = [];
  if (form.typeIngress) policyTypes.push('Ingress');
  if (form.typeEgress)  policyTypes.push('Egress');
  const spec = { podSelector:{ matchLabels:{ app:form.podSelector } }, policyTypes };
  if (form.typeIngress) {
    const peers = parsePeers(form.ingressPeers), ports = parsePorts(form.ingressPorts);
    spec.ingress = peers.length ? [{ from:peers, ...(ports?{ports}:{}) }] : [];
  }
  if (form.typeEgress) {
    const peers = parsePeers(form.egressPeers), ports = parsePorts(form.egressPorts);
    spec.egress = peers.length ? [{ to:peers, ...(ports?{ports}:{}) }] : [];
  }
  return toYamlFn({ apiVersion:'networking.k8s.io/v1', kind:'NetworkPolicy', metadata:{ name:form.name, namespace:form.namespace }, spec }).trimStart();
}
