export async function loadData() {
  const [graphRes, anomalyRes] = await Promise.all([
    fetch('/anomaly/api/network-graph', { credentials: 'same-origin' }).catch(() => null),
    fetch('/anomaly/api/anomalies?limit=200', { credentials: 'same-origin' }).catch(() => null),
  ]);
  const graph   = graphRes?.ok  ? await graphRes.json()  : { nodes: [], edges: [] };
  const anomaly = anomalyRes?.ok ? await anomalyRes.json() : { events: [] };
  return { graph, anomalyEvents: anomaly.events || [] };
}

function buildNodes(graph, snap) {
  const protectedNs = new Set(
    (snap?.network_policies || []).map(p => p.metadata?.namespace).filter(Boolean)
  );

  const nodeSet = new Set(graph.nodes || []);
  if (snap?.deployments) {
    for (const d of snap.deployments) {
      const ns = d.metadata?.namespace;
      if (protectedNs.has(ns))
        nodeSet.add(`${ns}/${d.metadata.name}`);
    }
  }

  const list = protectedNs.size > 0
    ? [...nodeSet].filter(key => protectedNs.has(key.slice(0, key.indexOf('/'))))
    : [...nodeSet];

  const cols = Math.max(3, Math.ceil(Math.sqrt(list.length)));
  return list.map((key, i) => {
    const slash = key.indexOf('/');
    return {
      id:    key,
      ns:    key.slice(0, slash),
      label: key.slice(slash + 1),
      x: 80 + (i % cols) * 200,
      y: 80 + Math.floor(i / cols) * 160,
    };
  });
}

function buildEdges(graph, nodesById) {
  const extNodes = {};
  const edges = [];
  for (const e of (graph.edges || [])) {
    const src = nodesById[e.src];
    let   dst = nodesById[e.dst_ip] || nodesById[e.dst_name];
    if (!dst) {
      const extKey = e.dst_name || e.dst_ip;
      if (!extNodes[extKey])
        extNodes[extKey] = { id: extKey, label: extKey, ns: 'external', x: 0, y: 0, external: true };
      dst = extNodes[extKey];
    }
    if (src && dst) edges.push({ src: src.id, dst: dst.id, port: e.dst_port, kind: e.kind });
  }
  return { edges, extNodes: Object.values(extNodes) };
}

export function buildYaml(pol) {
  const name    = pol.metadata?.name      || '—';
  const ns      = pol.metadata?.namespace || '—';
  const spec    = pol.spec    || {};
  const sel     = spec.podSelector?.matchLabels || {};
  const types   = spec.policyTypes || [];
  const egress  = spec.egress  || [];
  const ingress = spec.ingress || [];

  let y = `apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: ${name}\n  namespace: ${ns}\nspec:\n  podSelector:`;
  if (Object.keys(sel).length) {
    y += `\n    matchLabels:`;
    for (const [k, v] of Object.entries(sel)) y += `\n      ${k}: ${v}`;
  } else {
    y += `\n    {}`;
  }
  if (types.length) {
    y += `\n  policyTypes:`;
    types.forEach(t => { y += `\n    - ${t}`; });
  }
  if (egress.length) {
    y += `\n  egress:`;
    egress.forEach(() => { y += `\n    - {}`; });
  }
  if (ingress.length) {
    y += `\n  ingress:`;
    ingress.forEach(() => { y += `\n    - {}`; });
  }
  return y;
}
