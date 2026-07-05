
const BRIDGE = '/api';

export async function fetchStats() {
  const r = await fetch(`${BRIDGE}/stats`, { credentials: 'same-origin' });
  if (!r.ok) throw new Error(r.status);
  return r.json();
}

export async function fetchComponents() {
  const r = await fetch(`${BRIDGE}/components`, { credentials: 'same-origin' });
  if (!r.ok) throw new Error(r.status);
  return r.json();
}

export async function fetchK8sMetrics() {
  const r = await fetch(`${BRIDGE}/k8s-metrics`, { credentials: 'same-origin' });
  if (!r.ok) throw new Error(r.status);
  return r.json();
}

export async function fetchKafkaStats() {
  const r = await fetch(`${BRIDGE}/kafka-stats`, { credentials: 'same-origin' });
  if (!r.ok) throw new Error(r.status);
  return r.json();
}

