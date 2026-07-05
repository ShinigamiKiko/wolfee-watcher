import { KIND_META } from './alertsConstants';

function kindMeta(kind) {
  return KIND_META[kind] || { label: kind, color: 'info', icon: '•' };
}

function relTime(ts) {
  const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (diff < 60)   return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  return `${Math.floor(diff/3600)}h ago`;
}

function fmtPorts(ev) {
  if (ev.kind === 'port_scan' && ev.scanned_ports?.length) {
    const shown = ev.scanned_ports.slice(0, 6);
    const rest  = ev.scanned_ports.length - shown.length;
    return shown.join(', ') + (rest > 0 ? ` +${rest}` : '');
  }
  return ev.dst_port ? String(ev.dst_port) : '—';
}

function evtPattern(ev) {
  if (ev._isDigest) return `digest_change|${ev.src_pod || ev.src_namespace || ''}`;
  return [
    ev.kind || '',
    ev.src_namespace  || '',
    ev.src_deployment || ev.src_pod || '',
    ev.dst_ip   || '',
    ev.dst_port || '',
  ].join('|');
}

function evtSummary(ev) {
  if (ev._isDigest) return `digest_change · ${ev.src_pod || '—'}`;
  const src  = ev.src_pod || ev.src_deployment || '—';
  const dest = ev.dst_ip ? `${ev.dst_ip}${ev.dst_port ? ':'+ev.dst_port : ''}` : '—';
  return `${ev.kind} · ${src} → ${dest}`;
}

export { kindMeta, relTime, fmtPorts, evtPattern, evtSummary };
