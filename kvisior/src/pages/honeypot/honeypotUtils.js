import { SERVICES } from './honeypotConstants';
import { fmtDateTime } from '../../utils/format';

function svcByName(name, catalog) {
  const base = SERVICES.find(s => s.name === name);
  const live = (catalog || []).find(c => c.service === name);
  if (!base && !live) return { name, icon: 'honeypot', label: name || '—', port: '?', kind: '', defaultName: name, image: '' };
  return {
    ...(base || { name, icon: 'honeypot', label: name }),
    ...(live ? { kind: live.kind, defaultName: live.defaultName, port: live.port, image: live.image } : {}),
  };
}

function shortImage(image) {
  if (!image) return '';
  const parts = image.split('/');
  return parts[parts.length - 1];
}

function utcTs(ts) {
  return typeof ts === 'string' && /T\d{2}:\d{2}:\d{2}(\.\d+)?$/.test(ts) ? `${ts}Z` : ts;
}

const fmtTime = ts => fmtDateTime(utcTs(ts));

export { svcByName, shortImage, fmtTime };
