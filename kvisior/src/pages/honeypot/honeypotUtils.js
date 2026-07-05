import { SERVICES } from './honeypotConstants';
import { fmtDateTime } from '../../utils/format';

function svcByName(name) {
  return SERVICES.find(s => s.name === name) || { name, icon: '•', label: name, port: '?' };
}

const fmtTime = fmtDateTime;

export { svcByName, fmtTime };
