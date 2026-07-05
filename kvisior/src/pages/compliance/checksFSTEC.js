import { ISOLATION } from './checksFSTEC_isolation';
import { VULN }      from './checksFSTEC_vuln';
import { CONFIG }    from './checksFSTEC_config';
import { INTEGRITY, AUDIT, HOST_OS, ACCESS } from './checksFSTEC_audit';

const FSTEC = [...HOST_OS, ...ISOLATION, ...VULN, ...CONFIG, ...INTEGRITY, ...AUDIT, ...ACCESS];
export { FSTEC };
