export const TABS = ['CVEs', 'Images', 'Deployments', 'Nodes', 'Libs'];

function buildSBOM(results) {
  const pkgMap = new Map();
  results.forEach(result => {
    const imageLabel = `${result.name || result.image}:${result.tag || 'latest'}`;
    ;(result.cves || []).forEach(cve => {
      const key = `${cve.pkgName}__${cve.pkgVersion}__${cve.pkgType || ''}`;
      if (!pkgMap.has(key)) {
        pkgMap.set(key, { name: cve.pkgName || '', version: cve.pkgVersion || '', type: cve.pkgType || 'deb', license: cve.pkgLicense || '', cves: [], images: new Set() });
      }
      const pkg = pkgMap.get(key);
      if (!pkg.license && cve.pkgLicense) pkg.license = cve.pkgLicense;
      if (!pkg.cves.find(c => c.id === cve.id)) pkg.cves.push(cve);
      pkg.images.add(imageLabel);
    });
  });
  const out = [];
  pkgMap.forEach(p => out.push({ ...p, images: [...p.images] }));
  return out.sort((a, b) => {
    const ac = a.cves.filter(c => (c.severity||'').toUpperCase() === 'CRITICAL').length;
    const bc = b.cves.filter(c => (c.severity||'').toUpperCase() === 'CRITICAL').length;
    if (bc !== ac) return bc - ac;
    return b.cves.length - a.cves.length || a.name.localeCompare(b.name);
  });
}

function sbomLicTone(lic = '') {
  const l = lic.toLowerCase();
  if (l.includes('gpl'))    return 'danger';
  if (l.includes('apache')) return 'accent';
  if (l.includes('mit'))    return 'ok';
  return 'violet';
}
function sbomVulnInfo(cves) {
  if (!cves.length) return { dot: 'none', label: '0' };
  const hasCrit = cves.some(c => (c.severity||'').toUpperCase() === 'CRITICAL');
  const hasHigh = cves.some(c => (c.severity||'').toUpperCase() === 'HIGH');
  const dot     = hasCrit ? 'critical' : hasHigh ? 'high' : 'medium';
  const label   = hasCrit
    ? `${cves.filter(c => (c.severity||'').toUpperCase() === 'CRITICAL').length} critical`
    : hasHigh
      ? `${cves.filter(c => (c.severity||'').toUpperCase() === 'HIGH').length} high`
      : `${cves.length}`;
  return { dot, label };
}

export { buildSBOM, sbomLicTone, sbomVulnInfo };
