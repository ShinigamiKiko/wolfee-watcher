import { AUDIT_CHECKS } from '../policy/constants';

const CHECK_MAP = Object.fromEntries(AUDIT_CHECKS.map(c => [c.id, c]));

function eventMatchesCheck(event, checkId) {
  const def = CHECK_MAP[checkId];
  if (!def) return false;
  if (def.kind     && def.kind     !== event.kind)     return false;
  if (def.resource && def.resource !== event.resource) return false;
  return true;
}

export function matchAuditEvents(auditRules, events = []) {
  if (!events.length || !auditRules.length) return [];
  const results = [];
  for (const policy of auditRules) {
    if (policy.enabled === false) continue;
    const checks   = policy.auditChecks || [];
    const nsFilter = policy.namespace?.trim();
    for (const event of events) {
      const isConnectKind = event.kind === 'exec' || event.kind === 'attach' || event.kind === 'portforward';
      if (nsFilter && event.namespace && !isConnectKind && event.namespace !== nsFilter) continue;
      for (const checkId of checks) {
        if (!eventMatchesCheck(event, checkId)) continue;
        results.push({
          _eventId:  event.id,
          _policyId: policy.id,
          policy:    policy.name,
          sev:       (policy.sev || 'HIGH').toUpperCase(),
          check:     checkId,
          action:    policy.action,
          kind:      event.kind,
          resource:  event.resource,
          ns:        event.namespace || '(cluster)',
          name:      event.name,
          user:      event.user,
          groups:    event.groups,
          timestamp: event.timestamp,
          commands:  event.commands,
          container: event.container,
          ports:     event.ports,
          sourceIPs: event.sourceIPs,
          _detectedAt: event.timestamp ? new Date(event.timestamp).getTime() : Date.now(),
        });
      }
    }
  }
  return results;
}
