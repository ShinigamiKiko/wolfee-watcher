# Audit logs

kvisior records who changed what in the Kubernetes API, marks dangerous actions with audit rules, and
reports them as violations and alerts.

## Where events come from

| Source | What it sees | Needs |
|---|---|---|
| Admission webhook (`sentry-audit`, role `webhook`) | create, update, delete of objects; exec, attach, port-forward into pods; the user name and groups | nothing, works on any cluster, including managed ones |
| kube-apiserver audit log (`sentry-audit`, role `logtail`) | everything above plus source IP, client, response code, and read actions (`get`, `list`) | the audit log enabled on the API server and a file readable on control-plane nodes |

The two are joined exactly. The webhook returns the event id as an audit annotation
(`policyeval.wolfee-watcher.io/event-id`, `k8sevents.wolfee-watcher.io/event-id`), the API server writes
it into its own audit record, and the log reader sends that record back to kvisior, which adds source IP,
client and response code to the stored event. Without the log these fields stay empty; nothing is guessed.

Records without the annotation are requests the webhook does not see. They are stored as their own
events when they are worth keeping: reads by people, reads of secrets by service accounts, and writes by
anyone who is not a system component. Leases, events, endpoints and access reviews are dropped, as are
requests from nodes, `kube-*` components and `kube-system` service accounts. The lists are configurable.

## sentry-audit roles and scaling

`SENTRY_ROLES` selects what a pod does: `webhook`, `logtail`, or both.

- The chart runs the webhook as a Deployment (`sentryAudit.replicaCount`, default 2) with a
  PodDisruptionBudget and spread across nodes. Replicas are stateless: they share one TLS secret, every
  replica answers admission requests, and rules are evaluated in kvisior.
- Watching webhook configurations is done by one replica at a time, chosen through the
  `sentry-audit-watcher` lease, so those events are not duplicated.
- The log reader is a DaemonSet on control-plane nodes (`sentryAudit.auditLog.enabled`). Each API
  server writes its own file, so each node reads its own. It follows rotation and keeps its position in
  `sentryAudit.auditLog.stateDir` on the node, so a restart continues where it stopped.

```yaml
sentryAudit:
  replicaCount: 2
  auditLog:
    enabled: true
    path: /var/log/kubernetes/audit.log
```

### Enabling the API server audit log

kubeadm, in `/etc/kubernetes/manifests/kube-apiserver.yaml`:

```
--audit-policy-file=/etc/kubernetes/audit-policy.yaml
--audit-log-path=/var/log/kubernetes/audit.log
--audit-log-maxsize=100
--audit-log-maxbackup=10
```

with the policy file and the log directory mounted into the pod. `Metadata` level is enough; the event id
annotation is part of it. k3s takes the same flags as `--kube-apiserver-arg`. Managed control planes
(EKS, GKE, AKS) do not expose the file; there kvisior works from the admission webhook alone.

## Audit rules

Rules live in the `audit_rules` table and are shared by every kvisior. A rule can be limited to named
clusters. The 31 built-in rules are created by migration `0013-audit-rules`; existing Audit policies
from Policy Management are converted into rules by the same migration, one rule per check.

A rule matches on action (create, update, delete, exec, attach, portforward, get, list), resource,
namespace patterns and exclusions, object name, who (people or service accounts, named users, excluded
users), source IP (CIDR or `*` patterns, "only from" or "not from"), result (allowed or denied), and,
for exec, a command substring. Rules on reads or on source IP need the API log.

- **Enabled**: a match is written to `audit_violations`, shown on Violations, Audit, and highlighted
  in Audit logs, Monitoring.
- **Alert**: a match is also written to the alert log and delivered through its integrations, either
  every time or after N matches within M minutes.

API: `GET/POST /api/audit/rules`, `PUT/PATCH/DELETE /api/audit/rules/{id}`,
`POST /api/audit/rules/restore`. Changes need the admin role. Every kvisior reloads rules within 15 seconds.

## The page

Audit logs has three tabs.

- **Monitoring** shows a bounded window of the newest events (100, 200 or 500), updated live while the
  page is open. Dangerous actions are highlighted. Search works inside the window.
- **Investigation** searches stored events by time range, user, namespace, action, resource, source
  IP and result, with a histogram and grouping by user or by object.
- **Rules** lists, adds, edits and deletes rules.

## Retention

Audit events are kept for `ui.auditRetentionHours` (default 336, 14 days) in hourly partitions. Every
kvisior that shares the database, the hub included (`AUDIT_RETENTION_HOURS` in `hub.env`), must use the
same value: each instance drops partitions older than its own setting.
