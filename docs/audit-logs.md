# Audit logs

kvisior records who changed what in the Kubernetes API, marks dangerous actions with audit rules, and
reports them as violations and alerts.

`RequestResponse` is an optional improvement to attribution, not a prerequisite for startup,
event collection, or ordinary rules. With `Metadata`, the reader still enriches events and evaluates
rules that use source IP or the request result. Without the API log, the admission webhook and
watcher still collect events and evaluate rules whose conditions are available. Missing response
bodies never hold up ingestion; matching uses the available identifiers and then the fallback below.

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

### Who made the request

With the log connected, an event names the account that authenticated, not the one it acted as:

- Impersonation (`kubectl --as`, `--as-group`). The webhook only sees the impersonated account. The
  API server's record carries both, so the joined event gets the authenticated user and its groups in
  `user` and `groups`, and the impersonated account in `impersonatedUser` and `impersonatedGroups`
  (**Acted as** in the event). A violation already written for the event gets the same user. Rules
  are matched against the authenticated user.
- Changes to webhook configurations. Admission webhooks are not called for them, so they come from a
  watch and carry no user (`unknown`). The API server's record for the same change is merged into
  that event and supplies the user, groups, source IP and client; whichever of the two arrives first,
  the change is stored once. For these two resources successful writes by system accounts are kept
  too. A denied attempt is stored as its own event and never takes over someone else's change.

The record and the watch event are matched as the same change by the object's uid and by revisions,
not by time, so two people changing one object milliseconds apart keep their own changes. The chart
installs the `webhook-changes.wolfee-watcher.io` ValidatingAdmissionPolicy for this
(`sentryAudit.webhookChangePolicy.enabled`, Kubernetes 1.30 and later). It has no validations, its
binding only audits and its failure policy is `Ignore`, so policy evaluation errors do not reject a request; it
adds three audit annotations to changes of webhook configurations: the object uid, the
`resourceVersion` the request started from, and whether the request changed the object at all. A
request that changed nothing (a repeated apply) causes no watch event; it is stored as its own event,
marked `unchanged`, and is never taken for someone else's change.

When two writes collide, the API server retries the loser on the newer revision but keeps the
annotation from its first attempt. Such a record is matched to the earliest unclaimed change at or
after the revision it names, in the order the requests completed. That order is inferred, not read
from the record, and completion order does not guarantee storage commit order. With several API servers
the records of a collision between requests served by different ones come from different readers in
no particular order, so such a pair can be assigned the wrong way round. A `Metadata` record has
nothing that tells which revision a retried request finally wrote; only the response does. To make
this case exact too, log these two resources at `RequestResponse` level; the
record then carries the revision the change produced. Successful creates and updates with a response
uid and revision can be matched exactly regardless of delivery order, provided the corresponding watch
event is retained. Deletes can return a Status without a new revision and are matched separately.
Place this optional rule before a broader matching `Metadata` rule:

```yaml
- level: RequestResponse
  omitManagedFields: true
  verbs: ["create", "update", "patch", "delete"]
  resources:
    - group: admissionregistration.k8s.io
      resources: ["validatingwebhookconfigurations", "mutatingwebhookconfigurations"]
```

What the match trusts. No identifier is read from the request body. They come from what the API
server writes itself: the response object, the status of a delete, and the policy's annotations,
which are computed from the stored object. The uid and revision that a client sends in a full update
are used only for a successful update, where the API server has already refused any value that does
not match the stored object; in a create request they are ignored, and revision `0` (an unconditional
update) is not a revision. A dry-run request succeeds and changes nothing: it is recognised by the
`dryRun` parameter of the request. For a delete that option travels in the body, so it is recognised
with the policy or at `RequestResponse` level, where the logged delete options show it; at `Metadata`
level without the policy a dry-run delete looks like a real one. It is stored as its own event marked `dryRun` and never takes a real change. The reader
needs read access to the log only; whoever can rewrite the log file on a control-plane node, or
change the admission policy, can falsify the record itself, and that is outside what matching can
defend.

On Kubernetes 1.28 and 1.29 the chart installs the same policy through the `v1beta1` API when the
cluster has it enabled (the `ValidatingAdmissionPolicy` feature gate and
`--runtime-config=admissionregistration.k8s.io/v1beta1=true`).

Without the policy the identifiers are taken from the record when it has them: a full update and a
delete carry them at `Metadata` level. A record that has none is matched by order, not by the nearest
time: it takes the earliest unclaimed watch event of the same action and object name that was seen
after the request was received and no more than 20 seconds after it completed, and a watch event
takes the earliest completed unclaimed record the same way. The clocks of the API server and of the
watcher only bound that window, so a clock difference of seconds between nodes does not swap two
changes. What stays unknown here is whether a request changed anything: a repeated apply shortly
before someone else's change of the same object can take that change. The policy, or
`RequestResponse` level, removes this.

The log only adds to an event. A rule fires from the webhook or watch event as soon as it arrives,
without waiting for the log; the user, source IP and client are added to the event and to its
violation when the record comes, and the user in an alert that has already fired is replaced with
the real one. An alert delivered to an external receiver before that keeps the text it was sent
with. Alert Log shows the user and the action in separate columns; alerts from other sources have
no user. Only rules that need what the log alone provides wait for it: a
source IP condition, an allowed or denied result, a people-only rule on an event whose user is not
known yet, and read actions.

Without the log neither can be resolved: the event shows the impersonated account, and a webhook
configuration change shows `unknown`.

### Where the request came from

The API server records a list of addresses for a request: first whatever the `X-Forwarded-For` and
`X-Real-Ip` headers contained, then the address of the connection itself. Only the last one is
observed by the API server; the others can be set by the client. A rule such as "not from the office
network" must not be passable by sending `X-Forwarded-For: <an office address>`, so the source IP of
an event, of its violation and of its alert, and the one source IP rules compare, is the last address
in the list. The whole list stays in the event as `sourceIPs` and is shown as **Reported chain**; the
address in use is stored as `clientIP`.

When requests reach the API server through a load balancer or proxy, the last address is that
proxy. Kubernetes combines `X-Forwarded-For` and `X-Real-IP` into one list and does not preserve
which header supplied an address. A proxy that only adds `X-Forwarded-For` can still pass an
attacker's `X-Real-IP` through. Its address is used until forwarded addresses are explicitly enabled.

To use a reported client address, first verify that the proxy removes or overwrites client-supplied
`X-Real-IP` and builds `X-Forwarded-For` from the actual connection. Then list its addresses/CIDRs
in Settings, Integrations, **Kubernetes audit log**, **Trusted proxies in front of the API server**
and enable **Use forwarded client addresses**. Both the proxy list and this confirmation are stored
per cluster in `audit_trusted_proxies`. Existing configurations default to using the connection
address after an upgrade; the audit pipeline continues running without this confirmation.
With verified proxies, the list is read from the end: trusted hops are skipped and the first
untrusted address is the client. Networks covering every IPv4 or IPv6 address, including the
mapped IPv4 CIDR `::ffff:0:0/96`, are refused. The setting applies to new events within half a
minute; stored events are not rewritten.

For standalone API log events, `Audit-ID` remains correlation metadata. Clients can choose and
reuse that header, so deduplication uses a hash of the server's request timestamp and request
identity as well. Response stages and response object revisions do not change this identity:
replaying a record or changing between Metadata and RequestResponse does not duplicate the request.
No response body is required for these protections.

## sentry-audit roles and scaling

`SENTRY_ROLES` selects what a pod does: `webhook`, `logtail`, or both.

- The chart runs the webhook as a Deployment (`sentryAudit.replicaCount`, default 2) with a
  PodDisruptionBudget and spread across nodes. Replicas are stateless: they share one TLS secret, every
  replica answers admission requests, and rules are evaluated in kvisior.
- Watching webhook configurations is done by one replica at a time, chosen through the
  `sentry-audit-watcher` lease, so those events are not duplicated. When the watch reconnects, for
  example after an API server restart, every object is replayed with the revision it already had;
  that is not a change and produces no event.
- The log reader is a DaemonSet on control-plane nodes (`sentryAudit.auditLog.enabled`). Each API
  server writes its own file, so each node reads its own. It follows rotation and keeps its position in
  `sentryAudit.auditLog.stateDir` on the node, so a restart continues from the last HTTP acknowledgement. A failed push is kept
  in memory and retried with a growing pause of up to 30 seconds; the checkpoint advances only after
  kvisior commits the batch. After an outage or a restart the reader finishes the rotated file it
  stopped in and then reads every retained file rotated after it, oldest first, before the current
  one. Compressed backups are not read. Keep API-server log backups long enough to cover an outage;
  removed source bytes cannot be replayed. A record kvisior rejects for good (HTTP 400, 413, 422) is
  isolated, logged as `audit_record_rejected` and skipped, so one bad record does not stop the stream.
- For exec, attach and port-forward the reader takes the `ResponseStarted` record, written when the
  session opens, so source IP and IP rules do not wait for the session to end. A write that failed
  with a code other than 401 or 403 (404, 409, 422) is not stored as a standalone event.

```yaml
sentryAudit:
  replicaCount: 2
  auditLog:
    enabled: true
    path: /var/log/kubernetes/audit.log
```

### Connecting the log from the UI

Settings, Integrations, **Kubernetes audit log** does the same without a chart change, per cluster:

- The table lists every control-plane node. For each one sentry-audit reads the `kube-apiserver` pod
  in `kube-system` and reports whether `--audit-log-path` is set and where that file is on the node.
  With several API servers each node has its own row, its own reader pod and its own status.
- Leave the path empty to use what was found on each node; nodes with different paths are handled
  on their own. Enter a path to override it for all nodes. On k3s the API server is not a pod, so
  nothing is found and the path is entered by hand.
- **Test connection** in a node's row asks the reader on that node to open the file and read its
  last record. The answer appears as a notice for a few seconds: the path, its size and the age of
  the last record, or the reason it cannot be read. A node without a running reader answers at once.
- The switch starts and stops the reader. Until settings are saved here, the chart values above apply.

The setting is stored in `audit_log_settings`. kvisior has no rights in the cluster: the leading
sentry-audit replica pulls the setting every 30 seconds and rewrites the `sentry-audit-logtail`
DaemonSet (host directory mounts, the path variables, and a node selector that parks it when
reading is off). Its only extra right is `get` and `update` on that one DaemonSet by name. The
reader pods run under their own service account, `sentry-audit-logtail`, which has no rights.
A path must be absolute, without `..`, and inside a directory; the directory is mounted read-only.

### Enabling the API server audit log

kubeadm, in `/etc/kubernetes/manifests/kube-apiserver.yaml`:

```
--audit-policy-file=/etc/kubernetes/audit-policy.yaml
--audit-log-path=/var/log/kubernetes/audit.log
--audit-log-maxsize=100
--audit-log-maxbackup=10
```

with the policy file and the log directory mounted into the pod. `Metadata` level is enough; the event id
annotation is part of it. The optional `RequestResponse` rule above improves webhook-change attribution
without changing the requirements for other events.
k3s takes the same flags as `--kube-apiserver-arg`. Managed control planes
(EKS, GKE, AKS) do not expose the file; there kvisior works from the admission webhook alone.

## Audit rules

Rules live in the `audit_rules` table and are shared by every kvisior. A rule can be limited to named
clusters. The 31 built-in rules are created by migration `0013-audit-rules`; existing Audit policies
from Policy Management are converted into rules by the same migration, one rule per check.
A policy that cannot be converted (an unknown check, no checks, an unsupported severity) is left in
`runtime_policies`, is no longer evaluated, and is named in the migration log; the migration itself
continues. A disabled policy stays silent after conversion, and the built-in rule for a converted
check is switched off so one event does not produce two violations.

A rule matches on action (create, update, delete, exec, attach, portforward, get, list), resource,
namespace patterns and exclusions, object name, who (people or service accounts, named users, excluded
users), source IP (CIDR or `*` patterns, "only from" or "not from"), result (allowed or denied), and,
for exec, a command substring. Rules on reads, source IP, or final result need the API log. Admission approval is provisional;
allowed/denied rules wait for the API-server response.

- **Enabled**: a match is written to `audit_violations`, shown on Violations, Audit, and highlighted
  in Audit logs, Monitoring.
- **Alert**: a match is also written to the alert log and delivered through its integrations, either
  every time or after N matches within M minutes.

API: `GET/POST /api/audit/rules`, `PUT/PATCH/DELETE /api/audit/rules/{id}`,
`POST /api/audit/rules/restore`. Changes need the admin role. Every kvisior reloads rules within 15 seconds.

## The page

Audit logs has four tabs.

- **Monitoring** shows a bounded window of the newest events (100, 200 or 500), updated live while the
  page is open. Dangerous actions are highlighted. Search works inside the window.
- **Investigation** searches stored events by time range, user, namespace, action, resource, source
  IP and result, with a histogram and grouping by user or by object. Results show 50 or 100 rows per
  page in a fixed-height window. The browser holds at most 1000 rows at a time and fetches the next
  thousand when you page past them; the current thousand, the page and the query are kept in
  localStorage, so switching tabs or reloading returns to the same place. A new search, Clear or a
  different grouping discards them.
- **Rules** lists, adds, edits and deletes rules.
- **Silent** lists silences with the number of events each one hid.

## Silences

A silence hides noisy events from Monitoring and Investigation. It matches on any combination of
action, object (`resource/namespace/name`), user and source IP; Object and User accept `*`, Source IP
takes an address or a CIDR range. It lasts 1 hour, 8 hours, 24 hours, 7 days or until removed. Create
one in the Silent tab, or select an event and choose "Silence events like this".

A matching event is still stored in `audit_events`, and rules, violations and alerts work for it as
before. A copy goes to `audit_silenced_events`, and Monitoring, Investigation and their counts leave
it out; the Silent tab shows only how many events each silence hid and when the last one arrived. An event that matches only once the API log adds its source IP is silenced at that moment and
leaves the live window. Ending a silence stops it for new events and keeps what it hid; deleting it
returns those events to Monitoring and Investigation. Silences belong to the selected cluster; hidden
events follow audit retention.

API: `GET/POST /api/audit/silences`, `POST /api/audit/silences/{id}/end`,
`DELETE /api/audit/silences/{id}`, `GET /v1/audit/silenced?silence=&before=&limit=`. Changes need the
admin role. Schema `0017-audit-silences`.

## Retention

Audit events are kept for `ui.auditRetentionHours` (default 336, 14 days) in hourly partitions. Every
kvisior that shares the database, the hub included (`AUDIT_RETENTION_HOURS` in `hub.env`), must use the
same value: each instance drops partitions older than its own setting.

## Delivery and upgrades

Migration `0014-audit-delivery` adds a shared ingestion ledger, pending enrichment, per-event rule
claims, and threshold state. Deploy the rebuilt central-migrate image with the matching
`centralMigrate.schemaVersion` before the rebuilt kvisior image. The migration job keeps the
`0013-audit-rules` marker separately, so rerunning a later migration does not restore deleted rules.

Each event is processed in one PostgreSQL transaction, including violations, alerts, enrichment,
rule claims, and threshold updates. HTTP retries and multiple kvisior replicas share the same state.
An API-log record received before admission waits in the database for the admission event. After
five minutes without it, the record is stored as the event itself, and an admission event that
arrives later is merged into that row (see [`audit-delivery.md`](audit-delivery.md)). The merge looks for the admission event within one hour of the record's own
timestamp, so it touches two or three hourly partitions instead of the whole retention. An event
PostgreSQL cannot store is logged as `audit_event_rejected` and skipped; the rest of the batch is kept. Rule effects run once per event and rule; `each` alerts distinguish different
event IDs. Threshold windows use database processing time and are shared across replicas and restarts.
Processing state expires with audit retention; keep this setting consistent across kvisior replicas.

The numeric `/api/violations?since=` cursor uses one sequence for runtime and audit violations.
Existing audit violation IDs are renumbered once on upgrade; reset saved violation cursors when
upgrading. State changes and deletion continue to identify violations by fingerprint.

Database regression tests require a disposable database initialized by `central-migrate`:

```sh
AUDIT_TEST_DSN='postgres://.../audit_test' go test -race ./...
```

Run this in `central` and `kvisior`. Tests without this variable skip PostgreSQL scenarios.
The admission webhook's asynchronous forwarding queue still buffers in memory; the file-backed
logtail path provides replay while its source files remain available. On managed control planes
without accessible API logs, pod loss can still discard webhook events waiting in that queue.
