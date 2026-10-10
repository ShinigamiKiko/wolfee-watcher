{{- define "kvisior.namespace" -}}
{{- .Values.global.namespace | default .Release.Namespace -}}
{{- end -}}

{{- define "kvisior.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "kvisior.selectorLabels" -}}
app.kubernetes.io/name: {{ .app }}
app.kubernetes.io/component: {{ .app }}
{{- end -}}

{{- define "kvisior.image" -}}
{{ .repository }}:{{ .tag | default "latest" }}
{{- end -}}

{{- define "kvisior.serviceDSN" -}}
postgres://{{ .creds.user }}:{{ .creds.password }}@{{ include "kvisior.pgAppHost" .ctx }}:{{ include "kvisior.pgAppPort" .ctx }}/{{ .ctx.Values.postgres.database }}{{ include "kvisior.pgAppParams" .ctx }}
{{- end -}}

{{- define "kvisior.waitForSchema" -}}
{{- if .ctx.Values.centralMigrate.enabled -}}
- name: wait-for-schema
  image: "{{ .ctx.Values.postgres.image.repository }}:{{ .ctx.Values.postgres.image.tag }}"
  imagePullPolicy: {{ .ctx.Values.postgres.image.pullPolicy }}
  command: ["sh", "-c", "until psql \"$WAIT_DSN\" -tAc \"SELECT 1 FROM schema_migrations WHERE version = '$WAIT_SCHEMA_VERSION'\" 2>/dev/null | grep -q 1; do echo waiting-for-schema-$WAIT_SCHEMA_VERSION; sleep 2; done"]
  env:
    - name: WAIT_DSN
      value: {{ include "kvisior.directDSN" . | quote }}
    - name: WAIT_SCHEMA_VERSION
      value: {{ .ctx.Values.centralMigrate.schemaVersion | quote }}
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    runAsNonRoot: true
    runAsUser: 65534
    capabilities:
      drop: ["ALL"]
{{- end -}}
{{- end -}}

{{- define "kvisior.waitForDeps" -}}
{{- $ns := include "kvisior.namespace" . -}}
{{- $checks := list -}}
{{- $checks = append $checks (printf "until nc -z -w 3 %s %s; do echo waiting-for-postgres; sleep 2; done" (include "kvisior.pgDirectHost" .) (include "kvisior.pgDirectPort" .)) -}}
{{- if .Values.pgbouncer.enabled -}}{{- $checks = append $checks (printf "until nc -z -w 3 pgbouncer.%s.svc.cluster.local %v; do echo waiting-for-pgbouncer; sleep 2; done" $ns .Values.pgbouncer.port) -}}{{- end -}}
{{- if .Values.kafka.enabled -}}{{- $checks = append $checks (printf "until nc -z -w 3 kafka.%s.svc.cluster.local 9092; do echo waiting-for-kafka; sleep 2; done" $ns) -}}{{- end -}}
- name: wait-for-deps
  image: "{{ .Values.postgres.image.repository }}:{{ .Values.postgres.image.tag }}"
  imagePullPolicy: {{ .Values.postgres.image.pullPolicy }}
  command: ["sh", "-c", {{ join "; " $checks | quote }}]
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    runAsNonRoot: true
    runAsUser: 65534
    capabilities:
      drop: ["ALL"]
{{- end -}}

{{- define "kvisior.componentList" -}}
{{- $c := list
  "tracee-bridge|Tracee Bridge|deployment|tracee-bridge"
  "kvisior-ui|UI and API|deployment|kvisior-ui"
  "scanner-agent|Scanner Agent|deployment|scanner-agent"
  "tracee-ebpf|Tracee eBPF|daemonset|tracee"
  "kafka|Kafka|statefulset|kafka"
  "sensor|Sensor|deployment|sensor"
  (printf "sentry-audit|Sentry Audit|%s|sentry-audit" (ternary "statefulset" "deployment" .Values.sentryAudit.delivery.persistence.enabled))
  "sentry-audit-logtail|Audit Log Tail|daemonset|sentry-audit-logtail"
  "anomaly-detector|Anomaly Detector|deployment|anomaly-detector"
  "honey-operator|Honey Operator|deployment|honey-operator"
  "audit-runner|Audit Runner|deployment|audit-runner"
  "forensic-watcher|Forensic Watcher|daemonset|forensic-watcher"
  "cert-server|Cert Server|deployment|cert-server" -}}
{{- if .Values.auditDelivery.ingest.enabled }}{{ $c = append $c "kvisior-audit-ingest|Audit Ingest|deployment|kvisior-audit-ingest" }}{{ end }}
{{- if .Values.auditDelivery.processor.enabled }}{{ $c = append $c "kvisior-audit-processor|Audit Processor|deployment|kvisior-audit-processor" }}{{ end }}
{{- if .Values.postgres.enabled }}{{ $c = append $c "postgres|PostgreSQL|statefulset|postgres" }}{{ end }}
{{- join "," $c -}}
{{- end }}
