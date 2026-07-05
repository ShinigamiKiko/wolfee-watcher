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
{{- $ns := include "kvisior.namespace" .ctx -}}
postgres://{{ .creds.user }}:{{ .creds.password }}@postgres.{{ $ns }}.svc.cluster.local:5432/{{ .ctx.Values.postgres.database }}?sslmode=disable
{{- end -}}

{{- define "kvisior.waitForSchema" -}}
{{- if .ctx.Values.postgres.enabled -}}
- name: wait-for-schema
  image: "{{ .ctx.Values.postgres.image.repository }}:{{ .ctx.Values.postgres.image.tag }}"
  imagePullPolicy: {{ .ctx.Values.postgres.image.pullPolicy }}
  command: ["sh", "-c", "until psql \"$WAIT_DSN\" -tAc \"SELECT 1 FROM schema_migrations WHERE version = '$WAIT_SCHEMA_VERSION'\" 2>/dev/null | grep -q 1; do echo waiting-for-schema-$WAIT_SCHEMA_VERSION; sleep 2; done"]
  env:
    - name: WAIT_DSN
      value: {{ include "kvisior.serviceDSN" . | quote }}
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
{{- if .Values.postgres.enabled -}}{{- $checks = append $checks (printf "until nc -z -w 3 postgres.%s.svc.cluster.local 5432; do echo waiting-for-postgres; sleep 2; done" $ns) -}}{{- end -}}
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
