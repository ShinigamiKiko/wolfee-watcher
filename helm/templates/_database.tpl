{{- define "kvisior.pgDirectHost" -}}
{{- if .Values.postgres.external.enabled -}}
{{ .Values.postgres.external.host }}
{{- else -}}
postgres.{{ include "kvisior.namespace" . }}.svc.cluster.local
{{- end -}}
{{- end -}}

{{- define "kvisior.pgDirectPort" -}}
{{- if .Values.postgres.external.enabled -}}
{{ .Values.postgres.external.port }}
{{- else -}}
5432
{{- end -}}
{{- end -}}

{{- define "kvisior.pgSSLMode" -}}
{{- if .Values.postgres.external.enabled -}}
{{ .Values.postgres.external.sslMode }}
{{- else -}}
disable
{{- end -}}
{{- end -}}

{{- define "kvisior.pgAppHost" -}}
{{- if .Values.pgbouncer.enabled -}}
pgbouncer.{{ include "kvisior.namespace" . }}.svc.cluster.local
{{- else -}}
{{ include "kvisior.pgDirectHost" . }}
{{- end -}}
{{- end -}}

{{- define "kvisior.pgAppPort" -}}
{{- if .Values.pgbouncer.enabled -}}
{{ .Values.pgbouncer.port }}
{{- else -}}
{{ include "kvisior.pgDirectPort" . }}
{{- end -}}
{{- end -}}

{{- define "kvisior.pgAppParams" -}}
{{- if .Values.pgbouncer.enabled -}}
?sslmode=disable&default_query_exec_mode=exec
{{- else -}}
?sslmode={{ include "kvisior.pgSSLMode" . }}
{{- end -}}
{{- end -}}

{{- define "kvisior.directDSN" -}}
postgres://{{ .creds.user }}:{{ .creds.password }}@{{ include "kvisior.pgDirectHost" .ctx }}:{{ include "kvisior.pgDirectPort" .ctx }}/{{ .ctx.Values.postgres.database }}?sslmode={{ include "kvisior.pgSSLMode" .ctx }}
{{- end -}}

{{- define "kvisior.clusterEnv" -}}
- name: CLUSTER_ID
  value: {{ .Values.global.clusterId | quote }}
- name: POD_NAMESPACE
  valueFrom:
    fieldRef:
      fieldPath: metadata.namespace
{{- end -}}

{{- define "kvisior.advertiseURL" -}}
{{- if .Values.ui.advertiseURL -}}
{{ .Values.ui.advertiseURL }}
{{- else -}}
http://kvisior-ui.{{ include "kvisior.namespace" . }}.svc.cluster.local:{{ .Values.ui.servicePort }}
{{- end -}}
{{- end -}}
