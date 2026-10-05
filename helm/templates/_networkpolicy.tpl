{{- define "kvisior.np.selector" -}}
matchExpressions:
  - key: app.kubernetes.io/name
    operator: In
    values:
      {{- toYaml . | nindent 6 }}
{{- end -}}

{{- define "kvisior.np.components" -}}
- anomaly-detector
- audit-runner
- ca-bootstrap
- central-migrate
- cert-server
- forensic-watcher
- honey-operator
- kafka
- kvisior-ui
- kvisior-audit-ingest
- kvisior-audit-processor
- pgbouncer
- postgres
- scanner-agent
- sensor
- sentry-audit
- sentry-audit-logtail
- tracee-bridge
{{- end -}}

{{- define "kvisior.np.postgresClients" -}}
- anomaly-detector
- central-migrate
- kvisior-ui
- kvisior-audit-ingest
- kvisior-audit-processor
- pgbouncer
- tracee-bridge
{{- end -}}

{{- define "kvisior.np.urlEgress" -}}
{{- $u := urlParse .url -}}
{{- $port := regexFind ":[0-9]+$" $u.host | trimPrefix ":" | default .port -}}
{{- if regexMatch "^[0-9]+(\\.[0-9]+){3}$" $u.hostname }}
- toCIDR:
    - {{ printf "%s/32" $u.hostname }}
{{- else if contains ":" $u.hostname }}
- toCIDR:
    - {{ printf "%s/128" $u.hostname | quote }}
{{- else }}
- toFQDNs:
    - matchName: {{ $u.hostname | quote }}
{{- end }}
  toPorts:
    - ports:
        - port: {{ $port | quote }}
          protocol: TCP
{{- end -}}

{{- define "kvisior.np.cilium" -}}
{{- if and (dig "cilium" "enabled" false .Values.networkPolicy) (.Capabilities.APIVersions.Has "cilium.io/v2/CiliumNetworkPolicy") -}}
true
{{- end -}}
{{- end -}}
