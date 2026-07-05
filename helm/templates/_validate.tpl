{{- if and (eq (.Values.global.internalPushSecret | default "") "") (not .Values.global.internalPushSecretSkipValidation) -}}
{{- fail "global.internalPushSecret is required: an empty value disables authentication on /internal/push/* endpoints. Set it via --set global.internalPushSecret=<random> or a secrets manager. For development only: --set global.internalPushSecretSkipValidation=true" -}}
{{- end -}}
