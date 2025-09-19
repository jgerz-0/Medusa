{{- define "medusa.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "medusa.fullname" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "medusa.labels" -}}
app.kubernetes.io/name: {{ include "medusa.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: {{ .Values.component | default "core" }}
{{- end -}}

{{- define "medusa.selectorLabels" -}}
app.kubernetes.io/name: {{ include "medusa.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: {{ .Values.component | default "core" }}
{{- end -}}

{{- define "medusa.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "medusa.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "medusa.secrets.checksum" -}}
{{- if eq .Values.secrets.strategy "inline" -}}
{{ toYaml .Values.secrets.inline }}
{{- else if eq .Values.secrets.strategy "externalSecret" -}}
{{ toYaml .Values.secrets.externalSecret }}
{{- else if eq .Values.secrets.strategy "sealedSecret" -}}
{{ toYaml .Values.secrets.sealedSecret }}
{{- else -}}
{}
{{- end -}}
{{- end -}}
