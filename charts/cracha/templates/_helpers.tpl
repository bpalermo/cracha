{{/* Name used as the prefix of the chart's resources. */}}
{{- define "cracha.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 50 | trimSuffix "-" -}}
{{- end -}}

{{/* Labels common to every resource. */}}
{{- define "cracha.labels" -}}
app.kubernetes.io/name: {{ include "cracha.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{/*
Selector labels of one component. Call with (dict "root" . "component" "csi").
*/}}
{{- define "cracha.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cracha.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
An image reference: by digest when one is given, else by tag, else by the
chart's appVersion. Call with (dict "root" . "image" .Values.csi.image).
*/}}
{{- define "cracha.image" -}}
{{- if .image.digest -}}
{{ .image.repository }}@{{ .image.digest }}
{{- else -}}
{{ .image.repository }}:{{ .image.tag | default .root.Chart.AppVersion }}
{{- end -}}
{{- end -}}

{{/*
The security context of a container that only serves HTTPS: no root, no
capabilities, no writable filesystem.
*/}}
{{- define "cracha.restrictedSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
capabilities:
  drop:
    - ALL
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/* The log level of a component, checked. Call with the value. */}}
{{- define "cracha.logLevel" -}}
{{- if not (has . (list "debug" "info" "warn" "error")) -}}
{{- fail (printf "logLevel must be debug, info, warn or error, not %q" .) -}}
{{- end -}}
{{ . }}
{{- end -}}

{{/* The DNS name of a component's Service in the cluster. Call with (dict "root" . "component" "broker"). */}}
{{- define "cracha.serviceHost" -}}
{{ include "cracha.name" .root }}-{{ .component }}.{{ .root.Release.Namespace }}.svc
{{- end -}}

{{/* The URL the webhook points the pods' SDKs at. */}}
{{- define "cracha.brokerUrl" -}}
{{- if .Values.webhook.brokerUrl -}}
{{ .Values.webhook.brokerUrl }}
{{- else -}}
https://{{ include "cracha.serviceHost" (dict "root" . "component" "broker") }}:{{ .Values.broker.port }}
{{- end -}}
{{- end -}}

{{/* The Secret holding a component's certificate. Call with (dict "root" . "component" "broker"). */}}
{{- define "cracha.tlsSecret" -}}
{{- if eq .root.Values.tls.mode "existing" -}}
{{ required (printf "tls.existingSecrets.%s is required with tls.mode existing" .component) (index .root.Values.tls.existingSecrets .component) }}
{{- else -}}
{{ include "cracha.name" .root }}-{{ .component }}-tls
{{- end -}}
{{- end -}}

{{/* The TLS arguments of a component's container; the Secret is mounted at /etc/cracha/tls. */}}
{{- define "cracha.tlsArgs" -}}
- --tls-cert=/etc/cracha/tls/tls.crt
- --tls-key=/etc/cracha/tls/tls.key
{{- end -}}

{{/* The volume mount and volume of a component's certificate. Same arguments as cracha.tlsSecret. */}}
{{- define "cracha.tlsVolumeMount" -}}
- name: tls
  mountPath: /etc/cracha/tls
  readOnly: true
{{- end -}}

{{- define "cracha.tlsVolume" -}}
- name: tls
  secret:
    secretName: {{ include "cracha.tlsSecret" . }}
{{- end -}}

{{/*
The MutatingWebhookConfiguration (design 7.4). Call with
(dict "root" . "caBundle" <base64 PEM or ""> "annotations" <dict>): in the
generated mode tls.yaml renders it with the authority it just made, so the
two cannot disagree; the other modes render it from
webhook-configuration.yaml.
*/}}
{{- define "cracha.webhookConfiguration" -}}
{{- $root := .root -}}
{{- $excluded := list $root.Release.Namespace "kube-system" -}}
{{- range $ns := $root.Values.webhook.excludedNamespaces -}}
{{- if not (has $ns $excluded) }}{{ $excluded = append $excluded $ns }}{{ end -}}
{{- end -}}
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: {{ include "cracha.name" $root }}-webhook
  labels:
    {{- include "cracha.labels" $root | nindent 4 }}
    app.kubernetes.io/component: webhook
  {{- with .annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
webhooks:
  - name: pods.cracha.dev
    admissionReviewVersions: [v1]
    sideEffects: None
    # A pod must never be admitted unwired because the webhook was
    # unreachable.
    failurePolicy: Fail
    timeoutSeconds: {{ $root.Values.webhook.timeoutSeconds }}
    clientConfig:
      service:
        name: {{ include "cracha.name" $root }}-webhook
        namespace: {{ $root.Release.Namespace }}
        path: /mutate
        port: 443
      {{- with .caBundle }}
      caBundle: {{ . }}
      {{- end }}
    rules:
      - apiGroups: [""]
        apiVersions: [v1]
        operations: [CREATE]
        resources: [pods]
    # The release's own namespace is left out: a pod of the webhook's own
    # namespace must not depend on the webhook to start. kube-system runs
    # nothing the broker serves.
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values:
            {{- range $excluded }}
            - {{ . }}
            {{- end }}
{{- end -}}
