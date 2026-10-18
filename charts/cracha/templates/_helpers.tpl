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

{{/*
How the grant bundle's signature is verified, from broker.bundle: "" when no
bundle source is configured, else exactly one of "inline" (verifyKey, kept in
a Secret the chart makes), "secret" (existingSecret) or "kms" (kmsKey).
*/}}
{{- define "cracha.bundleKey" -}}
{{- $b := .Values.broker.bundle -}}
{{- $keys := list -}}
{{- if $b.verifyKey }}{{ $keys = append $keys "inline" }}{{ end -}}
{{- if $b.existingSecret }}{{ $keys = append $keys "secret" }}{{ end -}}
{{- if $b.kmsKey }}{{ $keys = append $keys "kms" }}{{ end -}}
{{- if not $b.source -}}
{{- if $keys }}{{ fail "broker.bundle.verifyKey, existingSecret and kmsKey need broker.bundle.source" }}{{ end -}}
{{- else if ne (len $keys) 1 -}}
{{- fail "broker.bundle.source needs exactly one of broker.bundle.verifyKey, broker.bundle.existingSecret or broker.bundle.kmsKey" -}}
{{- else -}}
{{ first $keys }}
{{- end -}}
{{- end -}}

{{/*
The directory of a local bundle source (broker.bundle.source local:<dir>),
or "" for S3 or no source. A local source needs broker.bundle.volume.
*/}}
{{- define "cracha.bundleDir" -}}
{{- $source := .Values.broker.bundle.source -}}
{{- if hasPrefix "local:" $source -}}
{{- $dir := trimPrefix "local:" $source -}}
{{- if not $dir }}{{ fail "broker.bundle.source local: needs a directory" }}{{ end -}}
{{- if not .Values.broker.bundle.volume }}{{ fail "a local broker.bundle.source needs broker.bundle.volume, the volume mounted at its directory" }}{{ end -}}
{{ $dir }}
{{- else if and $source (not (hasPrefix "s3://" $source)) -}}
{{- fail (printf "broker.bundle.source must be local:<dir> or s3://bucket[/prefix], not %q" $source) -}}
{{- end -}}
{{- end -}}

{{/*
The authorization backend of broker.authz, checked: "static" or "spicedb".
The SpiceDB knobs need the spicedb backend, which needs an endpoint and the
Secret holding its preshared key, and takes at most one of a CA and insecure.
*/}}
{{- define "cracha.authzBackend" -}}
{{- $a := .Values.broker.authz -}}
{{- $s := $a.spicedb -}}
{{- if not (has $a.backend (list "static" "spicedb")) -}}
{{- fail (printf "broker.authz.backend must be static or spicedb, not %q" $a.backend) -}}
{{- end -}}
{{- if eq $a.backend "static" -}}
{{- if or $s.endpoint $s.tokenSecret.name $s.ca $s.insecure -}}
{{- fail "broker.authz.spicedb needs broker.authz.backend spicedb" -}}
{{- end -}}
{{- else -}}
{{- if not $s.endpoint }}{{ fail "broker.authz.spicedb.endpoint is required with broker.authz.backend spicedb" }}{{ end -}}
{{- if not $s.tokenSecret.name }}{{ fail "broker.authz.spicedb.tokenSecret.name is required with broker.authz.backend spicedb: the Secret holding the preshared key" }}{{ end -}}
{{- if and $s.insecure $s.ca }}{{ fail "broker.authz.spicedb.insecure excludes broker.authz.spicedb.ca" }}{{ end -}}
{{- end -}}
{{ $a.backend }}
{{- end -}}

{{/*
A component's Workload API volume source (<component>.workloadAPI.volume):
the one of hostPath and csi that `type` names. Helm merges an install's
values into the defaults, so rendering the whole map would give a volume
that sets the default hostPath beside the csi source an install chose, which
the apiserver refuses; only the chosen source is rendered. Call with
(dict "component" "broker" "volume" .Values.broker.workloadAPI.volume).
*/}}
{{- define "cracha.workloadAPIVolumeSource" -}}
{{- $v := .volume -}}
{{- if not (has $v.type (list "hostPath" "csi")) -}}
{{- fail (printf "%s.workloadAPI.volume.type must be hostPath or csi, not %q" .component $v.type) -}}
{{- end -}}
{{- $source := index $v $v.type -}}
{{- if not $source -}}
{{- fail (printf "%s.workloadAPI.volume.%s is required with %s.workloadAPI.volume.type %s" .component $v.type .component $v.type) -}}
{{- end -}}
{{ $v.type }}:
  {{- toYaml $source | nindent 2 }}
{{- end -}}
