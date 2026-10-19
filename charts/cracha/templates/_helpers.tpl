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
Selector labels of one component. Call with (dict "root" . "component" "agent").
*/}}
{{- define "cracha.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cracha.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
An image reference: by digest when one is given, else by tag, else by the
chart's appVersion. Call with (dict "root" . "image" .Values.agent.image).
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
The SpiceDB knobs need the spicedb backend; with it, the endpoint is the
chart's own SpiceDB gateway (spicedb.enabled) unless one is given, and an
install that turns the chart's SpiceDB off must give one.
*/}}
{{- define "cracha.authzBackend" -}}
{{- $a := .Values.broker.authz -}}
{{- $s := $a.spicedb -}}
{{- if not (has $a.backend (list "static" "spicedb")) -}}
{{- fail (printf "broker.authz.backend must be static or spicedb, not %q" $a.backend) -}}
{{- end -}}
{{- if eq $a.backend "static" -}}
{{- if or $s.endpoint $s.serverSpiffeID -}}
{{- fail "broker.authz.spicedb needs broker.authz.backend spicedb" -}}
{{- end -}}
{{- else if and (not .Values.spicedb.enabled) (not $s.endpoint) -}}
{{- fail "broker.authz.spicedb.endpoint is required with broker.authz.backend spicedb and spicedb.enabled false: the SpiceDB gateway the broker reaches" -}}
{{- end -}}
{{ $a.backend }}
{{- end -}}

{{/* Whether the chart deploys SpiceDB and its gateway: spicedb.enabled with the spicedb backend. */}}
{{- define "cracha.spicedbEnabled" -}}
{{- if and (eq (include "cracha.authzBackend" .) "spicedb") .Values.spicedb.enabled -}}
true
{{- end -}}
{{- end -}}

{{/* The SpiceDB gateway the broker dials: broker.authz.spicedb.endpoint, or the chart's own. */}}
{{- define "cracha.spicedbEndpoint" -}}
{{- if .Values.broker.authz.spicedb.endpoint -}}
{{ .Values.broker.authz.spicedb.endpoint }}
{{- else -}}
{{ include "cracha.serviceHost" (dict "root" . "component" "spicedb") }}:{{ .Values.spicedb.gateway.port }}
{{- end -}}
{{- end -}}

{{/*
The SPIFFE ID the broker verifies the SpiceDB gateway by:
broker.authz.spicedb.serverSpiffeID, or the path of the chart's SpiceDB
ServiceAccount, which the broker completes in its own trust domain.
*/}}
{{- define "cracha.spicedbServerSpiffeID" -}}
{{- if .Values.broker.authz.spicedb.serverSpiffeID -}}
{{ .Values.broker.authz.spicedb.serverSpiffeID }}
{{- else -}}
/ns/{{ .Release.Namespace }}/sa/{{ include "cracha.name" . }}-spicedb
{{- end -}}
{{- end -}}

{{/*
The SPIFFE ID the gateway admits for one of its clients (spicedb.gateway.
identities.<client>), or by default the client's ServiceAccount in the
release's namespace and spicedb.gateway.trustDomain. Call with
(dict "root" . "client" "broker").
*/}}
{{- define "cracha.gatewayIdentity" -}}
{{- $id := index .root.Values.spicedb.gateway.identities .client -}}
{{- if $id -}}
{{- if not (hasPrefix "spiffe://" $id) }}{{ fail (printf "spicedb.gateway.identities.%s must be a SPIFFE ID, not %q" .client $id) }}{{ end -}}
{{ $id }}
{{- else -}}
spiffe://{{ required "spicedb.gateway.trustDomain is required with the chart's SpiceDB: the trust domain of the gateway's clients" .root.Values.spicedb.gateway.trustDomain }}/ns/{{ .root.Release.Namespace }}/sa/{{ include "cracha.name" .root }}-{{ .client }}
{{- end -}}
{{- end -}}

{{/*
SpiceDB's datastore engine (spicedb.datastore.engine), checked: memory
(development and kind only, one replica, everything lost on restart),
mysql or postgres, which need the connection URI's Secret.
*/}}
{{- define "cracha.spicedbEngine" -}}
{{- $d := .Values.spicedb.datastore -}}
{{- if not (has $d.engine (list "memory" "mysql" "postgres")) -}}
{{- fail (printf "spicedb.datastore.engine must be memory, mysql or postgres, not %q" $d.engine) -}}
{{- end -}}
{{- if eq $d.engine "memory" -}}
{{- if gt (int .Values.spicedb.replicas) 1 }}{{ fail "spicedb.datastore.engine memory holds the relationships in each pod: spicedb.replicas must be 1" }}{{ end -}}
{{- if or $d.uriSecret.name $d.caSecret.name $d.clientCertSecret.name }}{{ fail "spicedb.datastore's Secrets need engine mysql or postgres" }}{{ end -}}
{{- else -}}
{{- if not $d.uriSecret.name }}{{ fail (printf "spicedb.datastore.uriSecret.name is required with engine %s: the Secret holding the connection URI" $d.engine) }}{{ end -}}
{{- if and $d.clientCertSecret.name (ne $d.engine "postgres") }}{{ fail "spicedb.datastore.clientCertSecret needs engine postgres" }}{{ end -}}
{{- end -}}
{{- if $d.spiffe.enabled -}}
{{- if ne $d.engine "mysql" }}{{ fail "spicedb.datastore.spiffe needs engine mysql" }}{{ end -}}
{{- if not $d.spiffe.serverID }}{{ fail "spicedb.datastore.spiffe.serverID is required with spicedb.datastore.spiffe.enabled: the SPIFFE ID, or trust domain, the datastore server presents" }}{{ end -}}
{{- if $d.caSecret.name }}{{ fail "spicedb.datastore.caSecret and spicedb.datastore.spiffe exclude each other: with spiffe the server is verified against the Workload API's bundle" }}{{ end -}}
{{- range $k, $v := (dict "serverID" $d.spiffe.serverID "id" $d.spiffe.id "migrationID" $d.spiffe.migrationID) }}
{{- if and $v (not (hasPrefix "spiffe://" $v)) }}{{ fail (printf "spicedb.datastore.spiffe.%s must be a SPIFFE ID, spiffe://..., not %q" $k $v) }}{{ end -}}
{{- end -}}
{{- end -}}
{{ $d.engine }}
{{- end -}}

{{/*
The SPIFFE ID a SpiceDB container presents to the datastore with
spicedb.datastore.spiffe: the value given, or the path of its
ServiceAccount in spicedb.gateway.trustDomain. Call with (dict "root" .
"id" <value> "serviceAccount" <name>).
*/}}
{{- define "cracha.spicedbDatastoreSpiffeID" -}}
{{- if .id -}}
{{ .id }}
{{- else -}}
{{- $td := .root.Values.spicedb.gateway.trustDomain -}}
{{- if not $td }}{{ fail "spicedb.gateway.trustDomain is required with spicedb.datastore.spiffe and no spicedb.datastore.spiffe.id" }}{{ end -}}
spiffe://{{ $td }}/ns/{{ .root.Release.Namespace }}/sa/{{ .serviceAccount }}
{{- end -}}
{{- end -}}

{{/*
The arguments of SpiceDB's SPIFFE datastore identity (serve and migrate),
nothing without spicedb.datastore.spiffe. Call with (dict "root" . "id"
<the SPIFFE ID to present>).
*/}}
{{- define "cracha.spicedbDatastoreSpiffeArgs" -}}
{{- $s := .root.Values.spicedb -}}
{{- if $s.datastore.spiffe.enabled -}}
- --datastore-spiffe
- --datastore-spiffe-socket=unix:///spiffe-workload-api/{{ $s.workloadAPI.socket }}
- --datastore-spiffe-id={{ .id }}
- --datastore-spiffe-server-id={{ $s.datastore.spiffe.serverID }}
{{- end -}}
{{- end -}}

{{/*
Where the static backend's assignments come from, from
broker.assignments.source, checked: "file" (the document or an existing
ConfigMap, mounted and read once) or "published" (the assignments of the
version broker.bundle.source serves, verified and swapped with its bundle;
nothing is mounted). "" for the spicedb backend, which takes only the default.
*/}}
{{- define "cracha.assignmentsSource" -}}
{{- $source := .Values.broker.assignments.source | default "file" -}}
{{- if not (has $source (list "file" "published")) -}}
{{- fail (printf "broker.assignments.source must be file or published, not %q" $source) -}}
{{- end -}}
{{- if eq (include "cracha.authzBackend" .) "spicedb" -}}
{{- if eq $source "published" }}{{ fail "broker.assignments.source published needs broker.authz.backend static" }}{{ end -}}
{{- else -}}
{{- if and (eq $source "published") (not .Values.broker.bundle.source) -}}
{{- fail "broker.assignments.source published needs broker.bundle.source: the assignments come from the publication the bundle does" -}}
{{- end -}}
{{ $source }}
{{- end -}}
{{- end -}}

{{/*
The PEM of the bundle's verification keys (broker.bundle.verifyKey): a
string of one or more PUBLIC KEY blocks, or a list of them, joined.
*/}}
{{- define "cracha.bundleVerifyKey" -}}
{{- $k := .Values.broker.bundle.verifyKey -}}
{{- if kindIs "slice" $k -}}
{{- range $k }}{{ trim . }}
{{ end -}}
{{- else -}}
{{ $k }}
{{- end -}}
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

{{/* The agent's enrolment mode (design 7.2), checked: init or cni. */}}
{{- define "cracha.agentEnrol" -}}
{{- if not (has .Values.agent.enrol (list "init" "cni")) -}}
{{- fail (printf "agent.enrol must be init or cni, not %q" .Values.agent.enrol) -}}
{{- end -}}
{{ .Values.agent.enrol }}
{{- end -}}

{{/* The broker URL the agent calls (design 7.3): agent.brokerUrl, or the broker Service of this release. */}}
{{- define "cracha.agentBrokerUrl" -}}
{{- if .Values.agent.brokerUrl -}}
{{ .Values.agent.brokerUrl }}
{{- else -}}
https://{{ include "cracha.serviceHost" (dict "root" . "component" "broker") }}:{{ .Values.broker.port }}
{{- end -}}
{{- end -}}

{{/*
The SPIFFE ID the agent verifies the broker by (design 7.3):
agent.brokerSpiffeID, or the path of the broker's ServiceAccount in the
agent's own trust domain, which the agent completes from its SVID.
*/}}
{{- define "cracha.agentBrokerSpiffeID" -}}
{{- if .Values.agent.brokerSpiffeID -}}
{{ .Values.agent.brokerSpiffeID }}
{{- else -}}
/ns/{{ .Release.Namespace }}/sa/{{ include "cracha.name" . }}-broker
{{- end -}}
{{- end -}}

{{/*
A Go duration of whole seconds ("5s", "1m", "1m30s") as a number of seconds,
for the fields Kubernetes counts in seconds. Anything else fails the render.
*/}}
{{- define "cracha.seconds" -}}
{{- $d := toString . -}}
{{- if or (eq $d "") (not (regexMatch "^([0-9]+h)?([0-9]+m)?([0-9]+s)?$" $d)) -}}
{{- fail (printf "%q is not a duration of whole seconds, such as 5s or 1m30s" $d) -}}
{{- end -}}
{{- $h := regexFind "[0-9]+h" $d | trimSuffix "h" | int -}}
{{- $m := regexFind "[0-9]+m" $d | trimSuffix "m" | int -}}
{{- $s := regexFind "[0-9]+s" $d | trimSuffix "s" | int -}}
{{ add (mul $h 3600) (mul $m 60) $s }}
{{- end -}}

{{/*
The environment SpiceDB's containers (serve and migrate) reach the
datastore with: the connection URI from its Secret and, with a CA Secret,
SSL_CERT_FILE naming the mounted authority. Nothing for the memory engine.
*/}}
{{- define "cracha.spicedbDatastoreEnv" -}}
{{- $d := .Values.spicedb.datastore -}}
{{- if ne (include "cracha.spicedbEngine" .) "memory" -}}
- name: SPICEDB_DATASTORE_CONN_URI
  valueFrom:
    secretKeyRef:
      name: {{ $d.uriSecret.name }}
      key: {{ $d.uriSecret.key }}
{{- if $d.caSecret.name }}
# The datastore server's authority, in place of the system roots, so that
# tls=true (mysql) or sslmode=verify-full (postgres) verifies a private root.
- name: SSL_CERT_FILE
  value: /etc/spicedb/datastore-ca/{{ $d.caSecret.key }}
{{- end }}
{{- end -}}
{{- end -}}

{{/* The datastore's CA and client certificate mounts, if any. */}}
{{- define "cracha.spicedbDatastoreMounts" -}}
{{- $d := .Values.spicedb.datastore -}}
{{- if $d.caSecret.name }}
- name: datastore-ca
  mountPath: /etc/spicedb/datastore-ca
  readOnly: true
{{- end }}
{{- if $d.clientCertSecret.name }}
- name: datastore-client
  mountPath: /etc/spicedb/datastore-client
  readOnly: true
{{- end }}
{{- end -}}

{{/* The datastore's CA and client certificate volumes, if any. */}}
{{- define "cracha.spicedbDatastoreVolumes" -}}
{{- $d := .Values.spicedb.datastore -}}
{{- if $d.caSecret.name }}
- name: datastore-ca
  secret:
    secretName: {{ $d.caSecret.name }}
    items:
      - key: {{ $d.caSecret.key }}
        path: {{ $d.caSecret.key }}
{{- end }}
{{- if $d.clientCertSecret.name }}
- name: datastore-client
  secret:
    secretName: {{ $d.clientCertSecret.name }}
    defaultMode: 0400
    items:
      - key: {{ $d.clientCertSecret.certKey }}
        path: tls.crt
      - key: {{ $d.clientCertSecret.keyKey }}
        path: tls.key
{{- end }}
{{- end -}}
