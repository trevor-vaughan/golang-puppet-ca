{{/*
Chart name, overridable, truncated to the 63-char label limit.
*/}}
{{- define "openvox-ca.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name. Release names that already contain the chart name are
not doubled up, so `helm install openvox-ca` yields "openvox-ca" rather than
"openvox-ca-openvox-ca".
*/}}
{{- define "openvox-ca.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "openvox-ca.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "openvox-ca.namespace" -}}
{{- default .Release.Namespace .Values.namespaceOverride -}}
{{- end -}}

{{- define "openvox-ca.selectorLabels" -}}
app.kubernetes.io/name: {{ include "openvox-ca.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "openvox-ca.labels" -}}
helm.sh/chart: {{ include "openvox-ca.chart" . }}
{{ include "openvox-ca.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: certificate-authority
app.kubernetes.io/part-of: openvox
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "openvox-ca.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "openvox-ca.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Container image reference.

A digest wins over a tag. An explicit tag is used verbatim — that is how you
select the CentOS Stream variant, whose tags carry no suffix. With neither set,
the default is the Alpine variant of the chart's appVersion; a -dev appVersion
means the chart was built from an unreleased tree, whose published image is the
rolling "edge" tag rather than a version that exists in the registry.
*/}}
{{- define "openvox-ca.image" -}}
{{- $ref := .Values.image.repository -}}
{{- if .Values.image.registry -}}
{{- $ref = printf "%s/%s" .Values.image.registry .Values.image.repository -}}
{{- end -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" $ref .Values.image.digest -}}
{{- else -}}
{{- $tag := .Values.image.tag -}}
{{- if not $tag -}}
{{- $base := .Chart.AppVersion -}}
{{- if hasSuffix "-dev" $base -}}
{{- $base = "edge" -}}
{{- end -}}
{{- $tag = printf "%s-alpine" $base -}}
{{- end -}}
{{- printf "%s:%s" $ref $tag -}}
{{- end -}}
{{- end -}}

{{/*
Name of the ConfigMap holding config.yaml and its companion files.
*/}}
{{- define "openvox-ca.configMapName" -}}
{{- default (include "openvox-ca.fullname" .) .Values.existingConfigMap -}}
{{- end -}}

{{- define "openvox-ca.pvcName" -}}
{{- default (include "openvox-ca.fullname" .) .Values.persistence.existingClaim -}}
{{- end -}}

{{/*
Paths of the files the chart renders into the config ConfigMap.
*/}}
{{- define "openvox-ca.puppetServerFilePath" -}}
{{- printf "%s/puppet-server" (trimSuffix "/" .Values.configMount) -}}
{{- end -}}

{{- define "openvox-ca.autosignFilePath" -}}
{{- printf "%s/autosign.conf" (trimSuffix "/" .Values.configMount) -}}
{{- end -}}

{{- define "openvox-ca.configFilePath" -}}
{{- printf "%s/config.yaml" (trimSuffix "/" .Values.configMount) -}}
{{- end -}}

{{/*
The server's config.yaml.

Starts from what the chart's convenience blocks imply — cadir, listen address,
mounted TLS/CA paths, the metrics listener, the export targets — then merges
.Values.config over the top, so an explicit config key always wins.
*/}}
{{- define "openvox-ca.config" -}}
{{- $c := dict -}}
{{- $_ := set $c "cadir" .Values.persistence.mountPath -}}
{{- $_ := set $c "host" .Values.listen.host -}}
{{- $_ := set $c "port" (.Values.listen.port | int) -}}
{{/*
  verbosity goes through the config file rather than a --verbosity flag: a
  flag would outrank the file unconditionally, which would make
  config.verbosity silently ineffective and break the chart's "config always
  wins" contract for that one key.
*/}}
{{- $_ := set $c "verbosity" (.Values.verbosity | int) -}}
{{- if .Values.tls.existingSecret -}}
{{- $_ := set $c "tls_cert" (printf "%s/%s" (trimSuffix "/" .Values.tls.mountPath) .Values.tls.certKey) -}}
{{- $_ := set $c "tls_key" (printf "%s/%s" (trimSuffix "/" .Values.tls.mountPath) .Values.tls.keyKey) -}}
{{- end -}}
{{- if .Values.ca.existingSecret -}}
{{- $_ := set $c "ca_cert_file" (printf "%s/%s" (trimSuffix "/" .Values.ca.mountPath) .Values.ca.certKey) -}}
{{- $_ := set $c "ca_key_file" (printf "%s/%s" (trimSuffix "/" .Values.ca.mountPath) .Values.ca.keyKey) -}}
{{- end -}}
{{- if .Values.caKeyPassphrase.existingSecret -}}
{{- $_ := set $c "encrypt_ca_key" true -}}
{{- $_ := set $c "ca_key_passphrase_file" (printf "%s/%s" (trimSuffix "/" .Values.caKeyPassphrase.mountPath) .Values.caKeyPassphrase.key) -}}
{{- end -}}
{{- if .Values.puppetServers -}}
{{- $_ := set $c "puppet_server_file" (include "openvox-ca.puppetServerFilePath" .) -}}
{{- end -}}
{{- if .Values.autosign.patterns -}}
{{- $_ := set $c "autosign_config" (include "openvox-ca.autosignFilePath" .) -}}
{{- else if .Values.autosign.mode -}}
{{- $_ := set $c "autosign_config" (.Values.autosign.mode | toString) -}}
{{- end -}}
{{- if .Values.metrics.enabled -}}
{{- $_ := set $c "metrics_listen" (printf "%s:%v" .Values.metrics.host .Values.metrics.port) -}}
{{- end -}}
{{- if .Values.kubernetesExport.enabled -}}
{{- $ke := dict "targets" .Values.kubernetesExport.targets -}}
{{- if .Values.kubernetesExport.fieldManager -}}
{{- $_ := set $ke "field_manager" .Values.kubernetesExport.fieldManager -}}
{{- end -}}
{{- $_ := set $c "kubernetes_export" $ke -}}
{{- end -}}
{{- toYaml (mergeOverwrite $c (deepCopy .Values.config)) -}}
{{- end -}}

{{/*
The rendered contents of the config ConfigMap, as a filename -> body map. Used
both by the ConfigMap itself and by the pod-template checksum annotation.
*/}}
{{- define "openvox-ca.configMapData" -}}
config.yaml: |
{{ include "openvox-ca.config" . | indent 2 }}
{{- if .Values.puppetServers }}
puppet-server: |
{{- range .Values.puppetServers }}
  {{ . }}
{{- end }}
{{- end }}
{{- if .Values.autosign.patterns }}
autosign.conf: |
{{- range .Values.autosign.patterns }}
  {{ . }}
{{- end }}
{{- end }}
{{- range $name, $body := .Values.extraConfigFiles }}
{{ $name }}: |
{{ $body | trimSuffix "\n" | indent 2 }}
{{- end }}
{{- end -}}

{{/*
Whether the pod needs to talk to the Kubernetes API: for the export feature, or
for OpenBao's native Kubernetes auth (which reads the projected SA token).
*/}}
{{- define "openvox-ca.needsAPIAccess" -}}
{{- if .Values.kubernetesExport.enabled -}}
true
{{- else if eq (dig "openbao" "auth_method" "" .Values.config) "kubernetes" -}}
true
{{- else -}}
false
{{- end -}}
{{- end -}}

{{/*
automountServiceAccountToken: honour an explicit value, otherwise mount the
token only when something actually needs it.
*/}}
{{- define "openvox-ca.automountServiceAccountToken" -}}
{{- if kindIs "bool" .Values.automountServiceAccountToken -}}
{{- .Values.automountServiceAccountToken -}}
{{- else -}}
{{- include "openvox-ca.needsAPIAccess" . -}}
{{- end -}}
{{- end -}}

{{/*
Whether the chart can see the server's whole configuration.

It cannot when the config file is somebody else's (existingConfigMap), when
argv has been replaced outright (args), or when settings arrive from a
ConfigMap or Secret the chart never reads (envFrom) — each of those layers
outranks or replaces what the chart renders. Where the answer is "no", the
chart says so rather than asserting: it neither refuses an install it cannot
judge nor claims to know which scheme the probes should use.
*/}}
{{- define "openvox-ca.configFullyKnown" -}}
{{- if or .Values.existingConfigMap .Values.args .Values.envFrom -}}
false
{{- else -}}
true
{{- end -}}
{{- end -}}

{{/*
Whether the server will serve HTTPS.

It does so by either route: a certificate and key both configured, or
tls_self_provision, where the CA issues its own. Either counts, on any layer.
The config file is the one the chart renders; environment variables outrank it,
so PUPPET_CA_TLS_CERT/KEY and PUPPET_CA_TLS_SELF_PROVISION set through env or
extraEnv count too — the first pair is how someone feeds certificate paths in
from a Secret, and missing the third would render HTTP probes against an HTTPS
listener and fail openvox-ca.validate on a correct install.

When the configuration is not fully known this answers "true": HTTPS is the
normal case, and it is the answer that neither blocks a correct install nor
makes the probes fail on one.
*/}}
{{- define "openvox-ca.tlsConfigured" -}}
{{- if ne (include "openvox-ca.configFullyKnown" .) "true" -}}
true
{{- else -}}
{{- if eq (include "openvox-ca.selfProvisionEnabled" .) "true" -}}
true
{{- else -}}
{{- $config := include "openvox-ca.config" . | fromYaml -}}
{{- $cert := dig "tls_cert" "" $config -}}
{{- $key := dig "tls_key" "" $config -}}
{{- range $name, $value := .Values.env -}}
{{- if eq $name "PUPPET_CA_TLS_CERT" }}{{ $cert = $value }}{{ end -}}
{{- if eq $name "PUPPET_CA_TLS_KEY" }}{{ $key = $value }}{{ end -}}
{{- end -}}
{{- range .Values.extraEnv -}}
{{- if eq .name "PUPPET_CA_TLS_CERT" }}{{ $cert = "set" }}{{ end -}}
{{- if eq .name "PUPPET_CA_TLS_KEY" }}{{ $key = "set" }}{{ end -}}
{{- end -}}
{{- if and $cert $key -}}
true
{{- else -}}
false
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Whether the CA issues its own serving certificate.

Read from the merged config and from both environment layers, for the same
reason tlsConfigured reads them: an operator setting this by environment
variable must not get a chart that renders as though TLS were off.
*/}}
{{- define "openvox-ca.selfProvisionEnabled" -}}
{{- $config := include "openvox-ca.config" . | fromYaml -}}
{{- $on := dig "tls_self_provision" false $config -}}
{{- range $name, $value := .Values.env -}}
{{- if eq $name "PUPPET_CA_TLS_SELF_PROVISION" }}{{ $on = $value }}{{ end -}}
{{- end -}}
{{- range .Values.extraEnv -}}
{{- if eq .name "PUPPET_CA_TLS_SELF_PROVISION" }}{{ $on = .value }}{{ end -}}
{{- end -}}
{{- if kindIs "string" $on -}}
{{- if or (eq (lower $on) "true") (eq $on "1") -}}true{{- else -}}false{{- end -}}
{{- else -}}
{{- ternary "true" "false" (not (not $on)) -}}
{{- end -}}
{{- end -}}

{{/*
Scheme for the HTTP probes. The kubelet has to speak whatever the server
speaks, and without TLS the server serves cleartext.
*/}}
{{- define "openvox-ca.probeScheme" -}}
{{- if eq (include "openvox-ca.tlsConfigured" .) "true" -}}HTTPS{{- else -}}HTTP{{- end -}}
{{- end -}}

{{/*
One probe, with the scheme filled in when the operator has not chosen one. The
"enabled" key is a chart concept and never belongs in the emitted spec.
*/}}
{{- define "openvox-ca.probe" -}}
{{- $probe := omit .probe "enabled" -}}
{{- if and $probe.httpGet (not $probe.httpGet.scheme) -}}
{{- $httpGet := merge (dict "scheme" (include "openvox-ca.probeScheme" .root)) (deepCopy $probe.httpGet) -}}
{{- $probe = merge (dict "httpGet" $httpGet) (omit $probe "httpGet") -}}
{{- end -}}
{{- toYaml $probe -}}
{{- end -}}

{{/*
Preconditions, checked once from the Deployment so that every one of them
fails at `helm install` time with an explanation, rather than at runtime with a
CrashLoopBackOff or a Service that silently routes nowhere.
*/}}
{{- define "openvox-ca.validate" -}}
{{- $config := include "openvox-ca.config" . | fromYaml -}}

{{/*
  The server refuses to serve plain HTTP on a non-loopback address, because an
  on-path host could then inject forged certificates. Reproduce its condition
  so the operator is told at install time, with the same remedies, instead of
  watching the pod crash-loop.

  Only checked when the chart can see the whole configuration: a guard that
  fires on a configuration it cannot read is worse than no guard at all.

  The loopback forms are exactly the ones that work end to end. The server
  tests net.ParseIP(host).IsLoopback() or host == "localhost"
  (cmd/openvox-ca/main.go), which rejects the bracketed "[::1]"; and it builds
  its listen address as host + ":" + port, which turns a bare "::1" into the
  unparseable "::1:8140". That leaves 127.0.0.0/8 and localhost. Note that
  "[::]" — the chart's documented dual-stack spelling — is not loopback and
  correctly does not qualify.
*/}}
{{- if eq (include "openvox-ca.configFullyKnown" .) "true" -}}
{{- $host := dig "host" "" $config | toString -}}
{{- $loopback := or (hasPrefix "127." $host) (eq $host "localhost") -}}
{{- if and (ne (include "openvox-ca.tlsConfigured" .) "true") (not (dig "no_tls_required" false $config)) (not $loopback) -}}
{{- fail (printf "openvox-ca will refuse to start: no server TLS certificate is configured and the listen address (%s) is not loopback, which the server rejects as vulnerable to certificate injection.\n\nSet one of:\n  tls.existingSecret       a kubernetes.io/tls Secret holding the server certificate (recommended; Puppet agents require HTTPS)\n  config.tls_self_provision  true, to have the CA issue and renew its own serving certificate (also set config.hostname)\n  config.tls_cert/tls_key  paths to a certificate you mount yourself\n  env/extraEnv             PUPPET_CA_TLS_CERT and PUPPET_CA_TLS_KEY, to feed those paths in from a Secret\n  config.no_tls_required   true, only behind a trusted TLS proxy that re-originates TLS\n  listen.host              127.0.0.1 or localhost, for a sidecar-only deployment" $host) -}}
{{- end -}}

{{/*
  Self-provisioning needs a hostname: it is the certificate's common name and
  first SAN. Without it the server refuses to start, because its "puppet"
  fallback subject would produce a certificate no agent validates — which
  surfaces as a TLS handshake failure rather than as the configuration error
  it is. The chart does not set hostname by default, so this is the common
  mistake rather than an exotic one.
*/}}
{{- if eq (include "openvox-ca.selfProvisionEnabled" .) "true" -}}
{{- if not (dig "hostname" "" $config) -}}
{{- fail "config.tls_self_provision requires config.hostname: it becomes the common name and first subject alternative name of the certificate agents verify. Without it the server refuses to start." -}}
{{- end -}}

{{/*
  The two TLS routes are mutually exclusive at the server, so a chart that
  renders both produces a Deployment that cannot start. tls.existingSecret is
  the chart's own wiring for the file route, so it counts as tls_cert here.
*/}}
{{- if or .Values.tls.existingSecret (dig "tls_cert" "" $config) (dig "tls_key" "" $config) -}}
{{- fail "config.tls_self_provision cannot be combined with tls.existingSecret or config.tls_cert/tls_key: the CA either issues its own serving certificate or loads one from disk, not both. The server refuses to start with both configured." -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
  A route pointed at the metrics port when the exporter is off installs
  cleanly and then routes to a Service port that was never created.
*/}}
{{- if not .Values.metrics.enabled -}}
{{- range $name, $route := dict "ingress" .Values.ingress "gateway.tlsRoute" .Values.gateway.tlsRoute "gateway.httpRoute" .Values.gateway.httpRoute -}}
{{- if and $route.enabled (eq $route.backendPort "metrics") -}}
{{- fail (printf "%s.backendPort is \"metrics\", but metrics.enabled is false, so the Service has no metrics port to route to. Set metrics.enabled: true, or point it at \"https\"." $name) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
  Binding the export Role to the namespace's default ServiceAccount would
  hand create/patch on every Secret in the namespace to every pod in it.
*/}}
{{- if and .Values.kubernetesExport.enabled .Values.kubernetesExport.rbac.create -}}
{{- if eq (include "openvox-ca.serviceAccountName" .) "default" -}}
{{- fail "kubernetesExport.rbac.create would bind the export Role to the namespace's default ServiceAccount, granting create/patch on Secrets to every pod in the namespace. Set serviceAccount.create: true, or serviceAccount.name to a dedicated account." -}}
{{- end -}}
{{- end -}}

{{/*
  A ServiceMonitor for an exporter that is switched off scrapes nothing.
*/}}
{{- if and .Values.metrics.serviceMonitor.enabled (not .Values.metrics.enabled) -}}
{{- fail "metrics.serviceMonitor.enabled requires metrics.enabled: the exporter is off, so there is nothing to scrape." -}}
{{- end -}}

{{/*
  An autoscaler with no metric configured does not autoscale: it pins the
  replica count at minReplicas and reports healthy while doing it.
*/}}
{{- if .Values.autoscaling.enabled -}}
{{- if not (or .Values.autoscaling.targetCPUUtilizationPercentage .Values.autoscaling.targetMemoryUtilizationPercentage .Values.autoscaling.metrics) -}}
{{- fail "autoscaling.enabled is set but no metric is configured, so the HorizontalPodAutoscaler would hold the replica count at minReplicas rather than scale. Set autoscaling.targetCPUUtilizationPercentage, targetMemoryUtilizationPercentage, or metrics." -}}
{{- end -}}
{{- end -}}

{{/*
  puppetServers and autosign.patterns are written one per line into the config
  ConfigMap. An entry containing a newline would end that block scalar early
  and inject a key of its own — and these two lists are the mTLS admin
  allow list and the autosign allow list, so a mangled one fails open.
*/}}
{{- range $list := list .Values.puppetServers .Values.autosign.patterns -}}
{{- range $entry := $list -}}
{{- if or (contains "\n" ($entry | toString)) (not (trim ($entry | toString))) -}}
{{- fail (printf "puppetServers and autosign.patterns entries must each be a single non-empty line; got %q" $entry) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
The names the exporter will apply to, gathered from the merged config so that
targets supplied through config.kubernetes_export count too.

Returns the literal string "unknown" — distinct from an empty list — when the
export config is not the chart's to read, because the two mean opposite things
to the caller: "no targets, so grant nothing" versus "unknown targets, so grant
everything". A marker rather than a JSON null because Helm's fromJson rejects
anything that is not an object, so the caller has to test before decoding
anyway.
*/}}
{{- define "openvox-ca.exportTargetNames" -}}
{{- if .Values.existingConfigMap -}}
unknown
{{- else -}}
{{- $config := include "openvox-ca.config" . | fromYaml -}}
{{- $names := list -}}
{{- range (dig "kubernetes_export" "targets" list $config) -}}
{{- with (dig "metadata" "name" "" .) -}}
{{- $names = append $names . -}}
{{- end -}}
{{- end -}}
{{- $names | uniq | sortAlpha | toJson -}}
{{- end -}}
{{- end -}}

{{/*
The post-install notes.

Held in a named template rather than inline in NOTES.txt so that they can be
rendered — and therefore asserted — offline. `helm template` does not evaluate
NOTES.txt at all, and `helm install --dry-run` reaches for a cluster on Helm 3,
so a probe template that includes this is the only portable way to test the
warnings. They were the operator-facing half of a defect once already.
*/}}
{{- define "openvox-ca.notes" -}}
{{- $fullName := include "openvox-ca.fullname" . -}}
{{- $namespace := include "openvox-ca.namespace" . -}}
{{- $config := include "openvox-ca.config" . | fromYaml -}}
{{- $backend := dig "storage_backend" "filesystem" $config -}}
{{- $tls := eq (include "openvox-ca.tlsConfigured" .) "true" -}}
{{- $replicas := ternary (int .Values.autoscaling.minReplicas) (int .Values.replicaCount) .Values.autoscaling.enabled -}}
{{- $autosign := dig "autosign_config" "" $config | toString -}}
openvox-ca {{ .Chart.AppVersion }} has been deployed as {{ $fullName }} in namespace {{ $namespace }}.

Image:           {{ include "openvox-ca.image" . }}
Storage backend: {{ $backend }}
Service:         {{ $fullName }}.{{ $namespace }}.svc:{{ .Values.service.port }}

Watch it come up:

  kubectl --namespace {{ $namespace }} rollout status deployment/{{ $fullName }}

Fetch the CA certificate once it is ready:

  kubectl --namespace {{ $namespace }} port-forward svc/{{ $fullName }} 8140:{{ .Values.service.port }}
  curl {{ if $tls }}-k https{{ else }}http{{ end }}://localhost:8140/puppet-ca/v1/certificate/ca

{{- if not $tls }}

WARNING: no server TLS certificate is configured, so openvox-ca is serving
plain HTTP. Puppet agents require HTTPS, and every endpoint authenticated by
client certificate — signing, revoking, listing — is unavailable. This is only
safe behind a proxy that terminates TLS and re-originates it to the pod. Set
tls.existingSecret to a kubernetes.io/tls Secret to serve TLS directly.
{{- end }}
{{- if and (has $backend (list "filesystem" "sqlite")) (not .Values.persistence.enabled) }}

WARNING: the {{ $backend }} backend keeps the entire CA — including its private
key — in {{ .Values.persistence.mountPath }}, but persistence is disabled, so
that directory is an emptyDir. The CA will be regenerated from scratch on every
restart and previously issued certificates will stop verifying. Set
persistence.enabled: true, or switch to an external storage backend.
{{- end }}
{{- if and (has $backend (list "filesystem" "sqlite")) (gt $replicas 1) }}

WARNING: {{ if .Values.autoscaling.enabled }}autoscaling starts at {{ $replicas }} replicas{{ else }}replicaCount is {{ $replicas }}{{ end }}, but the
{{ $backend }} backend is not safe to share between replicas. Use postgres,
mysql, etcd, or redis to run more than one — see
https://github.com/voxpupuli/openvox-ca/blob/main/docs/storage-backends.md
{{- end }}
{{- if eq $autosign "true" }}

WARNING: autosigning is set to "true", so every CSR that reaches the CA is
signed without review. Anyone who can reach the API can obtain a valid
certificate for any name. Use this in development only.
{{- end }}
{{- if and .Values.metrics.enabled (not .Values.networkPolicy.enabled) }}

NOTE: the Prometheus exporter is enabled on port {{ .Values.metrics.port }}. Its
leaf-certificate series carry node hostnames as label values, and no
NetworkPolicy is in place to restrict who can scrape it. Consider
networkPolicy.enabled: true.
{{- end }}
{{- if and .Values.networkPolicy.enabled .Values.networkPolicy.egress.enabled (eq (include "openvox-ca.needsAPIAccess" .) "true") }}

NOTE: this pod talks to the Kubernetes API ({{ if .Values.kubernetesExport.enabled }}Kubernetes export{{ else }}OpenBao Kubernetes auth{{ end }}), but
egress is restricted and the chart cannot know your API server's address. Add a
rule for it to networkPolicy.egress.rules, or the feature will fail while
readiness still reports healthy.
{{- end }}
{{- if not (or .Values.puppetServers (dig "puppet_server" "" $config) (dig "puppet_server_file" "" $config)) }}

NOTE: no puppetServers are listed, so no CN is granted admin API access over
mTLS. Your OpenVox/Puppet Server compilers need to be listed here (or via
config.puppet_server) before they can sign, revoke, or list certificates.
{{- end }}

Full configuration reference: https://github.com/voxpupuli/openvox-ca/blob/main/docs/configuration.md
Chart documentation:          https://github.com/voxpupuli/openvox-ca/blob/main/docs/helm-chart.md
{{- end -}}
