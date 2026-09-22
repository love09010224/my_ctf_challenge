{{- define "reclaim.name" -}}
reclaim-gateway
{{- end -}}

{{- define "reclaim.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "reclaim.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "reclaim.labels" -}}
app.kubernetes.io/name: {{ include "reclaim.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end -}}

{{- define "reclaim.selectorLabels" -}}
app.kubernetes.io/name: {{ include "reclaim.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "reclaim.image" -}}
{{- $image := index . 0 -}}
{{- if $image.digest -}}
{{- printf "%s@%s" $image.repository $image.digest -}}
{{- else -}}
{{- printf "%s:%s" $image.repository $image.tag -}}
{{- end -}}
{{- end -}}

{{- define "reclaim.validate" -}}
{{- if ne (int .Values.gateway.replicaCount) 1 -}}
{{- fail "gateway.replicaCount must remain 1; multi-replica connection locking is not implemented" -}}
{{- end -}}
{{- if not .Values.secrets.existingSecret -}}
{{- fail "secrets.existingSecret is required" -}}
{{- end -}}
{{- if not .Values.redis.enabled -}}
{{- fail "redis.enabled must remain true for FIFO and active-slot state" -}}
{{- end -}}
{{- if not .Values.redis.existingSecret -}}
{{- fail "redis.existingSecret is required" -}}
{{- end -}}
{{- if ne (int .Values.challenge.maxInstances) 30 -}}
{{- fail "challenge.maxInstances must be exactly 30" -}}
{{- end -}}
{{- if not .Values.challenge.unsafeAllowNonContractResources -}}
{{- if ne (toString .Values.challenge.resources.requests.cpu) "250m" -}}
{{- fail "challenge CPU request must be exactly 250m" -}}
{{- end -}}
{{- if ne (toString .Values.challenge.resources.limits.cpu) "2" -}}
{{- fail "challenge CPU limit must be exactly 2" -}}
{{- end -}}
{{- if ne (toString .Values.challenge.resources.requests.memory) "640Mi" -}}
{{- fail "challenge memory request must be exactly 640Mi" -}}
{{- end -}}
{{- if ne (toString .Values.challenge.resources.limits.memory) "640Mi" -}}
{{- fail "challenge memory limit must be exactly 640Mi" -}}
{{- end -}}
{{- end -}}
{{- if not (has .Values.tls.mode (list "direct" "upstream" "plaintext")) -}}
{{- fail "tls.mode must be direct, upstream, or plaintext" -}}
{{- end -}}
{{- if and (eq .Values.tls.mode "direct") (not .Values.tls.existingSecret) -}}
{{- fail "tls.existingSecret is required for direct TLS" -}}
{{- end -}}
{{- if and (eq .Values.tls.mode "plaintext") (not .Values.tls.unsafeAllowPlaintext) -}}
{{- fail "plaintext mode requires tls.unsafeAllowPlaintext=true" -}}
{{- end -}}
{{- if and (eq .Values.tls.mode "upstream") (ne .Values.service.type "ClusterIP") -}}
{{- fail "upstream TLS mode requires service.type=ClusterIP to prevent public plaintext exposure" -}}
{{- end -}}
{{- if and (not .Values.ctfd.allowHttp) (not (hasPrefix "https://" .Values.ctfd.baseUrl)) -}}
{{- fail "ctfd.baseUrl must use https:// unless ctfd.allowHttp=true" -}}
{{- end -}}
{{- if lt (int .Values.challenge.timeoutSeconds) 60 -}}
{{- fail "challenge.timeoutSeconds must be at least 60" -}}
{{- end -}}
{{- if eq .Values.challenge.namespace .Release.Namespace -}}
{{- fail "challenge.namespace must differ from the gateway release namespace" -}}
{{- end -}}
{{- if .Values.quota.enabled -}}
{{- if ne (toString (index .Values.quota.hard "pods")) "30" -}}
{{- fail "quota.hard.pods must be exactly 30" -}}
{{- end -}}
{{- if ne (toString (index .Values.quota.hard "count/jobs.batch")) "30" -}}
{{- fail "quota.hard.count/jobs.batch must be exactly 30" -}}
{{- end -}}
{{- if ne (toString (index .Values.quota.hard "count/services")) "30" -}}
{{- fail "quota.hard.count/services must be exactly 30" -}}
{{- end -}}
{{- if ne (toString (index .Values.quota.hard "requests.cpu")) "7500m" -}}
{{- fail "quota.hard.requests.cpu must be exactly 7500m" -}}
{{- end -}}
{{- if ne (toString (index .Values.quota.hard "requests.memory")) "19200Mi" -}}
{{- fail "quota.hard.requests.memory must be exactly 19200Mi" -}}
{{- end -}}
{{- if ne (toString (index .Values.quota.hard "limits.cpu")) "60" -}}
{{- fail "quota.hard.limits.cpu must be exactly 60" -}}
{{- end -}}
{{- if ne (toString (index .Values.quota.hard "limits.memory")) "19200Mi" -}}
{{- fail "quota.hard.limits.memory must be exactly 19200Mi" -}}
{{- end -}}
{{- end -}}
{{- if .Values.networkPolicy.enabled -}}
{{- if eq (len .Values.networkPolicy.kubernetesApiCidrs) 0 -}}
{{- fail "networkPolicy.kubernetesApiCidrs must contain at least one exact API endpoint" -}}
{{- end -}}
{{- if eq (len .Values.networkPolicy.kubernetesApiEndpointCidrs) 0 -}}
{{- fail "networkPolicy.kubernetesApiEndpointCidrs must contain the ready API backend" -}}
{{- end -}}
{{- if and (eq (len .Values.networkPolicy.ctfdCidrs) 0) (not .Values.networkPolicy.ctfdPodSelector) -}}
{{- fail "networkPolicy must contain a CTFd IP or test Pod selector" -}}
{{- end -}}
{{- range .Values.networkPolicy.kubernetesApiCidrs -}}
{{- if or (eq . "0.0.0.0/0") (eq . "::/0") -}}
{{- fail "networkPolicy Kubernetes API egress cannot be internet-wide" -}}
{{- end -}}
{{- end -}}
{{- range .Values.networkPolicy.kubernetesApiEndpointCidrs -}}
{{- if or (eq . "0.0.0.0/0") (eq . "::/0") -}}
{{- fail "networkPolicy Kubernetes API backend egress cannot be internet-wide" -}}
{{- end -}}
{{- end -}}
{{- range .Values.networkPolicy.ctfdCidrs -}}
{{- if or (eq . "0.0.0.0/0") (eq . "::/0") -}}
{{- fail "networkPolicy CTFd egress cannot be internet-wide" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
