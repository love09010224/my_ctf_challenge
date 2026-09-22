#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
KIND=${KIND:-kind}
KUBECTL=${KUBECTL:-kubectl}
HOST_PORT=${E2E_HOST_PORT:-23137}
REAL_SERVICE_BUNDLE=${REAL_SERVICE_BUNDLE:-}
CLUSTER="reclaim-e2e-$$"
HELM_IMAGE=${HELM_IMAGE:-alpine/helm:3.18.6@sha256:c6d8088ddb279625a2e1ca3b08b22c18c946d1f65c8b810f28f1597435a1134c}
NODE_IMAGE=${KIND_NODE_IMAGE:-kindest/node:v1.34.3@sha256:08497ee19eace7b4b5348db5c6a1591d7752b164530a36f855cb0f2bdcbadd48}
REDIS_SOURCE_IMAGE=${REDIS_IMAGE:-redis:7.4.2-alpine@sha256:02419de7eddf55aa5bcf49efb74e88fa8d931b4d77c07eff8a6b2144472b6952}
REDIS_E2E_REPOSITORY="reclaim-q2-redis-e2e-$$"
REDIS_E2E_IMAGE="$REDIS_E2E_REPOSITORY:local"
GATEWAY_IMAGE=reclaim-gateway:kubernetes-local
MOCK_IMAGE=reclaim-k8s-e2e-mock:local
WORK=$(mktemp -d)
KUBECONFIG_FILE="$WORK/kubeconfig"
CREATED=0
REAL_MODE=0
REAL_IMAGE=""
CHALLENGE_REPOSITORY=reclaim-k8s-e2e-mock
CHALLENGE_TAG=local
CHALLENGE_CPU_REQUEST=10m
CHALLENGE_CPU_LIMIT=100m
CHALLENGE_MEMORY=64Mi

k() {
    "$KUBECTL" --kubeconfig "$KUBECONFIG_FILE" "$@"
}

load_image() {
    image=$1
    archive="$WORK/image-$2.tar"
    # Docker Desktop's containerd image store retains a multi-platform index
    # but only the host-platform blobs. kind's default --all-platforms import
    # then follows absent manifests. Export an explicit amd64 archive instead.
    docker image save --platform linux/amd64 "$image" -o "$archive"
    "$KIND" load image-archive --name "$CLUSTER" "$archive"
    ARCHIVE_TO_DELETE="$archive" python3 - <<'PY'
from pathlib import Path
import os
Path(os.environ["ARCHIVE_TO_DELETE"]).unlink(missing_ok=True)
PY
}

diagnose() {
    status=$1
    if [ "$status" -ne 0 ] && [ "$CREATED" -eq 1 ]; then
        echo "[KUBERNETES-KIND-E2E-DIAGNOSTIC]" >&2
        k get pods,jobs,services --all-namespaces -o wide >&2 || true
        k -n reclaim-gateway logs deployment/reclaim-reclaim-gateway \
            --all-containers --tail=200 >&2 || true
        k -n reclaim-gateway logs deployment/reclaim-reclaim-gateway \
            --all-containers --previous --tail=200 >&2 || true
        k -n reclaim-gateway logs deployment/reclaim-reclaim-gateway-redis \
            --all-containers --tail=100 >&2 || true
    fi
}

cleanup() {
    status=$?
    trap - EXIT INT TERM
    diagnose "$status"
    if [ "$CREATED" -eq 1 ]; then
        "$KIND" delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
    fi
    if [ -n "$REAL_IMAGE" ]; then
        docker image rm --force "$REAL_IMAGE" >/dev/null 2>&1 || true
    fi
    docker image rm --force "$REDIS_E2E_IMAGE" >/dev/null 2>&1 || true
    WORK_TO_DELETE="$WORK" python3 - <<'PY'
from pathlib import Path
import os, shutil
path = Path(os.environ["WORK_TO_DELETE"])
if path.exists():
    shutil.rmtree(path)
PY
    exit "$status"
}
trap cleanup EXIT INT TERM

for command in "$KIND" "$KUBECTL" docker openssl python3; do
    command -v "$command" >/dev/null || {
        echo "missing command: $command" >&2
        exit 1
    }
done

docker build -q -t "$GATEWAY_IMAGE" "$ROOT/broker" >/dev/null
docker build -q -t "$MOCK_IMAGE" "$ROOT/e2e" >/dev/null
if ! docker image inspect "$REDIS_SOURCE_IMAGE" >/dev/null 2>&1; then
    docker pull -q "$REDIS_SOURCE_IMAGE" >/dev/null
fi
docker tag "$REDIS_SOURCE_IMAGE" "$REDIS_E2E_IMAGE"

if [ -n "$REAL_SERVICE_BUNDLE" ]; then
    REAL_MODE=1
    REAL_SERVICE_BUNDLE=$(realpath "$REAL_SERVICE_BUNDLE")
    [ -f "$REAL_SERVICE_BUNDLE" ] || {
        echo "real service bundle is missing" >&2
        exit 1
    }
    mkdir -p "$WORK/real-service"
    BUNDLE="$REAL_SERVICE_BUNDLE" DESTINATION="$WORK/real-service" python3 - <<'PY'
from pathlib import Path
import os, tarfile
with tarfile.open(os.environ["BUNDLE"], "r:gz") as archive:
    archive.extractall(Path(os.environ["DESTINATION"]), filter="data")
PY
    (cd "$WORK/real-service" && sha256sum -c SHA256SUMS >/dev/null)
    CHALLENGE_REPOSITORY="reclaim-k8s-real-e2e-${RANDOM}"
    CHALLENGE_TAG=local
    CHALLENGE_CPU_REQUEST=250m
    CHALLENGE_CPU_LIMIT=2
    CHALLENGE_MEMORY=640Mi
    REAL_IMAGE="$CHALLENGE_REPOSITORY:$CHALLENGE_TAG"
    docker build -q -t "$REAL_IMAGE" "$WORK/real-service" >/dev/null
fi

cat > "$WORK/kind.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: 31337
        hostPort: $HOST_PORT
        protocol: TCP
EOF

"$KIND" create cluster --name "$CLUSTER" --image "$NODE_IMAGE" \
    --config "$WORK/kind.yaml" --kubeconfig "$KUBECONFIG_FILE" --wait 180s
CREATED=1
KUBE_API_ENDPOINT=$(
    k -n default get endpointslices \
        -l kubernetes.io/service-name=kubernetes \
        -o jsonpath='{.items[0].endpoints[0].addresses[0]}'
)
[ -n "$KUBE_API_ENDPOINT" ] || {
    echo "Kubernetes API EndpointSlice address is missing" >&2
    exit 1
}
load_image "$GATEWAY_IMAGE" gateway
load_image "$MOCK_IMAGE" mock
load_image "$REDIS_E2E_IMAGE" redis
if [ "$REAL_MODE" -eq 1 ]; then
    load_image "$REAL_IMAGE" real
fi

for namespace in reclaim-gateway reclaim-instances; do
    k create namespace "$namespace"
    k label namespace "$namespace" \
        pod-security.kubernetes.io/enforce=restricted \
        pod-security.kubernetes.io/enforce-version=latest
done

umask 077
openssl rand 48 > "$WORK/instance-name-hmac"
openssl rand -hex 32 > "$WORK/redis-password"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$WORK/tls.key" -out "$WORK/tls.crt" \
    -subj '/CN=localhost' \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' >/dev/null 2>&1
k -n reclaim-gateway create secret generic reclaim-gateway-secrets \
    --from-file=instance-name-hmac="$WORK/instance-name-hmac"
k -n reclaim-gateway create secret generic reclaim-q2-redis-auth \
    --from-file=password="$WORK/redis-password"
k -n reclaim-gateway create secret tls reclaim-gateway-tls \
    --cert="$WORK/tls.crt" --key="$WORK/tls.key"
k apply -f "$ROOT/e2e/ctfd-mock.yaml"

docker run --rm -v "$ROOT:/work:ro" "$HELM_IMAGE" \
    template reclaim /work/chart/reclaim-gateway \
    --namespace reclaim-gateway \
    --set gateway.image.repository=reclaim-gateway \
    --set gateway.image.tag=kubernetes-local \
    --set gateway.image.pullPolicy=Never \
    --set gateway.queuePollSeconds=0.2 \
    --set gateway.queueStatusSeconds=1 \
    --set ctfd.baseUrl=http://ctfd-mock.reclaim-gateway.svc:8081 \
    --set ctfd.allowHttp=true --set ctfd.challengeId=1 \
    --set-json 'networkPolicy.kubernetesApiCidrs=["10.96.0.1/32"]' \
    --set-string "networkPolicy.kubernetesApiEndpointCidrs[0]=$KUBE_API_ENDPOINT/32" \
    --set networkPolicy.kubernetesApiEndpointPort=6443 \
    --set-json 'networkPolicy.ctfdCidrs=[]' \
    --set-json 'networkPolicy.ctfdPodSelector={"app":"ctfd-mock"}' \
    --set networkPolicy.ctfdPort=8081 \
    --set tls.mode=direct --set tls.existingSecret=reclaim-gateway-tls \
    --set secrets.existingSecret=reclaim-gateway-secrets \
    --set redis.image.repository="$REDIS_E2E_REPOSITORY" \
    --set redis.image.tag=local --set-string redis.image.digest= \
    --set redis.image.pullPolicy=Never \
    --set redis.existingSecret=reclaim-q2-redis-auth \
    --set service.type=NodePort --set service.nodePort=31337 \
    --set service.externalTrafficPolicy=Local \
    --set challenge.namespace=reclaim-instances \
    --set challenge.image.repository="$CHALLENGE_REPOSITORY" \
    --set challenge.image.tag="$CHALLENGE_TAG" \
    --set challenge.image.pullPolicy=Never \
    --set challenge.timeoutSeconds=600 \
    --set challenge.finishedJobTtlSeconds=0 \
    --set challenge.backendStartupSeconds=60 \
    --set challenge.unsafeAllowNonContractResources=true \
    --set challenge.resources.requests.cpu="$CHALLENGE_CPU_REQUEST" \
    --set challenge.resources.limits.cpu="$CHALLENGE_CPU_LIMIT" \
    --set challenge.resources.requests.memory="$CHALLENGE_MEMORY" \
    --set challenge.resources.limits.memory="$CHALLENGE_MEMORY" > "$WORK/rendered.yaml"
k apply -f "$WORK/rendered.yaml"
k -n reclaim-gateway rollout status deployment/ctfd-mock --timeout=120s
k -n reclaim-gateway rollout status \
    deployment/reclaim-reclaim-gateway-redis --timeout=120s
k -n reclaim-gateway rollout status \
    deployment/reclaim-reclaim-gateway --timeout=180s

if [ "$REAL_MODE" -eq 1 ]; then
    python3 "$ROOT/e2e/real_client_smoke.py" --port "$HOST_PORT"
    for _ in $(seq 1 240); do
        counts=$(k -n reclaim-instances get jobs,pods,services -o name | wc -l)
        [ "$counts" -eq 0 ] && break
        sleep 0.25
    done
    k -n reclaim-instances get jobs,pods,services,resourcequotas -o json \
        > "$WORK/objects-after-cleanup.json"
    python3 "$ROOT/e2e/audit_live_objects.py" \
        --expected-instances 0 "$WORK/objects-after-cleanup.json"
else
    python3 "$ROOT/e2e/verify_live.py" \
        --port "$HOST_PORT" \
        --kubectl "$KUBECTL" --kubeconfig "$KUBECONFIG_FILE" \
        --capacity-objects "$WORK/objects-at-capacity.json" \
        --promoted-objects "$WORK/objects-after-promotion.json" \
        --cleanup-objects "$WORK/objects-after-cleanup.json" \
        --capacity-redis "$WORK/redis-at-capacity.json" \
        --promoted-redis "$WORK/redis-after-promotion.json"
    python3 "$ROOT/e2e/audit_live_objects.py" \
        --expected-instances 30 "$WORK/objects-at-capacity.json"
    python3 "$ROOT/e2e/audit_live_objects.py" \
        --expected-instances 30 "$WORK/objects-after-promotion.json"
    python3 "$ROOT/e2e/audit_live_objects.py" \
        --expected-instances 0 "$WORK/objects-after-cleanup.json"
fi

k -n reclaim-gateway logs deployment/reclaim-reclaim-gateway > "$WORK/gateway.log"
LOG_FILE="$WORK/gateway.log" python3 - <<'PY'
from pathlib import Path
import os
raw = Path(os.environ["LOG_FILE"]).read_bytes()
for forbidden in (b"integration-token-", b"invalid-integration-token", b"team:"):
    if forbidden in raw:
        raise SystemExit("gateway log contains bearer or raw team identity material")
print("[KUBERNETES-E2E-LOG-REDACTION-PASS]")
PY

if [ "$REAL_MODE" -eq 0 ]; then
    echo "[KUBERNETES-KIND-MOCK-E2E-COMPLETE]"
else
    echo "[KUBERNETES-KIND-REAL-SERVICE-SMOKE-PASS]"
fi
