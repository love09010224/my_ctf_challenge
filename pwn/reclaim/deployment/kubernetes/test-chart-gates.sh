#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HELM_IMAGE=${HELM_IMAGE:-alpine/helm:3.18.6@sha256:c6d8088ddb279625a2e1ca3b08b22c18c946d1f65c8b810f28f1597435a1134c}
WORK=$(mktemp -d)

cleanup() {
    WORK_TO_DELETE="$WORK" python3 - <<'PY'
from pathlib import Path
import os, shutil
path = Path(os.environ["WORK_TO_DELETE"])
if path.exists():
    shutil.rmtree(path)
PY
}
trap cleanup EXIT INT TERM

helm_template() {
    docker run --rm -v "$ROOT:/work:ro" "$HELM_IMAGE" \
        template reclaim /work/chart/reclaim-gateway "$@"
}

helm_template -f /work/values-development.yaml > "$WORK/development.yaml"
RENDERED="$WORK/development.yaml" python3 - <<'PY'
import os, yaml
with open(os.environ["RENDERED"], encoding="utf-8") as stream:
    docs = [item for item in yaml.safe_load_all(stream) if item]
services = [item for item in docs if item["kind"] == "Service"]
public = next(item for item in services if item["metadata"]["labels"].get("app.kubernetes.io/component") != "redis")
redis = next(item for item in services if item["metadata"]["labels"].get("app.kubernetes.io/component") == "redis")
assert public["spec"]["type"] == "NodePort"
assert public["spec"]["ports"][0]["nodePort"] == 31337
assert redis["spec"]["type"] == "ClusterIP"
assert redis["spec"]["ports"][0]["port"] == 6379
PY

helm_template -f /work/values-production.example.yaml > "$WORK/production.yaml"
RENDERED="$WORK/production.yaml" python3 - <<'PY'
import os, yaml
with open(os.environ["RENDERED"], encoding="utf-8") as stream:
    docs = [item for item in yaml.safe_load_all(stream) if item]
deployment = next(
    item for item in docs
    if item["kind"] == "Deployment"
    and item["metadata"]["labels"].get("app.kubernetes.io/component") != "redis"
)
environment = {
    item["name"]: item.get("value")
    for item in deployment["spec"]["template"]["spec"]["containers"][0]["env"]
}
assert environment["MAX_INSTANCES"] == "30"
assert environment["INSTANCE_TIMEOUT_SECONDS"] == "900"
assert environment["INSTANCE_MEMORY"] == "640Mi"
quota = next(item for item in docs if item["kind"] == "ResourceQuota")
assert environment["INSTANCE_CPU_REQUEST"] == "250m"
assert environment["INSTANCE_CPU_LIMIT"] == "2"
assert environment["INSTANCE_MEMORY"] == "640Mi"
assert quota["spec"]["hard"]["pods"] == "30"
assert quota["spec"]["hard"]["count/jobs.batch"] == "30"
assert quota["spec"]["hard"]["count/services"] == "30"
assert quota["spec"]["hard"]["requests.cpu"] == "7500m"
assert quota["spec"]["hard"]["requests.memory"] == "19200Mi"
assert quota["spec"]["hard"]["limits.cpu"] == "60"
assert quota["spec"]["hard"]["limits.memory"] == "19200Mi"
gateway_policy = next(
    item for item in docs
    if item["kind"] == "NetworkPolicy"
    and item["spec"]["podSelector"].get("matchLabels", {}).get(
        "reclaim.hspace.io/workload"
    ) == "gateway"
)
assert set(gateway_policy["spec"]["policyTypes"]) == {"Ingress", "Egress"}
assert len(gateway_policy["spec"]["egress"]) == 6
blocks = [
    peer["ipBlock"]["cidr"]
    for rule in gateway_policy["spec"]["egress"]
    for peer in rule.get("to", [])
    if "ipBlock" in peer
]
assert blocks == ["10.43.0.1/32", "192.0.2.2/32", "192.0.2.1/32"]
assert "0.0.0.0/0" not in blocks
assert "169.254.169.254/32" not in blocks
PY

if helm_template --set gateway.replicaCount=2 > "$WORK/invalid-replica" 2>&1; then
    echo "multi-replica gateway was not rejected" >&2
    exit 1
fi
if helm_template --set challenge.maxInstances=29 > "$WORK/invalid-capacity" 2>&1; then
    echo "capacity other than thirty was not rejected" >&2
    exit 1
fi
if helm_template --set challenge.resources.requests.cpu=251m > "$WORK/invalid-resource" 2>&1; then
    echo "non-contract instance resources were not rejected" >&2
    exit 1
fi
if helm_template --set-string quota.hard.count/services=29 > "$WORK/invalid-quota" 2>&1; then
    echo "non-contract instance quota was not rejected" >&2
    exit 1
fi
if helm_template --set redis.enabled=false > "$WORK/invalid-redis" 2>&1; then
    echo "disabled Redis state was not rejected" >&2
    exit 1
fi
if helm_template --set tls.mode=upstream --set service.type=LoadBalancer \
    > "$WORK/invalid-upstream" 2>&1; then
    echo "public plaintext upstream mode was not rejected" >&2
    exit 1
fi
if helm_template --set tls.mode=plaintext --set tls.existingSecret='' \
    > "$WORK/invalid-plaintext" 2>&1; then
    echo "unsafe plaintext mode was not rejected" >&2
    exit 1
fi
if helm_template --namespace reclaim-instances \
    > "$WORK/invalid-shared-namespace" 2>&1; then
    echo "shared gateway/instance namespace was not rejected" >&2
    exit 1
fi
if helm_template --set-json 'networkPolicy.kubernetesApiCidrs=[]' \
    > "$WORK/invalid-empty-api-egress" 2>&1; then
    echo "empty Kubernetes API egress allowlist was not rejected" >&2
    exit 1
fi
if helm_template --set-json 'networkPolicy.kubernetesApiEndpointCidrs=[]' \
    > "$WORK/invalid-empty-api-backend-egress" 2>&1; then
    echo "empty Kubernetes API backend egress allowlist was not rejected" >&2
    exit 1
fi
if helm_template --set-json 'networkPolicy.ctfdCidrs=[]' \
    > "$WORK/invalid-empty-ctfd-egress" 2>&1; then
    echo "empty CTFd egress allowlist was not rejected" >&2
    exit 1
fi
if helm_template --set-json 'networkPolicy.ctfdCidrs=["0.0.0.0/0"]' \
    > "$WORK/invalid-wide-ctfd-egress" 2>&1; then
    echo "internet-wide CTFd egress allowlist was not rejected" >&2
    exit 1
fi

helm_template --set tls.mode=upstream --set tls.existingSecret='' \
    --set service.type=ClusterIP > "$WORK/upstream.yaml"
RENDERED="$WORK/upstream.yaml" python3 - <<'PY'
import os, yaml
with open(os.environ["RENDERED"], encoding="utf-8") as stream:
    docs = [item for item in yaml.safe_load_all(stream) if item]
service = next(
    item for item in docs
    if item["kind"] == "Service"
    and item["metadata"]["labels"].get("app.kubernetes.io/component") != "redis"
)
assert service["spec"]["type"] == "ClusterIP"
assert "externalTrafficPolicy" not in service["spec"]
PY

echo "[Q2-HELM-NEGATIVE-GATES-PASS]"
