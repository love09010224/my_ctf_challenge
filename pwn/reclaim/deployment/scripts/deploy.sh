#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

[ "${EUID:-$(id -u)}" -eq 0 ] || die "deploy must run as root (sudo make deploy)"
load_config
init_kubernetes_clients
for command in docker k3s openssl python3 sha256sum flock base64 getent; do
    require_command "$command"
done
prepare_network_policy_egress

umask 077
mkdir -p "$RUNTIME_DIR/images"
chmod 0700 "$RUNTIME_DIR" "$RUNTIME_DIR/images"
exec 9>"$RUNTIME_DIR/deploy.lock"
flock -n 9 || die "another RE:CLAIM deployment is running"

"$SCRIPT_DIR/preflight.sh"

tree_digest() {
    SOURCE_TREE=$1 python3 - <<'PY'
from __future__ import annotations
import hashlib
import os
from pathlib import Path

root = Path(os.environ["SOURCE_TREE"]).resolve()
digest = hashlib.sha256()
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    if not path.is_file() or path.is_symlink():
        continue
    relative = path.relative_to(root).as_posix().encode("utf-8")
    digest.update(len(relative).to_bytes(4, "big"))
    digest.update(relative)
    data = path.read_bytes()
    digest.update(len(data).to_bytes(8, "big"))
    digest.update(data)
print(digest.hexdigest()[:20])
PY
}

build_and_archive() {
    local context=$1 image=$2 archive=$3
    if docker image inspect "$image" >/dev/null 2>&1; then
        note "reusing local content-tagged image $image"
    else
        note "building $image for linux/amd64"
        docker build --platform linux/amd64 --tag "$image" "$context"
    fi
    local platform
    platform=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image")
    [ "$platform" = linux/amd64 ] || die "$image has platform $platform, expected linux/amd64"

    local temporary="$archive.tmp.$$"
    rm -f "$temporary"
    docker image save --platform linux/amd64 --output "$temporary" "$image"
    mv -f "$temporary" "$archive"
    chmod 0600 "$archive"
    note "importing $image into k3s containerd"
    k3s ctr images import "$archive" >/dev/null
    k3s ctr images list -q | grep -Fx -- "$image" >/dev/null \
        || die "k3s containerd did not retain image $image"
}

gateway_tag="src-$(tree_digest "$ADMIN_ROOT/kubernetes/broker")"
challenge_tag="src-$(tree_digest "$ADMIN_ROOT/service")"
gateway_repository=reclaim.local/reclaim-gateway
challenge_repository=reclaim.local/reclaim-box-000
gateway_image="$gateway_repository:$gateway_tag"
challenge_image="$challenge_repository:$challenge_tag"
gateway_archive="$RUNTIME_DIR/images/gateway-$gateway_tag-linux-amd64.tar"
challenge_archive="$RUNTIME_DIR/images/challenge-$challenge_tag-linux-amd64.tar"

build_and_archive "$ADMIN_ROOT/kubernetes/broker" "$gateway_image" "$gateway_archive"
build_and_archive "$ADMIN_ROOT/service" "$challenge_image" "$challenge_archive"

node=$(single_node_name)
note "labeling single k3s node $node"
k label node "$node" workload=untrusted-qemu --overwrite >/dev/null

for namespace in "$GATEWAY_NAMESPACE" "$INSTANCE_NAMESPACE"; do
    k create namespace "$namespace" --dry-run=client -o yaml | k apply -f - >/dev/null
    k label namespace "$namespace" \
        pod-security.kubernetes.io/enforce=restricted \
        pod-security.kubernetes.io/enforce-version=latest \
        pod-security.kubernetes.io/audit=restricted \
        pod-security.kubernetes.io/audit-version=latest \
        pod-security.kubernetes.io/warn=restricted \
        pod-security.kubernetes.io/warn-version=latest \
        --overwrite >/dev/null
done

secret_file=$(mktemp "$RUNTIME_DIR/.secret.XXXXXX")
cleanup_secret_file() {
    rm -f "$secret_file"
}
trap cleanup_secret_file EXIT INT TERM

recover_secret_key() {
    local namespace=$1 name=$2 key=$3
    local encoded
    encoded=$(k -n "$namespace" get secret "$name" \
        -o "jsonpath={.data.${key}}")
    [ -n "$encoded" ] || die "Secret $namespace/$name has no $key key"
    printf '%s' "$encoded" | base64 -d > "$secret_file" \
        || die "Secret $namespace/$name contains invalid base64"
}

ensure_hmac_secret() {
    local namespace=$1 name=$2 key=$3
    if k -n "$namespace" get secret "$name" >/dev/null 2>&1; then
        recover_secret_key "$namespace" "$name" "$key"
        [ "$(wc -c < "$secret_file")" -ge 32 ] \
            || die "existing $namespace/$name is not a valid HMAC secret"
        note "reusing existing cluster Secret $namespace/$name"
    else
        openssl rand 48 > "$secret_file"
        k -n "$namespace" create secret generic "$name" \
            --from-file="$key=$secret_file" >/dev/null
        note "created cluster Secret $namespace/$name"
    fi
    : > "$secret_file"
}

ensure_redis_secret() {
    local namespace=$1 name=$2 key=$3
    if k -n "$namespace" get secret "$name" >/dev/null 2>&1; then
        recover_secret_key "$namespace" "$name" "$key"
        grep -Eq '^[0-9a-f]{64}$' "$secret_file" \
            || die "existing $namespace/$name is not a valid Redis password"
        note "reusing existing cluster Secret $namespace/$name"
    else
        openssl rand -hex 32 > "$secret_file"
        k -n "$namespace" create secret generic "$name" \
            --from-file="$key=$secret_file" >/dev/null
        note "created cluster Secret $namespace/$name"
    fi
    : > "$secret_file"
}

ensure_hmac_secret "$GATEWAY_NAMESPACE" reclaim-gateway-secrets instance-name-hmac
ensure_redis_secret "$GATEWAY_NAMESPACE" reclaim-q2-redis-auth password

# TLS material is declarative and intentionally refreshed on every deployment.
# Server-side apply avoids copying base64 private-key material into kubectl's
# client-side last-applied annotation.
k -n "$GATEWAY_NAMESPACE" create secret tls reclaim-gateway-tls \
    --cert="$TLS_CERT_FILE" --key="$TLS_KEY_FILE" --dry-run=client -o yaml \
    | k apply --server-side --force-conflicts \
        --field-manager=reclaim-deploy -f - >/dev/null
if [ -n "$CTFD_CA_FILE" ]; then
    k -n "$GATEWAY_NAMESPACE" create secret generic reclaim-ctfd-ca \
        --from-file="ca.crt=$CTFD_CA_FILE" --dry-run=client -o yaml \
        | k apply --server-side --force-conflicts \
            --field-manager=reclaim-deploy -f - >/dev/null
fi

values_file="$RUNTIME_DIR/values-production.json"
values_tmp="$values_file.tmp.$$"
export GATEWAY_IMAGE_REPOSITORY="$gateway_repository"
export GATEWAY_IMAGE_TAG="$gateway_tag"
export CHALLENGE_IMAGE_REPOSITORY="$challenge_repository"
export CHALLENGE_IMAGE_TAG="$challenge_tag"
python3 "$SCRIPT_DIR/render-values.py" > "$values_tmp"
mv -f "$values_tmp" "$values_file"
chmod 0600 "$values_file"

note "installing Helm release $RELEASE_NAME"
h upgrade --install "$RELEASE_NAME" \
    "$ADMIN_ROOT/kubernetes/chart/reclaim-gateway" \
    --namespace "$GATEWAY_NAMESPACE" \
    --values "$values_file" \
    --atomic --wait --timeout 10m

fullname=$(release_fullname)
# External Secrets are not rendered by Helm and therefore do not alter the Pod
# template checksum. Restart in dependency order so renewed TLS/CA bytes are
# guaranteed to be loaded. A deployment is a maintenance event and disconnects
# existing participant sessions by design.
k -n "$GATEWAY_NAMESPACE" rollout restart "deployment/$fullname-redis" >/dev/null
k -n "$GATEWAY_NAMESPACE" rollout status "deployment/$fullname-redis" --timeout=180s
k -n "$GATEWAY_NAMESPACE" rollout restart "deployment/$fullname" >/dev/null
k -n "$GATEWAY_NAMESPACE" rollout status "deployment/$fullname" --timeout=180s

max_instances=$(k -n "$GATEWAY_NAMESPACE" get deployment "$fullname" \
    -o 'jsonpath={.spec.template.spec.containers[?(@.name=="gateway")].env[?(@.name=="MAX_INSTANCES")].value}')
[ "$max_instances" = 30 ] || die "deployed MAX_INSTANCES is $max_instances, expected 30"
quota_pods=$(k -n "$INSTANCE_NAMESPACE" get resourcequota "$fullname" \
    -o 'jsonpath={.spec.hard.pods}')
[ "$quota_pods" = 30 ] || die "deployed Pod quota is $quota_pods, expected 30"
node_label=$(k get node "$node" -o 'jsonpath={.metadata.labels.workload}')
[ "$node_label" = untrusted-qemu ] || die "challenge node label was not retained"

gateway_image_id=$(docker image inspect --format '{{.Id}}' "$gateway_image")
challenge_image_id=$(docker image inspect --format '{{.Id}}' "$challenge_image")
gateway_archive_sha256=$(sha256sum "$gateway_archive" | awk '{print $1}')
challenge_archive_sha256=$(sha256sum "$challenge_archive" | awk '{print $1}')
tls_certificate_sha256=$(sha256sum "$TLS_CERT_FILE" | awk '{print $1}')
export DEPLOY_NODE="$node" DEPLOY_GATEWAY_IMAGE="$gateway_image"
export DEPLOY_CHALLENGE_IMAGE="$challenge_image" DEPLOY_GATEWAY_IMAGE_ID="$gateway_image_id"
export DEPLOY_CHALLENGE_IMAGE_ID="$challenge_image_id"
export DEPLOY_GATEWAY_ARCHIVE_SHA256="$gateway_archive_sha256"
export DEPLOY_CHALLENGE_ARCHIVE_SHA256="$challenge_archive_sha256"
export DEPLOY_TLS_CERTIFICATE_SHA256="$tls_certificate_sha256"
export DEPLOY_GIT_COMMIT
DEPLOY_GIT_COMMIT=$(git -C "$ADMIN_ROOT" rev-parse HEAD 2>/dev/null || printf unknown)
deployment_file="$RUNTIME_DIR/deployment.json"
deployment_tmp="$deployment_file.tmp.$$"
python3 - <<'PY' > "$deployment_tmp"
from __future__ import annotations
import json
import os
from datetime import datetime, timezone

record = {
    "schema": 1,
    "deployedAt": datetime.now(timezone.utc).isoformat(),
    "gitCommit": os.environ["DEPLOY_GIT_COMMIT"],
    "node": os.environ["DEPLOY_NODE"],
    "release": os.environ["RELEASE_NAME"],
    "gatewayNamespace": os.environ["GATEWAY_NAMESPACE"],
    "instanceNamespace": os.environ["INSTANCE_NAMESPACE"],
    "ctfdBaseUrl": os.environ["CTFD_BASE_URL"],
    "ctfdChallengeId": int(os.environ["CTFD_CHALLENGE_ID"]),
    "capacity": 30,
    "service": {
        "type": os.environ["PUBLIC_SERVICE_TYPE"],
        "port": 31337,
    },
    "images": {
        "gateway": {
            "reference": os.environ["DEPLOY_GATEWAY_IMAGE"],
            "imageId": os.environ["DEPLOY_GATEWAY_IMAGE_ID"],
            "archiveSha256": os.environ["DEPLOY_GATEWAY_ARCHIVE_SHA256"],
        },
        "challenge": {
            "reference": os.environ["DEPLOY_CHALLENGE_IMAGE"],
            "imageId": os.environ["DEPLOY_CHALLENGE_IMAGE_ID"],
            "archiveSha256": os.environ["DEPLOY_CHALLENGE_ARCHIVE_SHA256"],
        },
    },
    "tlsCertificateSha256": os.environ["DEPLOY_TLS_CERTIFICATE_SHA256"],
}
if os.environ.get("GATEWAY_DOMAIN", "").strip():
    record["gatewayDomain"] = os.environ["GATEWAY_DOMAIN"].strip()
json.dump(record, __import__("sys").stdout, indent=2, sort_keys=True)
print()
PY
mv -f "$deployment_tmp" "$deployment_file"
chmod 0600 "$deployment_file"

trap - EXIT INT TERM
cleanup_secret_file
note "deployment complete: release=$RELEASE_NAME node=$node capacity=30"
echo '[RECLAIM-Q2-K3S-DEPLOY-PASS]'
