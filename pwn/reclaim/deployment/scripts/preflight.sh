#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"
load_config
init_kubernetes_clients
validate_public_exposure

for command in docker k3s openssl curl python3 sha256sum awk grep df flock base64 getent; do
    require_command "$command"
done

[ "$(uname -m)" = x86_64 ] || die "the service requires an x86-64 host"
[ "$CTFD_CHALLENGE_ID" != REPLACE_WITH_NUMERIC_CHALLENGE_ID ] || die "set CTFD_CHALLENGE_ID in .env"
[ -r "$TLS_CERT_FILE" ] || die "cannot read TLS_CERT_FILE"
[ -r "$TLS_KEY_FILE" ] || die "cannot read TLS_KEY_FILE"
if [ -n "$CTFD_CA_FILE" ]; then
    [ -r "$CTFD_CA_FILE" ] || die "cannot read CTFD_CA_FILE"
fi
if [ -n "$SMOKE_CA_FILE" ]; then
    [ -r "$SMOKE_CA_FILE" ] || die "cannot read SMOKE_CA_FILE"
fi

openssl x509 -in "$TLS_CERT_FILE" -noout -checkend 604800 >/dev/null \
    || die "TLS certificate expires in less than seven days"
cert_key=$(openssl x509 -in "$TLS_CERT_FILE" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
private_key=$(openssl pkey -in "$TLS_KEY_FILE" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
[ "$cert_key" = "$private_key" ] || die "TLS certificate and private key do not match"
if [ -n "$GATEWAY_DOMAIN" ]; then
    openssl x509 -in "$TLS_CERT_FILE" -noout -checkhost "$GATEWAY_DOMAIN" >/dev/null \
        || die "TLS certificate does not cover GATEWAY_DOMAIN"
fi

docker info >/dev/null
k get --raw=/readyz >/dev/null
h version --short >/dev/null
docker image save --help 2>&1 | grep -q -- '--platform' \
    || die "docker image save must support --platform"
node=$(single_node_name)
prepare_network_policy_egress
arch=$(k get node "$node" -o jsonpath='{.status.nodeInfo.architecture}')
[ "$arch" = amd64 ] || die "Kubernetes node architecture is $arch, expected amd64"
pod_pids_limit=$(k get --raw "/api/v1/nodes/$node/proxy/configz" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("kubeletconfig", {}).get("podPidsLimit", ""))')
[ "$pod_pids_limit" = 128 ] \
    || die "kubelet podPidsLimit is $pod_pids_limit, expected 128"

logical_cpus=$(nproc)
physical_cores=$(python3 - <<'PY'
from pathlib import Path

pairs = set()
for cpu in Path("/sys/devices/system/cpu").glob("cpu[0-9]*"):
    online = cpu / "online"
    if online.is_file() and online.read_text(encoding="ascii").strip() != "1":
        continue
    try:
        package_id = (cpu / "topology/physical_package_id").read_text(
            encoding="ascii"
        ).strip()
        core_id = (cpu / "topology/core_id").read_text(encoding="ascii").strip()
    except OSError:
        continue
    pairs.add((package_id, core_id))
print(len(pairs))
PY
)
mem_kib=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
disk_kib=$(df -Pk "$ADMIN_ROOT" | awk 'NR==2 {print $4}')
if [ "$ALLOW_SMALL_HOST" != 1 ]; then
    [ "$physical_cores" -ge 60 ] || die "at least 60 online physical CPU cores are required for the accepted 30-slot contract (logical=$logical_cpus physical=$physical_cores); set ALLOW_SMALL_HOST=1 only for a smoke host"
    [ "$mem_kib" -ge 62914560 ] || die "at least 60 GiB visible RAM is required"
    [ "$disk_kib" -ge 31457280 ] || die "at least 30 GiB free disk is required"
fi

(cd "$ADMIN_ROOT/service" && sha256sum -c SHA256SUMS >/dev/null)
(
    cd "$ADMIN_ROOT/../handout"
    printf '%s  %s\n' \
      e7036d5a345960ad172bbab3dea5530ca718bf5f6936a24b8c9c1ffc2ee9fc66 \
      reclaim-box-000-player.tar.gz | sha256sum -c - >/dev/null
)
python3 "$SCRIPT_DIR/audit-release.py" >/dev/null

GATEWAY_IMAGE_REPOSITORY=reclaim.local/reclaim-gateway \
GATEWAY_IMAGE_TAG=preflight \
CHALLENGE_IMAGE_REPOSITORY=reclaim.local/reclaim-box-000 \
CHALLENGE_IMAGE_TAG=preflight \
    python3 "$SCRIPT_DIR/render-values.py" >/dev/null

curl_args=(
    --silent --show-error --output /dev/null --write-out '%{http_code}'
    --connect-timeout 5 --max-time 10 --max-redirs 0
    --header 'Accept: application/json' --header 'Content-Type: application/json'
)
if [ -n "$CTFD_CA_FILE" ]; then
    curl_args+=(--cacert "$CTFD_CA_FILE")
fi
status=$(curl "${curl_args[@]}" "$CTFD_BASE_URL/api/v1/users/me")
case "$status" in
    200|400|401|403) ;;
    *) die "unexpected CTFd /api/v1/users/me status: $status" ;;
esac

note "preflight pass node=$node logical_cpus=$logical_cpus physical_cores=$physical_cores memory_kib=$mem_kib disk_free_kib=$disk_kib pod_pids_limit=$pod_pids_limit"
echo '[RECLAIM-Q2-TARGET-PREFLIGHT-PASS]'
