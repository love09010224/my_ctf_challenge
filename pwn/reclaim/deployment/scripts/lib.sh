#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ADMIN_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
RUNTIME_DIR=${RUNTIME_DIR:-$ADMIN_ROOT/.runtime}
CONFIG_FILE=${CONFIG_FILE:-$ADMIN_ROOT/.env}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

note() {
    printf '[reclaim] %s\n' "$*"
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

load_config() {
    [ -f "$CONFIG_FILE" ] || die "missing $CONFIG_FILE; copy .env.example to .env"
    # The file is administrator-controlled and must contain shell-style KEY=value lines.
    set -a
    # shellcheck disable=SC1090
    . "$CONFIG_FILE"
    set +a

    : "${CTFD_BASE_URL:?CTFD_BASE_URL is required}"
    : "${CTFD_CHALLENGE_ID:?CTFD_CHALLENGE_ID is required}"
    : "${TLS_CERT_FILE:?TLS_CERT_FILE is required}"
    : "${TLS_KEY_FILE:?TLS_KEY_FILE is required}"

    CTFD_REQUIRE_TEAM=${CTFD_REQUIRE_TEAM:-true}
    CTFD_CA_FILE=${CTFD_CA_FILE:-}
    CTFD_EGRESS_CIDRS=${CTFD_EGRESS_CIDRS:-}
    KUBERNETES_API_EGRESS_CIDRS=${KUBERNETES_API_EGRESS_CIDRS:-}
    KUBERNETES_API_ENDPOINT_EGRESS_CIDRS=${KUBERNETES_API_ENDPOINT_EGRESS_CIDRS:-}
    KUBERNETES_API_ENDPOINT_EGRESS_PORT=${KUBERNETES_API_ENDPOINT_EGRESS_PORT:-}
    K3S_NODE_NAME=${K3S_NODE_NAME:-}
    PUBLIC_SERVICE_TYPE=${PUBLIC_SERVICE_TYPE:-LoadBalancer}
    PUBLIC_NODE_PORT=${PUBLIC_NODE_PORT:-31337}
    LOAD_BALANCER_IP=${LOAD_BALANCER_IP:-}
    LOAD_BALANCER_SOURCE_RANGES=${LOAD_BALANCER_SOURCE_RANGES:-}
    ALLOW_PUBLIC_SERVICE=${ALLOW_PUBLIC_SERVICE:-0}
    SMOKE_CONNECT_HOST=${SMOKE_CONNECT_HOST:-}
    SMOKE_CA_FILE=${SMOKE_CA_FILE:-}
    RELEASE_NAME=${RELEASE_NAME:-reclaim}
    GATEWAY_NAMESPACE=${GATEWAY_NAMESPACE:-reclaim-gateway}
    INSTANCE_NAMESPACE=${INSTANCE_NAMESPACE:-reclaim-instances}
    GATEWAY_DOMAIN=${GATEWAY_DOMAIN:-}
    ALLOW_SMALL_HOST=${ALLOW_SMALL_HOST:-0}
    export CTFD_REQUIRE_TEAM CTFD_CA_FILE CTFD_EGRESS_CIDRS
    export KUBERNETES_API_EGRESS_CIDRS KUBERNETES_API_ENDPOINT_EGRESS_CIDRS
    export KUBERNETES_API_ENDPOINT_EGRESS_PORT K3S_NODE_NAME PUBLIC_SERVICE_TYPE
    export PUBLIC_NODE_PORT LOAD_BALANCER_IP LOAD_BALANCER_SOURCE_RANGES
    export ALLOW_PUBLIC_SERVICE
    export RELEASE_NAME GATEWAY_NAMESPACE INSTANCE_NAMESPACE GATEWAY_DOMAIN
    export SMOKE_CONNECT_HOST SMOKE_CA_FILE
    export ALLOW_SMALL_HOST
}

validate_public_exposure() {
    case "$ALLOW_PUBLIC_SERVICE" in
        0|1) ;;
        *) die "ALLOW_PUBLIC_SERVICE must be 0 or 1" ;;
    esac

    case "$PUBLIC_SERVICE_TYPE" in
        LoadBalancer)
            if [ -z "$(printf '%s' "$LOAD_BALANCER_SOURCE_RANGES" | tr -d '[:space:],')" ] \
                && [ "$ALLOW_PUBLIC_SERVICE" != 1 ]; then
                die "LoadBalancer without source ranges is public; set a staging LOAD_BALANCER_SOURCE_RANGES CIDR or explicitly set ALLOW_PUBLIC_SERVICE=1"
            fi
            ;;
        NodePort)
            [ "$ALLOW_PUBLIC_SERVICE" = 1 ] \
                || die "NodePort may bypass host UFW rules; explicitly set ALLOW_PUBLIC_SERVICE=1"
            ;;
        *) die "PUBLIC_SERVICE_TYPE must be LoadBalancer or NodePort" ;;
    esac
}

prepare_network_policy_egress() {
    local ctfd_host resolved_ips api_ip api_endpoints api_endpoint_port normalized
    ctfd_host=$(python3 - <<'PY'
from os import environ
from urllib.parse import urlsplit
print(urlsplit(environ["CTFD_BASE_URL"]).hostname or "")
PY
)
    [ -n "$ctfd_host" ] || die "cannot derive the CTFd hostname"
    resolved_ips=$(getent ahostsv4 "$ctfd_host" \
        | awk '$2 == "STREAM" {print $1}' | sort -u)
    [ -n "$resolved_ips" ] || die "CTFd hostname has no IPv4 address: $ctfd_host"

    if [ -z "$CTFD_EGRESS_CIDRS" ]; then
        CTFD_EGRESS_CIDRS=$(printf '%s\n' "$resolved_ips" \
            | awk 'BEGIN { ORS="" } { printf "%s%s/32", (NR == 1 ? "" : ","), $1 }')
    else
        normalized=$(printf '%s' "$CTFD_EGRESS_CIDRS" | tr -d '[:space:]')
        while IFS= read -r api_ip; do
            case ",$normalized," in
                *",$api_ip/32,"*) ;;
                *) die "CTFD_EGRESS_CIDRS does not include current A record $api_ip/32" ;;
            esac
        done <<<"$resolved_ips"
        CTFD_EGRESS_CIDRS=$normalized
    fi

    api_ip=$(k -n default get service kubernetes -o jsonpath='{.spec.clusterIP}')
    [ -n "$api_ip" ] && [ "$api_ip" != None ] \
        || die "cannot derive Kubernetes API Service IP"
    if [ -z "$KUBERNETES_API_EGRESS_CIDRS" ]; then
        KUBERNETES_API_EGRESS_CIDRS="$api_ip/32"
    else
        normalized=$(printf '%s' "$KUBERNETES_API_EGRESS_CIDRS" | tr -d '[:space:]')
        case ",$normalized," in
            *",$api_ip/32,"*) ;;
            *) die "KUBERNETES_API_EGRESS_CIDRS does not include Service IP $api_ip/32" ;;
        esac
        KUBERNETES_API_EGRESS_CIDRS=$normalized
    fi
    read -r api_endpoint_port api_endpoints < <(
        k -n default get endpointslices \
            -l kubernetes.io/service-name=kubernetes -o json \
        | python3 -c '
import ipaddress, json, sys
data = json.load(sys.stdin)
addresses = set()
ports = set()
for item in data.get("items", []):
    for endpoint in item.get("endpoints", []):
        if endpoint.get("conditions", {}).get("ready") is False:
            continue
        for address in endpoint.get("addresses", []):
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                continue
            if parsed.version == 4:
                addresses.add(str(parsed))
    for endpoint_port in item.get("ports", []):
        if endpoint_port.get("name") == "https" and endpoint_port.get("protocol", "TCP") == "TCP":
            ports.add(endpoint_port.get("port"))
if not addresses or len(ports) != 1 or None in ports:
    raise SystemExit("Kubernetes API EndpointSlice is incomplete")
print(next(iter(ports)), ",".join(f"{address}/32" for address in sorted(addresses)))
'
    )
    [ -n "$api_endpoints" ] && [ -n "$api_endpoint_port" ] \
        || die "cannot derive Kubernetes API EndpointSlice address and port"
    if [ -z "$KUBERNETES_API_ENDPOINT_EGRESS_CIDRS" ]; then
        KUBERNETES_API_ENDPOINT_EGRESS_CIDRS=$api_endpoints
    else
        normalized=$(printf '%s' "$KUBERNETES_API_ENDPOINT_EGRESS_CIDRS" | tr -d '[:space:]')
        while IFS= read -r api_ip; do
            case ",$normalized," in
                *",$api_ip,"*) ;;
                *) die "KUBERNETES_API_ENDPOINT_EGRESS_CIDRS does not include $api_ip" ;;
            esac
        done < <(printf '%s' "$api_endpoints" | tr ',' '\n')
        KUBERNETES_API_ENDPOINT_EGRESS_CIDRS=$normalized
    fi
    if [ -n "$KUBERNETES_API_ENDPOINT_EGRESS_PORT" ] \
        && [ "$KUBERNETES_API_ENDPOINT_EGRESS_PORT" != "$api_endpoint_port" ]; then
        die "KUBERNETES_API_ENDPOINT_EGRESS_PORT does not match EndpointSlice port $api_endpoint_port"
    fi
    KUBERNETES_API_ENDPOINT_EGRESS_PORT=$api_endpoint_port
    export CTFD_EGRESS_CIDRS KUBERNETES_API_EGRESS_CIDRS
    export KUBERNETES_API_ENDPOINT_EGRESS_CIDRS KUBERNETES_API_ENDPOINT_EGRESS_PORT
}

release_fullname() {
    # render-values.py restricts RELEASE_NAME so this cannot require Helm's
    # truncation branch. Keeping the derivation here avoids fragile selectors.
    printf '%s-reclaim-gateway\n' "$RELEASE_NAME"
}

first_certificate_dns_name() {
    openssl x509 -in "$TLS_CERT_FILE" -noout -ext subjectAltName 2>/dev/null \
        | awk '
            {
                for (i = 1; i <= NF; i++) {
                    if ($i ~ /^DNS:/) {
                        sub(/^DNS:/, "", $i)
                        sub(/,$/, "", $i)
                        if ($i !~ /\*/) {
                            print $i
                            exit
                        }
                    }
                }
            }
        '
}

init_kubernetes_clients() {
    if [ -n "${KUBECTL_BIN:-}" ]; then
        read -r -a KUBECTL_COMMAND <<<"$KUBECTL_BIN"
    elif command -v k3s >/dev/null 2>&1; then
        KUBECTL_COMMAND=(k3s kubectl)
    elif command -v kubectl >/dev/null 2>&1; then
        KUBECTL_COMMAND=(kubectl)
    else
        die "missing k3s kubectl or kubectl"
    fi

    if [ -n "${HELM_BIN:-}" ]; then
        read -r -a HELM_COMMAND <<<"$HELM_BIN"
    elif command -v helm >/dev/null 2>&1; then
        HELM_COMMAND=(helm)
    else
        die "missing helm"
    fi

    if [ -n "${KUBECONFIG_PATH:-}" ]; then
        export KUBECONFIG=$KUBECONFIG_PATH
    elif [ -r /etc/rancher/k3s/k3s.yaml ]; then
        export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
    fi
}

k() {
    "${KUBECTL_COMMAND[@]}" "$@"
}

h() {
    "${HELM_COMMAND[@]}" "$@"
}

single_node_name() {
    local count name
    count=$(k get nodes -o name | wc -l)
    [ "$count" -eq 1 ] || die "local-image deployment requires exactly one node; found $count"
    name=${K3S_NODE_NAME:-$(k get nodes -o jsonpath='{.items[0].metadata.name}')}
    [ -n "$name" ] || die "cannot determine the k3s node name"
    k get node "$name" >/dev/null
    printf '%s\n' "$name"
}
