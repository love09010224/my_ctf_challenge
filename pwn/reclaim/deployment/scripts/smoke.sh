#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"
load_config
init_kubernetes_clients

fullname=$(release_fullname)
server_name=${GATEWAY_DOMAIN:-}
if [ -z "$server_name" ]; then
    server_name=$(first_certificate_dns_name)
fi
[ -n "$server_name" ] || die "set GATEWAY_DOMAIN; no DNS SAN was found in TLS_CERT_FILE"

service_port=31337
connect_host=${SMOKE_CONNECT_HOST:-}
if [ -z "$connect_host" ]; then
    if [ "$PUBLIC_SERVICE_TYPE" = LoadBalancer ]; then
        connect_host=$(k -n "$GATEWAY_NAMESPACE" get service "$fullname" \
            -o 'jsonpath={.status.loadBalancer.ingress[0].ip}')
        if [ -z "$connect_host" ]; then
            connect_host=$(k -n "$GATEWAY_NAMESPACE" get service "$fullname" \
                -o 'jsonpath={.status.loadBalancer.ingress[0].hostname}')
        fi
    else
        connect_host=$(k get node "$(single_node_name)" \
            -o 'jsonpath={.status.addresses[?(@.type=="ExternalIP")].address}')
        if [ -z "$connect_host" ]; then
            connect_host=$(k get node "$(single_node_name)" \
                -o 'jsonpath={.status.addresses[?(@.type=="InternalIP")].address}')
        fi
        service_port=$PUBLIC_NODE_PORT
    fi
fi
[ -n "$connect_host" ] || die "cannot determine the public endpoint; set SMOKE_CONNECT_HOST"

token=${CTFD_ACCESS_TOKEN:-}
if [ -z "$token" ] && [ -n "${CTFD_ACCESS_TOKEN_FILE:-}" ]; then
    [ -r "$CTFD_ACCESS_TOKEN_FILE" ] || die "cannot read CTFD_ACCESS_TOKEN_FILE"
    IFS= read -r token < "$CTFD_ACCESS_TOKEN_FILE" || true
fi
if [ -z "$token" ]; then
    if [ -t 0 ]; then
        IFS= read -r -s -p 'Participant CTFd Access Token: ' token
        printf '\n' >&2
    else
        IFS= read -r token || true
    fi
fi
[ -n "$token" ] || die "participant CTFd Access Token is empty"

args=(
    --host "$connect_host"
    --port "$service_port"
    --server-name "$server_name"
)
if [ -n "$SMOKE_CA_FILE" ]; then
    args+=(--ca-file "$SMOKE_CA_FILE")
fi

printf '%s\n' "$token" | python3 "$SCRIPT_DIR/smoke_gateway.py" "${args[@]}"
token=
unset CTFD_ACCESS_TOKEN || true
