#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"
load_config
init_kubernetes_clients

fullname=$(release_fullname)
node=$(single_node_name)

printf 'RE:CLAIM release: %s\n' "$RELEASE_NAME"
printf 'single node:       %s\n' "$node"
printf 'global capacity:   30\n'
printf '\n[gateway namespace]\n'
k -n "$GATEWAY_NAMESPACE" get deployment "$fullname" "$fullname-redis" -o wide
k -n "$GATEWAY_NAMESPACE" get service "$fullname" "$fullname-redis" -o wide
k -n "$GATEWAY_NAMESPACE" get pods \
    -l "app.kubernetes.io/instance=$RELEASE_NAME" -o wide

printf '\n[instance namespace]\n'
k -n "$INSTANCE_NAMESPACE" get resourcequota "$fullname"
k -n "$INSTANCE_NAMESPACE" get jobs,pods,services \
    -l reclaim.hspace.io/managed=true -o wide

max_instances=$(k -n "$GATEWAY_NAMESPACE" get deployment "$fullname" \
    -o 'jsonpath={.spec.template.spec.containers[?(@.name=="gateway")].env[?(@.name=="MAX_INSTANCES")].value}')
[ "$max_instances" = 30 ] || die "MAX_INSTANCES drifted to $max_instances"
quota_pods=$(k -n "$INSTANCE_NAMESPACE" get resourcequota "$fullname" \
    -o 'jsonpath={.spec.hard.pods}')
[ "$quota_pods" = 30 ] || die "Pod quota drifted to $quota_pods"
node_label=$(k get node "$node" -o 'jsonpath={.metadata.labels.workload}')
[ "$node_label" = untrusted-qemu ] || die "node workload label is missing"

k -n "$GATEWAY_NAMESPACE" rollout status "deployment/$fullname-redis" --timeout=5s >/dev/null
k -n "$GATEWAY_NAMESPACE" rollout status "deployment/$fullname" --timeout=5s >/dev/null

active_jobs=$(k -n "$INSTANCE_NAMESPACE" get jobs \
    -l reclaim.hspace.io/managed=true --no-headers 2>/dev/null | wc -l)
[ "$active_jobs" -le 30 ] || die "managed Job count exceeds the thirty-slot contract"

printf '\n[RECLAIM-Q2-K3S-STATUS-PASS] active_jobs=%s capacity=30\n' "$active_jobs"
