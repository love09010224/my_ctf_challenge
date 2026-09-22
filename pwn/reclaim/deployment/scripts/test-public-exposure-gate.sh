#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

expect_pass() {
    local service_type=$1 ranges=$2 allow=$3
    (
        PUBLIC_SERVICE_TYPE=$service_type
        LOAD_BALANCER_SOURCE_RANGES=$ranges
        ALLOW_PUBLIC_SERVICE=$allow
        validate_public_exposure
    )
}

expect_fail() {
    if expect_pass "$@" >/dev/null 2>&1; then
        printf 'exposure gate unexpectedly accepted: type=%s ranges=%s allow=%s\n' \
            "$1" "$2" "$3" >&2
        exit 1
    fi
}

expect_fail LoadBalancer '' 0
expect_fail LoadBalancer ' , ' 0
expect_pass LoadBalancer '167.179.87.240/32' 0
expect_pass LoadBalancer '' 1
expect_fail NodePort '' 0
expect_pass NodePort '' 1
expect_fail ClusterIP '' 1
expect_fail LoadBalancer '' true

echo '[RECLAIM-PUBLIC-EXPOSURE-GATE-PASS]'
