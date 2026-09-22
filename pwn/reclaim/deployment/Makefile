SHELL := /bin/bash
ROOT := $(abspath .)
RUNTIME := $(ROOT)/.runtime
SERVICE_BUNDLE := $(RUNTIME)/reclaim-box-000-service-private.tar.gz

.PHONY: help preflight deploy status smoke audit audit-artifacts mock-e2e real-e2e service-bundle compose-up compose-down

help:
	@printf '%s\n' \
	  'cp .env.example .env && edit required values plus the exposure gate' \
	  'sudo make preflight   # host/config/artifact checks' \
	  'sudo make deploy      # build, import and Helm deploy to single-node k3s' \
	  'sudo make status      # Kubernetes object status' \
	  'sudo make smoke       # authenticated uid-1000 round trip (prompts for token)'

preflight:
	./scripts/preflight.sh

deploy:
	./scripts/deploy.sh

status:
	./scripts/status.sh

smoke:
	./scripts/smoke.sh

audit:
	python3 ./scripts/audit-release.py
	./scripts/test-public-exposure-gate.sh
	docker compose -f docker-compose.yaml config >/dev/null
	$(MAKE) -C kubernetes audit

audit-artifacts: audit
	@test -f service/bzImage -a -f service/rootfs.cpio.gz || { echo 'extract the service Release asset first' >&2; exit 1; }
	(cd service && sha256sum -c SHA256SUMS)

mock-e2e:
	$(MAKE) -C kubernetes e2e

service-bundle:
	mkdir -p "$(RUNTIME)"
	python3 ./scripts/package-service.py --source service --output "$(SERVICE_BUNDLE)"

real-e2e: service-bundle
	$(MAKE) -C kubernetes real-e2e SERVICE_BUNDLE="$(SERVICE_BUNDLE)"

compose-up:
	docker compose -f docker-compose.yaml up --build

compose-down:
	docker compose -f docker-compose.yaml down --remove-orphans
