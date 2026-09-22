ROOT := $(abspath .)
CHART := $(ROOT)/chart/reclaim-gateway
BROKER := $(ROOT)/broker
BUILD := $(ROOT)/build
RENDERED := $(BUILD)/reclaim-gateway-rendered.yaml
FLAG_FILE ?=
HELM_IMAGE ?= alpine/helm:3.18.6@sha256:c6d8088ddb279625a2e1ca3b08b22c18c946d1f65c8b810f28f1597435a1134c
GATEWAY_IMAGE ?= q2-reclaim-gateway:local
REDIS_IMAGE ?= redis:7.4.2-alpine@sha256:02419de7eddf55aa5bcf49efb74e88fa8d931b4d77c07eff8a6b2144472b6952
CTFD_IMAGE ?= ctfd/ctfd:3.8.5@sha256:476211f53cc3e675cce72bcb495484d890da0a6d48d5de919577912c6da8d4ff
SERVICE_BUNDLE ?= $(abspath ../.runtime/reclaim-box-000-service-private.tar.gz)

.PHONY: test lint chart-gates render audit image image-smoke redis-test ctfd-compat e2e real-e2e package

test:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$(BROKER)" \
		python3 -m unittest discover -s "$(BROKER)/tests" -v
	python3 -c 'import ast,pathlib; [ast.parse(p.read_text(), filename=str(p)) for p in pathlib.Path("$(BROKER)/reclaim_gateway").glob("*.py")]'

lint:
	docker run --rm -v "$(ROOT):/work:ro" \
		"$(HELM_IMAGE)" lint /work/chart/reclaim-gateway

chart-gates:
	HELM_IMAGE="$(HELM_IMAGE)" bash "$(ROOT)/test-chart-gates.sh"

render:
	mkdir -p "$(BUILD)"
	docker run --rm -v "$(ROOT):/work:ro" \
		"$(HELM_IMAGE)" template reclaim /work/chart/reclaim-gateway \
		> "$(RENDERED)"

image:
	docker build -t "$(GATEWAY_IMAGE)" "$(BROKER)"

image-smoke: image
	docker run --rm --network none --read-only \
		--tmpfs /tmp:rw,noexec,nosuid,nodev,size=4m \
		--cap-drop ALL --security-opt no-new-privileges:true \
		--entrypoint python "$(GATEWAY_IMAGE)" -c \
		'import os,ssl,redis,reclaim_gateway; assert os.getuid()==65532; ssl.create_default_context(); print("[Q2-GATEWAY-IMAGE-SMOKE-PASS]")'

redis-test: image
	@set -eu; \
	name="q2-redis-test-$$$$"; net="q2-redis-net-$$$$"; \
	password="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"; \
	cleanup() { docker container rm -f "$$name" >/dev/null 2>&1 || true; docker network rm "$$net" >/dev/null 2>&1 || true; }; \
	trap cleanup EXIT INT TERM; \
	docker network create "$$net" >/dev/null; \
	docker run -d --name "$$name" --network "$$net" --network-alias redis \
		-e REDIS_PASSWORD="$$password" "$(REDIS_IMAGE)" \
		sh -ec 'exec redis-server --save "" --appendonly no --requirepass "$$REDIS_PASSWORD"' >/dev/null; \
	for attempt in $$(seq 1 40); do \
		if docker exec -e REDISCLI_AUTH="$$password" "$$name" redis-cli ping 2>/dev/null | grep -qx PONG; then break; fi; \
		[ "$$attempt" -lt 40 ] || { docker logs "$$name"; exit 1; }; \
		sleep 0.25; \
	done; \
	docker run --rm --network "$$net" \
		-e PYTHONPATH=/app -e REDIS_TEST_HOST=redis -e REDIS_TEST_PASSWORD="$$password" \
		-v "$(ROOT)/e2e/test_redis_state.py:/test_redis_state.py:ro" \
		--entrypoint python "$(GATEWAY_IMAGE)" /test_redis_state.py

ctfd-compat:
	docker run --rm --network none \
		-e SECRET_KEY=ctfd-compat-test-only \
		-e DATABASE_URL=sqlite:////tmp/ctfd-compat.db \
		-e UPLOAD_FOLDER=/tmp/uploads -e LOG_FOLDER=/tmp/logs \
		-v "$(BROKER):/gateway:ro" \
		-v "$(ROOT)/e2e/test_ctfd_compat.py:/test_ctfd_compat.py:ro" \
		--entrypoint python "$(CTFD_IMAGE)" /test_ctfd_compat.py

audit: test lint chart-gates render image-smoke redis-test ctfd-compat
	python3 "$(ROOT)/audit-rendered.py" \
		--rendered "$(RENDERED)" --source-root "$(ROOT)" \
		$(if $(FLAG_FILE),--flag-file "$(FLAG_FILE)",)

e2e:
	bash "$(ROOT)/e2e/run-kind-e2e.sh"

real-e2e:
	@test -f "$(SERVICE_BUNDLE)" || { echo 'private service bundle is missing' >&2; exit 1; }
	REAL_SERVICE_BUNDLE="$(SERVICE_BUNDLE)" E2E_HOST_PORT=23138 \
		bash "$(ROOT)/e2e/run-kind-e2e.sh"

package: audit
	python3 "$(ROOT)/package-reference.py" \
		--source "$(ROOT)" --output "$(BUILD)/q2-reclaim-kubernetes.tar.gz" \
		$(if $(FLAG_FILE),--flag-file "$(FLAG_FILE)",)
