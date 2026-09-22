# RE:CLAIM Q-2 Kubernetes 인프라

Problem B의 Q-2 `RE:CLAIM`을 하나의 참가자용 TCP/TLS endpoint 뒤에서 운영하는
gateway, Redis FIFO, 동적 QEMU Job용 Helm chart입니다. CTFd plugin이나 Docker
socket은 사용하지 않습니다.

## 확정 계약

- 참가자가 `Token:` prompt에 입력한 **CTFd Access Token**을 CTFd REST API로 직접
  검증합니다.
- 전역 QEMU 용량은 코드와 chart 모두 **정확히 30슬롯**으로 고정합니다.
- 같은 `team_id`는 서로 다른 개인 token이어도 active 또는 queued 연결을 합쳐서
  1개뿐입니다.
- 31번째 이후 연결은 Pod를 만들지 않고 Redis FIFO에서 기다립니다.
- slot을 받은 participant session마다 새 Job과 ClusterIP Service를 만듭니다. 같은
  allocation 안에서의 `ensure` 재호출만 idempotent하게 같은 object를 확인합니다.
- client disconnect, guest 종료/실패 또는 900초 만료 시 Job과 Service를 삭제합니다.
- active slot은 Kubernetes 삭제가 확인된 뒤에만 Redis에서 반납합니다.
- token과 raw CTFd team ID는 Redis, Kubernetes object, guest, log에 남기지 않습니다.

```text
participant (ncat/pwntools, TLS)
        │ Token: <CTFd Access Token>
        ▼
reclaim-gateway namespace
  gateway Deployment (replica 1)
        ├── GET CTFd /api/v1/users/me
        ├── optional GET /api/v1/challenges/<numeric-id>
        ├── team identity → HMAC-SHA256 → 24자리 opaque ID
        └── dedicated Redis FIFO / active lock
                       │
             first thirty only
                       ▼
reclaim-instances namespace
  fresh QEMU Job + private ClusterIP Service :31337
```

CTFd는 회원·팀·문제 공개·flag 채점만 담당합니다. 인스턴스 생성 버튼, custom
challenge type, CTFd 관리자 token은 필요하지 않습니다.

## 검증된 production 기준

30팀 acceptance를 통과한 host는 GCP `t2d-standard-60`입니다. 60 logical CPU가
각각 별도 physical core이고 SMT가 없으며, Kubernetes allocatable CPU도 60입니다.
각 Pod는 guest `2 vCPU / 512 MiB`를 유지하면서 request `250m/640Mi`, limit
`2 CPU/640Mi`를 사용합니다. 따라서 30개 합계는 request 7.5 CPU/18.75 GiB,
limit 60 CPU/18.75 GiB입니다.

이 환경에서 Route 1 30/30과 가장 무거운 Route 2의 독립적인 cold 30-way 세 batch가
모두 30/30으로 끝났습니다. client 재접속/retry는 없었고 모든 batch 뒤 object와
Redis state가 0으로 돌아왔습니다. 상세 수치와 artifact hash는
[`../ACCEPTANCE.md`](../ACCEPTANCE.md)를 참조합니다.

2026-09-15 실제 CTFd challenge ID 31, hostname SAN 인증서, DNS와 public
TCP/31337 전환을 완료했습니다. Helm release `reclaim` revision 11에서 production
image와 30-slot resource contract를 유지하며 외부 verified-TLS smoke와 cleanup을
통과했습니다.

## CTFd 인증

Gateway는 참가자의 token으로 아래 요청을 보냅니다.

```http
GET /api/v1/users/me
Authorization: Token <participant token>
Accept: application/json
Content-Type: application/json
```

CTFd 3.x 호환을 위해 GET에도 JSON `Content-Type`을 넣습니다. 응답의 `team_id`를
사용하며 `ctfd.requireTeam=true`이면 팀이 없는 계정을 거부합니다. banned 계정,
timeout, redirect, 비정상 JSON과 non-success 응답은 모두 fail-closed입니다.
`ctfd.challengeId`를 지정하면 참가자 token으로 해당 numeric challenge endpoint도
조회합니다.

실제 배포 전에 다음 값을 확정합니다.

- gateway에서 접근 가능한 CTFd HTTPS base URL
- private CA를 쓰는 경우 CA Secret과 `ctfd.caSecret`
- team 대회 여부인 `ctfd.requireTeam`
- 선택적인 numeric `ctfd.challengeId`

CORS는 browser 요청이 아닌 server-to-server 요청이므로 필요하지 않습니다.

## FIFO와 lifecycle

Redis에는 다음 challenge 전용 key만 사용합니다.

```text
q2:reclaim:queue   # 24자리 opaque ID의 FIFO list
q2:reclaim:queued  # opaque ID → random 32자리 connection ID
q2:reclaim:active  # opaque ID → random 32자리 connection ID
```

raw token, `team:<id>`, username은 저장하지 않습니다. Gateway는 한 replica로 고정해
Redis 전이와 Kubernetes 할당을 직렬화합니다.

1. token을 검증하고 raw identity를 즉시 버립니다.
2. HMAC으로 opaque ID를 만든 뒤 active/queued 중복 팀을 거부합니다.
3. FIFO head이면서 active 수가 30 미만인 연결 하나만 승격합니다.
4. 승격된 뒤에만 새 Job과 Service를 만듭니다.
5. non-consuming readiness와 EndpointSlice ready 상태를 확인한 뒤 QEMU backend에
   정확히 한 번 연결합니다.
6. 연결 종료 시 Service와 Job의 삭제를 확인하고 active slot을 반납합니다.

기본값은 instance 900초, queue 대기 3600초, 준비 전 client input 64 KiB입니다.
Gateway rollout은 `Recreate`입니다. 새 gateway는 이전 연결이 모두 끊긴 상태에서
관리 대상 orphan Job/Service를 먼저 지우고 challenge 전용 Redis state를 초기화합니다.

### QEMU readiness 주의사항

실제 service는 QEMU를 다음과 같은 one-client serial listener로 실행합니다.

```text
-chardev socket,...,server=on,wait=on
```

따라서 TCP readiness probe나 별도의 시험 연결은 참가자의 유일한 QEMU 연결을
소비하므로 금지합니다. 동적 Pod는 `/proc/net/tcp{,6}`의 listen 상태를 읽는 exec
probe를 사용합니다. Gateway는 ready EndpointSlice를 두 번 관측한 뒤 backend에 한
번만 연결하고, 첫 guest serial byte를 보존해 참가자에게 전달합니다.

## 보안 경계

- Kubernetes 이름/label은 secret-keyed HMAC의 24자리 hex ID만 사용합니다.
- HMAC/TLS/Redis Secret은 `reclaim-gateway` namespace에, untrusted QEMU Job은
  `reclaim-instances` namespace에 둡니다.
- QEMU Pod는 service-account token 없음, non-root, read-only rootfs, capabilities
  없음, privilege escalation 금지, `RuntimeDefault` seccomp로 실행합니다.
- instance namespace 전체에 deny-all egress를 적용하고 gateway에서 오는 TCP
  31337 ingress만 허용합니다.
- Redis는 private ClusterIP이며 gateway-only ingress, deny-all egress입니다.
- Gateway egress는 cluster DNS, Redis, managed instance TCP 31337,
  Kubernetes API Service/backend exact `/32`와 현재 CTFd HTTPS exact `/32`만
  허용합니다. kube-router는 API Service DNAT 이후 node endpoint를 정책 평가하므로
  wrapper가 현재 ready EndpointSlice 주소와 port도 함께 고정합니다. 표준
  NetworkPolicy에는 FQDN peer가 없으므로 CTFd A record도 배포 직전에 다시 확인해
  values에 고정합니다.
- Gateway Role은 instance namespace의 Job/Service `get,list,create,delete`와
  EndpointSlice `list`만 허용합니다. Secret, Pod/exec, cluster-wide 권한은 없습니다.
- 실제 flag가 든 challenge image는 private registry에만 두고 digest로 고정합니다.

`NetworkPolicy`는 사용하는 CNI가 실제 집행해야 합니다. 행사 전 instance Pod에서
internet, CTFd, Kubernetes API, 다른 namespace로의 egress가 막히는지 실측합니다.

Pod PID limit은 Pod resource field가 아니라 kubelet 설정입니다. 전용 challenge
worker의 `podPidsLimit`을 128로 설정하고 실제 QEMU Pod의 cgroup `pids.max`를
확인합니다. Worker에는 label과 taint를 적용해 다른 workload와 분리합니다.

## 이미지 준비

이 저장소의 권장 single-node k3s 배포는 상위 `deployment`에서 다음 명령으로
수행합니다.

```sh
cp .env.example .env
# 네 필수 값을 수정
sudo make -C .. deploy
```

상위 배포기는 `service/`의 실제 flag-bearing context와 이 directory의 gateway를
`linux/amd64` content tag로 로컬 build하고, 명시적인 amd64 image archive를 single-node
k3s containerd에 import합니다. private registry가 필요하지 않습니다.

아래 방식은 multi-node나 외부 registry를 직접 운영할 때만 사용합니다.

현재 directory에서 gateway image를 빌드합니다.

```sh
docker build -t registry.internal.example/reclaim-gateway:1.0.0 broker
docker push registry.internal.example/reclaim-gateway:1.0.0
```

`../service/`의 image에는 실제 flag-bearing rootfs가 있으므로 public registry에
올리면 안 됩니다. multi-node 방식에서는 두 image 모두 E2E가 통과한 private registry
digest를 `values-production.yaml`에 기록합니다.

## namespace와 Secret

```sh
kubectl create namespace reclaim-gateway
kubectl create namespace reclaim-instances

kubectl label namespace reclaim-gateway \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest
kubectl label namespace reclaim-instances \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest

umask 077
openssl rand 48 > instance-name-hmac
openssl rand -hex 32 > redis-password

kubectl -n reclaim-gateway create secret generic reclaim-gateway-secrets \
  --from-file=instance-name-hmac=./instance-name-hmac
kubectl -n reclaim-gateway create secret generic reclaim-q2-redis-auth \
  --from-file=password=./redis-password
kubectl -n reclaim-gateway create secret tls reclaim-gateway-tls \
  --cert=fullchain.pem --key=privkey.pem
```

Private registry credential은 instance namespace에 만듭니다.

```sh
kubectl -n reclaim-instances create secret docker-registry registry-credentials \
  --docker-server=REGISTRY \
  --docker-username=USERNAME \
  --docker-password=PASSWORD
```

HMAC secret은 행사 도중 회전하지 않습니다. Secret 원문과 실제 production values는
repository에 commit하지 않습니다.

## 배포

```sh
cp values-production.example.yaml values-production.yaml
# URL, challenge ID, image digest, node placement를 실제 값으로 수정

helm upgrade --install reclaim chart/reclaim-gateway \
  --namespace reclaim-gateway \
  -f values-production.yaml
```

`challenge.maxInstances`는 tuning 값이 아니라 확정 계약이므로 30 이외의 값을 chart가
거부합니다. 기본 QEMU resource는 instance당 request `250m/640Mi`, limit
`2 CPU/640Mi`이고 30개 합계 request는 7.5 CPU/18.75 GiB, limit은 60 CPU/18.75 GiB입니다.
상위 wrapper의 production preflight는 physical core 60개, visible RAM 60 GiB와
free disk 30 GiB를 최소 gate로 검사합니다. 이 수치는 임의로 줄일 tuning 값이
아니며 다른 topology에는 기존 acceptance를 그대로 적용하지 않습니다.

K3s ServiceLB/NodePort는 호스트 UFW 규칙보다 먼저 패킷을 처리할 수 있습니다. 내부
검증용 직접 Helm 배포에서는 `service.loadBalancerSourceRanges`를 운영자 source
CIDR로 제한하고, 외부 TCP 시험으로 실제 차단을 확인합니다. 공개 전환은 이 값을
의도적으로 제거하는 별도 변경으로 취급합니다. 상위 `deployment` wrapper는 빈 범위를
쓸 때 `ALLOW_PUBLIC_SERVICE=1`을 요구해 실수로 즉시 공개되는 것을 막습니다.

직접 TLS 종료 시 `tls.mode=direct`를 사용합니다. 외부 장비가 TLS를 종료하면
`tls.mode=upstream`과 `service.type=ClusterIP`을 함께 사용해야 하며 chart가 외부
plaintext 노출을 거부합니다. `plaintext`는 명시적으로 허용한 로컬 개발 전용입니다.

CTFd Connection Info 예시는 다음 한 줄입니다.

```text
ncat --ssl pwnable2.roomescapectf2026.site 31337
```

참가자는 CTFd `/settings`에서 Access Token을 만들고 prompt에 입력합니다. token을
shell argument나 URL에 넣지 않습니다.

## 검증

현재 directory에서 실행합니다.

```sh
make test          # broker unit tests
make ctfd-compat   # unmodified CTFd 3.8.5 실제 token 검증
make audit         # unit + Helm gates/render + image + Redis + CTFd 감사
make e2e           # 임시 kind에서 mock 32팀/30슬롯/FIFO/cleanup E2E
make real-e2e      # private QEMU bundle의 uid-1000 shell smoke
make package       # build/q2-reclaim-kubernetes.tar.gz
```

`make e2e`는 다음을 실제 Redis state와 Kubernetes object로 검사합니다.

- 1~30번 팀에 서로 다른 Job/Pod/Service 30개 생성
- 31·32번 팀은 Pod 없이 FIFO position 1·2
- active 하나 종료 시 31번만 승격되고 32번은 계속 대기
- active/queued 팀의 중복 연결과 invalid token 거부
- Redis 및 object에 opaque ID와 random connection ID만 존재
- instance egress 차단
- 모든 socket 종료 후 Job/Pod/Service 0개
- token/raw team identity의 object와 log 누출 없음

상위 `deployment`의 `make real-e2e`는 `service/`에서
`.runtime/reclaim-box-000-service-private.tar.gz`를 결정적으로 만든 뒤 그 bundle을
사용합니다. 이 directory에서 직접 실행할 때도 그 경로가 기본값이며, 다른 위치라면
`SERVICE_BUNDLE=/secure/reclaim-box-000-service-private.tar.gz`를 지정합니다.
이 검사는 uid 1000 shell 왕복만 수행하고 exploit/flag를 읽지 않으며 flag 형태 출력이
하나라도 있으면 실패합니다.

`make package` 결과는 private service bundle, build tool, rendered output, credential,
flag를 포함하지 않는 결정적 source archive입니다. 동일 source에서 반복 생성한
SHA-256이 같아야 합니다.

30 active, 31·32번째 Pod-free FIFO, same-team 중복 거부와 development-vault 30-way
solver acceptance를 완료했습니다. 실제 event flag로 부하 시험을 반복하지 않은 채,
실제 CTFd/인증서의 내부 authenticated uid-1000 smoke를 먼저 통과한 다음 DNS,
LoadBalancer 공개 source range와 tag-scoped TCP/31337 방화벽을 열었습니다. 외부
hostname-verified TLS smoke와 cleanup, CTFd Connection Info 반영도 완료됐습니다.
문제가 생기면 CTFd 문구만 바꾸지 말고 firewall과 source range를 먼저 재차단합니다.
세부 순서는 [`../README.md`](../README.md)의 “Event cutover 순서”를 따릅니다.
