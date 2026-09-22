# RE:CLAIM 운영자 배포 안내

> **Post-event 공개본:** 대회 당시 private였던 운영 코드입니다. `service/bzImage`와
> `service/rootfs.cpio.gz`는 Git history에 넣지 않았으며 GitHub Release의
> `reclaim-box-000-service-private.tar.gz`를 `service/`에 풀어 복원합니다. 실제 배포 전
> `.env.example`을 복사하고 모든 endpoint와 credential을 새로 설정하십시오.


> `service/rootfs.cpio.gz`에는 실제 대회 flag가 있습니다. 행사 중에는 운영자
> 전용이었지만 현재는 대회 종료 후 공개 자료입니다. 계정 credential은 포함하지 않습니다.

## Production quick start

30팀/Route 2 acceptance를 통과한 기준 머신은 Ubuntu 24.04 x86-64의 GCP
`t2d-standard-60`입니다. 이 머신은 **60 logical CPU = 60 physical core**, SMT 없음,
약 240 GiB RAM인 single-node k3s입니다. 전체 결과와 artifact hash는
[`ACCEPTANCE.md`](ACCEPTANCE.md)를 기준으로 합니다.

Preflight는 logical CPU 수가 아니라 online CPU topology의 고유한
`(physical_package_id, core_id)` 쌍을 세어 physical core 60개 이상을 요구합니다.
visible RAM 60 GiB와 free disk 30 GiB gate도 유지합니다. 다른 CPU topology나 더
작은 host는 단순 smoke에만 쓸 수 있고 30명 동시 성공 결과를 상속하지 않습니다.

Docker와 Helm이 설치되고 k3s API가 Ready인 상태에서 실행합니다. K3s kubelet에는
`pod-max-pids=128`을 설정해야 하며 preflight가 live configz 값을 검사합니다.

```sh
cd pwn/reclaim/deployment
cp .env.example .env
$EDITOR .env

sudo make preflight
sudo make deploy
sudo make status
```

기본적으로 바꿀 값은 다음 항목과 공개 범위 gate입니다.

```text
CTFD_BASE_URL
CTFD_CHALLENGE_ID
TLS_CERT_FILE
TLS_KEY_FILE
GATEWAY_DOMAIN
```

내부 검증 중에는 운영자/서버의 source CIDR만 허용합니다.

```text
LOAD_BALANCER_SOURCE_RANGES=203.0.113.10/32
ALLOW_PUBLIC_SERVICE=0
```

K3s ServiceLB와 NodePort의 iptables 경로는 호스트 UFW보다 먼저 처리될 수 있으므로,
UFW에 31337 허용 규칙이 없다는 사실만으로 비공개라고 판단하면 안 됩니다. 최종 외부
검증 직전에만 source range를 비우고 `ALLOW_PUBLIC_SERVICE=1`을 명시한 뒤 다시
`make preflight && make deploy`합니다. Wrapper는 source range가 빈 LoadBalancer나
모든 NodePort를 이 승인 없이 거부합니다.

`GATEWAY_DOMAIN`은 설치할 인증서의 실제 DNS SAN과 일치해야 합니다. DNS 전환 전
smoke에는 `SMOKE_CONNECT_HOST`에 LoadBalancer IP를 넣어 SNI와 접속 주소를
분리합니다. private CA나 고정 LoadBalancer IP가 필요할 때만 그 밖의 값을
수정합니다. Gateway
egress용 CTFd A record와 Kubernetes API Service 및 ready
EndpointSlice IP는 배포 직전에 각각 exact `/32`로 자동 산출하며, 필요할 때만
`.env`에서 고정할 수 있습니다. `.env`, TLS key와 `.runtime/`은 Git에서 제외됩니다.

`deploy.sh`는 다음을 한 번에 수행합니다.

1. 공개/player와 비공개 service artifact hash, host 자원, 인증서와 CTFd HTTPS
   도달성을 검사합니다.
2. gateway와 flag-bearing QEMU service image를 로컬에서 `linux/amd64`로 빌드합니다.
3. content-derived tag로 두 image를 single-node k3s containerd에 import합니다.
4. gateway/instance namespace와 Pod Security label을 만듭니다.
5. HMAC·Redis password를 최초 한 번만 생성하고 TLS Secret과 함께 갱신합니다.
6. node placement label을 설정하고 Helm release를 설치/갱신합니다.
7. gateway/Redis rollout과 실제 30-slot 설정을 확인합니다.
8. gateway egress를 cluster DNS, Redis, instance TCP 31337, Kubernetes API의
   exact Service/backend 쌍과 현재 CTFd HTTPS `/32`로만 제한합니다.

HMAC과 Redis password는 Kubernetes Secret에 최초 한 번만 생성되며 재배포 때 기존
값을 검증해 그대로 재사용합니다. 생성 과정의 임시 원문은 즉시 삭제합니다.
content-tagged image archive, 비밀 없는 runtime values와 배포 기록만
`deployment/.runtime/`에 mode 0700/0600으로 보관됩니다. HMAC Secret을 행사 도중
삭제하거나 바꾸지 마십시오.

`deploy.sh`는 service tree의 content-derived tag가 이미 로컬에 있으면 검증한 image를
재사용합니다. Acceptance를 통과한 production image/tag와 `.runtime/images/` archive를
최종 포트 개방 직전에 삭제하거나 service context를 수정하지 마십시오. 새 host에서
image를 다시 빌드하거나 context가 바뀌면 새 artifact로 간주하고 audit와 acceptance를
다시 수행해야 합니다.

## CTFd 설정

CTFd에 복사할 전체 필드와 참가자 공개 문구는 상위
[`CTFD_DESCRIPTION.md`](../CTFD_DESCRIPTION.md)가 기준입니다. 현재 live challenge는
다음과 같습니다.

- Name: `RE:CLAIM — BOX 000`
- Category: `추가 의뢰`
- Type: `dynamic` (`logarithmic`, initial `1000`, minimum `200`, decay `9`)
- State: `visible`
- Attribution: `KERN3L_P4N!C`
- Download: GitHub Release의 `reclaim-box-000-player.tar.gz`
- Flag: `../solutions/route-2/README.md`에 기록된 canonical 값
- Connection Info: `ncat --ssl pwnable2.roomescapectf2026.site 31337`

생성된 numeric challenge ID를 `.env`의 `CTFD_CHALLENGE_ID`에 입력합니다.
Gateway에는 관리자 token이나 CTFd DB/Redis credential을 주지 않습니다. 참가자가
prompt에 입력한 Access Token으로 `/api/v1/users/me`와 challenge endpoint를 직접
검증합니다.

## 운영 smoke

실제 참가자 token 하나로 uid 1000 shell 왕복과 disconnect cleanup을 확인합니다.
이 검사는 exploit이나 flag를 읽지 않습니다.

```sh
sudo make smoke
```

DNS 전환 전에는 `.env`에 `GATEWAY_DOMAIN`(TLS SNI)과
`SMOKE_CONNECT_HOST`(LoadBalancer IP)를 지정합니다. public CA가 아니라면
`SMOKE_CA_FILE`도 지정합니다. token은 숨김 prompt로 받고 명령행에 남기지 않습니다.

로컬 single-VM build contract만 확인할 때는 다음을 사용합니다. 이 Compose endpoint는
인증이 없으므로 loopback 밖으로 노출하지 않습니다.

```sh
make compose-up
nc 127.0.0.1 31337
make compose-down
```

전체 source audit과 격리된 kind E2E:

```sh
make audit
make mock-e2e
make real-e2e
```

30팀 control-plane과 development vault 부하 시험은 이미 완료됐으며 수치는
`ACCEPTANCE.md`에 고정돼 있습니다. 공개 전에는 그 시험을 실제 flag로 반복하지
말고, 아래 cutover에서 실제 CTFd token을 사용하는 비 exploit smoke와 최종 제출
경로만 확인합니다.

## 배포 계약

- 외부 공개 포트: gateway TCP/TLS 31337 하나
- 전역 QEMU: 정확히 30개
- 팀당 active 또는 queued 연결: 1개
- 31번째 이후: Pod 없이 Redis FIFO
- timeout: 900초
- disconnect/guest 종료: Job과 Service 즉시 삭제
- identity: HMAC 24자리 opaque ID만 Redis/Kubernetes에 저장
- instance namespace: service-account token 없음, deny-all egress

QEMU serial listener는 한 client만 받을 수 있습니다. TCP readiness probe나 임의의
backend 시험 연결을 추가하지 마십시오. 현재 구현은 `/proc/net/tcp{,6}`의 listen
상태와 EndpointSlice를 연결 없이 확인한 뒤 participant socket 하나만 전달합니다.

## Event cutover 순서

아래 순서는 2026-09-15 실제 event cutover에서 완료됐습니다. 현재 endpoint는
`pwnable2.roomescapectf2026.site:31337`이고 Helm release `reclaim` revision 11,
실제 CTFd challenge ID 31, 공개 LoadBalancer와 GCP의 tag-scoped TCP/31337 규칙을
사용합니다. 재배포나 rollback 때도 같은 순서를 유지하십시오.

1. `.env`에 실제 CTFd HTTPS URL, numeric challenge ID와 필요한 CA를 적용합니다.
2. 실제 gateway domain을 포함한 TLS 인증서/key를 설치하고 SAN을 확인합니다.
3. `LOAD_BALANCER_SOURCE_RANGES`를 운영자 `/32`로 둔 채
   `sudo make preflight && sudo make deploy && sudo make status`를 실행합니다.
4. `GATEWAY_DOMAIN`은 실제 SNI, `SMOKE_CONNECT_HOST`는 내부/LoadBalancer IP로 두고
   verified-TLS `sudo make smoke`와 cleanup을 확인합니다.
5. DNS record를 준비하고 의도한 주소와 인증서가 일치하는지 확인합니다.
6. 마지막 공개 변경에서만 source range를 비우고 `ALLOW_PUBLIC_SERVICE=1`로 배포한
   뒤 GCP ingress TCP/31337 방화벽을 엽니다.
7. 외부 네트워크에서 verified-TLS smoke와 Job/Pod/Service/Redis cleanup을
   확인합니다.
8. 마지막으로 CTFd Connection Info가 위 실제 endpoint와 일치하고
   Description이 기준 본문과 일치하는지 확인한 뒤 실제 flag 제출 경로를
   확인합니다.

Rollback은 먼저 GCP TCP/31337 방화벽을 닫고 LoadBalancer source range를 운영자
`/32`로 되돌린 뒤 상태를 조사합니다. CTFd 문구만 지워 공개 endpoint를 남겨 두지
마십시오.

## Single-node 제한

로컬 image import 방식은 Problem B 전용 single-node k3s를 전제로 합니다. node가 둘
이상이면 script가 중단됩니다. multi-node로 확장할 때는 private registry에 최종 image를
push하고 digest를 고정한 뒤 별도 운영 변경으로 전환해야 합니다.
