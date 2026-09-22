# RE:CLAIM 최소 서비스 납품

> **역사적 문서:** 아래 내용은 challenge/service 최소 납품 경계를 동결한 시점의 기록입니다.
> 최종 30-slot Kubernetes 운영 계약은 `capacity-and-acceptance.md`와
> `../deployment/kubernetes/README.md`를 기준으로 합니다.


## 결정

문제 제작자가 제공하는 범위는 다음 두 산출물로 제한합니다.

1. 참가자에게 공개하는 local player archive
2. 실제 대회 flag가 든 initramfs와 단일 QEMU TCP wrapper를 포함하는 비공개
   organizer service archive

CTFd 연동, 계정·팀 인증, 동적 port 할당, instance 생성·삭제·renew, 전체 용량
제어, 방화벽과 모니터링은 대회 운영 측의 책임입니다. 저장소의 기존 reference
Instancer는 공식 납품물에 넣지 않습니다.

## 생성

최종 kernel과 remote rootfs를 이미 검증한 workspace에서 실행합니다.

```sh
make v4-minimal-handoff
```

결과:

```text
build/v4handoff-minimal/
├── RELEASE-MANIFEST.txt
├── reclaim-box-000-player.tar.gz
└── reclaim-box-000-service-private.tar.gz
```

`service-private` archive는 실제 flag를 포함하므로 public file server, CTFd의
challenge download, public container registry에 올리면 안 됩니다. CTFd에는
별도 안전 채널로 전달한 canonical flag를 등록합니다.

## 서비스 계약

비공개 archive를 풀면 다음 파일이 있습니다.

```text
Dockerfile
README.md
SHA256SUMS
bzImage
docker-compose.example.yml
entrypoint.sh
rootfs.cpio.gz
run-qemu.sh
service-contract.json
```

기본 계약은 다음과 같습니다.

- container base는 검증한 Ubuntu 24.04 `linux/amd64` manifest
  `sha256:019e8eb29a85e74d64925745884f2ec79aa27e3feab36353d24656f4d6b89467`
  로 고정합니다. 상위 multi-arch index는
  `sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea`입니다.
- image는 TCP `31337`을 노출합니다.
- container 하나는 QEMU guest 하나와 client 하나를 담당합니다.
- 첫 TCP 연결 뒤 guest가 부팅합니다.
- reset은 container 교체입니다.
- 인증은 없으며 운영 측 proxy/instancer가 담당합니다.
- 기본 VM timeout은 900초입니다.
- `/dev/kvm`, host device, volume, privileged mode는 필요하지 않습니다.
- guest에는 emulated NIC가 없습니다.

따라서 운영 측 인스턴서는 최소한 다음 동작만 구현하면 됩니다.

1. 팀에 container 하나를 할당합니다.
2. container `31337/tcp`를 팀 전용 endpoint에 연결합니다.
3. endpoint 접근을 인증하거나 추측 불가능하게 보호합니다.
4. 900초 또는 운영 정책에 따라 container를 제거합니다.
5. 재생성 요청에서는 기존 container를 제거하고 새 container를 만듭니다.

`service-contract.json`은 위 값을 자동화 도구가 읽을 수 있는 형태로 제공합니다.

## 단독 smoke test

```sh
tar -xzf reclaim-box-000-service-private.tar.gz
sha256sum -c SHA256SUMS
docker compose -f docker-compose.example.yml up --build
nc 127.0.0.1 31337
```

Docker 없이 검증할 때는 Ubuntu 24.04의 QEMU를 사용합니다.

```sh
SERIAL_BIND_HOST=127.0.0.1 ./entrypoint.sh
```

## 운영 측 필수 보안 조건

- 비공개 rootfs/image를 참가자에게 배포하지 않습니다.
- 고정 shared port 하나를 인증 없이 모든 팀에 제공하지 않습니다.
- container는 non-root, read-only, capability 없음으로 실행합니다.
- 권장 상한은 memory 640 MiB, CPU 2, PID 128입니다.
- Docker bridge에서 시작되는 불필요한 outbound 연결을 host firewall에서
  차단합니다.
- 실제 대회 host에서 최종 TCP 경로와 실제 flag 제출을 한 번 검증합니다.
- base image digest만으로 `apt` package repository까지 재현되지는 않습니다. 검증한
  최종 service image를 private registry에 push하고, 행사 배포는 그 최종 manifest
  digest를 사용하며 현장에서 다시 빌드하지 않습니다.

이 조건을 만족하는 한 운영 측은 자체 CTFd plugin, Kubernetes, Docker 기반
인스턴서 또는 별도 TCP gateway 중 원하는 방식을 선택할 수 있습니다.

## 선택 가능한 Kubernetes reference

CTFd plugin과 팀별 public port를 운영하기 어려운 현장을 위해 별도의 reference
implementation을 `deploy/kubernetes/`에 제공합니다. 공식 최소 납품 범위나
제작자 유지보수 책임이 확장되는 것은 아닙니다.

이 방식은 다음과 같이 동작합니다.

```text
단일 TLS domain:31337
    -> Token: <participant CTFd Access Token>
    -> CTFd /api/v1/users/me에서 team_id 검증
    -> 팀별 Kubernetes Job + private ClusterIP Service
    -> QEMU :31337
```

CTFd에는 standard challenge와 Connection Info만 두며 plugin이나 관리자 API
token이 필요 없습니다. 토큰 검증에는 gateway Pod에서 접근할 수 있는 CTFd HTTPS
base URL이 필요하고, 선택적으로 numeric challenge ID를 설정해 해당 문제가 실제로
보이는지도 확인합니다. 참가자 bearer token은 gateway에서 소비하고 guest에는
전달하지 않습니다.

Gateway와 untrusted QEMU Job은 별도 namespace에 배치하며, instance namespace는
service-account token 없음, 전체 Pod egress 차단, gateway에서 오는 31337 ingress만
허용합니다. 실제 설치·TLS·private registry·용량·검사 절차는
[`deployment/kubernetes/README.md`](../deployment/kubernetes/README.md)를 따르십시오.
