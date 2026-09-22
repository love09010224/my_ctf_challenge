# RE:CLAIM — BOX 000 서버 번들

> **Post-event 공개본:** 이 디렉터리의 두 대용량 binary는 GitHub Release의
> `reclaim-box-000-service-private.tar.gz`에 있습니다. archive를 이 디렉터리에 풀면
> 아래 무결성·실행 절차를 그대로 사용할 수 있습니다.


> **비공개 운영자 전용:** `rootfs.cpio.gz`에는 실제 대회 flag가 들어 있습니다.
> 이 archive나 이 archive에서 만든 image를 참가자 또는 public registry에
> 공개하지 마십시오.

이 번들은 문제 VM을 TCP로 한 번 실행할 수 있는 최소 구성만 제공합니다.
CTFd plugin, 팀 인증, port 할당, instance 생성·삭제, renew, 전체 동시접속 제한과
운영 모니터링은 포함하지 않습니다.

Dockerfile의 Ubuntu 24.04 base는 검증에 사용한 `linux/amd64` manifest
`sha256:019e8eb29a85e74d64925745884f2ec79aa27e3feab36353d24656f4d6b89467`
로 고정돼 있습니다. 이 manifest가 속한 release index는
`sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea`입니다.

## 파일 무결성

```text
bzImage          c71f589dc3e84c00006821cb60869e59c452e03300ae9dd045fd218fb525feb8
rootfs.cpio.gz   87c508c6e459102a60f6899c946c76c6209df8ace6fdefd92548788ea48dc7b3
player archive   e7036d5a345960ad172bbab3dea5530ca718bf5f6936a24b8c9c1ffc2ee9fc66
```

압축을 푼 디렉터리에서 확인합니다.

```sh
sha256sum -c SHA256SUMS
```

## 단일 서비스 실행

Docker Compose가 있다면 다음 명령만으로 loopback에서 실행할 수 있습니다.

```sh
docker compose -f docker-compose.example.yml up --build
nc 127.0.0.1 31337
```

QEMU는 첫 TCP client를 기다린 뒤 부팅합니다. 기본 VM 제한 시간은 900초입니다.
종료하거나 초기화하려면 container를 제거하고 새로 만드십시오.
TCP serial 경로에서는 guest echo만 끄고 `nc`/`ncat`이 연결된 참가자 로컬 tty의
echo를 사용합니다. 따라서 BusyBox의 cursor-position 질의 응답이 화면에
`^[[<row>;<col>R`로 노출되지 않으며, 입력 명령도 한 번만 표시됩니다.

base digest를 고정해도 `apt-get` repository 내용까지 고정되는 것은 아닙니다.
현재 rootfs를 포함한 production image는 30-way acceptance 뒤 별도의 비 exploit
uid-1000 smoke까지 통과한 승격 대상입니다. 행사 포트를 여는 단계에서 이 context를
수정하거나 image를 다시 빌드하지 마십시오. single-node wrapper는 content-derived
local tag와 `.runtime/images/` archive를 보존해 같은 image를 재사용합니다. 이를
삭제했거나 새 host에서 다시 만들었다면 새 artifact로 보고 전체 audit와 acceptance를
다시 수행해야 합니다. multi-node라면 검증 직후 private registry에 push하고 registry가
반환한 digest를 고정합니다.

Docker 없이 Ubuntu 24.04의 `qemu-system-x86_64`와 GNU `timeout`을 사용해
확인할 수도 있습니다.

```sh
SERIAL_BIND_HOST=127.0.0.1 ./entrypoint.sh
```

## 인스턴서 연동 계약

- container image는 TCP `31337`을 노출합니다.
- container 하나가 QEMU guest 하나와 TCP serial client 하나를 담당합니다.
- guest는 NIC가 없으며 KASLR, PTI, SMEP, SMAP과 TCG 인자가 고정돼 있습니다.
- reset은 기존 container 삭제 후 새 container 생성입니다.
- `VM_TIMEOUT_SECONDS`의 기본값은 900이며 `0`은 운영자가 명시적으로 외부
  lifecycle을 강제할 때만 사용할 수 있습니다.
- 확정 production 제한은 memory `640 MiB`, CPU `2`, PID `128`, read-only rootfs,
  capability 없음, `no-new-privileges`, `/tmp` 4 MiB tmpfs입니다.
- persistent volume, host device, `/dev/kvm`, privileged mode는 필요하지 않습니다.

이 서비스에는 **인증 기능이 없습니다.** 할당 port를 그대로 인터넷에 노출하면
다른 팀이 먼저 접속할 수 있습니다. 운영 측 인스턴서나 TCP proxy가 팀 인증,
port 소유권, TTL과 동시접속 제한을 반드시 구현해야 합니다.

CTFd에는 별도 안전 채널로 전달된 canonical 실제 flag를 등록하십시오. 참가자에게는
이 서버 번들이 아니라 manifest에 적힌 public player archive만 제공합니다.
30팀 기준 resource, Route 1/E 결과와 완료된 public cutover 증거는
[`../ACCEPTANCE.md`](../ACCEPTANCE.md)를 참조하십시오.
