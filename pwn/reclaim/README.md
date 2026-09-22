# RE:CLAIM — BOX 000

Room Escape CTF 2026의 추가의뢰 Q-2로 출제한 x86-64 Linux kernel pwn
문제입니다. 이 디렉터리는 대회 종료 후 공개한 포트폴리오/재현용 전체 자료입니다.

| 항목 | 내용 |
|---|---|
| 분야 | Pwn / Linux Kernel |
| Kernel | Linux 6.12.103, KASLR/PTI/SMEP/SMAP |
| 참가자 권한 | uid 1000 BusyBox shell |
| Route 1 | last-owner race → key slab page 회수 → pipe page → forged key/cred → root |
| Route 2 | archive cursor UAF → xattr/inotify 두 consumer join → HMAC key 복구 |
| 운영 | CTFd token gateway + Redis FIFO + Kubernetes QEMU Job |
| 검증 용량 | 서로 다른 30팀 × 팀당 QEMU VM 1개 |
| 결과 | 전체 팀 기준 4 solves |

## 시나리오

> 의뢰인: “정산 분쟁 때문에 000번 보관함이 폐기 대상으로 넘어갔습니다.
> 반출 게이트가 승인서 원본만 받아요. 서버에 남아 있는 제 비밀키만 빼내 주세요.”

## 디렉터리

```text
handout/       참가자 안내와 canonical archive hash
challenge/     최종 module/UAPI/gate/rootfs/kernel config/build recipe
solutions/     Route 1와 Route 2 exploit 및 writeup
deployment/    standalone service, CTFd gateway, Redis FIFO, Helm/K3s 운영 코드
docs/          설계 감사, blind 검증, 30-way capacity/acceptance 기록
artifacts/     GitHub Release artifact hash
```

## Canonical artifacts

대용량 바이너리는 Git history 대신
[GitHub Release `reclaim-v1.0.0`](https://github.com/dkstjwls06/my_ctf_challenge/releases/tag/reclaim-v1.0.0)에
첨부합니다.

| 파일 | SHA-256 |
|---|---|
| `reclaim-box-000-player.tar.gz` | `e7036d5a345960ad172bbab3dea5530ca718bf5f6936a24b8c9c1ffc2ee9fc66` |
| `reclaim-box-000-service-private.tar.gz` | `e8c0acade016afeca334883de7019953570d99c4a6fbf04f4e59d9ea31542d9f` |
| `reclaim-route-1-exploit` | `063d9b4761e83ba2f26fbd03ad9593109e9bc48050798b81841b2de64a503729` |
| `reclaim-route-2-exploit` | `4bf27c63ccf36a28e586765d7fcadf7617ce227425538be32bf3966dc298301d` |

service bundle은 최종 production topology-512 module과 실제 대회 vault를 포함합니다.
대회 종료 후 공개하는 challenge 내부 값이며, GCP·CTFd·GitHub 계정 credential은 포함하지
않습니다.

## 빠른 실행

참가자 bundle을 내려받아 실행합니다.

```sh
sha256sum -c handout/SHA256SUMS
mkdir player && tar -xzf reclaim-box-000-player.tar.gz -C player
cd player
./run.sh
```

직접 빌드하려면 [`challenge/README.md`](challenge/README.md)를 참조하십시오. canonical
binary는 Ubuntu 24.04의 고정 toolchain에서 만들어졌으므로 다른 compiler/package로
재빌드하면 기능은 같아도 byte hash는 달라질 수 있습니다.

## 운영 결과

최종 gateway는 같은 팀의 active/queued 세션을 합쳐 하나로 제한하고, 전역 30슬롯을
넘는 연결은 Pod를 생성하지 않은 채 Redis FIFO에 대기시켰습니다. Route 1 30/30과 가장
무거운 Route 2의 독립적인 cold 30-way 세 batch가 모두 30/30으로 끝났습니다. 자세한
수치와 artifact identity는
[`docs/capacity-and-acceptance.md`](docs/capacity-and-acceptance.md)에 있습니다.

대회 당시 endpoint는 `pwnable2.roomescapectf2026.site:31337`이었습니다. 현재 가용성을
보장하지 않습니다.
