# RE:CLAIM production acceptance

이 문서는 현재 production artifact와 **서로 다른 30팀 × 팀당 1세션** 운영 계약을
승인한 근거입니다. 날짜가 없는 예전 smoke 문구보다 이 결과가 우선합니다.

- 검증일: 2026-09-15 (KST)
- production event cutover: Helm revision 11, 실제 CTFd challenge ID 31,
  `pwnable2.roomescapectf2026.site:31337`

## 고정 운영 계약

- 전역 active QEMU VM: 정확히 30개
- 팀 제한: 같은 `team_id`는 서로 다른 개인 Access Token이어도 active/queued 합계 1개
- 31번째 이후 팀: Pod/Job/Service를 만들지 않는 Redis FIFO
- instance timeout: 900초
- instance resource: request `250m / 640Mi`, limit `2 CPU / 640Mi`
- guest: `2 vCPU / 512 MiB`, TCG, NIC 없음
- disconnect/guest 종료: Job과 Service 삭제를 확인한 뒤 slot 반납

## 승인 artifact

| Artifact | SHA-256 |
| --- | --- |
| production `service/rootfs.cpio.gz` | `87c508c6e459102a60f6899c946c76c6209df8ace6fdefd92548788ea48dc7b3` |
| production rootfs의 stripped module | `d3448db0fed9ae561fcba3e9e69fa7ee45b8d3fa67e4bc2af51062b8c75d3f76` |
| canonical Route 2 exploit | `4bf27c63ccf36a28e586765d7fcadf7617ce227425538be32bf3966dc298301d` |
| public player archive | `e7036d5a345960ad172bbab3dea5530ca718bf5f6936a24b8c9c1ffc2ee9fc66` |

참가자 archive와 reference exploit은 topology 안정화 전후로 변경되지 않았습니다.

## 검증 환경

- GCP `t2d-standard-60`
- online/logical CPU 60, physical core 60, thread per core 1 (SMT 없음)
- Kubernetes allocatable CPU 60
- instance 30개 합계 request 7.5 CPU / 18.75 GiB
- instance 30개 합계 limit 60 CPU / 18.75 GiB
- private HTTPS CTFd mock, 개발 전용 고정 flag vault, 공개 ingress 차단

부하 시험은 실제 대회 flag가 출력될 수 없는 development vault에서 수행했습니다.
각 client는 한 번만 연결했고 exploit 재접속이나 client-level retry를 사용하지
않았습니다. Route 2 terminal 제한은 client당 720초였습니다.

## 결과

| 시험 | 결과 | 가장 늦은 terminal |
| --- | ---: | ---: |
| Route 2 single | 1/1 | 66.648초 |
| Route 1 cold 30-way | 30/30 | 8.573초 |
| Route 2 cold 30-way batch 1 | 30/30 | 168.898초 |
| Route 2 cold 30-way batch 2 | 30/30 | 134.125초 |
| Route 2 cold 30-way batch 3 | 30/30 | 158.464초 |

- 관측된 최대 host CPU: 76.1%
- 관측된 최대 aggregate QEMU RSS: 약 7.28 GiB
- 모든 batch 전후 managed Job/Pod/Service: 0
- 모든 batch 전후 challenge Redis queue/queued/active: 0
- capacity 시험 중 실제 대회 flag 출력: 0

이 결과로 위 T2D topology에서 가장 무거운 Route 2까지 30명 동시 성공 계약을
승인합니다. 다른 CPU topology, 더 적은 physical core, 다른 guest/resource 값으로 이
결과를 자동 상속하지 않습니다.

## 안정화 변경의 범위

이전 Route 2의 간헐 실패 원인은 host CPU 포화가 아니었습니다.
`reclaim_archive_ctx_create()`가 무작위 RB-tree에서 topology candidate 네 개 이상을
필요로 하면서 32개 layout만 시도했고, 모두 실패하면 잘못된 `-ENOMEM`을 반환하는
초기화 lottery가 있었습니다. 현재 module은 이 invariant를 세우는 시도 상한만
512로 올렸습니다.

취약점, consumer, 무작위 topology, reference exploit과 public player archive는
그대로입니다. exploit의 retry 상한을 늘리거나 더 큰 host로 실패를 가린 변경이
아닙니다.

## 완료된 범위와 event cutover

완료:

- 30 active + Pod-free FIFO + same-team 1연결 control-plane E2E
- development vault에서 Route 1 30/30 및 Route 2 연속 세 batch 30/30
- production rootfs/image build와 artifact audit
- production image의 uid 1000 비 exploit smoke 및 완전 cleanup
- 실제 CTFd HTTPS URL과 numeric challenge ID 31 적용
- 외부 방화벽을 닫은 상태에서 실제 CTFd authenticated uid-1000 smoke와 cleanup
- `pwnable2.roomescapectf2026.site` DNS 및 TLS hostname SAN 검증
- LoadBalancer source range 공개와 `reclaim-server` tag 전용 GCP TCP/31337 방화벽 개방
- 외부 hostname-verified TLS smoke와 cleanup
- CTFd Connection Info를
  `ncat --ssl pwnable2.roomescapectf2026.site 31337`로 반영

실제 대회 flag를 사용하는 30-way 또는 반복 exploit 시험은 수행하지 않았습니다.
capacity 증거는 위 development-vault 결과를 사용하고, 실제 flag terminal은 참가자
solve 경로에서만 발생시킵니다.

문제가 생기면 CTFd 문구를 먼저 바꾸는 대신 TCP/31337 방화벽과 LoadBalancer source
range를 다시 차단해 rollback합니다.
