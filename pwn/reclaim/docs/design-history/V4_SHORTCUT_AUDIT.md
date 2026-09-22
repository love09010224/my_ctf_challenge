# RE:CLAIM v4 whole-consumer / shortcut 감사

<!-- ORGANIZER-DOC-STATUS: CURRENT-V4-EVIDENCE -->

> **현재 v4 기술 근거:** 이 문서는 최종 v4의 설계·감사 증거입니다. 공식 납품
> 경계와 canonical hash는 [`README.md`](README.md) 및
> [`development-history.md`](../development-history.md)가 우선합니다. 아래의 CTFd/Instancer와 managed
> instance 언급은 remote 동등성 검증에 사용한 과거 harness이며 공식 납품물이
> 아닙니다. 과거 `reclaim-box-000-blind.tar.gz`는 현재 player archive와 byte-identical합니다.

날짜: 2026-08-20 KST

이 문서는 기능 성공과 공개 난도 판정을 분리합니다. 항목이 `pass`여도 fresh blind
2시간 gate를 대신하지 않으며, `pending`이 하나라도 남으면 player artifact를 만들지
않습니다.

## 최신 generic-snapshot delta

아래 초기 catalog 표보다 이 절이 최신입니다. archive 전용 selector/issue/order/lease/
next/recover ioctl은 모두 제거됐습니다. 현재 snapshot은 같은 public fingerprint에
대해 네 frame을 무작위 역할 순서로 발행합니다.

| frame 갈래 | normal receipt 효과 | stale bookmark 뒤 효과 | terminal 여부 |
|---|---|---|---|
| native-A | VIEW generation/locator-redaction | tmpfs xattr provenance 뒤 tree edge 하나 제거 | 단독 불가 |
| native-B | VIEW generation/locator-redaction | queued inotify provenance 뒤 redaction owner 하나 제거 | 단독 불가 |
| audit | APPLY가 실제 audit mask를 설정 | xattr/inotify native header에서 거부 | decoy만 |
| retention | RECONCILE이 실제 retention mask를 설정 | xattr/inotify native header에서 거부 | decoy만 |

audit+retention join은 serializer에 진짜 32-byte binary record를 추가하지만 source는
anchor payload의 별도 random region이므로 approval gate에서 거부되어야 합니다.
native-A/native-B가 같은 fingerprint에서 모두 성립해야만 anchor payload 첫 32바이트가
나옵니다. latest exact marker는
`[RELEASE-E-NORMAL-SNAPSHOT-DECOY-PASS]`, X/N/mismatch blocked marker와 matched root
marker까지 통과했습니다. normal decoy를 gate에 직접 제출하는 negative와 frame-role
side-channel whole-consumer 검사를 별도로 둡니다. 최신 exact run에서는 normal decoy를
setuid gate에 직접 제출해 `approval rejected`만 받고 root marker가 없음을 확인한
`[RELEASE-E-NORMAL-DECOY-GATE-BLOCKED-PASS]`도 통과했습니다. 따라서 normal-decoy
gate shortcut은 `pass`입니다. 추가 exact surface probe는 11개의 독립 snapshot에서
APPLY와 RECONCILE 역할의 allocation position이 각각 4개 전부, 두 native role이 차지한
위치쌍이 6개 전부 나타나는 것을 확인했습니다. 모든 passive VIEW는 locator 0이었고
역할과 allocation index가 고정되지 않았습니다. marker는
`[RELEASE-E-FRAME-ROLE-PERMUTATION-PASS] samples=11 apply=f reconcile=f native_pairs=3f`입니다.
이는 side-channel 차단 proof일 뿐 blind 난도 proof가 아닙니다.

snapshot frame 자체를 common fan-out race에 넣으면 frame kind의 stale close/apply가
다른 216-byte native owner를 해석하는 두 번째 root가 생겼습니다. release module은
frame backend에만 누락 fan-out reference를 정상 보충하고 statement/cursor root cause는
그대로 유지합니다. exact test는 frame token을 실제 two-receipt race에 넣고 ledger
owner를 철회한 뒤 같은 cache의 xattr 32개를 할당해도 두 번째 receipt가 원래 immutable
frame view를 유지함을 확인했습니다. marker는
`[RELEASE-E-FRAME-FANOUT-BALANCED-PASS]`입니다.

## 현재 구조적 변경

- `/dev/reclaim-archive` 단일 switch는 등록 전에 폐기했습니다.
- cursor issue는 case token을 직접 반환하지 않고 mixed ledger fingerprint만
  반환합니다.
- catalog frame은 전용 `DROP_FRAME` gadget이 아니라 mixed ledger의 실제 refcounted
  backend입니다. 정상 receipt는 generation을 읽지만 locator는 0으로 redaction되고,
  generic withdrawal만 마지막 owner를 해제합니다.
- module의 `page_offset_base`, `vmemmap_base`, `phys_base` relocation은 제거했습니다.
  key cohort는 page-aligned logical owner만 비교하고 workbench kernel access는
  `vmap/vunmap` lifecycle을 사용합니다. direct-map recovery는 organizer exploit의
  bounded AAR와 static kernel analysis에만 남습니다.

## Route 2 동적 negative matrix

| 후보 | 실제 관찰 | 상태 |
|---|---|---|
| 정상 catalog receipt | generation read, locator 0, APPLY/RECONCILE `EOPNOTSUPP` | pass |
| live cursor receipt | 정상 generation/nonce read, native xattr/event provenance 실패 | pass |
| stale cursor + catalog가 아직 slot owner | exact frame identity read, xattr/event header 모두 거부 | pass |
| xattr를 lease lane에 투입 | `EPROTOTYPE`, lease 불변 | pass |
| inotify event를 ordering lane에 투입 | `EPROTOTYPE`, tree 불변 | pass |
| X-only | real red right-leaf edge 제거, recovery 0 | pass |
| N-only | real lease bit 제거, recovery 0 | pass |
| mismatched X/N | 두 owner mutation, recovery 0 | pass |
| matched X/N | bounded record만 반환 | pass |
| no-challenge / wrong HMAC / replay | 각각 거부, challenge 1회 소비 | pass |
| correct HMAC | 별도 setuid gate saved-root transition과 root-only proof | pass |

`simple_xattr`의 native rb node/name/size와 queued inotify event의 list/mask/wd/name
lifecycle는 mutation 뒤에도 정상 `fgetxattr/removexattr` 및 `read()`로 확인합니다.
locator는 context의 immutable anchor domain으로 다시 매핑되므로 cred/text/external
parent를 입력하는 UAPI가 없습니다.

## Route removal

- `RECLAIM_ROUTE_KEY=0, RECLAIM_ROUTE_ARCHIVE=1`: key producer가 없는 generation에서
  Route 2 terminal 성공. 최초 evidence:
  `build/v4release/route-removal/no-key-20260820-021639/`.
- `RECLAIM_ROUTE_KEY=1, RECLAIM_ROUTE_ARCHIVE=0`: archive context/ioctl/crypto consumer가
  최적화로 제거된 module에서 Route 1 terminal 성공. 최초 evidence:
  `build/v4release/route-removal/no-archive-20260820-021704/`.
- 최신 player-vault source로 다시 빌드한 no-key module은 key allocation/lookup/put,
  keyring과 checkpoint import 없이 Route 2의 normal decoy/X/N/mismatch/matched join 및
  `SHA{test}` gate terminal에 도달했습니다. 증거는
  `build/v4candidate/route-removal-latest/no-key/`입니다.
- 최신 no-archive module은 rb-tree/xattr/inotify/evidence import와 device string 없이
  Route 1 pipe-stream AAR와 실제 randomized vault의 `SHA{test}` terminal에 도달했습니다.
  증거는 `build/v4candidate/route-removal-latest/no-archive/`입니다. Route 1가 flag를
  출력한 뒤 fake cred teardown에서 panic하는 것은 local fake-flag lifecycle로 별도
  기록하며 route independence나 blind 난도 근거로 사용하지 않습니다.

## 정적 terminal surface

`organizer/v4release/audit-static.sh`가 다음을 실패 조건으로 검사합니다.

- module import에 `commit_creds`, `prepare_kernel_cred`, usermode-helper/static-helper,
  `modprobe_path`, `core_pattern`
- module import에 direct-map bootstrap global
- monolithic archive device path 또는 dedicated frame-drop operation
- KALLSYMS, user namespace, BPF syscall, io_uring 활성화
- 비어 있지 않은 static usermode-helper path

현재 full pre-release module은 이 검사를 통과합니다. 이는 일반 kernel memory
corruption으로 가능한 모든 gadget을 부정하는 주장이 아니라, challenge가 제공한
bounded consumer가 의도한 reasoning layer를 건너뛰는 직접 shortcut을 제공하지
않는다는 최소 정적 gate입니다.

## shortcut family 최종 분류

1. ~~Route 1 normal-key replacement에 `APPLY`하여 revoke/destroy만으로 page transition
   또는 privilege가 생기는지.~~ `pass`: 24개의 알려진 donor vacancy와 한 개의
   16-object target slab만 사용하는 48-key exact probe에서 stale receipt가 정상
   replacement를 읽고 `APPLY`가 실제 revoke를 수행했지만 uid/euid 1000과 proof DAC가
   유지됐습니다. marker는 `[RELEASE-A-NORMAL-KEY-REVOKE-BLOCKED-PASS]`입니다.
2. key slab page를 controlled workbench가 아니라 cred/pipe/다른 normal page owner가
   받아 더 짧은 terminal을 만드는지. dangling receipt가 하나뿐인
   경우 full anonymous pipe page는 첫 bounded read까지 도달하지만 `pwrite`는
   `ESPIPE`, shared writable mmap은 `EACCES/ENODEV`이고, full-buffer append 및
   read/write cycle은 새 pipe buffer만 갱신하여 reclaimed page bytes가 불변이었습니다.
   exact log는 `build/v4release/route-1-pipe-shortcut.log`, marker는
   `[RELEASE-A-PIPE-FIRST-READ-BLOCKED-PASS]`입니다. 여러 receipt의 append-only pipe
   stream은 이후 Route 1의 공개 terminal carrier로 승격됐습니다. 따라서 이것을
   가려진 shortcut으로 세지 않으며, AAR 이후 task/file/receipt/pipe owner walk와
   revoke/destroy 중 어떤 late callback을 고르는지는 같은 proof layer의 허용된
   대안 endgame입니다.
3. ~~codec의 module-local entry만으로 core callback/AAR를 bootstrap하는지.~~ 초기
   callable rotate/XOR codec 세 개는 fake `key_type.read` carrier로 stale key 자기주소를
   축약 leak할 수 있어 삭제했습니다. 현재 module branch는 strict-RWX의 NX rodata
   identity만 반환합니다. `.rodata`의 13개 remaining callback carrier는 read/ioctl/
   open/release/fsync/llseek 전체를 분류했고, direct stale-object/core AAR를 반환하는
   transform은 없습니다. 정적 inventory는
   `build/v4candidate/local/codec-callback-audit.log`, marker는
   `[V4-CODEC-CALLBACK-SURFACE-PASS]`입니다.
4. schema index/compat/size family는 `pass`: effective index는 두 번째
   `ARRAY_SIZE(reclaim_codecs)` check로 0..11에 고정되고 12 및 `UINT32_MAX`는
   `ERANGE`입니다. compat handler는 동일 fixed-width UAPI를 사용하며 모든 user pointer는
   explicit `__u64` 뒤 `u64_to_user_ptr`로만 소비됩니다. receipt capacity는 PAGE_SIZE,
   publish capacity는 16, ledger index는 live count에서 각각 선행 차단됩니다.
5. readonly mirror family는 `not-applicable`: release build는
   `RECLAIM_ROUTE_WORK=0`이고 device, fops, string과 import가 최적화로 모두 제거됐습니다.
6. fake-key destroy/close는 `allowed-alternate`: controlled page address, core callback,
   valid fake cred/type까지 이미 구성한 뒤에만 가능하므로 A4 이전 proof layer를
   건너뛰지 않습니다. revoke 하나만 강제하는 one-way endgame보다 자연스러운 선택지로
   남깁니다.
7. ~~archive frame 자체의 common race.~~ `pass`: frame fan-out ref balancing과
   same-cache xattr pressure negative를 위 marker로 검증했습니다.
8. ~~gate/rootfs shortcut.~~ `pass`: uid1000 evidence/vault/write DAC, setuid 파일 단
   하나, read-only gate Dirty-Pipe-style splice/write 뒤 page-cache 불변, live gate의
   `/proc/pid/mem`, `/proc/pid/fd`, ptrace 차단과 wrong MAC 거부를 exact player rootfs에서
   확인했습니다. marker는 `[V4-GATE-SHORTCUT-BLOCKED-PASS]`입니다. interactive shell
   negative는 별도로 fresh nonce, no-response, `/proc/kallsyms` 부재까지 확인했습니다.

이 분류는 fresh blind 2시간 gate를 대체하지 않습니다. 당시 공개 후보 승격은 최신
full cold reliability와 사용자의 별도 blind 결과 뒤에만 가능했습니다.

최신 exact player-acceptance cold는 이후 완료됐습니다. 32-page carrier와 4-round race
window 가정은 각각 실제 pre-flag failure로 반박되어 128 pages/8 rounds로 교정했고,
기존 성공 횟수를 합산하지 않은 새 표본에서 A 5/5, E 5/5, contract 5/5를
통과했습니다. E 최대 lane 시도는 11/96이었습니다. 이 reliability 교정도 blind
난도에는 포함하지 않습니다. 이 시점에 남아 있던 공개 차단 조건은 stripped
candidate에 대한 사용자의 별도 fresh 2시간 blind test였고, 다음 절에서 완료됐습니다.

## blind 이후 shortcut 교정

단일 `gpt-5.6-sol/max` blind는 약 2시간 25분 뒤 actual remote terminal에
도달했습니다. Route 1 shortcut은 발견하지 않았고 Route 2에서 actual queued inotify
event 대신 controlled `msg_msgseg`로 event overlay를 합성했습니다. 그러므로 위의
“xattr/inotify native lifecycle” 증거는 organizer intended path가 정상임을 증명하지만,
`RECONCILE`이 alternate allocation을 배제한다는 증거는 아닙니다.

이 대체 producer는 lease mutation 하나만 제공하고 ordering xattr, same-record join,
bounded evidence와 approval gate를 건너뛰지 않았습니다. 2시간 gate도 race retry가
아닌 reverse/dataflow 비용으로 통과했으므로 shortest-path 판정은
`PASS-WITH-ALTERNATE-E`입니다. `V4_BLIND_AUDIT_01A01B9A.md`가 authoritative blind
기록입니다.

## 최종 handoff 경계

shortcut 판정이 끝난 동일 player bytes를 canonical public archive로 복사했고,
standalone service archive는 exact kernel과 secret-bearing rootfs, TCP/QEMU wrapper만
포함합니다. 두 archive의 member/hash 및 external-auth 계약은
`[V4-MINIMAL-HANDOFF-AUDIT-PASS]`, 직접 TCP uid-1000 shell은
`[V4-MINIMAL-SERVICE-SMOKE-PASS]`로 검증했습니다. reference CTFd/Instancer는 이
shortcut 판정이나 공식 납품의 일부가 아닙니다.
