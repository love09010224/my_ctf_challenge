# RE:CLAIM v4 release surface 계약

<!-- ORGANIZER-DOC-STATUS: CURRENT-V4-EVIDENCE -->

> **현재 v4 기술 근거:** 이 문서는 최종 v4의 설계·감사 증거입니다. 공식 납품
> 경계와 canonical hash는 [`README.md`](README.md) 및
> [`development-history.md`](../development-history.md)가 우선합니다. 아래의 CTFd/Instancer와 managed
> instance 언급은 remote 동등성 검증에 사용한 과거 harness이며 공식 납품물이
> 아닙니다. 과거 `reclaim-box-000-blind.tar.gz`는 현재 player archive와 byte-identical합니다.

날짜: 2026-08-20 KST

이 문서는 처음에는 `public-v4/` 생성 전 구현 계약으로 작성됐으며, 현재는 모든
acceptance와 blind gate를 통과한 최종 v4 surface 계약으로 동결했습니다.
`organizer/v4diag`의 capability proof를 그대로 공개 ABI로 옮기지 않는다는 원칙은
계속 유효합니다. 이름을 바꾸거나 심볼을 strip하는 것만으로 아래 분리를 충족한
것으로 세지 않습니다.

## 1. 현재 diagnostic surface의 release 거부 이유

다음 순서는 기능적으로 맞지만 한 device의 ioctl 목록만 읽어도 exploit spine을
추측할 수 있습니다.

```text
BUILD_ATTESTATION -> CATALOG_READ -> REGISTER/DISPATCH
-> RETIRE_COHORT -> EPOCH_FENCE -> SCHEMA_READ -> WORKPAD_CREATE
-> receipt READ/REVOKE
```

Route 2의 private diagnostic 순서도 마찬가지입니다.

```text
BUILD_CATALOG -> DROP_CATALOG -> receipt REINDEX
-> BUILD_LEASE_CATALOG -> NEXT_ROUND -> receipt RECONCILE
-> RECOVER_JOIN -> CHALLENGE/VERIFY
```

따라서 release 구현에는 `/dev/reclaim-archive`를 등록하지 않습니다. catalog frame도
archive 전용 `DROP` ioctl이 소유하지 않고 mixed ledger의 정상 refcounted record로
발행합니다. 정상 case receipt는 generation만 읽고 locator를 redaction하므로 실제
중간 효과가 있지만 mutation에는 부족합니다. generic ledger withdrawal이 마지막
frame reference를 해제했을 때만 같은 slot을 native producer가 소비할 수 있습니다.

단계 수가 길다는 사실은 난도가 아닙니다. producer와 바로 다음 consumer가 같은
UAPI에 exploit 전용 이름으로 나열되면 v2/v3.2와 같은 one-way intended 실패입니다.

## 2. release 역할과 file owner

한 모듈이 다음 세 개의 unprivileged application role을 등록합니다. 각 open file은 서로 다른
`private_data`, lock, mmap/close lifecycle을 갖습니다.

| role | 공개 file | 정상 역할 | exploit에서 얻는 사실 |
|---|---|---|---|
| case desk | `/dev/reclaim` | opaque record를 reviewer들에게 분배하고 receipt 발급 | 공통 last-owner race만 제공 |
| generation ledger | `/dev/reclaim-ledger` | 여러 backend record의 generation snapshot/expiry | key logical identity와 cohort lifecycle 또는 archive selector |
| codec directory | `/dev/reclaim-codec` | renderer profile record 한 개 조회 | module-only 또는 bounded core pointer 한 개 |

`/dev/reclaim-work`는 native pipe-stream shortcut 감사 뒤 release module에서 완전히
제거됐습니다. approval gate만 mode `0400`인 `/dev/reclaim-evidence`를 euid-root 상태에서
읽으며, uid 1000은 이 stream을 열 수 없습니다.

archive ordering과 redaction lease는 generation ledger의 두 정상 reconciliation
workflow이지만 실제 controlled allocation은 각각 tmpfs xattr와 queued inotify event가
생산합니다. approval은 별도 setuid userspace gate가 담당합니다.

이 분리는 cosmetic한 fd 분리가 아닙니다.

- case desk는 schema table이나 archive secret을 참조하지 않습니다.
- codec directory는 record token이나 receipt를 받지 않습니다.
- generation ledger는 receipt fd를 보지 않으며 key/cursor의 raw address를 반환하지
  않습니다.
- 각 file의 close/error path를 독립적으로 fuzz하고 route-removal build에서도 정상
  workflow가 유지되어야 합니다.

## 3. common desk의 실제 backend 갈래

case desk의 opaque token은 다음 backend 중 하나를 가리킵니다. dispatcher는 공통
`get/put/read/reconcile/apply` contract만 보며 backend별 raw type을 UAPI에 반환하지
않습니다.

| backend | 실제 owner | race 뒤 실제 효과 | terminal 여부 |
|---|---|---|---|
| signed statement | native `struct key`/private keyring | duplicate key reference, permission-0 payload read | Route 1만 가능 |
| archive cursor | accounted 216-byte kref/rbtree entry | stale ordering/lease receipt | Route 2만 가능 |
| memo | ordinary refcounted kmalloc record | same-cache stale payload/sequence read | bounded; page owner/terminal 없음 |
| notice | native event counter wrapper | duplicate close accounting과 wakeup | underflow-free reject; terminal 없음 |

memo/notice는 dead code가 아닙니다. 정상 create/import/read/close와 race miss/win 뒤의
후속 consumer를 exact runtime에서 검사합니다. 다만 key slab page, archive join 또는
privileged gate로 이어지는 owner가 없습니다.

## 4. Route 1에서 감춰야 하는 연결

1. ledger snapshot은 signed statement 외에도 memo/notice/archive token을 섞어
   반환합니다. token은 random generation-local value이며 Linux key serial을 노출하지
   않습니다.
2. receipt read의 signed-statement payload만 logical generation/ordinal/group digest를
   반환합니다. page/type/address는 없습니다.
3. ledger expiry는 group의 정상 retention policy이며 receipt/race 결과를 보지
   않습니다. expiry만으로는 empty key slab이 CPU partial에 남습니다.
4. 별도 native allocation activity가 CPU-partial chain을 drain해야 page owner가
   바뀝니다. 이 transition은 ledger operation이 자동 수행하지 않습니다.
5. codec directory의 core record는 key/workbench와 별도 file이고 key callback,
   heap pointer, terminal helper를 포함하지 않습니다.
6. freed key slab page의 release terminal carrier는 custom mmap device가 아니라 ordinary
   anonymous-pipe append stream입니다. 여러 stale receipt가 slot별 one-shot bounded
   read만 제공하며 module은 pipe/page identity를 반환하지 않습니다.
7. task/file/pipe/`struct page`/direct-map walk와 fake late method는 organizer exploit에만
   있고 module helper가 없습니다.

## 5. Route 2에서 감춰야 하는 연결

1. ledger의 ordinary binary serializer는 15개 anchor fingerprint를 모두 반환하고
   eligible target을 골라 주지 않으며 raw cursor/anchor/secret 주소가 없습니다.
2. `BOOKMARK`와 `SNAPSHOT` output도 동일한 mixed ledger에 들어갑니다. snapshot은 같은
   fingerprint에 대해 네 frame을 무작위 역할 순서로 만들고, normal receipt view는
   generation만 반환하고 locator와 역할을 가립니다.
3. ordering reconciliation은 native xattr header/provenance를, redaction reconciliation은
   native inotify event header/provenance를 각각 요구합니다. 서로의 bytes로는 mutation
   전에 거부됩니다.
4. X-only는 실제 tree edge를 제거하지만 live redaction lease가 recovery를 거부합니다.
5. N-only는 실제 lease를 제거하지만 tree reachability가 recovery를 거부합니다.
6. 나머지 두 snapshot frame은 normal APPLY/RECONCILE에서 실제 audit/retention state를
   만들며, 같은 fingerprint의 normal join은 serializer에 gate-rejected binary decoy를
   냅니다. dead code가 아닙니다.
7. 다른 record의 X/N pair는 둘 다 mutation한 뒤에도 join provenance가 맞지 않아
   private payload를 반환하지 않습니다.
8. serialized bounded candidate는 userspace gate challenge와 결합해야 하며 module이
   uid/cred를 직접 수정하지 않습니다.

## 6. intent-density gate

한 operation 또는 한 reclaimed object가 다음 중 세 개 이상을 새로 제공하면 release를
거부합니다.

```text
race win oracle / exact logical identity / KASLR or heap identity /
target selection / state mutation / terminal transition
```

특히 다음은 구현하지 않습니다.

- token 조회가 backend type, cohort와 allocator size를 한꺼번에 반환
- expiry 결과가 victim-reclaimed bit 또는 page address를 반환
- workbench가 physical/direct-map identity를 반환
- codec table이 key type, `commit_creds`, current task/cred를 직접 포함
- archive catalog가 secret parent/record와 mutation target을 함께 선택
- one-shot weak write로 `fsuid`, gate text 또는 static helper를 바꾸는 경로

## 7. 구현 전/후 acceptance — 완료

1. 네 role의 정상 workflow와 memo/notice backend를 먼저 구현해 실제 consumer임을
   확인합니다.
2. common race win/miss를 opaque token backend별로 확인합니다.
3. Route 1 organizer exploit은 diagnostic ioctl 없이 terminal에 도달해야 합니다.
4. Route 2 organizer exploit은 X-only/N-only/mismatch/match 네 join oracle을 거쳐야
   합니다.
5. `no-key`와 `no-archive` build에서 반대 route terminal이 각각 독립적으로
   유지되어야 합니다.
6. whole-consumer/shortcut 감사와 fresh artifact blind test 전에는 public archive,
   Docker image, Instancer 또는 CTFd를 만들거나 시작하지 않습니다.

위 여섯 gate는 모두 완료됐습니다. 6번의 Docker/Instancer/CTFd는 blind 전 조기
배포를 금지한 당시 control이며 현재 공식 납품 구성요소를 뜻하지 않습니다.

## 8. blind 이후 provenance 교정

fresh blind session은 `reclaim_archive_reconcile()`의 event header/name 검사가 native
inotify queue provenance 자체를 증명하지 않는다는 사실을 보였습니다. 같은
`kmalloc-cg-256`의 `msg_msgseg`로 `wd/mask/name_len/name`을 합성하면 lease mutation을
수행할 수 있습니다. 따라서 2절과 5절의 “native inotify provenance를 반드시
요구한다”는 표현은 intended organizer route의 계약이지 shortest-path negative가
아닙니다.

이 alternate는 frame generation/locator를 생산하지 않고, ordering edge를 바꾸거나
serializer/gate를 직접 통과시키지도 않습니다. 별도 snapshot role inference,
`simple_xattr` ordering mutation, same-record join과 approval HMAC이 모두 남습니다.
실제 artifact-only solve는 약 2시간 25분이 걸렸고 remote race는 deterministic했으므로
난도는 retry가 아니라 reverse/dataflow에서 나왔습니다. release 판정은
`PASS-WITH-ALTERNATE-E`이며 세부 내용은 `V4_BLIND_AUDIT_01A01B9A.md`에 있습니다.

## 9. 최종 납품 surface

public ABI와 runtime은 위 계약으로 동결하되, control plane은 문제 제작자의 공식
납품 범위에서 제외합니다. canonical 참가자 archive는
`build/v4handoff-minimal/reclaim-box-000-player.tar.gz`, 실제 flag-bearing 운영자
archive는 `build/v4handoff-minimal/reclaim-box-000-service-private.tar.gz`입니다.

비공개 archive는 TCP 31337에서 QEMU 하나를 제공하는 Docker build context와
`service-contract.json`만 포함합니다. CTFd plugin, team authentication, port 할당,
instance lifecycle과 capacity/firewall policy는 운영 측이 구현합니다. 과거 reference
CTFd/Instancer acceptance는 remote runtime 동등성 증거로만 보존합니다.
