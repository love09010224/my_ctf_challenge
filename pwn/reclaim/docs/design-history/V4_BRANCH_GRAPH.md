# RE:CLAIM v4 branch graph — prototype 전 계약

<!-- ORGANIZER-DOC-STATUS: CURRENT-V4-EVIDENCE -->

> **현재 v4 기술 근거:** 이 문서는 최종 v4의 설계·감사 증거입니다. 공식 납품
> 경계와 canonical hash는 [`README.md`](README.md) 및
> [`development-history.md`](../development-history.md)가 우선합니다. 아래의 CTFd/Instancer와 managed
> instance 언급은 remote 동등성 검증에 사용한 과거 harness이며 공식 납품물이
> 아닙니다. 과거 `reclaim-box-000-blind.tar.gz`는 현재 player archive와 byte-identical합니다.

날짜: 2026-08-19 KST

이 문서는 diagnostic 후보에서 최종 release graph까지의 변화를 시간순으로 보존합니다.
초기 graph는 falsification 계약이며, 문서 후반의 final status와
`V4_PUBLIC_GRAPH_DRAFT.md`가 실제 release 구현을 설명합니다.

## 공통 root node

```text
REGISTER resource
  resource owns exactly one native reference
        |
        v
DISPATCH traverses mutable reviewer list
  if current reviewer is not last: native_get(resource)
  if current reviewer is last:     transfer original reference
        |
        | expensive policy evaluation 사이에 ADD_REVIEWER(tail)
        v
old tail and new tail both observe "last"
  -> receipt_count = native_reference_budget + 1
```

이 root node가 제공하는 것은 arbitrary read/write가 아닙니다. 서로 다른 receipt가
같은 native reference 하나를 소유한다고 믿는 **ownership deficit**뿐입니다.

정상 miss:

- tail append가 last test 전에 일어나면 새 tail만 original reference를 받습니다.
- 모든 receipt를 close해도 reference budget이 정확히 0이 됩니다.
- kernel fault 없이 다음 attempt를 수행할 수 있어야 합니다.

race win:

- append가 old tail의 last test 뒤, iterator increment 전에 일어납니다.
- old tail과 new tail이 모두 original reference를 받습니다.
- resource kind에 따라 close consumer가 갈라집니다.

## Route 1 graph — native key lifetime

> **Release graph revision:** 아래의 diagnostic terminal graph는 localizability
> evidence로만 남깁니다. `attestation -> self/page/type -> AAR/callback` complete tuple은
> public reject입니다. address-free identity cohort, independent schema-directory core
> pointer, native append-only pipe owner를 결합하는 split graph와 near-success invariant는
> `organizer/V4_PUBLIC_GRAPH_DRAFT.md`가 현재 release 계약입니다.

```text
common ownership deficit
  -> user keyring link 제거
  -> N-1 receipt close
  -> kept receipt points to freed struct key
  -> key_jar slab sibling drain
  -> CPU partial -> node partial -> buddy owner transition
  -> controlled data page reclaims victim physical page
  -> kept receipt invokes normal key read consumer
  -> fake key with real user-key type gives bounded AAR
  -> recover exact stale page/module receipt owner
  -> same page hosts fake key_type and key/cred dual layout
  -> ENDBR-valid late method commits crafted capability-bearing cred
  -> current task opens random-name vault objects
  -> identify one text object among binary decoys and output flag
```

### A producer / owner / consumer 표

| Layer | Producer | Owner | Consumer/oracle |
|---|---|---|---|
| original ref | `key_lookup` during register | case resource | receipt release `key_put` |
| deficit | mutable last-owner traversal | two final receipts | N-1 close leaves kept dangling only on win |
| slab page | key spray/grooming | `key_jar` | private allocator observer; later controlled page readback |
| first strong primitive | fake key + real user type | kept receipt raw key pointer | key type `read` copies selected kernel bytes |
| terminal object | fake key_type + dual key/cred bytes | controlled page and receipt | late indirect call to ENDBR function entry |
| final output | current task cred | root-only vault | normal open/read/write syscalls |

### Route 1이 사용하지 않는 것

- page resource registration 또는 GUP
- active page-table page double put
- PTE alias
- eventpoll, dangling `struct file`, fdinfo, poll callback
- v1/v2/v3.2 carrier

## Route 2 graph — caged archive ordering divergence

> **Release graph revision:** 아래의 single catalog/xattr diagnostic은 terminal
> localizability evidence이지만 public graph로는 superseded되었습니다. secret parent를
> 고르는 catalog 하나와 ordering mutation 하나가 바로 secret으로 이어지는 직선은
> 다시 배포하지 않습니다. release 후보는 전역 archive의 ordering tree와 redaction
> lease를 각각 tmpfs xattr와 queued inotify event가 독립적으로 변경하고, 동일 record에서
> 두 owner divergence가 join되어야만 bounded recovery가 가능한 구조입니다. 상세
> 계약과 cross-lane negative tests는 `organizer/V4_PUBLIC_GRAPH_DRAFT.md`에 있습니다.

```text
common ownership deficit
  -> keep exactly two receipts for one indexed entry
  -> close receipt 1
     win: normal tree removal and final free
     miss: one valid entry reference remains
  -> tmpfs simple_xattr value reclaims the kmalloc-cg-256 slot
  -> receipt 2 interprets value bytes as a red ordering leaf
  -> consumer validates parent against live archive anchors
  -> only one real anchor right-edge can be removed
  -> ordering tree owner count and chronological list owner count diverge
  -> separate recovery serializer emits bounded orphan records
  -> recover per-boot signing secret from one private record
  -> HMAC response is accepted by a separate setuid approval gate
  -> gate restores uid/euid/gid/egid 0 and opens vault objects
```

### E producer / owner / consumer 표

| Layer | Producer | Owner | Consumer/oracle |
|---|---|---|---|
| original ref | indexed entry registration | case resource | receipt release refcount put |
| stale object | first final receipt close | `kmalloc-256` allocator | normal removal 뒤 kept receipt만 dangling |
| controlled metadata | tmpfs `simple_xattr` value | xattr inode tree/name/value lifecycle | exact same-slot marker, xattr stays usable |
| caged mutation | forged red leaf + real archive parent | stale receipt and immutable anchor list | external target EPERM; one anchor right-edge only |
| disclosure | tree/list reachability divergence | separate recovery serializer | bounded orphan records, no AAR/W |
| terminal secret | per-boot heap record | module HMAC verifier | wrong response reject, correct response only |
| final output | setuid approval process | saved-root transition | uid/euid/gid/egid 0, normal vault read |

### Route 2가 사용하지 않는 것

- key serial, keyring, `key_jar`, key callback 또는 key AAR
- GUP, PTE, physical alias 또는 kernel text patch
- slab-to-buddy/page transition과 pipe page
- `msg_msg -> pipe page -> cred slab`
- packet ring/notifier page UAF

## 독립성 test

두 diagnostic/release build flag를 둡니다.

```text
CONFIG_RECLAIM_ROUTE_KEY=n   # Route 1 register/consumer를 제거
CONFIG_RECLAIM_ROUTE_ARCHIVE=n  # Route 2 register/consumer를 제거
```

acceptance 조건:

| Build | exploit A | exploit E | 기대 결과 |
|---|---|---|---|
| full | terminal | terminal | 둘 다 실제 flag-object consumer |
| no-key | ABI에서 거부 | terminal | Route 2가 Route 1 artifact 없이 동작 |
| no-archive | terminal | ABI에서 거부 | Route 1이 Route 2 artifact 없이 동작 |

공통 root cause와 generic receipt allocation만 공유할 수 있습니다. KASLR leak,
heap/page address leak, AAR/W, PTE alias, fake callback, target discovery helper는
공유하면 실패입니다. organizer exploit source도 공통 race helper 외에는 별도 file로
유지합니다.

## shortest-path 감사 계약

아래 family는 구현 뒤 반드시 실제 negative exploit 또는 whole-consumer static
evidence로 판정합니다.

| 후보 shortcut | A 영향 | E 영향 | 현재 상태 |
|---|---|---|---|
| 정상 same-cache key reclaim | stale key가 새 정상 key를 소비 | 없음 | terminal 여부 미검증 |
| key slab -> cred slab | callback geometry가 cred와 맞는지 | 없음 | 미검증 |
| key slab -> pipe/control page | intended A carrier 후보 | 없음 | 대체 page producer와 비교 필요 |
| live receipt direct reindex | 없음 | UAF/xattr 없이 edge divergence 가능한지 | 동적 negative 필요 |
| forged external parent/cred | 없음 | cage 우회로 arbitrary NULL write 가능한지 | exact EPERM 통과; public 재검증 필요 |
| alternate xattr tree corruption | 없음 | actual xattr header/node가 terminal consumer인지 | destructor/serializer 동적 감사 필요 |
| secret pointer/global read | 없음 | orphan serializer를 건너뛸 leak이 있는지 | private oracle 제거 뒤 static audit 필요 |
| gate text/page-cache patch | Route 1이 이미 root | weak write로 approval bypass 가능한지 | public gate binary에서 동적 negative 필요 |
| weak scalar -> fsuid/DAC | 가능 | arbitrary target 없음 | D shortcut으로 판정 기준 확정 |
| static usermode helper/core_pattern | 가능 | 가능 | config/rootfs negative 필요 |
| v3.2 manifest/pipe carrier 재사용 | 금지 | 금지 | v4 module에 ABI/import가 없어야 함 |

## 난도 oracle

2시간 목표는 다음과 분리합니다.

1. **구조 oracle:** 두 independent terminal exploit과 route-removal build.
2. **runtime oracle:** exact wrapper cold boot에서 owner transition을 debugger 없이
   재현합니다.
3. **shortcut oracle:** 가장 짧은 native consumer path가 organizer route보다 짧지
   않거나, 짧다면 그 route도 2시간 blind gate 대상에 포함합니다.
4. **blind oracle:** fresh artifact-only GPT-5.6-sol/max session이 실제 local flag를
   출력하기까지 최소 7,200초입니다. timeout, crash, 낮은 race 확률은 난도 성공으로
   계산하지 않습니다.

## 현재 status

- common root: `proven`, exact uid-1000 TCG cold boot 5/5. 정상 miss는
  `receipts=2, budget=2, underflow=0`; win은
  `receipts=2, budget=1, duplicate=1, underflow=1`입니다. 증거는
  `build/v4diag/root-race-cold-20260819-123648/`입니다.
- Route 1 native key: `terminal-diagnostic-proven`. key RCU unlink owner, stale
  replacement read, 12개의 15/16 partial donor를 이용한 deterministic key slab page
  release, first pipe-page reclaim, `key.type +0x98 == cred.ucounts +0x98` dual layout,
  ENDBR64 callback, uid/euid 0과 root-only read가 exact cold boot 5/5입니다
  (`build/v4diag/key-root-cold-20260819-132934/`). public release에는 private address,
  current-cred template, layout oracle를 포함하지 않으며 독립 leak/bootstrap을 별도로
  설계해야 합니다.
  별도 attestation diagnostic은 one-shot key-type epoch retirement와 CPU별 정상
  permission-0 user-key cohort로 exact replacement/direct-read reject/stale-read를 cold
  boot 5/5 입증했습니다
  (`build/v4diag/key-attestation-cold-20260819-235840/`). 하지만 현재 private payload의
  self/page/offset/type complete tuple은 `public-reject`이며 route graph에 그대로
  승격하지 않습니다.
- Route B ordinary GUP: `diagnostic-proven / release-dead`. anonymous source/data allocation은
  migratetype 불일치로 dead입니다. unmovable driver mapping을 ordinary GUP로 import한
  뒤 `first free -> exact leaf PTE -> stale put -> pipe backing page -> reversible
  self-PTE`는 exact wrapper cold boot 5/5로 통과했습니다
  (`build/v4diag/page-cold-20260819-130248/`). 한 PTE page에 2 MiB 간격 kernel-base
  후보 512개를 넣으면 self-PFN leak 없이도 physical text alias를 한 shot에 찾고
  patch할 수 있어 2시간 하한을 무너뜨립니다. 새 evidence 없이 reopen하지 않습니다.
- Candidate C active_mm: `dead`
- Candidate D intrusive ordering: `terminal-diagnostic-proven`. exact 6.12.103의
  red-leaf `rb_erase` constrained NULL store로 scratch를 먼저 지운 뒤 독립 instance
  네 개로 cred ID qword와 root-only proof까지 도달했습니다. exact-wrapper cold boot
  5/5는 `build/v4diag/tree-root-cold-20260819-134410/`에 있습니다. 25개 store 중
  first-attempt exact-slot은 23/25였고 나머지는 두 번째 fresh context에서 성공했으므로
  public design은 이 retry를 난도로 쓰지 않고 deterministic producer를 요구합니다.
  그러나 별도 `tree-shortcut` exact run에서 한 instance가 `cred.fsuid/fsgid` qword만
  zero하여 uid/euid/suid 1000인 채 root:root 0400 proof를 읽었습니다
  (`build/v4diag/tree-fsuid-shortcut.log`). unrestricted rb parent target은 weak-write
  terminal 자체이므로 Candidate D는 release에서 `dead/reject`입니다.
- Candidate E caged archive: `terminal-diagnostic-proven`. 216-byte accounted cursor와
  `simple_xattr(40)+value(176)`의 exact same-slot type confusion, real-anchor-only red
  leaf mutation, tree 15→14/list 15 divergence, bounded one-record secret disclosure,
  wrong-HMAC reject와 correct-HMAC setuid-root consumer가 exact wrapper cold boot 5/5입니다
  (`build/v4diag/archive-root-cold-20260819-234408/`). catalog generation/random locator와
  final-release provenance 변경까지 포함한 최신 build이며, 10개의 xattr reclaim은
  모두 first attempt였습니다. 이전 `archive-root-cold-20260819-171639/`은
  superseded입니다. public release에는 raw cursor/anchor, private secret id/plain secret
  oracle가 없어야 하며 remaining shortcut negative tests가 남았습니다.
- E split producer: `inotify-lane-diagnostic-proven`. exact 6.12.103의 accounted
  `inotify_event_info(32)+183-byte filename+NUL`이 cursor와 같은 stale slot을 cold boot
  5/5 first attempt로 회수했습니다. catalog→notify와 notify→xattr cross-lane은 모두
  mutation 전에 거부됐고, caged lease state 변경 뒤 normal event read가 보존됐습니다
  (`build/v4diag/archive-notify-cold-20260820-002413/`). `msg_msg` 후보는 hardened
  `kmem_buckets` cache 때문에 dead입니다.
- E split composition: `two-owner-terminal-diagnostic-proven`. N-only는 real lease
  mutation 뒤 tree reachability에서, X-only는 real orphan 뒤 redaction lease에서,
  mismatched X/N는 두 mutation 뒤 record join에서 각각 차단됐습니다. matched record만
  bounded key를 반환했고 wrong/correct HMAC terminal까지 exact cold boot 5/5였습니다
  (`build/v4diag/archive-join-cold-20260820-003307/`). private default-secret selector와
  secret oracle는 release 전 제거 대상입니다.

위 diagnostic 이후 release graph는 xattr/lease two-owner join과 anonymous-pipe append
stream으로 교체됐습니다. cross-lane/X-only/N-only/mismatch/matched negative,
no-key/no-archive terminal, exact-wrapper cold 5/5와 sealed artifact leakage 감사가
완료됐습니다. fresh `gpt-5.6-sol/max` blind는 약 2시간 25분 뒤 실제 remote flag까지
도달해 난도 gate를 통과했습니다. 이 과정에서 actual queued inotify event 대신
controlled `msg_msgseg`로 lease overlay를 합성하는 E-family alternate가 확인됐지만,
ordering owner와 join/gate를 건너뛰지 않으므로 accepted alternate로 분류합니다.
현재 status는 `runtime-proven / blind-proven / pass-with-alternate-E`입니다.

공식 전달은 이 graph를 구현한 player archive와 비공개 standalone TCP/QEMU service
archive 두 개로 제한합니다. CTFd/Instancer와 team lifecycle은 graph의 terminal
consumer가 아니라 운영 측 control plane이므로 납품 범위 밖입니다.
