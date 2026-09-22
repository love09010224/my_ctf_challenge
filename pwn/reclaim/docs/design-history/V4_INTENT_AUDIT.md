# RE:CLAIM v4 solver-visible intent 감사

<!-- ORGANIZER-DOC-STATUS: CURRENT-V4-EVIDENCE -->

> **현재 v4 기술 근거:** 이 문서는 최종 v4의 설계·감사 증거입니다. 공식 납품
> 경계와 canonical hash는 [`README.md`](README.md) 및
> [`development-history.md`](../development-history.md)가 우선합니다. 아래의 CTFd/Instancer와 managed
> instance 언급은 remote 동등성 검증에 사용한 과거 harness이며 공식 납품물이
> 아닙니다. 과거 `reclaim-box-000-blind.tar.gz`는 현재 player archive와 byte-identical합니다.

날짜: 2026-08-20 KST

## 최초 release branch 판정(대체됨)

아래 판정은 explicit workbench와 archive selector ioctl이 남아 있던 최초 branch에
대한 기록입니다. 당시 `organizer/v4release/`는 두 terminal capability와
route-removal proof를 갖지만 **release surface로는 탈락**했습니다. 원인은 심볼이나 문자열이 아니라 정상 API와
상태 전이의 out-degree가 너무 작아, 공개 artifact를 읽은 solver에게 다음 단계가
사실상 한 개씩만 남기 때문입니다.

strip, ioctl 번호 변경, 구조체 field 난독화로 이 판정을 뒤집지 않습니다.

## Route 1에서 노출되는 문장

현재 구조는 다음 사실을 서로 바로 연결합니다.

1. statement payload가 page 단위로 정확히 16개인 group을 노출합니다.
2. `EXPIRE(group)`가 그 group 전체를 한 번에 retire합니다.
3. `CHECKPOINT`가 native key GC 완료를 직접 기다립니다.
4. workbench가 movable scratch, readonly mirror, writable shared page를 나란히
   제공합니다.
5. 같은 source에서 shared만 `GFP_KERNEL` reclaim과 live writable mapping을 동시에
   만족합니다.
6. codec directory의 bounded OOB 한 entry가 core KASLR을 직접 제공합니다.
7. receipt `VIEW`와 `APPLY`가 각각 fake key read와 late callback을 그대로 소비합니다.

memo/notice와 scratch/mirror가 실제 정상 효과를 내더라도, 한 단계의 결과가 다음
consumer를 고르는 데 필요한 metadata를 거의 모두 주므로 solver-visible chain은
여전히 단선입니다.

## Route 2에서 노출되는 문장

다음 공개 operation 집합은 이름을 지워도 switch와 data structure로 같은 순서를
복원할 수 있습니다.

```text
SELECTOR -> ISSUE -> SELECT_ORDER / SELECT_LEASE -> WITHDRAW
-> receipt APPLY / RECONCILE -> NEXT -> RECOVER
-> COMMITMENT -> CHALLENGE -> VERIFY
```

X-only/N-only/mismatch가 실제 mutation 뒤 별도 invariant에서 멈추는 것은 좋은
capability 분리지만, `SELECT_ORDER`, `SELECT_LEASE`, `RECOVER`와 HMAC 세 operation이
exploit의 두 lane, join, terminal을 UAPI 순서로 직접 서술합니다. 이는 v2의
단일 intended spine과 같은 release 실패입니다.

## pipe whole-consumer 결과

단일 dangling key만 허용한 default build에서는 full anonymous pipe page가 첫
bounded read를 제공하지만 positional write, writable mmap, full-buffer append와
read/write cycle이 reclaimed page를 갱신하지 못했습니다.

그러나 group deficit cap을 diagnostic에서 제거하자 같은 16-object key slab의
16 receipt를 물리 slot별 one-shot reader로 사용할 수 있었습니다.

```text
16 ownership deficits
-> freed full key slab page
-> 0x100-byte anonymous-pipe append 단위
-> slot 0: target pipe와 CPU percpu base
-> slots 1..10: current task/cred/files/pipe/struct page/direct-map walk
-> slot 11: fake cred/key
-> slot 12: fake key_type(read + revoke)
-> late APPLY -> uid 0
```

첫 warmed sequential race는 4-round window가 끝나 `ENOSPC`로 반박됐습니다. 반복
case만 public maximum인 8 rounds로 바꾼 다음 exact run은 9.051초에
`[RELEASE-A-PIPE-STREAM-AAR-PASS]`와
`[RELEASE-A-PIPE-STREAM-ROOT-PASS]`를 모두 통과했습니다. 증거는
`build/v4release/route-1-pipe-stream-second.log`입니다.

이 결과는 default cap이 필요한 이유만 증명하는 것이 아닙니다. custom workbench가
제공하던 노골적인 writable page를 제거하고, native append-only owner와 여러
independent stale receipts를 조합하는 Route 1로 교체할 수 있다는 후보 evidence입니다.
구체 chain을 그대로 release한다고 자동으로 2시간 난도가 되는 것은 아니며 fresh
blind test가 필요합니다.

## 다음 release surface 계약

현재 구현을 그대로 strip하여 배포하지 않습니다. 다음 변경이 선행되어야 합니다.

1. `/dev/reclaim-work`의 writable terminal carrier를 제거합니다. scratch/mirror가
   남더라도 terminal path와 자동 연결되지 않아야 합니다.
2. Route 1의 group-wide `EXPIRE`와 explicit `CHECKPOINT`를 제거하고, generic per-token
   withdrawal과 정상 durability boundary(`fsync`)로 native owner lifecycle을
   표현합니다.
3. archive 전용 `SELECT_ORDER`, `SELECT_LEASE`, `NEXT`, `RECOVER`,
   `COMMITMENT`, `CHALLENGE`, `VERIFY` operation을 release ABI에서 제거합니다.
4. ordering/redaction frame은 정상 ledger snapshot/view가 여러 opaque frame을
   생산하도록 하고, 어느 한 operation도 domain locator와 다음 mutation consumer를
   동시에 반환하지 않게 합니다.
5. recovery는 별도 exploit 이름의 ioctl이 아니라 정상 export serializer의 기존
   output rule이어야 합니다.
6. approval gate는 module verifier ioctl을 호출하지 않고, setuid process가 root-only
   module secret stream을 시작 시 읽은 뒤 자체 nonce/HMAC protocol을 수행합니다.
7. 최종 stripped artifact를 기준으로 각 effect 뒤의 plausible next consumer 수를
   다시 계산합니다. 한 단계에서 유효한 다음 consumer가 하나뿐이면 release를 다시
   거부합니다.

## Generic snapshot 구현 후 재감사

기존 판정에서 지적한 archive 전용 operation 일곱 개는 최신 pre-release source와
UAPI에서 제거했습니다. 대체 surface는 다음뿐입니다.

```text
ordinary ledger read() -> 15 fingerprints
BOOKMARK(marker)        -> mixed ledger token 하나
SNAPSHOT(fp, revision)  -> 역할을 공개하지 않는 frame 네 개
ordinary read()         -> 동일 serializer의 최신 materialization
```

이 변경은 단순 이름 변경이 아닙니다.

- snapshot이 order/lease 중 하나를 선택하지 않고, 같은 fingerprint에 대해 네 owner를
  무작위 순서로 동시에 발행합니다.
- normal receipt VIEW는 generation만 보이고 locator와 owner role을 가립니다.
- 두 frame은 normal APPLY/RECONCILE에서 실제 audit/retention state를 각각 변경하며,
  둘의 join은 32-byte binary decoy를 serializer에 실제로 추가합니다.
- 나머지 두 frame만 stale bookmark와 native xattr/inotify provenance가 결합될 때 tree
  또는 redaction owner를 변경합니다. stale VIEW는 겹친 frame 하나의 identity만
  제공하며 둘 중 어느 consumer인지 알려 주지 않습니다.
- serializer는 normal-frame join과 native-owner join을 같은 record grammar로 내므로,
  output이 생겼다는 사실만으로 gate candidate인지 확정할 수 없습니다.

첫 exact run에서 normal decoy, X-only, N-only, mismatch와 matched terminal이 모두
실제 효과를 보였습니다. 다만 당시에는 이것만으로 `public-pass`가 아니었고 다음을
통과해야 재승격할 수 있었습니다.

1. frame role을 정상 receipt 부작용이나 allocation index로 terminal 전에 완전히
   분류하는 shortcut이 없는지 확인.
2. normal audit/retention decoy가 실제 approval key나 secret payload를 절대 선택하지
   않는지 gate negative로 확인.
3. latest no-key/no-archive build와 E cold 5/5를 다시 고정.
4. stripped module+bzImage만 제공한 fresh blind solve에서 2시간 gate를 평가.

## 최신 stripped-surface 재판정

- frame token까지 common race가 적용되던 것은 branch entropy가 아니라 cursor
  provenance를 건너뛰는 두 번째 root였습니다. frame backend의 fan-out만 정상
  accounting으로 복구했고 xattr same-cache pressure 뒤 immutable view 유지로
  검증했습니다.
- passive frame view는 역할을 노출하지 않으며 allocation index와도 고정되지 않습니다.
  normal APPLY/RECONCILE은 각각 실제 decoy state를 바꾸므로 두 역할을 분류할 수 있지만,
  그 결과만으로 남은 두 native owner의 xattr/inotify 소비자를 구별할 수 없습니다.
  동적 permutation coverage는 side-channel proof이지 난도 proof로 세지 않습니다.
- module codec branch의 callable rotate/XOR 함수는 stale-key self-address oracle이 될 수
  있어 삭제했습니다. 지금은 NX rodata identity만 반환하며 core callback은 별도
  record에 남습니다. 이는 module-base decoy가 다음 page-owner consumer를 직접 제공하지
  않게 하는 구조 수정입니다.
- player 후보에는 solution-shaped UAPI/header를 넣지 않지만, 이를 분기 엔트로피로
  세지 않습니다. strip과 이름 제거도 동일하게 hygiene일 뿐입니다. 난도 판정은
  statement/cursor race 이후의 실제 consumer graph와 fresh blind 결과만 사용합니다.
- 최신 no-key/no-archive route removal, 실제 randomized `SHA{test}` vault terminal,
  full exact-wrapper A/E/contract cold 5/5와 sealed kernel/module leakage 감사까지
  통과했습니다. 이후 `gpt-5.6-sol/max` artifact-only blind가 약 2시간 25분 뒤 actual
  remote terminal에 도달했습니다. Route 1의 storage-group/codec shortcut은 발견하지
  않았고, Route 2에서 actual inotify allocation을 controlled `msg_msgseg`가 대체하는
  alternate가 발견됐습니다. 이 alternate는 ordering/join/gate layer를 유지하므로
  현재 판정은 `runtime-proven / blind-proven / pass-with-alternate-E`입니다. 자세한
  실제 archive 표면과 blind 결과는 `V4_SEALED_SURFACE_AUDIT.md`,
  `V4_BLIND_AUDIT_01A01B9A.md`에 기록합니다.

## 외부 자료에서 취한 추상 원칙

- Google kernelCTF의 최신 submission들은 trigger, heap grooming/cross-cache,
  leak, primitive conversion과 terminal을 명시적으로 분리해 문서화합니다. challenge
  설계에서도 이 proof layer를 한 custom ioctl에 합치지 않습니다.
- 최근 submission의 복잡성은 API 이름을 숨기는 데서가 아니라 native subsystem의
  서로 다른 owner와 consumer를 맞추는 데서 나옵니다. 특정 CVE의
  trigger/target/endgame tuple은 복사하지 않습니다.

참고:

- https://github.com/google/security-research/tree/master/pocs/linux/kernelctf
- https://github.com/google/security-research/blob/master/pocs/linux/kernelctf/CVE-2025-40364_lts_cos/docs/exploit.md
- https://github.com/google/security-research/blob/master/pocs/linux/kernelctf/CVE-2025-40019_lts_cos_mitigation/docs/exploit.md

## 최종 납품 판정

solver-visible graph 판정과 운영 control plane을 분리합니다. 현재 player bytes는
`build/v4handoff-minimal/reclaim-box-000-player.tar.gz`로 동결됐고, 실제 flag가 든
서버 측 runtime은 `reclaim-box-000-service-private.tar.gz`의 standalone TCP/QEMU
계약으로 전달합니다. CTFd plugin, token gate, dynamic port와 TTL 구현은 문제
surface가 아니며 운영 측이 선택합니다.
