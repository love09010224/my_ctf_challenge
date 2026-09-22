# RE:CLAIM v4 sealed artifact 표면 감사

<!-- ORGANIZER-DOC-STATUS: CURRENT-V4-EVIDENCE -->

> **현재 v4 기술 근거:** 이 문서는 최종 v4의 설계·감사 증거입니다. 공식 납품
> 경계와 canonical hash는 [`README.md`](README.md) 및
> [`development-history.md`](../development-history.md)가 우선합니다. 아래의 CTFd/Instancer와 managed
> instance 언급은 remote 동등성 검증에 사용한 과거 harness이며 공식 납품물이
> 아닙니다. 과거 `reclaim-box-000-blind.tar.gz`는 현재 player archive와 byte-identical합니다.

날짜: 2026-08-20 KST

현재 참가자 납품 대상은 아래 archive입니다.

```text
build/v4handoff-minimal/reclaim-box-000-player.tar.gz
SHA-256 e7036d5a345960ad172bbab3dea5530ca718bf5f6936a24b8c9c1ffc2ee9fc66
```

감사 당시 원본 path
`build/v4candidate/blind-20260820-043516/reclaim-box-000-blind.tar.gz`와 byte 단위로
같습니다. 비공개 standalone service archive는 이 player-surface 감사 대상이 아니며
별도 `[V4-MINIMAL-HANDOFF-AUDIT-PASS]`로 member와 hash 경계를 검사합니다.

이 문서는 private source의 의도를 설명해 artifact를 합리화하는 문서가 아닙니다.
처음 보는 solver가 실제로 얻는 파일·ELF relocation·문자열·operation만으로 다음
consumer가 하나로 좁혀지는지를 따로 기록합니다. hygiene 통과를 난도 통과로
간주하지 않습니다.

## 1. 기계적 artifact 결과

`audit-sealed-candidate.py`와 archive 자체의 `run.sh` smoke가 다음을 확인했습니다.

```text
[V4-SEALED-SURFACE-AUDIT-PASS]
[V4-BLIND-BUNDLE-RUN-PASS]
```

- top-level member는 `README.md`, `bzImage`, `rootfs.cpio.gz`, `run.sh` 네 개뿐입니다.
- canonical mode는 0444/0444/0444/0555, owner는 0:0입니다.
- extracted kernel payload에는 `.symtab`, debug/BTF, 일반 `nm` symbol과
  `kallsyms_{names,offsets,token_table}`가 없습니다.
- loadable ET_REL module은 kernel import resolution을 위한 `.symtab`과 relocation을
  유지해야 합니다. `--strip-unneeded` 뒤 challenge-local text name은 init/cleanup을
  제외하고 0개입니다. 이것을 “모듈에 심볼 table이 전혀 없다”고 표현하지 않습니다.
- UAPI/header, organizer exploit, private manifest, approval material은 rootfs에 없습니다.
- uid 1000은 evidence/vault를 열 수 없고, setuid file은 approval gate 하나뿐입니다.

참가자에게 보이는 native import에는 다음 family가 남습니다.

```text
key_alloc, key_instantiate_and_link, key_lookup, key_put,
key_type_user, key_unlink,
rb_erase, rb_first, rb_insert_color, rb_next
```

이는 reverse engineering으로 당연히 복구되는 의미이며 감추지 않습니다. 반대로
`pipe_buffer`, xattr/inotify 이름, `commit_creds`, `prepare_kernel_cred`, usermode-helper,
archive 전용 device와 custom work device는 literal/import로 노출되지 않습니다.
이 부재는 shortcut/hint hygiene일 뿐 branch entropy로 세지 않습니다.

## 2. 실제 solver-visible operation graph

header를 주지 않아도 ioctl 비교와 fops를 역분석하면 다음 역할은 복구할 수 있습니다.

```text
case desk       : reviewer 추가 / opaque token attach / receipt publish
receipt         : bounded view / apply / reconcile / disarm / close
ledger          : generation sync / indexed token read / memo / notice /
                  generic withdrawal / two snapshot-related transitions /
                  ordinary fixed-size serialization / fsync
codec directory : bounded indexed word read
approval gate   : nonce를 출력하고 한 response를 검증
```

operation 이름을 숨겼다는 이유로 어려운 것이 아닙니다. 다음 표는 한 효과에서 실제로
보이는 후속 consumer가 몇 개인지를 기록합니다.

| 관찰 효과 | 실제 가능한 후속 surface | 고유 경로 여부 |
|---|---|---|
| mixed ledger token/fingerprint | statement, memo, notice, cursor, frame의 정상 receipt 동작 | 고유하지 않음 |
| duplicate-transfer receipt | VIEW/APPLY/RECONCILE/DISARM/close 및 backend별 서로 다른 lifetime | 고유하지 않음 |
| statement logical identity | normal-key replacement, sibling retirement, 여러 native page owner, callback/read consumer | **고위험: 물리 page group이 너무 직접적인지 blind 판정 필요** |
| codec의 out-of-range word | module rodata identity 여러 개 또는 core text 한 개; heap/page/target 정보 없음 | 독립 KASLR producer지만 **shortcut 위험을 blind에서 측정** |
| snapshot의 frame 네 개 | normal audit, normal retention, native ordering, native lease의 무작위 역할 | 네 갈래 모두 실제 효과 |
| normal audit/retention join | serializer에 real binary decoy 생성, gate 거부 | dead code 아님 |
| native ordering 하나 | real tree edge mutation, lease invariant에서 정지 | terminal 아님 |
| native lease 하나 | real lease mutation, reachability invariant에서 정지 | terminal 아님 |
| 다른 fingerprint의 native pair | 두 mutation 뒤 join provenance에서 정지 | terminal 아님 |
| matched native pair | bounded candidate만 생성; 별도 nonce/MAC gate 필요 | 직접 uid/flag transition 아님 |

## 3. 가장 위험한 one-way 후보

현재 artifact의 가장 짧은 Route 1는 아래 두 독립 사실을 결합합니다.

1. statement envelope의 logical group은 실제 key slab page의 16개 slot과 일치합니다.
2. codec directory의 제한된 index confusion은 core text pointer 하나를 제공합니다.

둘 중 어느 것도 page address, pipe identity, task/cred, fake type 또는 terminal을 직접
주지는 않습니다. native full-page consumer도 module이 골라 주지 않습니다. 하지만
경험 있는 solver가 `16 x 0x100` geometry에서 anonymous pipe append stream을 거의
자동으로 선택하고 codec pointer와 곧바로 결합한다면, 갈래가 여러 개라는 내부 설명과
무관하게 one-way intended 실패입니다.

따라서 이 조합은 현재 `structural-risk / blind-unproven`입니다. 다음 중 하나라도 fresh
blind transcript에서 나타나면 archive를 release하지 않습니다.

- logical group을 읽은 직후 별도 runtime 사실 없이 “그 page를 pipe로 가져간다”가
  유일한 다음 단계로 결정됨
- codec word 하나가 pipe/key callback의 전체 bootstrap을 사실상 완성함
- normal-key, PTE/data-page, socket/buffer 등 다른 page consumer는 검토할 가치조차 없는
  외형적 decoy로 즉시 배제됨
- solver가 terminal chain을 2시간 전에 완성했지만 낮은 race/reclaim 확률이나 timeout
  때문에 flag만 늦게 나옴

이 경우 race window 축소, pipe page 수 축소, ioctl 번호 변경, group encoding, symbol
추가 제거로 고치지 않습니다. producer/consumer dataflow를 다시 나누거나 Route 1를
제거·교체합니다.

## 4. Route 2의 one-way 거부 기준

snapshot 뒤 frame 네 개의 allocation index와 역할은 고정되지 않고, normal 두 역할은
별도 state를 실제로 만들며 gate-rejected record까지 생산합니다. 남은 native 두 역할은
passive VIEW로 구별되지 않습니다. 그래도 다음 현상이 있으면 실패입니다.

- reverse된 switch가 xattr → inotify → serializer → gate 순서를 사실상 한 문장으로
  제공함
- frame 하나가 native header, exact locator, target fingerprint와 mutation 성공을
  동시에 알려 줌
- X-only/N-only/mismatch가 실질적인 state transition 없이 오류 코드만 내는 가짜 갈래임
- normal decoy output이 terminal candidate와 다른 grammar/size/index로 즉시 구별됨

현재 exact negative는 이 네 항목을 차단하지만, 난도 판정은 fresh blind transcript가
담당합니다.

## 5. blind 이후 판정

```text
artifact hygiene       PASS
kernel/module leakage  PASS
shortcut negatives     PASS-WITH-ALTERNATE-E
two route terminals    PASS
one-way intent         PASS
2-hour difficulty      PASS (2h25 transcript / 2h31 task)
public/minimal handoff PASS
```

fresh session `01a01b9a-a6e3-78f2-814d-65a5140b391f`는 Route 2에서 actual
queued-inotify producer 대신 controlled `msg_msgseg`를 사용할 수 있음을 밝혔습니다.
기존의 “alternate object는 native provenance에서 거부된다”는 negative는 폐기합니다.
다만 이 alternate도 별도 ordering xattr, same-record join, bounded evidence와 nonce/HMAC
gate를 요구했고 실제 terminal까지 2시간 25분이 걸렸습니다. 따라서 one-way shortcut이
아니라 E-family alternate로 승인합니다. 상세 timeline과 reliability는
`V4_BLIND_AUDIT_01A01B9A.md`에 있습니다.
