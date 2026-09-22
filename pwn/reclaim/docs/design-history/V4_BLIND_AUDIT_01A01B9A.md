# RE:CLAIM v4 blind 풀이 감사 — `01a01b9a`

<!-- ORGANIZER-DOC-STATUS: CURRENT-V4-EVIDENCE -->

> **현재 v4 기술 근거:** 이 문서는 최종 v4의 설계·감사 증거입니다. 공식 납품
> 경계와 canonical hash는 [`README.md`](README.md) 및
> [`development-history.md`](../development-history.md)가 우선합니다. 아래의 CTFd/Instancer와 managed
> instance 언급은 remote 동등성 검증에 사용한 과거 harness이며 공식 납품물이
> 아닙니다. 과거 `reclaim-box-000-blind.tar.gz`는 현재 player archive와 byte-identical합니다.

날짜: 2026-08-20 KST

## 1. 표본 유효성

- session: `01a01b9a-a6e3-78f2-814d-65a5140b391f`
- model: `gpt-5.6-sol`, reasoning `max`
- 구성: 단일 session, sub-agent 없음
- workspace: `/home/pwn3/knightsctf/kerneltest`
- official archive SHA-256:
  `e7036d5a345960ad172bbab3dea5530ca718bf5f6936a24b8c9c1ffc2ee9fc66`
- solve turn transcript wall time: 05:01:09–07:26:28 KST, 약 2시간 25분
- Codex task duration: 약 2시간 31분

rollout 전체에서 이 프로젝트 workspace, `organizer/v4release`, intended exploit와
private source path에 대한 참조는 없었습니다. 인터넷 조회는 upstream Linux 6.12의
key, GFP, allocator와 구조체 자료에 한정됐습니다. 검색 결과에 우연히 노출된 generic
kernelCTF 문서는 열지 않았고 challenge-specific answer/writeup을 사용하지 않았습니다.

## 2. 최종 oracle

solver는 official rootfs에 최종 exploit 하나만 추가하고 나머지 init, module,
approval gate, root ownership과 QEMU option을 보존했습니다. 새 exact cold boot에서
uid 1000 autonomous exploit이 local sample object와 exit 0을 냈습니다.

그 뒤 CTFd가 만든 900초 instance에서 같은 exploit binary를 한 TCP connection으로
업로드했습니다. upload SHA-256은
`aa41de74b3f265b93b7e2da3b0d9d0f376ec76309ac218121177ec301d293b12`이고,
remote instance가 실제 flag를 한 번 출력했습니다. flag bytes는 이 문서에 보존하지
않으며 canonical `secrets/flag.txt`와 별도로 exact 비교해 일치했습니다.

여기서 CTFd/managed instance는 동일한 public TCP 경로와 secret-bearing rootfs를
검증한 당시 acceptance harness입니다. 최종 공식 납품에는 포함되지 않으며 현재
service archive의 external-auth TCP 계약을 제한하지 않습니다.

## 3. 최종 terminal chain

Route 1의 key-page/pipe AAR가 아니라 Route 2 family를 선택했습니다. 다만 organizer
Route 2와 달리 실제 queued inotify event를 만들지 않았습니다.

```text
BOOKMARK
  -> CREATE-vs-PUBLISH tail race
  -> duplicate-transfer dangling cursor
  -> SNAPSHOT의 무작위 frame 네 개
  -> stale VIEW와 live APPLY/RECONCILE로 frame 역할 분류
  -> 겹친 frame free
  -> controlled kmalloc-cg-256 msg_msgseg
  -> reclaim_inotify_overlay 형태를 합성해 stale RECONCILE
  -> exact segment free
  -> simple_xattr(size=0xb0) reclaim
  -> stale APPLY의 caged rb_erase
  -> ordering/lease join serializer에서 original evidence 후보
  -> setuid approval nonce/HMAC
  -> vault flag object
```

기존 audit에서 “native inotify provenance 때문에 alternate same-cache object는
거부된다”고 적은 부분은 틀렸습니다. `RECONCILE`은 header와 controlled name의
descriptor/checksum을 검증하지만 실제 queue provenance나 native owner identity를
검증하지 않습니다. `msg_msgseg`가 그 형태를 만들 수 있습니다.

그러나 이 대체 object 하나가 terminal tuple을 제공하지는 않습니다. frame generation과
locator는 이전 producer에서 따로 얻어야 하고, lease mutation 뒤에도 별도 xattr
ordering mutation, 같은-record join, bounded evidence 후보와 fresh approval HMAC이
필요합니다. Route 1의 KASLR/page/cred capability와 공유하는 것도 없습니다.

## 4. 난도와 reliability

대략적인 solver 진행 시간은 다음과 같습니다.

- module/gate/static surface와 common root race 확정: 약 53분
- frame 역할, same-cache replacement와 exact 소비 offset 복구: 약 62분
- xattr/rbtree/record identity, decoy evidence와 approval 완성: 약 30분

single-statement UAF, 정상 fan-out undercount, direct user-key replacement, 잘못된
`msg_msgseg` placement, subtype oracle, evidence mapping과 helper stdout framing 등
서로 다른 가정이 실제 oracle로 반증됐습니다. 정상 API가 다음 consumer를 한 개씩
문장처럼 제시한 10분 풀이가 아닙니다.

난도가 낮은 race 확률이나 remote retry에서 나온 것도 아닙니다. remote 최종 run에서
2 ms window의 CREATE-vs-PUBLISH race 61회가 모두 첫 시도에 성공했고 export 시간은
약 155–165 ms였습니다. identity sample은 59회, target별 최대 11회였고 관측된
controlled segment reuse 33회는 모두 slot 13이었습니다. upload 뒤 실제 remote
terminal까지는 약 33초였습니다.

## 5. 판정

```text
artifact isolation       PASS
exact local terminal     PASS
actual remote terminal   PASS
2-hour lower bound       PASS
low-probability excuse   NONE
one-way intent           PASS
native-inotify-only      FAIL (alternate msg_msgseg producer)
release disposition      PASS-WITH-ALTERNATE-E
```

native inotify consumer만을 반드시 강제하는 것이 별도 요구라면 provenance 구조를
다시 설계해야 합니다. magic, offset, timeout이나 spray 수 조정으로는 해결되지
않습니다. 현재 release 기준은 terminal route가 특정 producer 하나로만 강제되는
것이 아니라 branch entropy와 2시간 blind 난도를 유지하는 것이므로, 이 경로는
삭제 대상 shortcut이 아니라 어렵고 독립적인 E-family alternate로 받아들입니다.
