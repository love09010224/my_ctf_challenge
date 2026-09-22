# RE:CLAIM v4 공개자료 조사와 provenance 경계

<!-- ORGANIZER-DOC-STATUS: CURRENT-V4-EVIDENCE -->

> **현재 v4 기술 근거:** 이 문서는 최종 v4의 설계·감사 증거입니다. 공식 납품
> 경계와 canonical hash는 [`README.md`](README.md) 및
> [`development-history.md`](../development-history.md)가 우선합니다. 아래의 CTFd/Instancer와 managed
> instance 언급은 remote 동등성 검증에 사용한 과거 harness이며 공식 납품물이
> 아닙니다. 과거 `reclaim-box-000-blind.tar.gz`는 현재 player archive와 byte-identical합니다.

날짜: 2026-08-19 KST

이 문서는 운영자 전용입니다. 참가자 archive에 포함하지 않습니다.

## 조사 목적

공개 challenge writeup(고난도 문제 포함), kernelCTF 제출자료와 1-day exploit에서
가져오는 것은 다음 질문의 답뿐입니다. 공개 writeup 자체를 금지하지 않습니다.
오히려 풀이 시간을 늘린 원인이 무엇이었는지와 solver가 어떤 잘못된 갈래를 실제로
검증해야 했는지를 추상 motif로 비교합니다.

1. 최초 memory-safety bug를 찾은 뒤에도 어떤 **owner 전환**을 별도로 증명해야 했는가?
2. 메모리 모양이 맞는 것과 실제 syscall/worker가 그 객체를 **소비하는 것**은 어디서
   갈렸는가?
3. leak, write, page ownership, control flow가 한 객체에 모이지 않도록 어떤 경계를
   두었는가?
4. 실패를 crash가 아닌 안전한 oracle로 구분할 수 있었는가?

다음은 가져오지 않습니다.

- source 또는 exploit code
- object 크기와 field offset
- 상수, spray 수, CPU timing 값
- 동일한 subsystem/API와 race trigger
- 동일한 reclaim target과 동일한 endgame
- 자료 하나의 `trigger -> target -> terminal consumer` 전체 tuple

따라서 아래 자료는 아이디어 출처이지 v4의 구현 사양이 아닙니다. 후보는 반드시
Linux 6.12.103의 실제 source/config/allocator에서 별도 producer와 consumer로
localize하고, 원 자료의 코드·상수·layout·`trigger -> target -> terminal` tuple과
구별되는 provenance를 기록해야 합니다.

## 정확한 local 환경

```text
kernel             Linux 6.12.103 x86_64
memory / vCPU      512 MiB / 2 vCPU
allocator          SLUB
hardening          freelist hardened + randomized, hardened usercopy,
                   KASLR, SMEP, SMAP, KPTI, STRICT_KERNEL_RWX,
                   STRICT_MODULE_RWX, x86 IBT
disabled           USER_NS, BPF_SYSCALL, IO_URING, KALLSYMS,
                   MODULE_UNLOAD, KASAN/KCSAN/KFENCE
enabled surfaces   SYSVIPC, POSIX_MQUEUE, KEYS, EPOLL, EVENTFD, TIMERFD,
                   SIGNALFD, INOTIFY, TMPFS/SHMEM, UNIX/INET/PACKET
endgame restriction STATIC_USERMODEHELPER_PATH=""
```

`USER_NS=n`이므로 user namespace 안의 `CAP_NET_ADMIN` 또는 `CAP_NET_RAW`에
의존하는 upstream trigger는 localizable하지 않습니다. 해당 자료에서는 lifecycle과
consumer motif만 취합니다. `CONFIG_X86_KERNEL_IBT=y`이므로 fake callback 후보는
임의 mid-function JOP를 전제로 삼지 않고 실제 ENDBR function entry 또는 data-only
consumer를 사용해야 합니다.

## 최신 upstream / kernelCTF 자료

### CVE-2026-31419, google/security-research PR 397

- 자료: <https://github.com/google/security-research/pull/397>
- 원본 현상: mutable bonding membership을 순회하면서 original skb를 사용할 마지막
  consumer 판정이 바뀌어 동일 resource가 두 번 전달됩니다.
- 취할 motif: **순회 도중 last owner가 바뀌면 clone이 아니라 original resource의
  ownership deficit이 생긴다.** 단순 stale pointer보다 이후 payload별 destructor를
  다르게 설계할 수 있습니다.
- 복제 금지: bonding, skb, qdisc/XDP, network namespace trigger, 해당 timing과
  exploit target 전체.
- 6.12.103 적용: custom case membership list와 receipt transfer에만 추상화합니다.

### CVE-2026-46242 “Bad Epoll”

- 자료:
  - <https://www.openwall.com/lists/oss-security/2026/07/08/13>
  - <https://github.com/J-jaeyoung/security-research/tree/submit-cve-2026-46242/pocs/linux/kernelctf/CVE-2026-46242_lts_cos>
- 원본 현상: close-vs-close race의 제약된 post-free write를 별도 watched object의
  lifetime 파괴에 사용하고, 안전한 graph-depth oracle로 race miss를 재시도합니다.
- 취할 motif: 첫 UAF effect가 곧 arbitrary R/W가 아니라 **두 번째 owner relation을
  끊는 제약된 mutation**이고, win/miss를 kernel panic 없이 구분합니다.
- 복제 금지:

  ```text
  epoll write-zero
  -> dangling struct file
  -> filp slab cross-cache to pipe page
  -> /proc/self/fdinfo AAR
  -> file->f_op->poll ROP
  ```

- 6.12.103 적용: epoll 자체를 쓰지 않습니다. v4 공통 race도 timer IRQ나 false
  sharing을 필수로 하지 않습니다.

### CVE-2026-52910, google/security-research PR 407

- 자료: <https://github.com/google/security-research/pull/407>
- 원본 현상: reuseport cBPF program의 RCU UAF가 fake `bpf_prog` callback으로
  이어집니다.
- 결론: callback tuple이 너무 직접적이고 v4 config는 `BPF_SYSCALL=n`입니다.
  source layout과 callback target은 사용하지 않습니다. “ref owner와 lookup reader의
  grace-period 계약을 분리해 감사한다”는 원칙만 남깁니다.

### CVE-2026-23274, google/security-research PR 352

- 자료: <https://github.com/google/security-research/pull/352>
- 원본 현상: 초기화되지 않은 timer callback을 직접 control-flow로 바꿉니다.
- 결론: single callback target은 v3.2보다 더 짧은 graph가 되므로 reject합니다.

### CVE-2025-38617, google/security-research PR 339

- 자료: <https://github.com/google/security-research/pull/339>
- 원본 현상: packet ring reconfiguration과 notifier teardown의 두 lifecycle이
  엇갈린 뒤 stale ring page를 page primitive로 승격합니다.
- 취할 motif: page owner를 없애는 transition과 stale consumer가 실행되는
  transition을 분리해 검증합니다.
- 복제 금지: packet socket/ring/notifier, xattr/page primitive, 해당 page reclaim
  tuple. `USER_NS=n`이므로 원 trigger도 service에서 그대로 도달하지 않습니다.

### 2026-08-11에 병합된 kernelCTF 자료

로컬 연구 사본은 `build/research/v4-upstream/merged-20260811/` 아래에 있고 release
artifact에 포함하지 않습니다.

| PR / CVE | 취할 추상 motif | 금지 tuple 또는 local 불가 이유 |
|---|---|---|
| PR 292 / CVE-2025-40214 | uninitialized state가 바로 RIP가 아니라 page owner UAF로 바뀌는 단계 분리 | 원 socket/SCC spray, pipe callback endgame 복제 금지 |
| PR 305 / CVE-2025-40019 | partial reclaim 뒤에도 남는 residual link와 두 pass 사이의 정보 전달 | ESSIV/AF_ALG scatterlist, crafted IV, PTE/core_pattern tuple 복제 금지 |
| PR 265 / CVE-2025-39964 | write destination을 return-value boolean oracle로 좁히는 방법 | AF_ALG SGL OOB 및 physical binary search 복제 금지 |
| PR 288 / CVE-2025-40018 | deterministic free/use 사이에 별도 CPU가 reclaim하는 owner ordering | IPVS/netns/timerfd storm, user-key/msg overlap tuple 복제 금지; USER_NS=n |
| PR 253 / CVE-2025-38616 | 동일 packet의 upper/lower layer가 ref를 다르게 해석하는 경우 | TLS/TCP skb arbitrary-free 및 core_pattern 금지 |
| PR 244 / CVE-2025-38678 | notifier cleanup 후 cross-cache가 실제 native consumer에 도달하는지 확인 | netfilter/netdev namespace trigger 및 skb target 금지 |
| PR 227 / CVE-2025-38083 | hierarchy accounting underflow와 늦은 tree consumer를 분리 | qdisc/HFSC pointer write와 ops overwrite 금지 |
| PR 223 / CVE-2025-38001 | reentrant insertion이 동일 logical node를 ordering tree에 두 번 남기는 현상 | HFSC/NETEM qdisc와 RB-tree target을 그대로 복제하지 않음 |

## 공개 challenge writeup

### D3CTF 2025 `d3kshrm`

- 자료: <https://github.com/arttnba3/D3CTF2025_d3kshrm>
- 취할 교훈: isolated cache 때문에 same-cache spray가 안 될 때 page ownership으로
  경계를 옮기는 reasoning과, **처음 생긴 slab이 아니라 이후 새 slab의 owner를
  모델링해야 했던 점**을 취합니다. 또한 intended memory corruption과 무관하게
  OOM이 `busybox init`의 `askfirst` root shell을 다시 띄운 unintended가 있었으므로,
  module consumer뿐 아니라 init/OOM/TTY lifecycle도 terminal shortcut으로 감사합니다.
- 금지: isolated cache OOB page mapping에서 pipe/page-cache read-only file patch로
  가는 tuple.

### LACTF 2025 `messenger`

- 취할 교훈: 몇 byte의 작은 corruption도 allocator page owner를 바꾸면 강해질 수
  있으므로 weak-write shortcut을 별도로 감사합니다.
- 금지: `msg_msg` 3-byte OOB에서 pipe page UAF, cred slab reclaim으로 이어지는 tuple.

### ACTF 2026 `AGPU`

- 자료: <https://github.com/team-s2/ACTF-2026/blob/main/pwn/AGPU/WRITEUP_en.md>
- 취할 교훈: objective가 DAC 또는 `fsuid` 하나라면 one-shot weak write도 terminal일
  수 있습니다. v4 rootfs가 약한 scalar write만으로 열리지 않는지 검사합니다.
- 금지: Mali page array, predictable vmalloc, physical kernel text mapping,
  `__sys_setresuid` patch.

### TRX CTF 2026 `krwd`

- 자료: <https://kqx.io/writeups/krwd/>
- 관찰: underdocumented workqueue `active_mm` behavior는 흥미롭지만 GPT-5.5가
  one-shot으로 풀었습니다. 한 hidden kernel fact와 고정 privileged-process target이
  일직선으로 연결되면 2시간 gate가 되지 않습니다.
- 결정: v4 terminal route로 사용하지 않습니다. 별도 root helper scheduling에
  의존하는 confused-deputy 경로도 reject합니다.

### backdoor CTF 2025 `vibe-kode`

- 자료: <https://kqx.io/writeups/vibe_kode/>
- 취할 교훈: async free와 usercopy가 만든 UAF가 있어도 page-table, pipe, IOPL 등
  여러 실제 terminal consumer를 전체 환경에서 감사해야 합니다.
- 금지: FUSE-stalled kmalloc-4k write, TSS I/O bitmap, fw_cfg physical write.

### ASIS CTF 2025 `FileNo`

- 자료:
  - <https://jkrshnmenon.github.io/blog/2025/asisctf25fileno/>
  - <https://kqx.io/writeups/fileno/>
- 취할 교훈: heap 모양이 아니라 buddy order와 late callback consumer를 따로
  모델링해야 합니다. `file->private_data`를 직접 읽고 쓸 수 있는 순간
  `seq_file` callback까지의 graph가 지나치게 짧아졌고, CPU entry area나 warning
  output 같은 wrapper/kernel surface도 본래 heap chain을 건너뛸 수 있었습니다.
- 금지: regular-file `private_data` arbitrary write, fake seq_file in CEA, adjacent
  buddy pipe-page ROP.

### HCMUS-CTF 2025 Final `LEGv8.1`

- 자료: <https://blog.ktranowl.site/posts/hcmus-ctf-2025-final-pwn-challenges/>
- 취할 교훈: 동일한 stale local pointer라도 비동기 cleanup이 어느 실행 단계의
  sleep 중 끼어드는지에 따라 이후 instruction fetch, register read, memory access,
  writeback에서 생존 조건이 서로 달랐습니다. 대부분의 지점은 실제 stale access를
  만들고도 다음 consumer의 non-NULL/writable invariant에서 종료됐습니다.
- v4 적용 경계: timeout이나 signal timing을 복제하지 않고, 각 public route에
  **실제 intermediate effect를 만들지만 서로 다른 다음 owner invariant에서 멈추는
  갈래**를 둔다는 구조만 취합니다. race phase를 맞히는 도박이나 local-value timing,
  VM instruction set, fd-close/reverse-shell terminal은 사용하지 않습니다.

### DiceCTF 2026 `CornelSlop`

- 과거 local session과 source를 다시 감사한 결과는
  `organizer/KERNEL_SESSION_DEEP_AUDIT.md`에 있습니다.
- 취할 교훈: stale lookup, second RCU free, CPU/node partial, buddy return, PTE/page
  consumer를 각각 독립 oracle로 보아야 합니다.
- 금지:

  ```text
  custom SLAB_NO_MERGE cache + xarray/RCU stale lookup
  -> slab-to-page
  -> PTE/page-cache
  -> root-executed file mutation
  ```

### HITCON 2024 `Halloween`

- 취할 교훈: 여러 bug와 여러 ioctl이 있어도 auth bypass, race, leak, forge가 모두
  하나의 terminal spine에만 있으면 multi-route가 아닙니다.
- v4는 “중간 primitive가 둘”이 아니라 route 제거 build 두 개로 terminal
  독립성을 검사합니다.

## v4 후보 비교

### Rejected native producer — Linux 6.12 `msg_msg` buckets

- exact 6.12.103의 `ipc/msgutil.c`는 `msg_msg`를 ordinary `kmalloc-cg-*`에서
  할당하지 않고 `kmem_buckets_create("msg_msg", SLAB_ACCOUNT, ...)`로 만든 hardened
  bucket cache에서 할당합니다.
- accounted 216-byte archive cursor 뒤 `msgsnd(168)`를 두 번 localize했지만 stale
  slot을 차지한 것은 queue/control 또는 ancillary allocation이었고 actual
  `msg_msg::m_ts/text`가 아니었습니다
  (`build/v4diag/archive-msg-first.log`, `archive-msg-second.log`).
- 결정: `msg_msg`를 spray/timing으로 계속 밀지 않습니다. Route 2의 두 번째 producer는
  ordinary `GFP_KERNEL_ACCOUNT` 가변 allocation인 queued inotify event로 교체하며,
  message header/layout/consumer는 복제하지 않습니다.

### Candidate A — mutable fan-out + native key reference

```text
last-owner race
-> 동일한 한 개의 key reference가 receipt 두 개에 transfer
-> keyring reference 제거 + receipt close ordering
-> dangling native key consumer
-> key_jar slab page가 실제 buddy allocator로 반환
-> controlled data page로 cross-cache reclaim
-> real user-key read method를 이용한 제한된 AAR
-> module receipt owner 또는 freed-page direct-map address 복구
-> fake key_type + key/cred dual-layout
-> late key method가 fake cred를 현재 task에 commit
-> uid/capability와 vault consumer
```

의도적으로 필요한 runtime fact:

1. victim key가 있는 slab page가 CPU partial/node partial을 떠나 buddy로 반환됐는가?
2. 어떤 controlled page가 stale key address를 reclaim했고 direct-map address는
   무엇인가?
3. kept receipt가 실제 freed key를 소비하는가, 아니면 정상 key 또는 다른 reclaim을
   소비하는가?

원 자료와의 차이:

- epoll, file, fdinfo, poll callback을 사용하지 않습니다.
- key UAF는 common fan-out ownership deficit에서 생깁니다.
- 첫 callback은 바로 ROP가 아니라 real key read를 통한 AAR로 쓰고, terminal object는
  key와 cred가 동일 page bytes를 다르게 해석하는 challenge 전용 dual layout입니다.

위험/shortcut:

- key method가 너무 직접적인 callback으로 보일 수 있습니다.
- pipe backing page를 controlled page로 쓰면 공개 cross-cache pattern이므로, 다른
  unprivileged page producer도 prototype에서 비교해야 합니다.
- fake key/cred가 `commit_creds()` validation을 정확히 통과하는지 IBT-enabled exact
  kernel에서 입증해야 합니다.

**2026-08-19 attestation diagnostic:** `rcu_barrier()`로 keyring assoc-array의 link
destructor를 끝낸 뒤 1회용 registered key-type epoch를 `unregister_key_type()`하여
native key GC pass 완료를 기다렸습니다. 어느 CPU가 victim frozen slab을 가졌는지
고르는 oracle 없이 CPU 0/1 각각 permission-0 root-owned user key 32개를 생성했고,
exact victim slot replacement, 일반 `KEYCTL_READ`의 `EACCES`, stale receipt의 정상
`key_type_user.read` payload를 cold boot 5/5로 입증했습니다
(`build/v4diag/key-attestation-cold-20260819-235840/`). 이는 fixed sleep을 제거한
localizability proof입니다.

그러나 diagnostic payload가 `self/page/offset/user_type`을 한 번에 주는 현재 형태는
**public reject**입니다. 이 한 객체가 exact overlap oracle, heap identity와 KASLR
bootstrap까지 겸하면 이후 slab drain/AAR/callback을 한 방향으로 강제하여 이전
v2/v3.2 실패를 반복합니다. release 후보는 identity와 type/KASLR material을 서로 다른
정상 workflow로 나누고, 각각의 단독 consumer는 실제 중간 효과를 내되 terminal에
필요한 다른 invariant에서 멈춰야 합니다. opaque encoding이나 field rename은 분리로
인정하지 않습니다.

### Candidate B — mutable fan-out + ordinary GUP page reference

```text
last-owner race
-> 한 개의 ordinary GUP reference가 receipt 두 개에 transfer
  -> unmovable driver-backed normal user mapping 제거
-> 첫 receipt close / put_page: original page free
-> sparse mapping으로 같은 physical page를 active PTE page로 reclaim
-> 둘째 receipt close / put_page: active PTE page free
  -> type 검증 없는 unmovable backing-page consumer가 동일 physical page를 reclaim
-> live page-table walk와 writable user alias가 owner를 다르게 봄
-> PTE observation/mutation
-> task/cred data-only promotion 또는 별도 audited terminal consumer
-> vault consumer
```

의도적으로 필요한 runtime fact:

1. first close가 원 page를 실제 PCP/buddy ownership으로 반환했는가?
2. 그 page를 page-table allocation이 소비했는가?
3. second close 뒤 어느 user data page가 active page table을 reclaim했는가?

Route 1와 공유하지 않는 것:

- key cache, key callback, key AAR, fake cred/key layout, module-base traversal을 전혀
  사용하지 않습니다.
- common membership race와 receipt ownership deficit만 공유합니다.

위험/shortcut:

- **2026-08-19 diagnostic 결과:** anonymous GUP/data page는 movable이고 PTE는
  unmovable이라 직접 LIFO overlap 가정이 반박됐습니다. `GFP_KERNEL` page를
  `vm_insert_page()`한 정상 VMA를 GUP로 import하면 leaf PTE 전환이 성립했고, stale
  PTE type을 거부하지 않는 pipe backing page가 두 번째 reclaim을 수행했습니다.
  private PFN oracle를 쓴 reversible self-PTE가 exact cold boot 5/5였습니다. 이는
  localizability proof이지 public solve path 선정이 아닙니다.
- PTE alias가 만들어진 뒤 kernel text physical patch가 가장 짧은 endgame이 될 수
  있습니다. 이는 route 자체의 terminal 후보로 인정할 수 있지만 2시간 하한은 root
  race와 두 번의 page-owner 전환까지 포함한 blind evidence로만 주장합니다.
- `msg_msg -> pipe -> page UAF`나 custom slab-to-page가 아니어도 Dirty Pagetable이
  지나치게 익숙한 shortcut일 수 있으므로 Candidate D와 비교한 뒤 확정합니다.

### Candidate C — async active_mm confused deputy

실제 writeup에서는 kernel worker가 예상과 다른 userspace `mm`에 usercopy를 수행해
privileged process memory를 덮었습니다. v4에 넣으면 root helper의 scheduling과
고정 userspace target이 필요하고, 최신 GPT가 이미 짧게 복구한 family입니다.

**상태: dead/reject.** 새로운 evidence 없이 다시 열지 않습니다.

### Candidate D — intrusive ordering metadata + variable-length native serializer

common fan-out의 inline heap resource를 stale intrusive ordering tree에 남기고,
정상 reindex가 reclaimed variable-length native object의 header를 제한적으로
변경하도록 하는 후보입니다. OOB serializer leak은 가능하지만 독립적인 terminal
write consumer가 아직 증명되지 않았습니다.

**상태: terminal-diagnostic-proven / public graph 미선정.** 216-byte indexed entry의
final free 뒤 같은 `kmalloc-256` slot에 controlled memo를 놓고, stale receipt의 정상
reindex가 red-leaf `rb_erase` case 1을 밟게 하여 선택한 qword에 NULL 한 번을 쓰는 것은
exact 6.12.103에서 성립했습니다. scratch proof 뒤 서로 독립적인 네 instance가 current
cred의 ID qword들을 지우고 root-only proof를 읽었으며 cold boot 5/5였습니다
(`build/v4diag/tree-root-cold-20260819-134410/`). 이 결과는 terminal capability의
localizability만 증명합니다. private ABI가 same-size arbitrary memo, raw entry/cred
address, layout, 직접 이름 붙인 `REINDEX`를 모두 제공하므로 그대로 배포하면 또 하나의
단일 spine이 됩니다. public 후보는 variable-length native serializer가 controlled
metadata를 간접 생산하고 ordering consumer를 정상 workflow 속에 숨겨야 하며,
pointer/bootstrap과 target recovery도 Route 1와 공유하면 안 됩니다.

추가 shortest-path 감사에서 이 후보는 release에서 탈락했습니다. root:root 0400
objective에는 current cred의 `fsuid/fsgid` qword 하나만 zero해도 충분했습니다. exact
`tree-shortcut` run은 uid/euid/suid 1000을 유지한 채 proof를 읽었습니다
(`build/v4diag/tree-fsuid-shortcut.log`). 즉 네 번의 ID write, full root, capability,
callback은 필요하지 않습니다. unrestricted rb parent target을 유지한 채 serializer나
symbol만 숨기는 것은 구조적 수정이 아니므로 Candidate D를 `dead/reject`로 둡니다.

### Candidate E — caged ordering divergence + approval-secret disclosure

공통 race 뒤 freed ordering cursor를 native variable-length producer가 reclaim하되,
stale consumer가 임의 kernel address가 아니라 **검증된 같은 archive의 실제 tree
edge**만 끊을 수 있도록 target domain을 제한합니다. chronological owner list와
visible ordering tree를 서로 다른 정상 serializer가 소비하게 하여, edge orphan이
직접 cred write가 아니라 bounded private-record disclosure로 승격되는지를 봅니다.
private record에는 module이나 rootfs에 정적으로 들어 있지 않은 per-boot signing
secret이 있고, 정상 setuid approval gate는 그 secret으로 만든 응답을 검증한 뒤에만
uid 0을 부여합니다.

이 후보에서 취하는 공개 motif는 다음뿐입니다.

- caged primitive가 target domain 밖의 cred/text/page를 직접 건드리지 못하게 하기
- count owner와 fill/traversal owner가 다른 정상 serializer의 divergence
- leak consumer와 privileged terminal consumer를 별도 process/lifetime으로 분리
- decoy가 실제 leak/mutation까지 가더라도 final owner가 소비하지 않으면 dead인 구조

복제하지 않는 tuple은 기존 challenge의 rb-tree write, key/PTE/page-cache endgame,
SMM password oracle, active-mm worker, eventpoll/file callback입니다. 첫 gate는 exact
6.12.103 tmpfs xattr(또는 다른 native flexible object)의 allocation cache와 controlled
offset이 cursor와 실제로 맞는지 확인하는 것입니다. 그 뒤 real-edge mutation,
serializer disclosure, HMAC/approval gate를 각각 독립 diagnostic으로 입증합니다.

**2026-08-19 diagnostic 결과:** 세 gate 모두 성립했습니다. accounted 216-byte cursor와
`simple_xattr`의 40+176 layout은 compile-time assertion과 exact same-slot marker로
확인했습니다. external/current-cred parent는 `EPERM`이고 tree/list가 불변이었으며,
live archive parent는 red-leaf case에서 right edge 하나만 끊어 tree 15/list 15의
divergence를 만들었습니다. recovery serializer가 반환한 orphan record 한 개에서
per-boot secret을 얻었고, wrong HMAC은 거부, correct HMAC만 setuid gate의 saved-root
transition과 root-only proof를 열었습니다. 이후 catalog가 독립 random locator와
generation을 생산하고 stale `DESCRIBE`만 이를 회수하도록 raw anchor 선택을
제거했으며, 실제 final-release provenance가 없는 live receipt의 `REINDEX`도
`ESTALE`로 막았습니다. 이 최신 변경의 exact-wrapper cold boot 5/5, 총 10 xattr
reclaim first-attempt 증거는 `build/v4diag/archive-root-cold-20260819-234408/`입니다.
이전 `archive-root-cold-20260819-171639/`은 superseded입니다. 상태는
`terminal-diagnostic-proven`입니다. release 전 남은 핵심은 public layout에서 raw
cursor/anchor 및 secret-id/plain-secret diagnostic field를 완전히 제거하고 catalog
object 자체 reindex, challenge reuse/no-challenge verify, gate page-cache patch와 다른
kmalloc-cg-256 native producer shortcut을 반증하는 것입니다.

## 선택 gate

public v4 ABI를 작성하기 전에 다음을 모두 통과해야 합니다.

1. actual concurrent append로 receipt/native-reference deficit가 발생합니다.
2. race miss는 panic 없이 정리되고 반복 가능합니다.
3. Route 1는 key same-cache replacement가 아니라 slab page buddy return과 late key
   consumer까지 도달합니다.
4. Route 2는 xattr slot, caged edge, tree/list divergence, bounded secret serializer,
   approval consumer를 각각 관찰합니다.
5. Route 1 consumer를 compile out한 build에서 Route 2가 terminal이고, Route 2 consumer를 compile
   out한 build에서 Route 1이 terminal입니다.
6. 어느 route도 v1/v2/v3.2 primitive나 정적 usermode helper를 필요로 하지 않습니다.
7. shortest-path 표에 safe miss, leak, write, callback, page owner, output consumer를
   모두 적고, 한 object가 세 역할 이상을 겸하면 설계를 다시 엽니다.
8. 한 operation이나 reclaimed object가 overlap 확인, heap/KASLR 복구와 terminal target
   선택을 모두 제공하면 public 구현을 reject합니다. 적어도 두 개의 실제
   producer/consumer 갈래가 독립 invariant를 요구해야 하며 dead code decoy는 세지
   않습니다.

## 당시 결정과 최종 해소

이 연구 단계에서는 Route 1과 Route 2를 `terminal-diagnostic-proven` 후보로만 두고 private
oracle 제거, bootstrap graph, route-removal, shortcut/whole-consumer audit 전에는
player artifact나 service image를 만들지 않았습니다.

이후 generic mixed-ledger surface, no-key/no-archive route-removal, exact A/E/contract
cold 5/5, sealed artifact 감사와 fresh blind를 모두 완료했습니다. blind는 약 2시간
25분 뒤 `msg_msgseg` lease-overlay alternate로 actual remote terminal에 도달했고,
ordering/join/gate는 유지됐으므로 최종 판정은 `PASS-WITH-ALTERNATE-E`입니다.

공식 납품은 canonical player archive와 비공개 standalone TCP/QEMU service archive로
제한합니다. 이 문서의 research candidate나 reference CTFd/Instancer는 납품물이
아닙니다.
