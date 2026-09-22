# RE:CLAIM Route 1 풀이

## 1. 공격 표면

게스트는 uid 1000 BusyBox shell에서 `/dev/reclaim`, `/dev/reclaim-ledger`,
`/dev/reclaim-codec`를 제공합니다. ledger에는 signed statement, archive cursor,
memo, notice가 섞여 있고 token은 backend 종류나 커널 주소를 직접 노출하지 않습니다.
receipt의 정상 read 결과와 backend별 정상 동작을 이용해 signed statement만 분류해야
합니다.

Route 1의 목표는 approval key를 계산하는 것이 아니라 커널 credential을 직접
획득하는 것입니다. root가 된 뒤 `/root/quarantine/000`의 128개 객체 중 한 줄짜리
`SHA{...}` 객체를 찾아 출력합니다.

## 2. 공통 last-owner race

case resource는 native object reference 하나를 소유합니다. `PUBLISH`가 reviewer list를
순회할 때 마지막 reviewer라면 reference를 새로 얻지 않고 원래 reference를 receipt로
넘깁니다. 문제는 expensive policy evaluation 중 다른 CPU가 reviewer를 tail에 추가할
수 있다는 점입니다.

1. CPU 0에서 두 reviewer가 달린 case를 publish합니다.
2. 기존 tail이 자신을 마지막 reviewer로 판단한 직후 CPU 1이 새 tail을 추가합니다.
3. 두 reviewer가 모두 원래 reference를 전달받았다고 판단합니다.
4. receipt 수가 실제 native reference budget보다 하나 많아집니다.

race miss에서는 모든 close 뒤 refcount가 정확히 0이므로 재시도할 수 있습니다. win이면
receipt 하나만 남겨도 그 receipt가 이미 해제된 native object를 계속 가리킵니다.

## 3. signed statement와 key slab page 회수

signed statement backend의 실제 owner는 Linux `struct key`입니다. exploit은 mixed
ledger를 정상 API로 열거하고 envelope의 generation, digest, checksum을 검사해 statement
512개를 찾습니다. 이어 같은 storage group에 속한 16개 statement를 선택합니다.

last-owner race로 dangling key receipt를 만든 뒤 donor key와 동일 group의 key를 정리해
해당 `key_jar` slab page의 모든 live object를 제거합니다. CPU slab, CPU partial,
node partial에 남은 page가 buddy allocator로 반환되도록 별도의 native allocation
activity도 발생시킵니다. 단순히 key를 많이 free하는 것만으로는 page owner가 바뀌지
않는다는 점이 핵심입니다.

## 4. pipe page와 bounded arbitrary read

반환된 물리 페이지를 anonymous pipe의 backing page로 다시 할당받습니다. pipe는
append-only stream이므로 참가자가 page 내용을 채울 수 있고, dangling receipt는 같은
page 안의 예전 key slot을 정상 key read consumer로 해석합니다.

가짜 key의 `type`을 실제 `key_type_big_key`로, payload를 읽고 싶은 커널 주소로 맞추면
receipt read가 제한된 길이의 커널 메모리를 사용자 버퍼로 복사합니다. codec의 독립된
core pointer와 `kernel_offsets.h`의 delta로 KASLR base, `init_task`, `init_cred`,
`key_type_big_key`, `vmemmap_base`, `page_offset_base`를 복원합니다.

이 primitive로 task list에서 현재 PID를 찾고 다음을 순서대로 따라갑니다.

```text
current task
  → cred / real_cred
  → files
  → fdtable
  → pipe file
  → pipe_inode_info
  → pipe_buffer page
  → direct-map address
```

## 5. 가짜 key_type과 credential 전환

같은 pipe page에 다음 객체가 동시에 성립하도록 배치합니다.

- dangling receipt가 해석할 가짜 `struct key`
- late callback을 가진 가짜 `struct key_type`
- 현재 task의 기존 값을 보존하면서 uid/gid와 capability만 root로 바꾼 가짜 `cred`

`RECLAIM_RECEIPT_IOC_APPLY`가 late method를 호출하면 ENDBR-valid 커널 함수 entry를 통해
현재 task의 credential pointer가 조작된 cred로 전환됩니다. exploit은 uid/euid가 0이
되었는지 확인하고 root-only vault를 정상 `open/read/write` syscall로 읽습니다.

## 6. 힙 풍수의 의미

이 경로는 단순한 key spray가 아닙니다. `key_jar`의 특정 slab page에서 모든 key를
제거하고 allocator의 partial-list 상태까지 진행시킨 뒤, 그 **동일한 물리 페이지**를
pipe page로 회수해야 합니다. 객체의 배치뿐 아니라 slab page에서 buddy page, 다시
pipe backing page로 이어지는 page-owner 전환을 통제하므로 전형적인 kernel heap
feng shui에 해당합니다.

공식 exploit은 다음 terminal을 출력합니다.

```text
[RELEASE-A-VAULT-TERMINAL] SHA{...}
```

flag terminal 뒤 발생하는 panic이나 EOF는 이미 획득한 flag를 무효화하지 않습니다.
