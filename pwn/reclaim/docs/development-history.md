# RE:CLAIM 개발·운영 요약

- Linux 6.12.103과 x86-64 QEMU를 기준으로 두 독립 terminal route를 설계했습니다.
- Route 1는 native key reference의 last-owner race와 SLUB page-owner 전환을 이용합니다.
- Route 2는 같은 race root에서 출발하지만 tmpfs xattr와 inotify event라는 별도의 native
  consumer 둘을 join해 approval HMAC key를 복구합니다.
- player artifact를 모르는 외부 환경에서 blind solve를 수행하고 shortcut과 노출 surface를
  반복 감사했습니다.
- 참가자 artifact는 SHA-256 `e7036d5a…fc66`으로 동결했습니다.
- TCP serial의 CPR echo 문제를 guest cmdline marker로만 해결해 로컬 handout 동작은
  바꾸지 않았습니다.
- CTFd Access Token을 같은 TLS socket에서 검증하고 token bytes를 guest에 전달하지 않는
  gateway를 구현했습니다.
- 같은 팀은 active/queued 합계 한 세션으로 제한하고, 31번째 팀부터 Redis FIFO에서
  Pod-free 상태로 대기하도록 했습니다.
- Route 1 30/30, Route 2 single 1/1 및 독립적인 30-way 세 batch 30/30을 검증했습니다.
- 최종 production module은 archive topology 시도의 비본질적 초기화 실패를 제거하기 위해
  layout attempt를 512로 조정했습니다.
- 대회 전체 기준 4팀이 solve했습니다.

세부 설계 판단과 rejected shortcut은 [`design-history/`](design-history/) 문서에 남겼습니다.
