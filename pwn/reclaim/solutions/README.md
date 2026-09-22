# Solutions

- [Route 1](route-1/) — Linux key lifetime, SLUB page reclaim, pipe-page feng shui와 forged credential을 이용한 kernel privilege escalation
- [Route 2](route-2/) — archive cursor lifetime bug, xattr/inotify consumer join과 approval HMAC key 복구

두 경로는 공통 last-owner race에서 출발하지만 이후 사용하는 native owner와 terminal
capability가 겹치지 않도록 설계했습니다. 공식 정적 바이너리는 GitHub Release에 있습니다.
