# Route 1 — key slab page → pipe page → forged key/cred

> 내부 source와 canonical binary의 `[RELEASE-A-*]` marker는 대회 당시 동결된 호환 이름이며, 공개 문서의 Route 1을 뜻합니다.


Route 1은 RE:CLAIM의 Linux kernel 권한 상승 풀이입니다. 공통 last-owner race로
`struct key`의 소유권 deficit을 만들고, dangling receipt가 가리키는 key slab page를
완전히 비운 뒤 해당 물리 페이지를 pipe backing page로 재할당합니다. 참가자가
제어하는 pipe page에 가짜 `struct key`, `struct key_type`, `struct cred`를 구성하고
`APPLY`의 late method를 호출해 현재 프로세스의 credential을 root로 바꿉니다.

## 파일

- `exploit.c`: 검증된 Route 1 exploit source
- `reclaim_v4_uapi.h`: device ABI
- `kernel_offsets.h`: 배포된 Linux 6.12.103/bzImage용 정적 offset
- `solve_remote.py`: TLS gateway 인증, 업로드 및 실행 자동화
- `writeup.md`: 전체 exploit chain

공식 정적 바이너리는 GitHub Release의 `reclaim-route-1-exploit`입니다.

```text
063d9b4761e83ba2f26fbd03ad9593109e9bc48050798b81841b2de64a503729
```

## 빌드

Ubuntu 24.04 계열에서 다음과 같이 빌드합니다.

```sh
sudo apt-get install build-essential libc6-dev
make
```

## 원격 실행

대회 당시 endpoint는 아래와 같았습니다. 대회 종료 후에는 동작을 보장하지 않습니다.
Access Token은 명령행이 아니라 숨김 prompt 또는 표준입력으로 전달합니다.

```sh
python3 solve_remote.py \
  --host pwnable2.roomescapectf2026.site \
  --port 31337 \
  --server-name pwnable2.roomescapectf2026.site
```

실제 flag가 출력되면 이후 VM panic이나 연결 종료 여부와 무관하게 성공입니다.
