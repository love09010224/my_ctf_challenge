# Route 2 — archive ordering/redaction join → approval key

> 내부 source와 canonical binary의 `[RELEASE-E-*]` marker는 대회 당시 동결된 호환 이름이며, 공개 문서의 Route 2를 뜻합니다.


## 문제 정보

- 분야: Pwn / Linux kernel
- 작성자: `dkstjwls06`
- 원격 모델: CTFd Access Token 인증 뒤 팀별 일회성 QEMU VM
- Flag: `SHA{9a73f71c816d7bae202fd5a6c175ace1}`

`reclaim-route-2-exploit`은 GitHub Release에 첨부된 production service rootfs에 대응하는 정적 `linux/amd64` Route 2
바이너리입니다. 참가자 배포물에는 포함하지 않습니다. 같은 exploit과 현재 stripped
module을 사용한 development-vault acceptance는 client-level retry 없이 single 1/1,
독립적인 cold 30-way 세 batch 연속 30/30을 통과했습니다. 상세 수치는
[`../../docs/capacity-and-acceptance.md`](../../docs/capacity-and-acceptance.md)를 참조합니다.

## 파일

```text
reclaim-route-2-exploit  GitHub Release의 검증된 정적 Route 2 바이너리
exploit.c               exploit source
reclaim_v4_uapi.h       공개 device ABI 사본
solve_remote.py         TLS/token 인증, 업로드, 실행 자동화
writeup.md              취약점과 exploit chain
```

검증된 바이너리 SHA-256:

```text
4bf27c63ccf36a28e586765d7fcadf7617ce227425538be32bf3966dc298301d  reclaim-route-2-exploit
```

## 빌드

Ubuntu 계열에서 static glibc와 OpenSSL 개발 파일을 준비한 뒤 실행합니다.

```sh
sudo apt-get install build-essential libc6-dev libssl-dev
make
file exploit
```

컴파일러와 static library 버전에 따라 재빌드 hash는 달라질 수 있습니다. 운영 E2E와
공식 풀이에는 위 hash의 Release asset `reclaim-route-2-exploit`을 사용합니다.

## 원격 실행

Access Token은 명령행 인자가 아니라 숨김 prompt 또는 표준입력으로 전달합니다.

```sh
python3 solve_remote.py \
  --host pwnable2.roomescapectf2026.site \
  --port 31337 \
  --server-name pwnable2.roomescapectf2026.site
```

private CA라면 `--ca-file ca.crt`를 추가합니다. 성공 시 solver는 guest에서 직접 받은
flag 한 줄만 출력하고 연결을 닫습니다.

> 대회 당시 endpoint는 기록 목적으로 남겼으며, 대회 종료 후 가용성은 보장하지 않습니다.
