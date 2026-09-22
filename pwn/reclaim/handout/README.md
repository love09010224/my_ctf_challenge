# RE:CLAIM — BOX 000

의뢰인: “정산 분쟁 때문에 000번 보관함이 폐기 대상으로 넘어갔습니다.
반출 게이트가 승인서 원본만 받아요. 서버에 남아 있는 제 비밀키만 빼내 주세요.”

## 제공 파일

- `reclaim-box-000-player.tar.gz`
- SHA-256: `e7036d5a345960ad172bbab3dea5530ca718bf5f6936a24b8c9c1ffc2ee9fc66`

압축을 풀면 로컬 실행용 `bzImage`, `rootfs.cpio.gz`, `run.sh`가 있습니다.
Linux x86-64와 QEMU가 설치된 환경에서 `./run.sh`로 실행할 수 있습니다.

## 원격 접속

CTFd 문제 페이지의 Connection Info를 기준으로 TLS endpoint에 접속합니다.
먼저 CTFd의 `/settings`에서 자신의 Access Token을 생성하고, 접속 직후 `Token:`
prompt에 입력합니다. Access Token을 명령행 인자나 URL에 넣지 마십시오.

## 세션 규칙

- 같은 팀은 서로 다른 개인 Access Token을 사용해도 active/queued를 합쳐 한 연결만
  유지할 수 있습니다.
- 할당된 VM의 제한 시간은 900초입니다.
- 연결을 끊거나 VM이 종료된 뒤 다시 접속하면 이전 상태가 없는 새 VM이 할당됩니다.
- 정답 형식은 `SHA{...}`입니다.
