# RE:CLAIM — BOX 000 CTFd 등록 기준

이 파일은 CTFd에 복사할 필드와 참가자 공개 설명의 기준본입니다. 대회 당시 production
gateway는 `pwnable2.roomescapectf2026.site:31337`입니다.

## 문제 필드

| 필드 | 값 |
| --- | --- |
| Name | `RE:CLAIM — BOX 000` |
| Category | `추가 의뢰` |
| Type | `dynamic` (`logarithmic`, initial `1000`, minimum `200`, decay `9`) |
| State | `visible` |
| Attribution | `KERN3L_P4N!C` |
| Attachment | GitHub Release의 `reclaim-box-000-player.tar.gz` |
| Attachment SHA-256 | `e7036d5a345960ad172bbab3dea5530ca718bf5f6936a24b8c9c1ffc2ee9fc66` |

Connection Info:

```text
ncat --ssl pwnable2.roomescapectf2026.site 31337
```

실제 flag는 이 파일에 중복 기록하지 않습니다. CTFd에는
`solutions/route-2/README.md`의 canonical 값을 등록합니다.

## Description

아래 블록을 참가자 공개 설명으로 사용합니다.

```markdown
의뢰인: “정산 분쟁 때문에 000번 보관함이 폐기 대상으로 넘어갔습니다.
반출 게이트가 승인서 원본만 받아요. 서버에 남아 있는 제 비밀키만 빼내 주세요.”

### 제공 파일

- `reclaim-box-000-player.tar.gz`
- SHA-256: `e7036d5a345960ad172bbab3dea5530ca718bf5f6936a24b8c9c1ffc2ee9fc66`

압축을 풀면 로컬 실행용 `bzImage`, `rootfs.cpio.gz`, `run.sh`가 있습니다.
Linux x86-64와 QEMU가 설치된 환경에서 `./run.sh`로 실행할 수 있습니다.

### 원격 접속

1. CTFd의 `/settings`에서 자신의 Access Token을 생성합니다.
2. Connection Info의 TLS endpoint에 접속합니다.
3. 접속 직후 표시되는 `Token:` prompt에 Access Token을 입력합니다.

Access Token을 명령행 인자나 URL에 넣지 마십시오.

- 같은 팀은 서로 다른 개인 token을 사용해도 active/queued를 합쳐 한 연결만 유지할
  수 있습니다.
- 할당된 VM의 제한 시간은 900초입니다.
- 연결을 끊고 다시 접속하면 이전 상태가 없는 새 VM이 할당됩니다.
- 정답 형식은 `SHA{...}`입니다.
```
