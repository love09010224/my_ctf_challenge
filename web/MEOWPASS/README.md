# MEOWPASS

서울시립대학교 방탈출 CTF
**〈주말에 뭐 하세요? 바쁘세요? 해결 가능하신가요?〉**의 독립 추가 의뢰로
제작한 초급 Web 문제다.

## 구조

```text
for_user/
├── README.md                 # CTFd에 사용할 참가자 의뢰문
└── app.py                    # 유일한 참가자 첨부 파일

for_admin/
├── app.py
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── static/
├── templates/
├── tests/
└── solution/
    ├── README.md
    ├── writeup.md
    └── solve.py
```

저장소 경로는 `web/MEOWPASS/`다.

`for_user/app.py`는 취약점과 화면 동작이 운영 소스와 같고 기본 플래그만
`SHA{local_dummy_flag}`로 치환되어 있다. 참가자에게 첨부하는 파일은 이
`app.py` 하나뿐이며, 의존성·템플릿·정적 파일은 제공하지 않는다. 실제 플래그,
풀이, 테스트, 화면 리소스와 운영 설정은 계속 `for_admin/`에만 둔다.

## 로컬 실행

```bash
cd for_admin
docker compose up --build -d
python3 solution/solve.py http://127.0.0.1:40584
```

종료:

```bash
docker compose down
```

외부 포트 `40584`는 저장소의 다른 대표 Compose 포트와 겹치지 않으며,
루트 배포 문서와 업로드 기록에도 반영되어 있다.
