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
