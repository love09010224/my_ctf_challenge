# MEOWPASS 운영 안내

화이트박스 추가 의뢰용 Flask/Gunicorn 서비스다. 참가자에게는 `for_user/app.py`
하나만 제공하고 이 운영 디렉터리 자체는 배포하지 않는다.

## 시작

```bash
cp .env.example .env
# .env의 FLAG와 SECRET_KEY를 운영값으로 교체
docker compose up --build -d
curl -fsS http://127.0.0.1:40584/healthz
```

## 종료

```bash
docker compose down
```

## 검수

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q
python3 solution/solve.py http://127.0.0.1:40584
```

상세 문제 정보와 플래그는 [`solution/README.md`](solution/README.md), 취약점
설명은 [`solution/writeup.md`](solution/writeup.md)를 확인한다.

## 운영 경계

- 외부 포트: `40584/tcp`
- health endpoint: `/healthz`
- 런타임: 비루트 사용자, read-only root filesystem, capability 전체 제거
- worker 수를 늘릴 때는 모든 worker에 동일한 `SECRET_KEY`를 반드시 설정한다.
- 운영 플래그를 설정하지 않으면 로컬 기본 플래그가 사용되므로 배포 전 `.env`를
  반드시 검수한다.
- `.env.example`의 `FLAG` 또는 `SECRET_KEY` 예시 문구가 그대로 남아 있으면
  애플리케이션은 시작을 거부한다.
- 공개 분석에 필요한 서비스 로직을 수정할 때는 `for_user/app.py`도 동기화하되,
  실제 플래그·풀이·테스트·의존성·템플릿·정적 파일·운영 설정은 복사하지 않는다.
