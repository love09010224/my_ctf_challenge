# MEOWPASS

## 문제 정보

- **분야:** Web
- **담당자:** `dkstjwls06`
- **분류:** 추가 의뢰
- **의뢰명:** 새벽 4시 04분의 손님
- **난이도:** Beginner
- **의도 취약점:** 로그인 SQL Injection
- **플래그:** `SHA{wh0_ate_the_tuna_at_0404}`
- **기본 외부 포트:** `40584/tcp`

## 참가자 공개 설명

참가자 문안은 [`../../for_user/README.md`](../../for_user/README.md)를 그대로
사용한다. 이 문제는 본편 이민성 교수 사건과 인물·증거·결과를 공유하지 않는
사무소 404의 독립 추가 의뢰다.

## 빌드 및 실행

```bash
cd for_admin
docker compose up --build -d
curl -fsS http://127.0.0.1:40584/healthz
```

운영 플래그를 바꾸려면 `.env.example`을 `.env`로 복사한 뒤 `FLAG`를 설정한다.
`FLAG`와 `SECRET_KEY` 중 하나라도 예시 문구 그대로면 서비스는 시작을 거부한다.
Compose 파일에는 저장소 배포기가 읽는 다음 메타데이터가 포함되어 있다.

```yaml
x-uos-ctf:
  category: web
```

서비스는 한 개의 Gunicorn worker와 네 thread로 동작한다. Flask 서명 키는
프로세스 시작 시 무작위로 생성되므로 소스만으로 관리자 세션을 위조할 수 없다.
관리자 암호 역시 시작 시 무작위로 생성된다.

## 검증

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q
python3 solution/solve.py http://127.0.0.1:40584
```

기대 결과:

```text
SHA{wh0_ate_the_tuna_at_0404}
```

## 참가자 배포 범위

이 문제는 완전 초심자를 위한 화이트박스 Web 문제다. 참가자에게는
`for_user/README.md`의 문제 설명과 실제 플래그를 더미로 치환한 `app.py` 하나만
공개한다. 의존성, 템플릿, 정적 파일, `for_admin/`, 풀이, 테스트, 운영 환경변수와
실제 플래그는 제공하지 않는다.
