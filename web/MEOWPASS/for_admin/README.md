## 시작

```bash
cp .env.example .env
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
