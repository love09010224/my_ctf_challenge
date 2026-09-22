FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_PATH=/tmp/meowpass.db

WORKDIR /app

RUN useradd --create-home --uid 10001 meowpass

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=meowpass:meowpass app.py ./
COPY --chown=meowpass:meowpass templates ./templates
COPY --chown=meowpass:meowpass static ./static

USER meowpass
EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')" || exit 1

CMD ["gunicorn", "--workers", "1", "--threads", "4", "--bind", "0.0.0.0:8000", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
