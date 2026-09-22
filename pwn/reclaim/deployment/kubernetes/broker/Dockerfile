FROM python:3.12-slim-bookworm@sha256:0f5b26b9518d002b6173fd61daad821fa340635ebfec5bba471013f9ca114579

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir --require-hashes -r /app/requirements.txt
COPY reclaim_gateway /app/reclaim_gateway

ENV HOME=/nonexistent \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 65532:65532
EXPOSE 31337/tcp 8080/tcp

ENTRYPOINT ["python", "-m", "reclaim_gateway"]
