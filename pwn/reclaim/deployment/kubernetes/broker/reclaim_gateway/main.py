from __future__ import annotations

import asyncio
import logging
import ssl

from .broker import Broker
from .config import ConfigError, Settings
from .ctfd import CTFdClient
from .kubernetes import InstanceController, KubernetesApi
from .state import RedisSessionState, SessionState, StateError


LOGGER = logging.getLogger(__name__)


async def health_handler(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    state: SessionState,
) -> None:
    status = b"200 OK"
    body = b"ok\n"
    try:
        request = await asyncio.wait_for(reader.read(4096), timeout=2)
        first_line = request.split(b"\r\n", 1)[0]
        if b" /readyz " in first_line:
            try:
                await state.ping()
            except StateError:
                status = b"503 Service Unavailable"
                body = b"not ready\n"
        writer.write(
            b"HTTP/1.1 "
            + status
            + b"\r\nContent-Type: text/plain\r\nContent-Length: "
            + str(len(body)).encode("ascii")
            + b"\r\nConnection: close\r\n\r\n"
            + body
        )
        await writer.drain()
    except (ConnectionError, OSError, TimeoutError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


def tls_context(settings: Settings) -> ssl.SSLContext | None:
    if settings.tls_mode != "direct":
        return None
    assert settings.tls_cert_file is not None
    assert settings.tls_key_file is not None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(settings.tls_cert_file, settings.tls_key_file)
    return context


async def run(settings: Settings) -> None:
    validator = CTFdClient(settings)
    api = KubernetesApi(settings.namespace)
    controller = InstanceController(settings, api)
    state = RedisSessionState(settings)

    # Recreate strategy guarantees that any previous gateway connections are
    # gone. Remove their orphaned workloads before admitting a new connection,
    # then reset only this challenge's Redis keys.
    await state.ping()
    await controller.destroy_all()
    await state.reset()

    broker = Broker(settings, validator, controller, state)
    gateway = await asyncio.start_server(
        broker.handle,
        settings.listen_host,
        settings.listen_port,
        ssl=tls_context(settings),
        limit=2048,
    )
    health = await asyncio.start_server(
        lambda reader, writer: health_handler(reader, writer, state),
        settings.health_host,
        settings.health_port,
        limit=4096,
    )
    LOGGER.info(
        "gateway ready port=%d health_port=%d tls_mode=%s namespace=%s capacity=%d",
        settings.listen_port,
        settings.health_port,
        settings.tls_mode,
        settings.namespace,
        settings.max_instances,
    )
    try:
        async with gateway, health:
            await asyncio.gather(gateway.serve_forever(), health.serve_forever())
    finally:
        await state.close()


def main() -> None:
    try:
        settings = Settings.from_env()
    except ConfigError as error:
        raise SystemExit(f"configuration error: {error}") from error
    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        asyncio.run(run(settings))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
