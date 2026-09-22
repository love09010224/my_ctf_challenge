#!/usr/bin/env python3
"""Exercise the broker against an unmodified CTFd 3.8.5 application."""

from __future__ import annotations

import logging
import sys
import threading
from pathlib import Path


def main() -> int:
    Path("/tmp/uploads").mkdir(exist_ok=True)
    Path("/tmp/logs").mkdir(exist_ok=True)
    sys.path[:0] = ["/opt/CTFd", "/gateway"]

    from CTFd import create_app
    from CTFd.models import Challenges, Teams, Users, db
    from CTFd.utils import set_config
    from CTFd.utils.security.auth import generate_user_token
    from reclaim_gateway.config import Settings
    from reclaim_gateway.ctfd import CTFdClient
    from werkzeug.serving import make_server

    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    app = create_app()
    with app.app_context():
        db.create_all()
        set_config("setup", True)
        set_config("user_mode", "teams")

        team = Teams(
            name="compat-team",
            email="team@example.invalid",
            password="not-used-for-this-test",
        )
        db.session.add(team)
        db.session.commit()
        user = Users(
            name="compat-user",
            email="user@example.invalid",
            password="not-used-for-this-test",
            type="user",
            verified=True,
            team_id=team.id,
        )
        challenge = Challenges(
            name="compat-challenge",
            description="",
            value=500,
            category="pwn",
            type="standard",
            state="visible",
        )
        db.session.add_all([user, challenge])
        db.session.commit()
        team_id = team.id
        challenge_id = challenge.id
        token = generate_user_token(user).value

    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        settings = Settings(
            ctfd_base_url=f"http://127.0.0.1:{server.server_port}",
            ctfd_challenge_id=challenge_id,
            ctfd_require_team=True,
            ctfd_ca_file=None,
            ctfd_timeout_seconds=5,
            namespace="reclaim-instances",
            challenge_image="compat.invalid/reclaim@sha256:" + "a" * 64,
            instance_name_secret=b"x" * 32,
            tls_mode="plaintext",
        )
        identity = CTFdClient(settings).validate(token)
        if identity.subject != f"team:{team_id}":
            raise RuntimeError("CTFd returned an unexpected team identity")
    finally:
        token = ""
        server.shutdown()
        thread.join(timeout=5)

    print("[KUBERNETES-CTFD-3.8.5-COMPAT-PASS]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
