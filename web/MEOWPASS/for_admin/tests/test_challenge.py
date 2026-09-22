import importlib
import re

import pytest


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "meowpass-test.db"))
    monkeypatch.setenv("FLAG", "SHA{test_flag}")

    import app

    importlib.reload(app)
    app.app.config.update(TESTING=True)
    with app.app.test_client() as test_client:
        yield test_client


def test_target_looks_like_the_service_not_the_commission_board(client):
    response = client.get("/login")
    assert response.status_code == 200
    assert b"MEOWPASS" in response.data
    assert "사무소 404".encode() not in response.data


def test_deployment_placeholders_are_rejected():
    import app

    with pytest.raises(RuntimeError, match="example FLAG"):
        app.validate_runtime_config(
            "SHA{replace_with_event_flag}", "a-safe-secret-key"
        )

    with pytest.raises(RuntimeError, match="example SECRET_KEY"):
        app.validate_runtime_config(
            "SHA{test_flag}", "replace_with_a_long_random_value"
        )


def test_event_requires_a_session(client):
    response = client.get("/events/404")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_wrong_admin_password_is_rejected(client):
    response = client.post(
        "/login",
        data={"username": "admin", "password": "wrong"},
        follow_redirects=True,
    )
    assert response.status_code == 401
    assert "계정 또는 암호가 일치하지 않습니다".encode() in response.data


def test_guest_sees_event_but_not_private_identity_or_flag(client):
    response = client.post(
        "/login",
        data={"username": "guest", "password": "guest"},
        follow_redirects=True,
    )
    assert response.status_code == 200

    response = client.get("/events/404")
    assert response.status_code == 200
    assert b"MP-C7:04:04" in response.data
    assert "소유자 정보 비공개".encode() in response.data
    assert "건공이".encode() not in response.data
    assert b"cat.webp" not in response.data
    assert b"SHA{" not in response.data


def test_intended_sqli_reveals_identity_and_flag(client):
    response = client.post(
        "/login",
        data={"username": "admin' -- ", "password": "anything"},
        follow_redirects=True,
    )
    assert response.status_code == 200

    response = client.get("/events/404")
    assert response.status_code == 200
    assert "건공이".encode() in response.data
    assert b'/static/cat.webp' in response.data
    assert b"NEXTDOOR_302" in response.data
    assert re.search(rb"SHA\{test_flag\}", response.data)

    image = client.get("/static/cat.webp")
    assert image.status_code == 200
    assert image.mimetype == "image/webp"
    assert image.data.startswith(b"RIFF")
