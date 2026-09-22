import mimetypes
import os
import secrets
import sqlite3
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, session, url_for


DATABASE = Path(os.getenv("DATABASE_PATH", "/tmp/meowpass.db"))
FLAG = os.getenv("FLAG", "SHA{local_dummy_flag}")
CONFIGURED_SECRET_KEY = os.getenv("SECRET_KEY")

# python:slim does not include every system MIME mapping by default.
mimetypes.add_type("image/webp", ".webp")


def validate_runtime_config(flag: str, secret_key: str | None) -> None:
    if flag == "SHA{" + "replace_with_event_flag}":
        raise RuntimeError("Replace the example FLAG before starting MEOWPASS")
    if secret_key == "replace_with_a_long_random_value":
        raise RuntimeError("Replace the example SECRET_KEY before starting MEOWPASS")


validate_runtime_config(FLAG, CONFIGURED_SECRET_KEY)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=CONFIGURED_SECRET_KEY or secrets.token_hex(32),
    MAX_CONTENT_LENGTH=4096,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


EVENTS = {
    404: {
        "id": 404,
        "occurred_at": "2026.09.18 04:04:04",
        "device": "현관 급식기 A-04",
        "tag_id": "MP-C7:04:04",
        "menu": "참치 습식사료 85 g",
        "result": "급식 완료",
        "pet_name": "건공이",
        "pet_type": "코리안 쇼트헤어 · 치즈태비",
        "pet_image": "cat.webp",
        "guardian": "NEXTDOOR_302",
        "cause": "인접 세대 태그가 공유 급식 그룹 M-04에 잘못 연결됨",
        "verification_code": FLAG,
    },
    317: {
        "id": 317,
        "occurred_at": "2026.09.17 19:32:18",
        "device": "주방 급식기 B-01",
        "tag_id": "MP-11:20:AB",
        "menu": "닭고기 건식사료 42 g",
        "result": "급식 완료",
        "pet_name": "나비",
        "pet_type": "코리안 쇼트헤어 · 고등어태비",
        "guardian": "EMPTY_BOWL",
        "cause": "정상 등록 태그",
        "verification_code": None,
    },
    316: {
        "id": 316,
        "occurred_at": "2026.09.17 08:10:03",
        "device": "주방 급식기 B-01",
        "tag_id": "MP-11:20:AB",
        "menu": "닭고기 건식사료 42 g",
        "result": "급식 완료",
        "pet_name": "나비",
        "pet_type": "코리안 쇼트헤어 · 고등어태비",
        "guardian": "EMPTY_BOWL",
        "cause": "정상 등록 태그",
        "verification_code": None,
    },
}


def get_db() -> sqlite3.Connection:
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


def init_db() -> None:
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    DATABASE.unlink(missing_ok=True)

    with get_db() as db:
        db.executescript(
            """
            CREATE TABLE accounts (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role     TEXT NOT NULL CHECK (role IN ('guest', 'admin'))
            );
            """
        )

        # The unknown password keeps guessing from becoming an alternate route.
        # Admin is inserted first so the generic beginner payload also works.
        db.execute(
            "INSERT INTO accounts (username, password, role) VALUES (?, ?, ?)",
            ("admin", secrets.token_urlsafe(32), "admin"),
        )
        db.execute(
            "INSERT INTO accounts (username, password, role) VALUES (?, ?, ?)",
            ("guest", "guest", "guest"),
        )


def current_role_label() -> str:
    return "운영자" if session.get("role") == "admin" else "체험 계정"


@app.after_request
def add_response_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


@app.get("/")
def index():
    if session.get("account_id"):
        return redirect(url_for("events"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if session.get("account_id"):
            return redirect(url_for("events"))
        return render_template("login.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # INTENTIONALLY VULNERABLE FOR THE CTF CHALLENGE.
    # Never construct authentication queries this way in a real service.
    query = (
        "SELECT id, username, role FROM accounts "
        f"WHERE username = '{username}' AND password = '{password}' LIMIT 1"
    )

    try:
        with get_db() as db:
            account = db.execute(query).fetchone()
    except sqlite3.Error:
        flash("로그인 요청을 처리하지 못했습니다. 입력값을 확인해 주세요.", "error")
        return render_template("login.html"), 400

    if account is None:
        flash("계정 또는 암호가 일치하지 않습니다.", "error")
        return render_template("login.html"), 401

    session.clear()
    session["account_id"] = account["id"]
    session["username"] = account["username"]
    session["role"] = account["role"]
    return redirect(url_for("events"))


@app.get("/events")
def events():
    if not session.get("account_id"):
        return redirect(url_for("login"))

    rows = [EVENTS[event_id] for event_id in sorted(EVENTS, reverse=True)]
    return render_template(
        "events.html",
        events=rows,
        username=session.get("username"),
        role_label=current_role_label(),
    )


@app.get("/events/<int:event_id>")
def event_detail(event_id: int):
    if not session.get("account_id"):
        return redirect(url_for("login"))

    event = EVENTS.get(event_id)
    if event is None:
        return render_template("404.html"), 404

    is_admin = session.get("role") == "admin"
    return render_template(
        "event_detail.html",
        event=event,
        is_admin=is_admin,
        username=session.get("username"),
        role_label=current_role_label(),
    )


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "meowpass"}


init_db()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")), debug=False)
