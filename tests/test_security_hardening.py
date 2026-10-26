"""Regression tests for the 2026-10-26 security review of the backend.

Each test pins one fix:
  * reset links are single-use (they were valid for their full hour, reusable);
  * a zip that would expand past the caps is refused before anything is written;
  * oversized uploads are rejected at the door with a JSON 413;
  * rate limits are per visitor (behind Render's proxy they were site-wide);
  * the app refuses to start on Render with the public default secret.
"""

import io
import re
import uuid
import zipfile

import auth
import pytest
import scanner_service
from app import create_app
from config import DEV_SECRET, Config


def _register(client, password="password123"):
    email = f"user-{uuid.uuid4().hex[:8]}@test.com"
    client.post("/api/v1/auth/register",
                json={"email": email, "password": password, "accept_terms": True})
    return email


def _reset_token(client, monkeypatch, email):
    sent = []
    monkeypatch.setattr(auth, "send_email", lambda subject, to, body: sent.append(body))
    client.post("/api/v1/auth/forgot", json={"email": email})
    return re.search(r"reset=(\S+)", sent[0]).group(1)


def test_reset_link_works_once(client, monkeypatch):
    email = _register(client)
    token = _reset_token(client, monkeypatch, email)

    first = client.post("/api/v1/auth/reset", json={"token": token, "password": "new-password-1"})
    assert first.status_code == 200
    again = client.post("/api/v1/auth/reset", json={"token": token, "password": "new-password-2"})
    assert again.status_code == 400

    login = client.post("/api/v1/auth/login", json={"email": email, "password": "new-password-1"})
    assert login.status_code == 200


def test_old_style_reset_token_is_rejected(client, app):
    """A token carrying only the user id (the old format) must not verify."""
    _register(client)
    with app.app_context():
        legacy = auth._serializer().dumps(1, salt=auth.RESET_SALT)
    resp = client.post("/api/v1/auth/reset", json={"token": legacy, "password": "new-password-1"})
    assert resp.status_code == 400


def _zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_zip_that_expands_past_the_cap_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner_service, "_MAX_EXTRACTED_BYTES", 1_000)
    path = tmp_path / "bomb.zip"
    path.write_bytes(_zip({"a.py": b"0" * 5_000}))   # compresses to ~30 bytes
    with pytest.raises(ValueError, match="expands past"):
        scanner_service._safe_extract(str(path), str(tmp_path / "out"))
    assert not (tmp_path / "out" / "a.py").exists()


def test_zip_with_too_many_files_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner_service, "_MAX_ARCHIVE_FILES", 2)
    path = tmp_path / "many.zip"
    path.write_bytes(_zip({f"f{i}.py": b"x = 1\n" for i in range(3)}))
    with pytest.raises(ValueError, match="more than"):
        scanner_service._safe_extract(str(path), str(tmp_path / "out"))


def test_oversized_upload_gets_json_413(app):
    app.config["MAX_CONTENT_LENGTH"] = 1_000
    resp = app.test_client().post(
        "/api/v1/scan", data={"file": (io.BytesIO(b"0" * 5_000), "big.zip")},
        content_type="multipart/form-data")
    assert resp.status_code == 413
    assert "25 MB" in resp.get_json()["error"]


def test_rate_limits_are_per_visitor():
    application = create_app(Config)
    application.config["RATELIMIT_ENABLED"] = True
    client = application.test_client()
    a = {"CF-Connecting-IP": f"198.51.100.{uuid.uuid4().int % 250 + 1}"}
    b = {"CF-Connecting-IP": "203.0.113.77"}
    body = {"email": "nobody@test.com", "password": "wrong-password"}

    codes = [client.post("/api/v1/auth/login", json=body, headers=a).status_code
             for _ in range(21)]
    assert codes[-1] == 429, "the 21st login from one visitor should be limited"
    assert client.post("/api/v1/auth/login", json=body, headers=b).status_code == 401, (
        "a different visitor must not inherit the first one's limit")


def test_refuses_to_start_on_render_with_the_default_secret(monkeypatch):
    class Default(Config):
        SECRET_KEY = DEV_SECRET
        JWT_SECRET_KEY = DEV_SECRET

    monkeypatch.setenv("RENDER", "true")
    with pytest.raises(RuntimeError, match="must be set in production"):
        create_app(Default)
