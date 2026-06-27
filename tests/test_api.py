"""End-to-end API tests against the real Flask app (in-memory DB)."""

import io
import zipfile

import pytest


def make_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.py",
                    "import hashlib\n"
                    "from cryptography.hazmat.primitives.asymmetric import rsa\n"
                    "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
                    "h = hashlib.md5(b'x')\n")
    buf.seek(0)
    return buf


# ---- auth ----------------------------------------------------------------- #

def test_register_returns_token(client):
    r = client.post("/api/v1/auth/register", json={"email": "a@b.com", "password": "password123"})
    assert r.status_code == 201
    assert r.get_json()["token"]


def test_register_rejects_short_password(client):
    r = client.post("/api/v1/auth/register", json={"email": "a@b.com", "password": "short"})
    assert r.status_code == 400


def test_register_rejects_duplicate(client):
    client.post("/api/v1/auth/register", json={"email": "dup@b.com", "password": "password123"})
    r = client.post("/api/v1/auth/register", json={"email": "dup@b.com", "password": "password123"})
    assert r.status_code == 409


def test_login_and_bad_login(client):
    client.post("/api/v1/auth/register", json={"email": "l@b.com", "password": "password123"})
    assert client.post("/api/v1/auth/login", json={"email": "l@b.com", "password": "password123"}).status_code == 200
    assert client.post("/api/v1/auth/login", json={"email": "l@b.com", "password": "nope"}).status_code == 401


def test_protected_endpoint_requires_auth(client):
    assert client.get("/api/v1/overview").status_code == 401


# ---- api keys ------------------------------------------------------------- #

def test_apikey_generation(auth_client):
    client, headers = auth_client
    r = client.post("/api/v1/user/apikey", headers=headers)
    assert r.status_code == 201
    assert r.get_json()["api_key"].startswith("qs_live_")


# ---- scanning ------------------------------------------------------------- #

def test_scan_upload_and_persist(auth_client):
    client, headers = auth_client
    r = client.post("/api/v1/scan", headers=headers,
                    data={"file": (make_zip(), "code.zip")},
                    content_type="multipart/form-data")
    assert r.status_code == 201
    report = r.get_json()["report"]
    assert report["risk_score"] > 0
    assert report["summary"]["high"] >= 2


def test_scan_via_api_key(auth_client):
    client, headers = auth_client
    key = client.post("/api/v1/user/apikey", headers=headers).get_json()["api_key"]
    r = client.post("/api/v1/scan", headers={"X-API-Key": key},
                    data={"file": (make_zip(), "code.zip")},
                    content_type="multipart/form-data")
    assert r.status_code == 201


def test_list_detail_overview_migration(auth_client):
    client, headers = auth_client
    sid = client.post("/api/v1/scan", headers=headers,
                      data={"file": (make_zip(), "code.zip")},
                      content_type="multipart/form-data").get_json()["scan_id"]

    assert client.get("/api/v1/scans", headers=headers).get_json()["total"] == 1
    detail = client.get(f"/api/v1/scans/{sid}", headers=headers).get_json()["scan"]
    assert len(detail["findings"]) > 0
    assert client.get("/api/v1/overview", headers=headers).get_json()["total_scans"] == 1
    mig = client.get(f"/api/v1/scans/{sid}/migration", headers=headers).get_json()
    assert len(mig["plan"]["HIGH"]) > 0


@pytest.mark.parametrize("fmt,needle", [
    ("csv", "file_path"),
    ("html", "<!DOCTYPE html>"),
])
def test_exports(auth_client, fmt, needle):
    client, headers = auth_client
    sid = client.post("/api/v1/scan", headers=headers,
                      data={"file": (make_zip(), "code.zip")},
                      content_type="multipart/form-data").get_json()["scan_id"]
    r = client.get(f"/api/v1/scans/{sid}/export?format={fmt}", headers=headers)
    assert r.status_code == 200
    assert needle in r.get_data(as_text=True)


def test_free_plan_scan_limit(auth_client):
    client, headers = auth_client
    for _ in range(3):
        assert client.post("/api/v1/scan", headers=headers,
                           data={"file": (make_zip(), "code.zip")},
                           content_type="multipart/form-data").status_code == 201
    # 4th scan in the same month should be blocked for a free user.
    r = client.post("/api/v1/scan", headers=headers,
                    data={"file": (make_zip(), "code.zip")},
                    content_type="multipart/form-data")
    assert r.status_code == 402


def test_billing_not_configured(auth_client):
    client, headers = auth_client
    r = client.post("/api/v1/billing/checkout", headers=headers, json={"plan": "pro"})
    assert r.status_code == 503  # no Stripe keys in test env
