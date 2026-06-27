"""Shared pytest fixtures.

Tests run against an in-memory SQLite database and the real application code
(no mocks). The backend uses flat module imports, so we add backend/ to the
path here.
"""

import os
import sys

# Make backend modules importable (config, app, models, ...).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

# Configure a safe, isolated test environment before importing the app.
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-long-enough-1234567890")
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-key-that-is-long-enough-0987654321")

import pytest  # noqa: E402

from app import create_app  # noqa: E402
from config import Config  # noqa: E402


@pytest.fixture
def app():
    application = create_app(Config)
    application.config["RATELIMIT_ENABLED"] = False
    return application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_client(client):
    """A test client already registered + authenticated, returning (client, headers)."""
    import uuid
    email = f"user-{uuid.uuid4().hex[:8]}@test.com"
    resp = client.post("/api/v1/auth/register", json={"email": email, "password": "password123"})
    token = resp.get_json()["token"]
    return client, {"Authorization": f"Bearer {token}"}
