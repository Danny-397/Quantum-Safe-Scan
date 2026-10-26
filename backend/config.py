"""Application configuration, loaded from environment variables.

All secrets come from the environment (or a local .env in development). Nothing
sensitive is hardcoded.
"""

import os
import re

from dotenv import load_dotenv

load_dotenv()


def _normalize_db_url(url: str) -> str:
    # Render/Heroku hand out postgres:// URLs; SQLAlchemy needs postgresql://.
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    return url


def _merge_origins(configured: list, defaults: list) -> list:
    """Configured origins first, then any default not already among them.

    A module-level helper rather than a comprehension in the class body: a
    comprehension there gets its own scope and cannot see the class's other
    names, which raises NameError at import time.
    """
    return configured + [
        o for o in defaults
        if not (isinstance(o, str) and o in configured)
    ]


DEV_SECRET = "dev-secret-change-me"


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", DEV_SECRET)
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = 60 * 60 * 24 * 7  # 7 days (seconds)

    # Flask otherwise accepts an upload of any size and writes it to disk before
    # scanner_service checks its 25 MB limit; refuse it at the door instead.
    MAX_CONTENT_LENGTH = 26 * 1024 * 1024

    SQLALCHEMY_DATABASE_URI = _normalize_db_url(
        os.environ.get("DATABASE_URL", "sqlite:///quantumsafe.db")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # CORS: comma-separated list of allowed dashboard origins.
    #
    # We normalize away trailing slashes (a common .env footgun: flask-cors does
    # an exact match, so "https://x.vercel.app/" would NOT match the browser's
    # origin "https://x.vercel.app" and every request fails with "Failed to
    # fetch"). On top of the explicitly configured origins we always allow the
    # production domain, any Vercel deployment (production + preview URLs) and
    # localhost, so the dashboard works even if FRONTEND_ORIGIN is unset or
    # points at a different Vercel URL.
    #
    # The production domain is hardcoded deliberately. It used to be reachable
    # only through FRONTEND_ORIGIN, and with that unset the browser got no
    # Access-Control-Allow-Origin at all from quantumsafescan.com: the page
    # loaded and the UI rendered, but every scan failed in the console. curl
    # could not catch it, because curl does not enforce CORS. The domain is
    # stable, so it does not belong in environment config that can silently go
    # missing on a redeploy.
    FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "http://localhost:3000")
    _configured_origins = [
        o.strip().rstrip("/") for o in FRONTEND_ORIGIN.split(",") if o.strip()
    ]
    _default_origins = [
        "https://quantumsafescan.com",                        # production
        "https://www.quantumsafescan.com",
        re.compile(r"^https://[A-Za-z0-9-]+\.vercel\.app$"),  # any Vercel deploy
        re.compile(r"^http://localhost:\d+$"),                # local dev
        re.compile(r"^http://127\.0\.0\.1:\d+$"),
    ]
    # De-duplicate so an origin also present in FRONTEND_ORIGIN is not listed
    # twice (flask-cors would otherwise emit it twice in the header).
    CORS_ORIGINS = _merge_origins(_configured_origins, _default_origins)

    # Rate limiting backend (memory:// in dev; redis://... in prod).
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_DEFAULT = os.environ.get("RATELIMIT_DEFAULT", "200 per hour")

    # Mail (email verification)
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", "587"))
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", MAIL_USERNAME or "no-reply@quantumsafe.dev")

    # Public URLs used to build links in emails.
    DASHBOARD_URL = os.environ.get(
        "DASHBOARD_URL", FRONTEND_ORIGIN.split(",")[0].strip().rstrip("/")
    )
    API_URL = os.environ.get("API_URL", "http://localhost:5000")
