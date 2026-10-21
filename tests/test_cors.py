"""Tests for CORS, which no other test could have caught.

The bug these exist for: the production domain https://quantumsafescan.com was
reachable only via the FRONTEND_ORIGIN environment variable. With that unset on
the deployed service, the browser received no Access-Control-Allow-Origin
header, so the dashboard loaded and rendered but every scan failed in the
console with "blocked by CORS policy".

Nothing in the suite noticed, and neither did manual checking with curl --
curl sends no Origin and does not enforce CORS, so the same request that a
browser refuses comes back 200 with a full report. These tests send an Origin
header and assert on the response headers, which is the only way to see it.

A second defect: /health was outside the CORS resource map while the dashboard
pre-warms the instance by fetching it on page load, so that ping was blocked
on every visit and the cold start it exists to absorb was paid by the user's
first real scan.
"""

import pytest

from config import Config

PROD = "https://quantumsafescan.com"
PROD_WWW = "https://www.quantumsafescan.com"
ALLOW = "access-control-allow-origin"


def _get(client, path, origin):
    return client.get(path, headers={"Origin": origin})


def _preflight(client, path, origin, method="POST"):
    return client.options(
        path,
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": method,
            "Access-Control-Request-Headers": "content-type",
        },
    )


# --------------------------------------------------------------------------- #
# The production domain
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("origin", [PROD, PROD_WWW])
def test_production_domain_is_allowed_without_any_env_config(origin):
    """The whole point: this must not depend on FRONTEND_ORIGIN being set."""
    assert origin in Config.CORS_ORIGINS, (
        f"{origin} must be allowed by default, not only via FRONTEND_ORIGIN -- "
        "an unset env var silently breaks every scan in the browser"
    )


@pytest.mark.parametrize("origin", [PROD, PROD_WWW])
def test_api_preflight_from_production_returns_allow_origin(client, origin):
    res = _preflight(client, "/api/v1/demo-scan", origin)
    assert res.status_code in (200, 204)
    assert res.headers.get(ALLOW) == origin


@pytest.mark.parametrize("origin", [PROD, PROD_WWW])
def test_health_is_fetchable_from_production(client, origin):
    """The pre-warm ping the dashboard makes on page load."""
    res = _get(client, "/health", origin)
    assert res.status_code == 200
    assert res.headers.get(ALLOW) == origin, (
        "/health must be in the CORS resource map or the pre-warm ping is "
        "blocked and the cold start hits the first real scan"
    )


# --------------------------------------------------------------------------- #
# The origins that were already working stay working
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("origin", [
    "https://quantumsafe.vercel.app",
    "https://quantumsafe-git-main-danny.vercel.app",
    "http://localhost:3000",
    "http://127.0.0.1:8080",
])
def test_vercel_and_local_origins_still_allowed(client, origin):
    res = _preflight(client, "/api/v1/demo-scan", origin)
    assert res.headers.get(ALLOW) == origin


# --------------------------------------------------------------------------- #
# ...and the ones that should not be
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("origin", [
    "https://evil.example.com",
    "https://quantumsafescan.com.evil.com",       # suffix attack
    "https://notquantumsafescan.com",             # prefix attack
    "http://quantumsafescan.com",                 # plain http
    "https://quantumsafescan.com:8443",           # unexpected port
    "https://evil.vercel.app.attacker.com",       # regex must be anchored
])
def test_unrelated_origins_are_refused(client, origin):
    res = _preflight(client, "/api/v1/demo-scan", origin)
    assert res.headers.get(ALLOW) != origin, f"{origin} must not be allowed"


def test_allow_origin_is_never_a_wildcard(client):
    """With supports_credentials=True a wildcard would be a real hole."""
    res = _get(client, "/health", PROD)
    assert res.headers.get(ALLOW) != "*"


def test_origin_is_not_echoed_twice_when_also_in_frontend_origin():
    """A duplicated header value is rejected by browsers.

    The production domain is in the defaults; if someone also sets it in
    FRONTEND_ORIGIN it must not end up listed twice.
    """
    assert Config.CORS_ORIGINS.count(PROD) == 1


def test_no_configured_origin_has_a_trailing_slash():
    """flask-cors matches exactly; a trailing slash never matches an Origin."""
    for origin in Config.CORS_ORIGINS:
        if isinstance(origin, str):
            assert not origin.endswith("/"), origin
