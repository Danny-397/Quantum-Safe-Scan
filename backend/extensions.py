"""Shared Flask extension instances, initialized in app.create_app()."""

from flask import request
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy


def client_ip() -> str:
    """The visitor's address, for rate limiting.

    On Render every request reaches Flask from Render's proxy, so
    get_remote_address() is the same for everyone and all visitors shared one
    bucket -- 20 logins and 5 password resets per hour for the whole site.
    Render serves through Cloudflare, which sets CF-Connecting-IP and
    overwrites any value a client sends. Locally the header is absent and this
    falls back to the socket address.
    """
    return request.headers.get("CF-Connecting-IP") or get_remote_address()


db = SQLAlchemy()
jwt = JWTManager()
mail = Mail()
limiter = Limiter(key_func=client_ip)
