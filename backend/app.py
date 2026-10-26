"""QuantumSafe backend — Flask application factory.

Run locally:
    cd backend
    flask --app app run --debug      (or: python app.py)
"""

from __future__ import annotations

import os

from flask import Flask, jsonify
from flask_cors import CORS

from config import DEV_SECRET, Config
from extensions import db, jwt, limiter, mail


def create_app(config_object: type = Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_object)

    # The default secret is public (it is in this file's repository), so tokens
    # signed with it can be forged by anyone. render.yaml generates real ones,
    # but a service created by hand would silently fall back -- refuse to start
    # on Render instead. (RENDER is set on every Render instance.)
    if os.environ.get("RENDER") and DEV_SECRET in (app.config["SECRET_KEY"],
                                                    app.config["JWT_SECRET_KEY"]):
        raise RuntimeError("SECRET_KEY / JWT_SECRET_KEY must be set in production.")

    # Extensions
    db.init_app(app)
    jwt.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)
    app.config["RATELIMIT_STORAGE_URI"] = app.config.get("RATELIMIT_STORAGE_URI", "memory://")

    # CORS restricted to the dashboard origin(s) only.
    #
    # /health is covered alongside /api/*: the dashboard pre-warms the Render
    # instance by fetching it on page load, and with only /api/* in the map
    # that fetch was blocked by CORS on every visit. The ping never landed, so
    # the cold start it exists to absorb was paid by the user's first real
    # scan instead (~23s).
    CORS(
        app,
        resources={
            r"/api/*": {"origins": app.config["CORS_ORIGINS"]},
            r"/health": {"origins": app.config["CORS_ORIGINS"]},
        },
        supports_credentials=True,
    )

    # Blueprints
    from auth import auth_bp
    from api import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)

    # Health check
    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "service": "quantumsafe-api"})

    @app.route("/")
    def index():
        return jsonify({"service": "QuantumSafe API", "version": "v1", "docs": "/api/v1"})

    # JSON error handlers
    @app.errorhandler(404)
    def not_found(_e):
        return jsonify({"error": "Not found."}), 404

    @app.errorhandler(413)
    def too_large(_e):
        return jsonify({"error": "Upload exceeds the 25 MB limit."}), 413

    @app.errorhandler(429)
    def ratelimited(_e):
        return jsonify({"error": "Rate limit exceeded. Slow down and try again."}), 429

    @app.errorhandler(500)
    def server_error(_e):
        return jsonify({"error": "Internal server error."}), 500

    # Create missing tables, then self-heal additive schema drift so existing
    # deployments keep working (and keep their accounts) when the model gains
    # columns — no manual migration or data wipe required.
    with app.app_context():
        db.create_all()
        _ensure_user_columns()

    return app


def _ensure_user_columns() -> None:
    """Reconcile the live `users` table with the current model — without data loss.

    db.create_all() never ALTERs existing tables, so a database that predates a
    model change keeps the old shape: missing newly-added columns (breaks SELECT)
    and/or leftover obsolete columns that are NOT NULL (breaks INSERT). Both make
    login/register 500. This adds the missing columns and drops the obsolete ones
    in place, preserving all existing rows. Safe + idempotent on every boot.
    """
    import logging

    from sqlalchemy import inspect, text

    log = logging.getLogger(__name__)
    pg = db.engine.dialect.name == "postgresql"
    ts = "TIMESTAMP WITH TIME ZONE" if pg else "TIMESTAMP"
    true_, false_ = ("TRUE", "FALSE") if pg else ("1", "0")
    wanted = {
        "email_verified": f"BOOLEAN NOT NULL DEFAULT {false_}",
        "verification_token": "VARCHAR(64)",
        "api_key_hash": "VARCHAR(64)",
        "api_key_prefix": "VARCHAR(32)",
        "alert_on_high": f"BOOLEAN NOT NULL DEFAULT {true_}",
        "terms_accepted_at": ts,
    }
    obsolete = ("plan", "stripe_customer_id")  # removed from the model

    # 1) Add missing columns.
    try:
        insp = inspect(db.engine)
        if "users" not in insp.get_table_names():
            return
        existing = {c["name"] for c in insp.get_columns("users")}
        missing = {c: ddl for c, ddl in wanted.items() if c not in existing}
        for col, ddl in missing.items():
            db.session.execute(text(f"ALTER TABLE users ADD COLUMN {col} {ddl}"))
        if missing:
            db.session.commit()
            log.info("Schema self-heal added columns: %s", ", ".join(missing))
    except Exception as exc:
        db.session.rollback()
        log.warning("Schema self-heal (add) skipped: %s", exc)

    # 2) Drop obsolete columns (kept separate so it can't undo step 1). A leftover
    #    NOT NULL column with no default is what blocks new registrations.
    try:
        existing = {c["name"] for c in inspect(db.engine).get_columns("users")}
        dropped = [c for c in obsolete if c in existing]
        for col in dropped:
            db.session.execute(text(f"ALTER TABLE users DROP COLUMN {col}"))
        if dropped:
            db.session.commit()
            log.info("Schema self-heal dropped obsolete columns: %s", ", ".join(dropped))
    except Exception as exc:
        db.session.rollback()
        log.warning("Schema self-heal (drop) skipped: %s", exc)


app = create_app()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)
