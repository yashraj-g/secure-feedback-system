"""Secure Online Feedback System - Flask application."""
import hmac
import logging
import os
import re
import secrets
import sqlite3
import time
from datetime import timedelta
from logging.handlers import RotatingFileHandler

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

import db
import validators
from auth import role_required

app_log = logging.getLogger("feedback.app")      # errors / security events
audit_log = logging.getLogger("feedback.audit")  # administrative operations

GENERIC_ERROR = "Unable to process your request. Please try again later."
HTTP_MESSAGES = {
    400: "Your request could not be verified. Please reload the page and try again.",
    403: "You are not authorized to access this page.",
    404: "The page you requested was not found.",
}
# Used to make "unknown user" take the same time as "wrong password".
DUMMY_HASH = generate_password_hash("not-a-real-password")


def setup_logging(log_dir):
    os.makedirs(log_dir, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    for logger, filename in ((app_log, "app.log"), (audit_log, "audit.log")):
        logger.setLevel(logging.INFO)
        logger.propagate = False
        for h in list(logger.handlers):
            logger.removeHandler(h)
            h.close()
        handler = RotatingFileHandler(
            os.path.join(log_dir, filename), maxBytes=1_000_000, backupCount=5, encoding="utf-8"
        )
        handler.setFormatter(fmt)
        logger.addHandler(handler)


def safe_log(value, limit=100):
    """Strip control characters (prevents log injection) and truncate."""
    return re.sub(r"[\x00-\x1f\x7f]", "?", str(value))[:limit]


def write_audit(action, target_id=None, admin_id=None):
    admin_id = admin_id if admin_id is not None else g.user["id"]
    ip = request.remote_addr
    db.execute(
        "INSERT INTO audit_log (admin_id, action, target_id, ip_address) VALUES (?, ?, ?, ?)",
        (admin_id, action, target_id, ip),
    )
    audit_log.info("admin_id=%s action=%s target_id=%s ip=%s", admin_id, action, target_id, ip)


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        DATABASE=os.environ.get("DATABASE", os.path.join(app.root_path, "feedback.db")),
        LOG_DIR=os.environ.get("LOG_DIR", os.path.join(app.root_path, "logs")),
        SESSION_TIMEOUT=15 * 60,                      # seconds of inactivity
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",  # set to 1 behind HTTPS
        MAX_CONTENT_LENGTH=16 * 1024,                 # reject huge request bodies
        MAX_FAILED_ATTEMPTS=5,
        LOCKOUT_SECONDS=15 * 60,
    )
    if test_config:
        app.config.update(test_config)
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(seconds=app.config["SESSION_TIMEOUT"])

    setup_logging(app.config["LOG_DIR"])
    if not os.environ.get("SECRET_KEY"):
        app_log.warning("SECRET_KEY not set - using a random key (sessions reset on restart).")

    app.teardown_appcontext(db.close_db)
    with app.app_context():
        db.init_db()

    # ------------------------------------------------------------------ CSRF
    def get_csrf_token():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)
        return session["csrf_token"]

    app.jinja_env.globals["csrf_token"] = get_csrf_token

    # -------------------------------------------- request hooks (order matters)
    @app.before_request
    def load_user_and_enforce_timeout():
        g.user = None
        user_id = session.get("user_id")
        if user_id is None:
            return
        now = int(time.time())
        if now - session.get("last_active", 0) > app.config["SESSION_TIMEOUT"]:
            session.clear()
            flash("Your session expired due to inactivity. Please log in again.", "info")
            return
        session["last_active"] = now
        user = db.query_one("SELECT id, name, email, role FROM users WHERE id = ?", (user_id,))
        if user is None:
            session.clear()
            return
        g.user = user

    @app.before_request
    def csrf_protect():
        if request.method == "POST":
            sent = request.form.get("csrf_token", "").encode()
            expected = session.get("csrf_token", "").encode()
            if not expected or not hmac.compare_digest(sent, expected):
                app_log.warning("CSRF_FAILURE path=%s ip=%s", safe_log(request.path), request.remote_addr)
                abort(400)

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'none'; style-src 'self'; img-src 'self'; "
            "frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
        )
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # ---------------------------------------------------------------- errors
    @app.errorhandler(HTTPException)
    def handle_http_error(e):
        return render_template("error.html", message=HTTP_MESSAGES.get(e.code, GENERIC_ERROR)), e.code

    @app.errorhandler(Exception)
    def handle_unexpected_error(e):
        # Full details go to the log file ONLY. The user sees a generic message.
        app_log.exception("UNHANDLED_ERROR method=%s path=%s error=%s",
                          request.method, safe_log(request.path), e)
        return render_template("error.html", message=GENERIC_ERROR), 500

    # ---------------------------------------------------------------- routes
    @app.route("/")
    def home():
        if g.user is None:
            return redirect(url_for("login"))
        return redirect(url_for("admin_dashboard" if g.user["role"] == "admin" else "feedback"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if g.user:
            return redirect(url_for("home"))
        errors, form = [], {}
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            errors = validators.validate_registration(name, email, password)
            if not errors:
                try:
                    # Role is fixed server-side: nobody can register as admin.
                    db.execute(
                        "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'user')",
                        (name, email, generate_password_hash(password)),
                    )
                except sqlite3.IntegrityError:
                    errors.append("Unable to complete registration. Please check your details and try again.")
                else:
                    flash("Registration successful. Please log in.", "success")
                    return redirect(url_for("login"))
            form = {"name": name, "email": email}
        return render_template("register.html", errors=errors, form=form)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.user:
            return redirect(url_for("home"))
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            now = int(time.time())
            user, ok = None, False
            if validators.validate_login_input(email, password):
                user = db.query_one(
                    "SELECT id, role, password_hash, failed_attempts, locked_until "
                    "FROM users WHERE email = ?", (email,))
            if user is None or user["locked_until"] > now:
                check_password_hash(DUMMY_HASH, password)   # constant-ish timing
            else:
                ok = check_password_hash(user["password_hash"], password)

            if ok:
                db.execute("UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?", (user["id"],))
                session.clear()                              # new session after login
                session["user_id"] = user["id"]
                session["last_active"] = now
                session.permanent = True
                if user["role"] == "admin":
                    write_audit("ADMIN_LOGIN", admin_id=user["id"])
                return redirect(url_for("home"))

            app_log.warning("LOGIN_FAILED email=%s ip=%s", safe_log(email), request.remote_addr)
            if user is not None and user["locked_until"] <= now:
                attempts = user["failed_attempts"] + 1
                if attempts >= app.config["MAX_FAILED_ATTEMPTS"]:
                    db.execute("UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?",
                               (now + app.config["LOCKOUT_SECONDS"], user["id"]))
                    app_log.warning("ACCOUNT_LOCKED user_id=%s ip=%s", user["id"], request.remote_addr)
                else:
                    db.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (attempts, user["id"]))
            # One message for every failure: no user enumeration.
            flash("Invalid email or password, or account temporarily locked.", "error")
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        if g.user and g.user["role"] == "admin":
            write_audit("ADMIN_LOGOUT")
        session.clear()
        flash("You have been logged out.", "success")
        return redirect(url_for("login"))

    @app.route("/feedback", methods=["GET", "POST"])
    @role_required("user")
    def feedback():
        errors, message = [], ""
        if request.method == "POST":
            raw = request.form.get("message", "")
            message, errors = validators.validate_feedback(raw)
            if not errors:
                db.execute("INSERT INTO feedback (user_id, message) VALUES (?, ?)", (g.user["id"], message))
                flash("Thank you! Your feedback has been submitted.", "success")
                return redirect(url_for("feedback"))
            message = raw[: validators.FEEDBACK_MAX]
        # Filtered by the session's user id: users can only ever see their own rows.
        items = db.query_all(
            "SELECT id, message, created_at FROM feedback WHERE user_id = ? ORDER BY id DESC",
            (g.user["id"],))
        return render_template("feedback.html", errors=errors, message=message, items=items,
                               max_len=validators.FEEDBACK_MAX)

    @app.route("/admin")
    @role_required("admin")
    def admin_dashboard():
        items = db.query_all(
            "SELECT f.id, f.message, f.created_at, u.name, u.email "
            "FROM feedback f JOIN users u ON u.id = f.user_id ORDER BY f.id DESC")
        write_audit("VIEW_ALL_FEEDBACK")
        return render_template("admin.html", items=items)

    @app.route("/admin/delete/<int:feedback_id>", methods=["POST"])
    @role_required("admin")
    def delete_feedback(feedback_id):
        if db.query_one("SELECT id FROM feedback WHERE id = ?", (feedback_id,)) is None:
            abort(404)
        db.execute("DELETE FROM feedback WHERE id = ?", (feedback_id,))
        write_audit("DELETE_FEEDBACK", target_id=feedback_id)
        flash("Feedback deleted.", "success")
        return redirect(url_for("admin_dashboard"))

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
