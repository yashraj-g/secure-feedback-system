"""Role-based authorization decorators."""
import logging
from functools import wraps

from flask import abort, flash, g, redirect, request, url_for

app_log = logging.getLogger("feedback.app")


def role_required(role):
    """Allow only logged-in users whose role (read from the DB) matches `role`."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                flash("Please log in to continue.", "info")
                return redirect(url_for("login"))
            if g.user["role"] != role:
                app_log.warning(
                    "UNAUTHORIZED_ACCESS user_id=%s role=%s method=%s path=%s ip=%s",
                    g.user["id"], g.user["role"], request.method, request.path, request.remote_addr,
                )
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator
