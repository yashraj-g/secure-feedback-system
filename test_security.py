"""Security test suite - run with:  python -m unittest -v test_security
Each test maps to a requirement in the project (evidence for the testing report)."""
import os
import secrets
import shutil
import sqlite3
import tempfile
import unittest
from unittest import mock

from werkzeug.security import generate_password_hash

import db
from app import create_app

ADMIN = ("Admin User", "admin@college.edu", "Admin@12345")
USER1 = ("Asha Verma", "asha@college.edu", "Student@123")
USER2 = ("Rohan Singh", "rohan@college.edu", "Student@456")


class BaseCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.logdir = os.path.join(self.tmp, "logs")
        self.app = create_app({"TESTING": True, "DATABASE": os.path.join(self.tmp, "t.db"),
                               "LOG_DIR": self.logdir})
        with self.app.app_context():
            db.execute("INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'admin')",
                       (ADMIN[0], ADMIN[1], generate_password_hash(ADMIN[2])))

    def tearDown(self):
        import logging
        for name in ("feedback.app", "feedback.audit"):
            for h in list(logging.getLogger(name).handlers):
                logging.getLogger(name).removeHandler(h)
                h.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- helpers
    def csrf(self, client):
        with client.session_transaction() as s:
            return s.setdefault("csrf_token", secrets.token_hex(16))

    def post(self, client, url, data, token=True):
        data = dict(data)
        if token:
            data["csrf_token"] = self.csrf(client)
        return client.post(url, data=data)

    def register(self, client, user):
        return self.post(client, "/register", {"name": user[0], "email": user[1], "password": user[2]})

    def login(self, client, user):
        return self.post(client, "/login", {"email": user[1], "password": user[2]})

    def new_user_client(self, user=USER1):
        c = self.app.test_client()
        self.register(c, user)
        self.login(c, user)
        return c

    def admin_client(self):
        c = self.app.test_client()
        self.login(c, ADMIN)
        return c

    def read_log(self, name):
        path = os.path.join(self.logdir, name)
        for h in __import__("logging").getLogger("feedback.app").handlers + \
                __import__("logging").getLogger("feedback.audit").handlers:
            h.flush()
        with open(path, encoding="utf-8") as f:
            return f.read()


class TestValidation(BaseCase):
    def test_valid_registration(self):
        r = self.register(self.app.test_client(), USER1)
        self.assertEqual(r.status_code, 302)

    def test_invalid_email_rejected(self):
        for bad in ("notanemail", "a@b", "x@@y.com", "a b@c.com", "' OR 1=1 --@x.com"):
            r = self.register(self.app.test_client(), ("Asha Verma", bad, "Student@123"))
            self.assertEqual(r.status_code, 200, bad)
            self.assertIn(b"valid email", r.data)

    def test_invalid_name_rejected(self):
        for bad in ("A", "<script>alert(1)</script>", "Robert'); DROP TABLE users;--", "1234", "x" * 51):
            r = self.register(self.app.test_client(), (bad, "n@college.edu", "Student@123"))
            self.assertEqual(r.status_code, 200, bad)
            self.assertIn(b"Name must be", r.data)

    def test_weak_password_rejected(self):
        r = self.register(self.app.test_client(), ("Asha Verma", "a@college.edu", "password"))
        self.assertIn(b"Password must", r.data)

    def test_duplicate_email_gives_generic_message(self):
        self.register(self.app.test_client(), USER1)
        r = self.register(self.app.test_client(), USER1)
        self.assertIn(b"Unable to complete registration", r.data)

    def test_feedback_length_limit(self):
        c = self.new_user_client()
        r = self.post(c, "/feedback", {"message": "a" * 1000})
        self.assertIn(b"must not exceed 500", r.data)
        r = self.post(c, "/feedback", {"message": "a" * 500})
        self.assertEqual(r.status_code, 302)

    def test_suspicious_input_rejected(self):
        c = self.new_user_client()
        payloads = ["<script>alert(1)</script>", "hello <img src=x onerror=alert(1)>",
                    "javascript:alert(1) is bad", "x' UNION SELECT password FROM users",
                    "1; DROP TABLE feedback; -- ok", "name' OR 1=1 --", "bad\x00null byte here"]
        for p in payloads:
            r = self.post(c, "/feedback", {"message": p})
            self.assertEqual(r.status_code, 200, p)
            self.assertIn(b"not allowed", r.data, p)
        with self.app.app_context():
            self.assertEqual(db.query_one("SELECT COUNT(*) AS n FROM feedback")["n"], 0)

    def test_normal_feedback_not_blocked(self):
        c = self.new_user_client()
        r = self.post(c, "/feedback", {"message": "The library should stay open till 10 PM. Thanks!"})
        self.assertEqual(r.status_code, 302)


class TestAuthentication(BaseCase):
    def test_password_is_hashed(self):
        self.register(self.app.test_client(), USER1)
        with self.app.app_context():
            row = db.query_one("SELECT password_hash FROM users WHERE email = ?", (USER1[1],))
        self.assertNotIn(USER1[2], row["password_hash"])
        self.assertTrue(row["password_hash"].startswith(("scrypt:", "pbkdf2:")))

    def test_sql_injection_login_fails(self):
        c = self.app.test_client()
        r = self.post(c, "/login", {"email": ADMIN[1], "password": "' OR '1'='1"})
        self.assertIn(b"Invalid email or password", r.data)
        r = self.post(c, "/login", {"email": "' OR '1'='1' --", "password": "x"})
        self.assertIn(b"Invalid email or password", r.data)
        self.assertEqual(c.get("/admin").status_code, 302)

    def test_login_message_does_not_reveal_whether_user_exists(self):
        self.register(self.app.test_client(), USER1)
        a = self.post(self.app.test_client(), "/login", {"email": USER1[1], "password": "Wrong@1234"})
        b = self.post(self.app.test_client(), "/login", {"email": "ghost@college.edu", "password": "Wrong@1234"})
        self.assertEqual(a.status_code, b.status_code)
        self.assertIn(b"Invalid email or password", a.data)
        self.assertIn(b"Invalid email or password", b.data)

    def test_account_lockout_after_repeated_failures(self):
        self.register(self.app.test_client(), USER1)
        c = self.app.test_client()
        for _ in range(5):
            self.post(c, "/login", {"email": USER1[1], "password": "Wrong@1234"})
        r = self.login(c, USER1)                       # correct password, but locked
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Invalid email or password", r.data)
        self.assertIn("ACCOUNT_LOCKED", self.read_log("app.log"))

    def test_csrf_token_required(self):
        c = self.app.test_client()
        r = self.post(c, "/login", {"email": ADMIN[1], "password": ADMIN[2]}, token=False)
        self.assertEqual(r.status_code, 400)

    def test_session_timeout(self):
        c = self.new_user_client()
        self.assertEqual(c.get("/feedback").status_code, 200)
        with c.session_transaction() as s:
            s["last_active"] = s["last_active"] - (15 * 60 + 5)     # 15 min 5 s idle
        r = c.get("/feedback")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])

    def test_session_cookie_flags(self):
        c = self.app.test_client()
        r = self.login(c, ADMIN)
        cookie = r.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)


class TestAuthorization(BaseCase):
    def test_anonymous_redirected_to_login(self):
        c = self.app.test_client()
        for url in ("/feedback", "/admin"):
            r = c.get(url)
            self.assertEqual(r.status_code, 302)
            self.assertIn("/login", r.headers["Location"])

    def test_user_cannot_open_admin_page(self):
        c = self.new_user_client()
        self.assertEqual(c.get("/admin").status_code, 403)
        self.assertIn("UNAUTHORIZED_ACCESS", self.read_log("app.log"))

    def test_user_cannot_delete_feedback(self):
        c = self.new_user_client()
        self.post(c, "/feedback", {"message": "This is my feedback message."})
        r = self.post(c, "/admin/delete/1", {})
        self.assertEqual(r.status_code, 403)
        with self.app.app_context():
            self.assertEqual(db.query_one("SELECT COUNT(*) AS n FROM feedback")["n"], 1)

    def test_user_sees_only_own_feedback(self):
        c1 = self.new_user_client(USER1)
        c2 = self.new_user_client(USER2)
        self.post(c1, "/feedback", {"message": "Asha's private feedback text."})
        self.post(c2, "/feedback", {"message": "Rohan's private feedback text."})
        body = c1.get("/feedback").get_data(as_text=True)
        self.assertIn("Asha&#39;s private", body)
        self.assertNotIn("Rohan", body)

    def test_cannot_register_as_admin(self):
        c = self.app.test_client()
        self.post(c, "/register", {"name": "Evil Hacker", "email": "evil@college.edu",
                                   "password": "Evil@12345", "role": "admin"})
        with self.app.app_context():
            row = db.query_one("SELECT role FROM users WHERE email = ?", ("evil@college.edu",))
        self.assertEqual(row["role"], "user")

    def test_admin_can_view_all_and_delete_with_audit_log(self):
        u1 = self.new_user_client(USER1)
        u2 = self.new_user_client(USER2)
        self.post(u1, "/feedback", {"message": "Feedback from Asha about the canteen."})
        self.post(u2, "/feedback", {"message": "Feedback from Rohan about the labs."})
        admin = self.admin_client()
        page = admin.get("/admin").get_data(as_text=True)
        self.assertIn("Asha Verma", page)
        self.assertIn("Rohan Singh", page)
        r = self.post(admin, "/admin/delete/1", {})
        self.assertEqual(r.status_code, 302)
        with self.app.app_context():
            self.assertEqual(db.query_one("SELECT COUNT(*) AS n FROM feedback")["n"], 1)
            logs = db.query_all("SELECT action, target_id FROM audit_log ORDER BY id")
        actions = [(row["action"], row["target_id"]) for row in logs]
        self.assertIn(("DELETE_FEEDBACK", 1), actions)
        self.assertIn(("ADMIN_LOGIN", None), actions)
        self.assertIn("action=DELETE_FEEDBACK target_id=1", self.read_log("audit.log"))


class TestOutputAndErrors(BaseCase):
    def test_output_is_html_escaped(self):
        c = self.new_user_client()
        with self.app.app_context():                      # simulate bad data already in the DB
            db.execute("INSERT INTO feedback (user_id, message) VALUES (1 + 0, ?)", ("<b>bold</b>",))
            uid = db.query_one("SELECT id FROM users WHERE email = ?", (USER1[1],))["id"]
            db.execute("UPDATE feedback SET user_id = ?", (uid,))
        body = c.get("/feedback").get_data(as_text=True)
        self.assertIn("&lt;b&gt;bold&lt;/b&gt;", body)
        self.assertNotIn("<b>bold</b>", body)

    def test_database_error_shows_generic_message_and_is_logged(self):
        c = self.new_user_client()
        boom = sqlite3.OperationalError("Table feedback does not exist at localhost:3306")
        with mock.patch.object(db, "query_all", side_effect=boom):
            r = c.get("/feedback")
        body = r.get_data(as_text=True)
        self.assertEqual(r.status_code, 500)
        self.assertIn("Unable to process your request", body)
        self.assertIn("Please try again later", body)
        for leak in ("Table feedback", "localhost", "3306", "sqlite3", "Traceback"):
            self.assertNotIn(leak, body)
        log = self.read_log("app.log")
        self.assertIn("Table feedback does not exist at localhost:3306", log)
        self.assertIn("Traceback", log)

    def test_unknown_page_is_generic_404(self):
        r = self.app.test_client().get("/nope")
        self.assertEqual(r.status_code, 404)
        self.assertNotIn(b"Werkzeug", r.data)

    def test_security_headers_present(self):
        r = self.app.test_client().get("/login")
        for h in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"):
            self.assertIn(h, r.headers)


if __name__ == "__main__":
    unittest.main(verbosity=2)
