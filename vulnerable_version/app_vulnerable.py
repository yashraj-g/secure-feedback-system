"""
!!! INTENTIONALLY INSECURE - FOR SAST / CLASSROOM COMPARISON ONLY - NEVER DEPLOY !!!

Same features as the secure app, but written the WRONG way so that SAST tools
(Bandit, Semgrep) have something to report. Each flaw is tagged with its category.
Run the scan on this file first, then on ../app.py and compare (before vs after).
"""
import hashlib
import sqlite3

from flask import Flask, make_response, request

app = Flask(__name__)
app.secret_key = "admin123"                                   # VULN: hardcoded secret (A02/A05)
DB = "vulnerable.db"


def conn():
    c = sqlite3.connect(DB)
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, password TEXT, role TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS feedback (id INTEGER PRIMARY KEY, user_id INTEGER, message TEXT)")
    return c


@app.route("/register", methods=["POST"])
def register():
    name, email, pw = request.form["name"], request.form["email"], request.form["password"]
    role = request.form.get("role", "user")                   # VULN: client chooses role (A01)
    pw_hash = hashlib.md5(pw.encode()).hexdigest()            # VULN: weak, unsalted hash (A02)
    c = conn()
    c.execute(f"INSERT INTO users (name, email, password, role) VALUES ('{name}', '{email}', '{pw_hash}', '{role}')")  # VULN: SQL built from input (A03)
    c.commit()
    return "registered"


@app.route("/login", methods=["POST"])
def login():
    email, pw = request.form["email"], request.form["password"]
    pw_hash = hashlib.md5(pw.encode()).hexdigest()
    try:
        row = conn().execute(
            "SELECT id, role FROM users WHERE email = '" + email + "' AND password = '" + pw_hash + "'"  # VULN: SQL injection (A03)
        ).fetchone()
    except Exception as e:
        return "Database error: " + str(e), 500               # VULN: leaks internals (A05)
    if not row:
        return "No such user or wrong password", 401           # VULN: user enumeration style message
    resp = make_response("logged in")
    resp.set_cookie("uid", str(row[0]))                        # VULN: no HttpOnly/Secure/SameSite, no timeout (A07)
    resp.set_cookie("role", row[1])                            # VULN: role stored on client (A01)
    return resp


@app.route("/feedback", methods=["POST"])
def submit():
    c = conn()
    c.execute("INSERT INTO feedback (user_id, message) VALUES (%s, '%s')" % (request.cookies.get("uid"), request.form["message"]))  # VULN: no length/validation, SQL injection
    c.commit()
    return "saved"


@app.route("/admin")
def admin():
    if request.cookies.get("role") != "admin":                 # VULN: trusts client cookie (A01)
        return "Not allowed", 403
    rows = conn().execute("SELECT id, message FROM feedback").fetchall()
    return "<br>".join(f"{r[0]}: {r[1]}" for r in rows)        # VULN: unescaped output -> XSS (A03)


@app.route("/admin/delete/<fid>")                              # VULN: state change via GET, no CSRF, no audit log (A01/A09)
def delete(fid):
    if request.cookies.get("role") != "admin":
        return "Not allowed", 403
    c = conn()
    c.execute("DELETE FROM feedback WHERE id = " + fid)        # VULN: SQL injection
    c.commit()
    return "deleted"


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)                        # VULN: debug mode + binds to all interfaces (A05)
