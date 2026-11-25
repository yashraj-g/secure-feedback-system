# Secure Online Feedback System (Flask + SQLite)

Capstone project - Secure Coding & Vulnerabilities.

## Run
```bash
pip install -r requirements.txt
python create_admin.py "Admin Name" admin@college.edu     # asks for password
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python app.py                                              # http://127.0.0.1:5000
```
Behind HTTPS set `COOKIE_SECURE=1`.  Windows PowerShell: `$env:SECRET_KEY="..."`.

## Run tests (evidence for the testing report)
```bash
python -m unittest -v test_security
```

## Requirement -> where implemented
| Requirement | File / function |
|---|---|
| Validate name & email | `validators.py` (`NAME_RE`, `EMAIL_RE`, `validate_registration`) |
| Limit feedback length | `validators.validate_feedback` (500) + `CHECK(length(message) <= 500)` in `schema.sql` |
| Reject suspicious input | `validators.SUSPICIOUS_RE`, control-char check, Jinja auto-escaping |
| Role-based authorization | `auth.role_required`, role always read from DB |
| Hash passwords | `werkzeug.security.generate_password_hash` (salted scrypt) |
| Parameterized SQL | every query in `app.py` / `db.py` uses `?` placeholders |
| Session timeout | `load_user_and_enforce_timeout` (15 min inactivity) + cookie lifetime |
| Log admin operations | `write_audit` -> `audit_log` table + `logs/audit.log` |
| Generic error messages | `handle_http_error`, `handle_unexpected_error`; details only in `logs/app.log` |
| Extras | CSRF tokens, account lockout, generic login error, session reset on login, security headers, log-injection protection |

## SAST
```bash
pip install bandit semgrep pip-audit
bandit -r vulnerable_version -f html -o reports/bandit_before.html
bandit -r . -x ./vulnerable_version,./test_security.py -f html -o reports/bandit_after.html
semgrep --config p/owasp-top-ten --config p/flask vulnerable_version
semgrep --config p/owasp-top-ten --config p/flask app.py db.py auth.py validators.py
pip-audit -r requirements.txt
```
`vulnerable_version/app_vulnerable.py` is intentionally insecure - for the BEFORE scan only. Never deploy it.

## Using MySQL instead of SQLite
Only `db.py` and `schema.sql` change (use `mysql-connector-python`, placeholders become `%s`, `AUTOINCREMENT` -> `AUTO_INCREMENT`, store DB credentials in environment variables, use a least-privilege DB user).
