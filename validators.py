"""Server-side input validation (allow-list first, then suspicious-pattern rejection)."""
import re
import unicodedata

NAME_MIN, NAME_MAX = 2, 50
FEEDBACK_MIN, FEEDBACK_MAX = 10, 500
PASSWORD_MIN, PASSWORD_MAX = 8, 128
EMAIL_MAX = 254

# Letters (any language), spaces, dot, apostrophe, hyphen. Must start with a letter.
NAME_RE = re.compile(r"^[^\W\d_](?:[^\W\d_]|[ .'\-]){1,49}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}$")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
SUSPICIOUS_RE = re.compile(
    r"[<>]"                                              # HTML / script tags
    r"|javascript\s*:"                                   # javascript: URLs
    r"|\bon(?:error|load|click|mouseover|focus)\s*="     # inline event handlers
    r"|\bunion\b\s+\bselect\b"                           # SQL injection patterns
    r"|\bdrop\b\s+\btable\b"
    r"|;\s*--|/\*|\*/"
    r"|\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
    re.IGNORECASE,
)


def is_valid_email(email):
    return bool(email) and len(email) <= EMAIL_MAX and bool(EMAIL_RE.match(email))


def validate_registration(name, email, password):
    errors = []
    if not NAME_RE.match(name or ""):
        errors.append(f"Name must be {NAME_MIN}-{NAME_MAX} characters: letters, spaces, . ' - only.")
    if not is_valid_email(email):
        errors.append("Please enter a valid email address.")
    if not (PASSWORD_MIN <= len(password or "") <= PASSWORD_MAX):
        errors.append(f"Password must be {PASSWORD_MIN}-{PASSWORD_MAX} characters long.")
    else:
        if not (re.search(r"[a-z]", password) and re.search(r"[A-Z]", password) and re.search(r"\d", password)):
            errors.append("Password must contain an uppercase letter, a lowercase letter and a digit.")
    return errors


def validate_login_input(email, password):
    return is_valid_email(email) and 0 < len(password or "") <= PASSWORD_MAX


def validate_feedback(message):
    """Return (clean_message, errors)."""
    errors = []
    text = unicodedata.normalize("NFC", message or "").replace("\r\n", "\n").strip()
    if len(text) < FEEDBACK_MIN:
        errors.append(f"Feedback must be at least {FEEDBACK_MIN} characters.")
    elif len(text) > FEEDBACK_MAX:
        errors.append(f"Feedback must not exceed {FEEDBACK_MAX} characters.")
    elif CONTROL_RE.search(text) or SUSPICIOUS_RE.search(text):
        errors.append("Your feedback contains characters or patterns that are not allowed.")
    return text, errors
