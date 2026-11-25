"""Create an admin account (admins can NOT self-register through the website).

Usage:  python create_admin.py "Admin Name" admin@college.edu
"""
import getpass
import sqlite3
import sys

from werkzeug.security import generate_password_hash

import db
import validators
from app import create_app


def main():
    if len(sys.argv) != 3:
        sys.exit('Usage: python create_admin.py "Admin Name" admin@college.edu')
    name, email = sys.argv[1].strip(), sys.argv[2].strip().lower()
    password = getpass.getpass("Admin password: ")
    errors = validators.validate_registration(name, email, password)
    if errors:
        sys.exit("\n".join(errors))
    app = create_app()
    with app.app_context():
        try:
            db.execute(
                "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'admin')",
                (name, email, generate_password_hash(password)),
            )
        except sqlite3.IntegrityError:
            sys.exit("An account with that email already exists.")
    print("Admin created.")


if __name__ == "__main__":
    main()
