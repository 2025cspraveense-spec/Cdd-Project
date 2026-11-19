"""Interactively provisions an administrator account in the configured MongoDB."""

import getpass
import re
import sys

from app.auth import Role, hash_password
from app.db import DatabaseClient
from config import Config


def main() -> int:
    username = input("Admin username: ").strip()
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{3,32}", username):
        print("Username must be 3-32 letters, digits, dots, underscores, or dashes.")
        return 1

    password = getpass.getpass("Admin password (minimum 16 characters): ")
    confirmation = getpass.getpass("Confirm admin password: ")
    if len(password) < 16 or len(password) > 72 or password != confirmation:
        print("Password confirmation failed or the password is too short.")
        return 1

    try:
        db = DatabaseClient(
            mongo_uri=Config.MONGO_URI,
            db_name=Config.MONGO_DB_NAME,
            ttl_seconds=Config.MONGO_TTL_SECONDS,
            use_mock=False,
            allow_mock_fallback=False,
        )
    except RuntimeError:
        print("Unable to connect to the configured MongoDB.")
        return 1
    try:
        if db.get_user_by_username(username):
            print("An account with that username already exists.")
            return 1
        if not db.create_user({
            "username": username,
            "password_hash": hash_password(password),
            "role": Role.ADMIN,
        }):
            print("MongoDB did not create the administrator account.")
            return 1
    finally:
        db.close()

    print(f"Administrator account {username!r} created.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
