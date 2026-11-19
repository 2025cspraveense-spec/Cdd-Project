"""Interactively provisions an administrator account in the configured MongoDB."""

import getpass
import argparse
import re
import sys

from app import create_app
from app.auth import Role, hash_password, verify_password


def main() -> int:
    parser = argparse.ArgumentParser(description="Create or reset a Secret Leak Guard administrator.")
    parser.add_argument("--username", help="Administrator username.")
    parser.add_argument(
        "--reset-existing",
        action="store_true",
        help="Reset the password and administrator role when the account already exists.",
    )
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read the password from stdin instead of prompting interactively.",
    )
    args = parser.parse_args()

    username = (args.username or input("Admin username: ")).strip()
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{3,32}", username):
        print("Username must be 3-32 letters, digits, dots, underscores, or dashes.")
        return 1

    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
        confirmation = password
    else:
        password = getpass.getpass("Admin password (minimum 16 characters): ")
        confirmation = getpass.getpass("Confirm admin password: ")
    if len(password) < 16 or len(password) > 72 or password != confirmation:
        print("Password confirmation failed or the password is too short.")
        return 1

    try:
        app = create_app()
        db = app.extensions["db"]
        if db.is_mock:
            raise RuntimeError("The configured database resolved to mongomock.")
    except Exception:
        print("Unable to connect to the configured MongoDB.")
        return 1

    existing_user = db.get_user_by_username(username)
    if existing_user:
        if not args.reset_existing:
            print("An account with that username already exists; use --reset-existing to replace its password.")
            return 1
        db.db["users"].update_one(
            {"username": username},
            {"$set": {"password_hash": hash_password(password), "role": Role.ADMIN}},
        )
        action = "reset"
    else:
        if not db.create_user({
            "username": username,
            "password_hash": hash_password(password),
            "role": Role.ADMIN,
        }):
            print("MongoDB did not create the administrator account.")
            return 1
        action = "created"
    saved_user = db.get_user_by_username(username)
    if not saved_user or not verify_password(password, saved_user.get("password_hash", "")):
        print("Administrator credential verification failed.")
        return 1
    db.close()

    print(f"Administrator account {username!r} {action}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
