"""Authentication, RBAC, and JWT Token Management for Secret Leak Guard v2.0."""

import datetime
from functools import wraps
import re
from typing import Any, Callable, Dict, List, Optional, Union
import bcrypt
from flask import current_app, g, jsonify, request
import jwt


class Role:
    """RBAC Roles defined by specification."""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"

    ALL = {ADMIN, ANALYST, VIEWER}


def hash_password(password: str) -> str:
    """Hashes a password using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def generate_jwt_token(
    user_id: str,
    username: str,
    role: str,
    secret_key: Optional[str] = None,
    algorithm: str = "HS256",
    expires_in_hours: int = 24,
) -> str:
    """Generates a signed JWT token containing user identity and role."""
    key = secret_key or current_app.config.get("JWT_SECRET_KEY", "fallback-jwt-secret")
    now = datetime.datetime.now(datetime.timezone.utc)
    expiration = now + datetime.timedelta(hours=expires_in_hours)

    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iat": now,
        "exp": expiration,
        "iss": "secret-leak-guard-v2",
    }

    return jwt.encode(payload, key, algorithm=algorithm)


def decode_jwt_token(
    token: str,
    secret_key: Optional[str] = None,
    algorithm: str = "HS256",
) -> Dict[str, Any]:
    """Decodes and validates a JWT token."""
    key = secret_key or current_app.config.get("JWT_SECRET_KEY", "fallback-jwt-secret")
    return jwt.decode(
        token,
        key,
        algorithms=[algorithm],
        issuer="secret-leak-guard-v2",
        options={"require": ["exp", "iat", "sub", "role"]},
    )


def extract_bearer_token() -> Optional[str]:
    """Extracts the Bearer token from the Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def require_auth(f: Callable) -> Callable:
    """Decorator to enforce JWT Bearer authentication on endpoints."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = extract_bearer_token()
        if not token:
            return jsonify({
                "status": "error",
                "code": 401,
                "error": "Authentication required",
                "message": "Missing or malformed Authorization header. Expected: 'Bearer <token>'."
            }), 401

        try:
            payload = decode_jwt_token(token)
            g.current_user = {
                "user_id": payload.get("sub"),
                "username": payload.get("username"),
                "role": payload.get("role", Role.VIEWER),
            }
        except jwt.ExpiredSignatureError:
            return jsonify({
                "status": "error",
                "code": 401,
                "error": "Token expired",
                "message": "The supplied authentication token has expired. Please log in again."
            }), 401
        except jwt.InvalidTokenError as e:
            return jsonify({
                "status": "error",
                "code": 401,
                "error": "Invalid token",
                "message": f"Token verification failed: {str(e)}"
            }), 401

        return f(*args, **kwargs)

    return decorated_function


def require_role(allowed_roles: Union[str, List[str], set]) -> Callable:
    """Decorator to enforce Role-Based Access Control (RBAC)."""
    if isinstance(allowed_roles, str):
        allowed_roles = {allowed_roles}
    else:
        allowed_roles = set(allowed_roles)

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        @require_auth
        def decorated_function(*args, **kwargs):
            user = getattr(g, "current_user", None)
            if not user or user.get("role") not in allowed_roles:
                user_role = user.get("role") if user else "unauthenticated"
                return jsonify({
                    "status": "error",
                    "code": 403,
                    "error": "Forbidden",
                    "message": (
                        f"User role '{user_role}' is not authorized to access this resource. "
                        f"Required roles: {list(allowed_roles)}."
                    ),
                }), 403
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def validate_register_payload(data: Any) -> Dict[str, str]:
    """Validates user registration payload."""
    if not isinstance(data, dict):
        raise ValueError("Payload must be a valid JSON object.")

    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()
    role = str(data.get("role", Role.ANALYST)).strip().lower()

    if not username or len(username) < 3 or len(username) > 32:
        raise ValueError("Username must be between 3 and 32 characters.")

    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", username):
        raise ValueError("Username can only contain alphanumeric characters, dots, underscores, or dashes.")

    if not password or len(password) < 8 or len(password) > 72:
        raise ValueError("Password must be between 8 and 72 characters long.")

    if role not in {Role.ANALYST, Role.VIEWER}:
        raise ValueError(
            "Public registration supports analyst and viewer roles only. "
            "Admin accounts must be provisioned by an administrator."
        )

    return {
        "username": username,
        "password": password,
        "role": role,
    }


def validate_login_payload(data: Any) -> Dict[str, str]:
    """Validates login credentials payload."""
    if not isinstance(data, dict):
        raise ValueError("Payload must be a valid JSON object.")

    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    if not username or not password:
        raise ValueError("Both 'username' and 'password' are required fields.")

    return {
        "username": username,
        "password": password,
    }
