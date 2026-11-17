"""Pytest Fixtures and Global Test Configuration."""

import os
import shutil
import tempfile
import pytest
from app import create_app
from app.auth import Role, generate_jwt_token, hash_password


@pytest.fixture(scope="session")
def test_temp_root():
    """Provides a temporary root directory for test workspaces and archives."""
    temp_dir = tempfile.mkdtemp(prefix="slg_test_")
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def app(test_temp_root):
    """Provides a test Flask application configured with in-memory mongomock."""
    test_config = {
        "TESTING": True,
        "DEBUG": True,
        "MONGO_USE_MOCK": True,
        "VAULT_ENABLED": False,
        "JWT_SECRET_KEY": "test-super-secret-jwt-key-for-unit-testing",
        "WORKSPACE_BASE_DIR": os.path.join(test_temp_root, "workspaces"),
        "ALLOWED_LOCAL_SCAN_PATHS": [test_temp_root, tempfile.gettempdir()],
        "RATELIMIT_ENABLED": False,  # Disable limiter in test environment for smooth runs
    }
    flask_app = create_app(config_name="testing", config_override=test_config)

    # Seed test users
    with flask_app.app_context():
        db = flask_app.extensions["db"]
        # Clear any prior collections in mock
        for col_name in ["users", "scan_reports", "finding_fingerprints", "historical_metrics"]:
            if col_name in db.db.list_collection_names():
                db.db[col_name].delete_many({})

        # Insert standard test accounts
        db.create_user({
            "username": "admin_user",
            "password_hash": hash_password("AdminP@ssword123"),
            "role": Role.ADMIN,
        })
        db.create_user({
            "username": "analyst_user",
            "password_hash": hash_password("AnalystP@ssword123"),
            "role": Role.ANALYST,
        })
        db.create_user({
            "username": "viewer_user",
            "password_hash": hash_password("ViewerP@ssword123"),
            "role": Role.VIEWER,
        })

    yield flask_app

    # Cleanup orchestrator threads
    with flask_app.app_context():
        flask_app.extensions["orchestrator"].shutdown()


@pytest.fixture
def client(app):
    """Provides a Flask test client."""
    return app.test_client()


@pytest.fixture
def db(app):
    """Provides direct access to the database client."""
    return app.extensions["db"]


@pytest.fixture
def admin_token(app):
    with app.app_context():
        return generate_jwt_token(
            user_id="user_admin_01",
            username="admin_user",
            role=Role.ADMIN,
            secret_key=app.config["JWT_SECRET_KEY"],
        )


@pytest.fixture
def analyst_token(app):
    with app.app_context():
        return generate_jwt_token(
            user_id="user_analyst_01",
            username="analyst_user",
            role=Role.ANALYST,
            secret_key=app.config["JWT_SECRET_KEY"],
        )


@pytest.fixture
def viewer_token(app):
    with app.app_context():
        return generate_jwt_token(
            user_id="user_viewer_01",
            username="viewer_user",
            role=Role.VIEWER,
            secret_key=app.config["JWT_SECRET_KEY"],
        )


@pytest.fixture
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def analyst_headers(analyst_token):
    return {"Authorization": f"Bearer {analyst_token}"}


@pytest.fixture
def viewer_headers(viewer_token):
    return {"Authorization": f"Bearer {viewer_token}"}
