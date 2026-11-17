"""Unit tests for HashiCorp Vault Client with KV-v2 and Fallback."""

import os
from unittest.mock import MagicMock, patch
import pytest
from app.vault_client import VaultClient


def test_vault_disabled_fallback_mode():
    """When disabled, VaultClient operates in local environment fallback mode."""
    client = VaultClient(enabled=False)
    assert not client.is_connected

    os.environ["TEST_FALLBACK_KEY"] = "my_fallback_secret_value"
    val = client.get_secret("TEST_FALLBACK_KEY")
    assert val == "my_fallback_secret_value"

    # Default fallback
    assert client.get_secret("NON_EXISTENT_KEY", default="default_123") == "default_123"


def test_vault_set_secret_local_fallback():
    """set_secret works and caches locally in fallback mode."""
    client = VaultClient(enabled=False)
    client.set_secret("APP_DYNAMIC_KEY", "dynamic_value_999")
    assert client.get_secret("APP_DYNAMIC_KEY") == "dynamic_value_999"


def test_vault_rotate_secret_fallback():
    """rotate_secret executes properly even in fallback mode."""
    client = VaultClient(enabled=False)
    result = client.rotate_secret("ROTATED_KEY", "new_val_123")

    assert result["key"] == "ROTATED_KEY"
    assert result["rotated"] is True
    assert client.get_secret("ROTATED_KEY") == "new_val_123"


def test_vault_kv2_connected_read_write():
    """Test full KV-v2 reading and writing when connected to simulated Vault."""
    mock_hvac = MagicMock()
    mock_hvac.is_authenticated.return_value = True

    # Mock KV-v2 read
    mock_hvac.secrets.kv.v2.read_secret_version.return_value = {
        "data": {
            "data": {
                "JWT_SECRET_KEY": "vault-stored-jwt-secret-xyz",
                "MONGO_URI": "mongodb://vault-user:vault-pass@prod-cluster:27017",
            }
        }
    }

    with patch("hvac.Client", return_value=mock_hvac):
        client = VaultClient(vault_addr="http://127.0.0.1:8200", enabled=True)
        assert client.is_connected

        jwt_key = client.get_secret("JWT_SECRET_KEY")
        assert jwt_key == "vault-stored-jwt-secret-xyz"

        mongo_uri = client.get_secret("MONGO_URI")
        assert "vault-user:vault-pass" in mongo_uri


def test_vault_dynamic_lease_renewal():
    """Test dynamic lease renewal."""
    mock_hvac = MagicMock()
    mock_hvac.is_authenticated.return_value = True
    mock_hvac.sys.renew_lease.return_value = {"lease_duration": 3600}

    with patch("hvac.Client", return_value=mock_hvac):
        client = VaultClient(vault_addr="http://127.0.0.1:8200", enabled=True)
        result = client.renew_lease("database/creds/readonly/12345", increment=3600)
        assert result["renewed"] is True
        assert result["lease_duration"] == 3600


def test_vault_health_check_reporting():
    """Test health check reporting for both connected and degraded states."""
    client_offline = VaultClient(enabled=False)
    health_offline = client_offline.health_check()
    assert health_offline["status"] == "fallback"
    assert health_offline["connected"] is False

    mock_hvac = MagicMock()
    mock_hvac.is_authenticated.return_value = True
    mock_hvac.sys.read_health_status.return_value = {"sealed": False, "version": "1.15.6"}

    with patch("hvac.Client", return_value=mock_hvac):
        client_online = VaultClient(enabled=True)
        health_online = client_online.health_check()
        assert health_online["status"] == "healthy"
        assert health_online["sealed"] is False
        assert health_online["version"] == "1.15.6"
