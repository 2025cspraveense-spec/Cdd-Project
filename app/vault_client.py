"""HashiCorp Vault 1.15.6 Integration Client using hvac.

Features:
- HashiCorp Vault KV-v2 secret engine integration
- Token-based authentication
- Dynamic secret leasing & lease renewal
- Secret rotation helper methods
- Graceful environment variable fallback for offline / dev / testing modes
"""

import logging
import os
from typing import Any, Dict, Optional
import hvac
from hvac.exceptions import InvalidPath, VaultError

from app.redactor import redact_secret

logger = logging.getLogger(__name__)


class VaultClient:
    """Production-ready HashiCorp Vault client with KV-v2 and local fallback support."""

    def __init__(
        self,
        vault_addr: Optional[str] = None,
        vault_token: Optional[str] = None,
        mount_point: str = "secret",
        secret_path: str = "secret-leak-guard",
        enabled: bool = True,
        timeout: int = 5,
    ):
        self.vault_addr = vault_addr or os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
        self.vault_token = vault_token or os.getenv("VAULT_TOKEN", "")
        self.mount_point = mount_point
        self.secret_path = secret_path
        self.enabled = enabled
        self.timeout = timeout
        self.client: Optional[hvac.Client] = None
        self.is_connected = False
        self._local_cache: Dict[str, Any] = {}

        if self.enabled:
            self.connect()

    def connect(self) -> bool:
        """Initializes connection to Vault and verifies authentication."""
        if not self.enabled:
            self.is_connected = False
            return False

        try:
            self.client = hvac.Client(
                url=self.vault_addr,
                token=self.vault_token,
                timeout=self.timeout,
            )
            if self.client.is_authenticated():
                self.is_connected = True
                logger.info("Successfully authenticated to HashiCorp Vault.")
                return True
            raise RuntimeError("Vault token authentication failed.")
        except Exception as error:
            self.is_connected = False
            logger.error("Vault connection or authentication failed (%s).", type(error).__name__)
            raise RuntimeError("Vault is enabled but unavailable or unauthenticated.") from error

    def get_secret(
        self,
        key: str,
        default: Optional[str] = None,
        path: Optional[str] = None,
        mount_point: Optional[str] = None,
    ) -> Optional[str]:
        """Read a secret; environment fallback is allowed only when Vault is disabled."""
        if not self.enabled:
            if key in self._local_cache:
                return self._local_cache[key]
            return os.getenv(key, default)
        if not self.is_connected or not self.client:
            raise RuntimeError("Vault is enabled but not authenticated.")

        if self.client:
            target_path = path or self.secret_path
            target_mount = mount_point or self.mount_point
            try:
                response = self.client.secrets.kv.v2.read_secret_version(
                    path=target_path,
                    mount_point=target_mount,
                )
                secret_data = response.get("data", {}).get("data", {})
                if key in secret_data:
                    return secret_data[key]
            except InvalidPath:
                raise KeyError(f"Secret key '{key}' was not provisioned in Vault.")
            except VaultError as error:
                logger.error("Vault secret read failed (%s).", type(error).__name__)
                raise RuntimeError("Vault secret read failed.") from error
            except Exception as error:
                logger.error("Vault secret read failed (%s).", type(error).__name__)
                raise RuntimeError("Vault secret read failed.") from error
        raise RuntimeError("Vault is enabled but not authenticated.")

    def provision_secrets(
        self,
        secrets: Dict[str, str],
        path: Optional[str] = None,
        mount_point: Optional[str] = None,
    ) -> Dict[str, str]:
        """Write only missing bootstrap keys to KV-v2, preserving existing stored values."""
        if not self.enabled or not self.is_connected or not self.client:
            raise RuntimeError("Vault provisioning requires an authenticated, enabled Vault client.")
        target_path = path or self.secret_path
        target_mount = mount_point or self.mount_point
        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                path=target_path,
                mount_point=target_mount,
            )
            current_data = response.get("data", {}).get("data", {})
        except InvalidPath:
            current_data = {}
        missing = {key: value for key, value in secrets.items() if key not in current_data}
        if missing:
            self.client.secrets.kv.v2.create_or_update_secret(
                path=target_path,
                mount_point=target_mount,
                secret={**current_data, **missing},
            )
            current_data = {**current_data, **missing}
            logger.info("Provisioned %s missing bootstrap secret(s) in Vault KV-v2.", len(missing))
        return {key: current_data[key] for key in secrets if key in current_data}

    def set_secret(
        self,
        key: str,
        value: str,
        path: Optional[str] = None,
        mount_point: Optional[str] = None,
    ) -> bool:
        """Stores or updates a secret in Vault KV-v2, or locally when explicitly disabled."""
        if not self.enabled:
            self._local_cache[key] = value
            os.environ[key] = value
            return True
        if not self.is_connected or not self.client:
            raise RuntimeError("Vault is enabled but not authenticated.")

        if self.client:
            target_path = path or self.secret_path
            target_mount = mount_point or self.mount_point
            try:
                # Read existing secret map to avoid clobbering other keys
                current_data = {}
                try:
                    existing = self.client.secrets.kv.v2.read_secret_version(
                        path=target_path,
                        mount_point=target_mount,
                    )
                    current_data = existing.get("data", {}).get("data", {})
                except InvalidPath:
                    current_data = {}

                current_data[key] = value
                self.client.secrets.kv.v2.create_or_update_secret(
                    path=target_path,
                    mount_point=target_mount,
                    secret=current_data,
                )
                logger.info("A secret was updated in Vault KV-v2.")
                return True
            except Exception as error:
                logger.error("Failed to persist a secret to Vault (%s).", type(error).__name__)
                raise RuntimeError("Failed to persist secret to Vault.") from error
        raise RuntimeError("Vault is enabled but not authenticated.")

    def rotate_secret(
        self,
        key: str,
        new_value: str,
        path: Optional[str] = None,
        mount_point: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Rotates an existing secret key to a new value in Vault KV-v2."""
        target_path = path or self.secret_path
        target_mount = mount_point or self.mount_point
        self.set_secret(key, new_value, path=target_path, mount_point=target_mount)
        return {
            "key": key,
            "status": "rotated",
            "vault_connected": self.is_connected,
            "path": f"{target_mount}/{target_path}",
            "rotated": True,
        }

    def renew_token(self, increment: int = 3600) -> Dict[str, Any]:
        """Renew the authenticated Vault token when its policy permits renewal."""
        if not self.enabled or not self.is_connected or not self.client:
            raise RuntimeError("Vault token renewal requires an authenticated Vault connection.")
        try:
            result = self.client.auth.token.renew_self(increment=increment)
            return {
                "renewed": True,
                "lease_duration": result.get("auth", {}).get("lease_duration"),
            }
        except Exception as error:
            logger.error("Vault token renewal failed (%s).", type(error).__name__)
            raise RuntimeError("Vault token renewal failed.") from error

    def renew_lease(self, lease_id: str, increment: int = 3600) -> Dict[str, Any]:
        """Renews a dynamic secret lease (e.g., database credentials)."""
        if not self.is_connected or not self.client:
            return {
                "lease_id": redact_secret(lease_id),
                "renewed": False,
                "message": "Lease renewal is unavailable while Vault is disabled.",
            }
        try:
            result = self.client.sys.renew_lease(lease_id=lease_id, increment=increment)
            logger.info("Successfully renewed Vault lease by %s seconds.", increment)
            return {
                "lease_id": redact_secret(lease_id),
                "renewed": True,
                "lease_duration": result.get("lease_duration", increment),
            }
        except Exception as error:
            logger.error("Failed to renew Vault lease (%s).", type(error).__name__)
            return {
                "lease_id": redact_secret(lease_id),
                "renewed": False,
                "error": type(error).__name__,
            }

    def generate_database_credentials(
        self,
        role: str,
        mount_point: str = "database",
    ) -> Dict[str, Any]:
        """Generate a time-bound database user and return its private lease data."""
        if not self.enabled or not self.is_connected or not self.client:
            raise RuntimeError("Database credentials require an authenticated Vault connection.")
        if not role or not role.strip():
            raise ValueError("A Vault database role is required.")

        try:
            response = self.client.secrets.database.generate_credentials(
                name=role.strip(),
                mount_point=mount_point,
            )
            data = response.get("data") or {}
            credentials = {
                "username": data.get("username"),
                "password": data.get("password"),
                "lease_id": response.get("lease_id"),
                "lease_duration": response.get("lease_duration"),
            }
            if not all(credentials.get(key) for key in ("username", "password", "lease_id")):
                raise RuntimeError("Vault returned incomplete database lease data.")
            return credentials
        except Exception as error:
            logger.error("Vault database credential generation failed (%s).", type(error).__name__)
            raise RuntimeError("Vault database credential generation failed.") from error

    def revoke_lease(self, lease_id: str) -> bool:
        """Revokes a dynamic secret lease."""
        if not self.is_connected or not self.client:
            return False

        try:
            self.client.sys.revoke_lease(lease_id=lease_id)
            logger.info("Successfully revoked Vault lease.")
            return True
        except Exception as e:
            logger.error("Failed to revoke Vault lease (%s).", type(e).__name__)
            return False

    def health_check(self) -> Dict[str, Any]:
        """Performs a health check on the Vault instance."""
        if not self.is_connected or not self.client:
            return {
                "status": "disabled",
                "connected": False,
                "message": "Vault is explicitly disabled; environment fallback is active.",
            }

        try:
            health = self.client.sys.read_health_status(method="GET")
            return {
                "status": "healthy",
                "connected": True,
                "sealed": health.get("sealed", False),
                "version": health.get("version", "unknown"),
            }
        except Exception as e:
            return {
                "status": "degraded",
                "connected": False,
                "error": type(e).__name__,
            }
