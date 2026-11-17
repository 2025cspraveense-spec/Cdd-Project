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
        self.vault_token = vault_token or os.getenv("VAULT_TOKEN", "root")
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
            logger.info("Vault client is disabled. Operating in environment variable fallback mode.")
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
                logger.info(f"Successfully authenticated to HashiCorp Vault at {self.vault_addr}")
                return True
            else:
                logger.warning(
                    f"Vault token authentication failed at {self.vault_addr}. Switching to env fallback."
                )
                self.is_connected = False
                return False
        except Exception as e:
            logger.warning(
                f"Could not connect to HashiCorp Vault at {self.vault_addr} ({e}). "
                "Gracefully falling back to environment variables."
            )
            self.is_connected = False
            return False

    def get_secret(
        self,
        key: str,
        default: Optional[str] = None,
        path: Optional[str] = None,
        mount_point: Optional[str] = None,
    ) -> Optional[str]:
        """Retrieves a single secret from Vault KV-v2 or falls back to environment variables."""
        # 1. Attempt Vault retrieval if connected
        if self.is_connected and self.client:
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
                logger.debug(f"Vault path '{target_path}' not found on mount '{target_mount}'.")
            except VaultError as ve:
                logger.warning(f"Error reading secret '{key}' from Vault: {ve}")
            except Exception as e:
                logger.warning(f"Unexpected error communicating with Vault: {e}")

        # 2. Check local in-memory cache
        if key in self._local_cache:
            return self._local_cache[key]

        # 3. Graceful fallback to OS environment variable or default
        return os.getenv(key, default)

    def set_secret(
        self,
        key: str,
        value: str,
        path: Optional[str] = None,
        mount_point: Optional[str] = None,
    ) -> bool:
        """Stores or updates a secret key-value in Vault KV-v2."""
        self._local_cache[key] = value

        if self.is_connected and self.client:
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
                logger.info(f"Secret '{key}' updated in Vault path '{target_path}'.")
                return True
            except Exception as e:
                logger.error(f"Failed to persist secret '{key}' to Vault: {e}")
                return False

        # In fallback mode, store in os.environ and local cache
        os.environ[key] = value
        return True

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
        old_value = self.get_secret(key, path=target_path, mount_point=target_mount)

        success = self.set_secret(key, new_value, path=target_path, mount_point=target_mount)
        return {
            "key": key,
            "status": "rotated" if success else "failed",
            "vault_connected": self.is_connected,
            "path": f"{target_mount}/{target_path}",
            "rotated": success,
        }

    def renew_lease(self, lease_id: str, increment: int = 3600) -> Dict[str, Any]:
        """Renews a dynamic secret lease (e.g., database credentials)."""
        if not self.is_connected or not self.client:
            return {
                "lease_id": lease_id,
                "renewed": False,
                "message": "Vault is not connected; simulated fallback active.",
            }

        try:
            result = self.client.sys.renew_lease(lease_id=lease_id, increment=increment)
            logger.info(f"Successfully renewed lease '{lease_id}' by {increment}s.")
            return {
                "lease_id": lease_id,
                "renewed": True,
                "lease_duration": result.get("lease_duration", increment),
                "data": result,
            }
        except Exception as e:
            logger.error(f"Failed to renew lease '{lease_id}': {e}")
            return {"lease_id": lease_id, "renewed": False, "error": str(e)}

    def revoke_lease(self, lease_id: str) -> bool:
        """Revokes a dynamic secret lease."""
        if not self.is_connected or not self.client:
            return True

        try:
            self.client.sys.revoke_lease(lease_id=lease_id)
            logger.info(f"Successfully revoked lease '{lease_id}'.")
            return True
        except Exception as e:
            logger.error(f"Failed to revoke lease '{lease_id}': {e}")
            return False

    def health_check(self) -> Dict[str, Any]:
        """Performs a health check on the Vault instance."""
        if not self.is_connected or not self.client:
            return {
                "status": "fallback",
                "connected": False,
                "vault_addr": self.vault_addr,
                "message": "Vault is disabled or unreachable. Using environment variable fallback.",
            }

        try:
            health = self.client.sys.read_health_status(method="GET")
            return {
                "status": "healthy",
                "connected": True,
                "vault_addr": self.vault_addr,
                "sealed": health.get("sealed", False),
                "version": health.get("version", "unknown"),
            }
        except Exception as e:
            return {
                "status": "degraded",
                "connected": False,
                "vault_addr": self.vault_addr,
                "error": str(e),
            }
