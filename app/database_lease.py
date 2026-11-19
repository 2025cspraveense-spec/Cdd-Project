"""Automatic renewal and rotation for Vault-issued MongoDB credentials."""

import logging
import threading
from typing import Any, Dict

from app.db import DatabaseClient
from app.vault_client import VaultClient

logger = logging.getLogger(__name__)


class DatabaseLeaseManager:
    def __init__(
        self,
        vault: VaultClient,
        database: DatabaseClient,
        auth_source: str,
        role: str,
        lease: Dict[str, Any],
    ):
        self.vault = vault
        self.database = database
        self.auth_source = auth_source
        self.role = role
        self.lease = dict(lease)
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="vault-mongodb-lease",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=2)

    def renew_or_rotate_once(self) -> str:
        lease_id = self.lease["lease_id"]
        duration = int(self.lease.get("lease_duration") or 3600)
        renewed = self.vault.renew_lease(lease_id, increment=duration)
        if renewed.get("renewed"):
            self.lease["lease_duration"] = renewed.get("lease_duration", duration)
            return "renewed"

        replacement = self.vault.generate_database_credentials(self.role)
        try:
            self.database.rotate_credentials(
                username=replacement["username"],
                password=replacement["password"],
                auth_source=self.auth_source,
            )
        except Exception:
            self.vault.revoke_lease(replacement["lease_id"])
            raise

        self.lease = replacement
        if not self.vault.revoke_lease(lease_id):
            logger.warning("Previous MongoDB credential lease could not be revoked after rotation.")
        return "rotated"

    def _renewal_interval(self) -> int:
        duration = int(self.lease.get("lease_duration") or 3600)
        return max(30, min(duration // 2, 1800))

    def _run(self) -> None:
        interval = self._renewal_interval()
        while not self._stop.wait(interval):
            try:
                outcome = self.renew_or_rotate_once()
                logger.info("Vault MongoDB credential lease %s.", outcome)
                interval = self._renewal_interval()
            except Exception as error:
                logger.error("Vault MongoDB lease maintenance failed (%s).", type(error).__name__)
                interval = 30
