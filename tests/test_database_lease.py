from unittest.mock import MagicMock

from app.database_lease import DatabaseLeaseManager


def test_database_lease_manager_renews_a_live_lease():
    vault = MagicMock()
    vault.renew_lease.return_value = {"renewed": True, "lease_duration": 3600}
    database = MagicMock()
    manager = DatabaseLeaseManager(
        vault=vault,
        database=database,
        auth_source="secret_leak_guard_v2",
        role="slg-backend-role",
        lease={"lease_id": "old-lease", "lease_duration": 3600},
    )

    assert manager.renew_or_rotate_once() == "renewed"
    assert manager.lease["lease_duration"] == 3600
    database.rotate_credentials.assert_not_called()
    vault.generate_database_credentials.assert_not_called()


def test_database_lease_manager_rotates_credentials_when_renewal_fails():
    vault = MagicMock()
    vault.renew_lease.return_value = {"renewed": False}
    vault.generate_database_credentials.return_value = {
        "username": "new-user",
        "password": "new-password",
        "lease_id": "new-lease",
        "lease_duration": 3600,
    }
    vault.revoke_lease.return_value = True
    database = MagicMock()
    manager = DatabaseLeaseManager(
        vault=vault,
        database=database,
        auth_source="secret_leak_guard_v2",
        role="slg-backend-role",
        lease={"lease_id": "old-lease", "lease_duration": 3600},
    )

    assert manager.renew_or_rotate_once() == "rotated"
    database.rotate_credentials.assert_called_once_with(
        username="new-user",
        password="new-password",
        auth_source="secret_leak_guard_v2",
    )
    vault.revoke_lease.assert_called_once_with("old-lease")
    assert manager.lease["lease_id"] == "new-lease"
