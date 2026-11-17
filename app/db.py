"""MongoDB 7.0 Persistence & Indexing Layer for Secret Leak Guard v2.0.

Provides schemas, compound & single indexes, TTL automatic record expiration,
and seamless fallback to mongomock when live MongoDB is not present.
"""

import datetime
import logging
from typing import Any, Dict, List, Optional
import pymongo
from pymongo import ASCENDING, DESCENDING, IndexModel
from pymongo.errors import ConnectionFailure, PyMongoError

from app.redactor import redact_dict, redact_finding

logger = logging.getLogger(__name__)


class DatabaseClient:
    """MongoDB 7.0 Client manager with indexing, TTL expiration, and mock fallback."""

    def __init__(
        self,
        mongo_uri: str = "mongodb://localhost:27017",
        db_name: str = "secret_leak_guard_v2",
        ttl_seconds: int = 30 * 24 * 3600,
        use_mock: bool = False,
    ):
        self.mongo_uri = mongo_uri
        self.db_name = db_name
        self.ttl_seconds = ttl_seconds
        self.use_mock = use_mock
        self.client: Optional[pymongo.MongoClient] = None
        self.db = None
        self.is_mock = False

        self.connect()

    def connect(self) -> None:
        """Establishes connection to MongoDB or falls back to mongomock."""
        if self.use_mock:
            self._init_mock()
            return

        try:
            # Connect to MongoDB with timeout
            self.client = pymongo.MongoClient(
                self.mongo_uri,
                serverSelectionTimeoutMS=2000,
                connectTimeoutMS=2000,
            )
            # Verify connectivity
            self.client.admin.command("ping")
            self.db = self.client[self.db_name]
            self.is_mock = False
            logger.info(f"Connected to live MongoDB at {self.mongo_uri} (db: {self.db_name})")
            self.ensure_indexes()
        except (ConnectionFailure, PyMongoError, Exception) as e:
            logger.warning(
                f"Failed to connect to live MongoDB at {self.mongo_uri} ({e}). "
                "Switching to in-memory mongomock database."
            )
            self._init_mock()

    def _init_mock(self) -> None:
        """Initializes in-memory mongomock client."""
        try:
            import mongomock
            self.client = mongomock.MongoClient()
            self.db = self.client[self.db_name]
            self.is_mock = True
            logger.info("mongomock initialized successfully.")
            self.ensure_indexes()
        except ImportError:
            raise RuntimeError("mongomock package is required for mock database execution.")

    def ensure_indexes(self) -> Dict[str, List[str]]:
        """Creates required single, compound, and TTL indexes across all collections."""
        created_indexes = {}

        try:
            # 1. scan_reports Collection Indexes
            scan_reports = self.db["scan_reports"]
            scan_reports.create_index([("job_id", ASCENDING)], unique=True, name="idx_scan_job_id_unique")
            scan_reports.create_index([("project_id", ASCENDING)], name="idx_scan_project_id")
            scan_reports.create_index(
                [("project_id", ASCENDING), ("created_at", DESCENDING)],
                name="idx_scan_project_created_compound"
            )
            # TTL Index: Automatically expire old scan records
            scan_reports.create_index(
                [("expires_at", ASCENDING)],
                expireAfterSeconds=0,
                name="idx_scan_reports_ttl"
            )
            created_indexes["scan_reports"] = [idx["name"] for idx in scan_reports.list_indexes()]

            # 2. finding_fingerprints Collection Indexes
            fingerprints = self.db["finding_fingerprints"]
            fingerprints.create_index(
                [("project_id", ASCENDING), ("fingerprint", ASCENDING)],
                unique=True,
                name="idx_fingerprint_proj_fp_unique"
            )
            fingerprints.create_index([("fingerprint", ASCENDING)], name="idx_fingerprint_single")
            fingerprints.create_index([("last_seen", DESCENDING)], name="idx_fingerprint_last_seen")
            created_indexes["finding_fingerprints"] = [idx["name"] for idx in fingerprints.list_indexes()]

            # 3. project_configs Collection Indexes
            configs = self.db["project_configs"]
            configs.create_index([("project_id", ASCENDING)], unique=True, name="idx_project_config_id_unique")
            created_indexes["project_configs"] = [idx["name"] for idx in configs.list_indexes()]

            # 4. historical_metrics Collection Indexes
            metrics = self.db["historical_metrics"]
            metrics.create_index(
                [("project_id", ASCENDING), ("created_at", DESCENDING)],
                name="idx_metrics_proj_created_compound"
            )
            metrics.create_index(
                [("expires_at", ASCENDING)],
                expireAfterSeconds=0,
                name="idx_metrics_ttl"
            )
            created_indexes["historical_metrics"] = [idx["name"] for idx in metrics.list_indexes()]

            # 5. users Collection Indexes
            users = self.db["users"]
            users.create_index([("username", ASCENDING)], unique=True, name="idx_user_username_unique")
            created_indexes["users"] = [idx["name"] for idx in users.list_indexes()]

            logger.info("All MongoDB compound, unique, and TTL indexes verified/created.")
        except Exception as e:
            logger.error(f"Error creating MongoDB indexes: {e}")

        return created_indexes

    def save_scan_report(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Saves or updates a scan report ensuring strict redaction before write."""
        # Enforce redaction before database persistence!
        sanitized = redact_dict(report_data)

        # Set creation and expiration timestamps
        now = datetime.datetime.now(datetime.timezone.utc)
        if "created_at" not in sanitized:
            sanitized["created_at"] = now
        sanitized["updated_at"] = now

        if "expires_at" not in sanitized:
            sanitized["expires_at"] = now + datetime.timedelta(seconds=self.ttl_seconds)

        job_id = sanitized["job_id"]
        self.db["scan_reports"].update_one(
            {"job_id": job_id},
            {"$set": sanitized},
            upsert=True,
        )
        return sanitized

    def get_scan_report(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a scan report by job_id, removing internal Mongo _id."""
        doc = self.db["scan_reports"].find_one({"job_id": job_id})
        if doc and "_id" in doc:
            doc["_id"] = str(doc["_id"])
        return doc

    def list_scan_reports(
        self,
        project_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        skip: int = 0,
    ) -> List[Dict[str, Any]]:
        """Lists scan reports filtered by project and status."""
        query = {}
        if project_id:
            query["project_id"] = project_id
        if status:
            query["status"] = status.upper()

        cursor = self.db["scan_reports"].find(query).sort("created_at", DESCENDING).skip(skip).limit(limit)
        results = []
        for doc in cursor:
            if "_id" in doc:
                doc["_id"] = str(doc["_id"])
            results.append(doc)
        return results

    def record_finding_fingerprints(
        self,
        project_id: str,
        findings: List[Dict[str, Any]]
    ) -> int:
        """Records finding fingerprints to track first-seen and last-seen occurrences."""
        now = datetime.datetime.now(datetime.timezone.utc)
        recorded = 0

        for f in findings:
            fp = f.get("fingerprint")
            if not fp:
                continue

            # Redact finding before storing
            sanitized_finding = redact_finding(f)

            self.db["finding_fingerprints"].update_one(
                {"project_id": project_id, "fingerprint": fp},
                {
                    "$setOnInsert": {
                        "project_id": project_id,
                        "fingerprint": fp,
                        "rule_id": sanitized_finding.get("rule_id"),
                        "severity": sanitized_finding.get("severity"),
                        "first_seen": now,
                        "file_path": sanitized_finding.get("file_path"),
                    },
                    "$set": {
                        "last_seen": now,
                        "status": "open",
                    },
                    "$inc": {"occurrence_count": 1},
                },
                upsert=True,
            )
            recorded += 1

        return recorded

    def save_historical_metrics(self, metrics: Dict[str, Any]) -> None:
        """Saves aggregate metrics for a project."""
        now = datetime.datetime.now(datetime.timezone.utc)
        doc = dict(metrics)
        doc["created_at"] = now
        doc["expires_at"] = now + datetime.timedelta(seconds=self.ttl_seconds)
        self.db["historical_metrics"].insert_one(doc)

    def get_historical_metrics(self, project_id: str, limit: int = 30) -> List[Dict[str, Any]]:
        """Retrieves historical metrics for a project."""
        cursor = (
            self.db["historical_metrics"]
            .find({"project_id": project_id})
            .sort("created_at", DESCENDING)
            .limit(limit)
        )
        results = []
        for doc in cursor:
            if "_id" in doc:
                doc["_id"] = str(doc["_id"])
            results.append(doc)
        return results

    def create_user(self, user_doc: Dict[str, Any]) -> bool:
        """Creates a new user record."""
        now = datetime.datetime.now(datetime.timezone.utc)
        user_doc["created_at"] = now
        try:
            self.db["users"].insert_one(user_doc)
            return True
        except PyMongoError:
            return False

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Retrieves a user by username."""
        return self.db["users"].find_one({"username": username})

    def close(self) -> None:
        """Closes the MongoDB connection."""
        if self.client:
            self.client.close()
