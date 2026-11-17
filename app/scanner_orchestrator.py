"""Asynchronous Scan Job Orchestrator & Engine Concurrency Manager.

Coordinates:
- Ingestion of targets into isolated temporary workspaces
- Parallel execution of 4 security engines via ThreadPoolExecutor
- Weighted risk scoring & deterministic fingerprint deduplication
- End-to-end secret redaction before persistence
- Workspace lifecycle and cleanup
"""

import concurrent.futures
from datetime import datetime, timezone
import logging
import os
from typing import Any, Dict, List, Optional

from app.db import DatabaseClient
from app.engines import (
    BaseEngine,
    ContainerEngine,
    SASTEngine,
    SCAEngine,
    SecretEngine,
)
from app.ingestion import (
    cleanup_workspace,
    clone_git_repo,
    create_workspace,
    extract_archive_safely,
    ingest_dockerfile,
    validate_local_path,
)
from app.redactor import redact_dict, redact_findings
from app.scoring import calculate_risk_score

logger = logging.getLogger(__name__)


class ScanStatus:
    """Scan Job Lifecycle States defined by specification."""
    PENDING = "PENDING"
    INGESTING = "INGESTING"
    SCANNING = "SCANNING"
    SCORING = "SCORING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ScannerOrchestrator:
    """Manages asynchronous scan jobs and concurrent security engine execution."""

    def __init__(
        self,
        db_client: DatabaseClient,
        max_workers: int = 4,
        workspace_base_dir: Optional[str] = None,
        allowed_local_paths: Optional[List[str]] = None,
        custom_engines: Optional[Dict[str, BaseEngine]] = None,
    ):
        self.db = db_client
        self.max_workers = max_workers
        self.workspace_base_dir = workspace_base_dir
        self.allowed_local_paths = allowed_local_paths or [os.getcwd()]

        # Initialize the 4 security static analysis engines
        self.engines: Dict[str, BaseEngine] = custom_engines or {
            "SecretEngine": SecretEngine(),
            "SASTEngine": SASTEngine(),
            "SCAEngine": SCAEngine(),
            "ContainerEngine": ContainerEngine(),
        }

        # Thread pools: one for background scan jobs, one for concurrent engines
        self.job_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="scan-job"
        )
        self.engine_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=len(self.engines) * 2,
            thread_name_prefix="scan-engine"
        )

    def submit_scan(
        self,
        job_id: str,
        project_id: str,
        ingestion_mode: str,
        target: Any,
        user: Dict[str, Any],
        selected_engines: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Registers a new scan job and queues it for asynchronous parallel execution."""
        now = datetime.now(timezone.utc)
        initial_report = {
            "job_id": job_id,
            "project_id": project_id,
            "status": ScanStatus.PENDING,
            "ingestion_mode": ingestion_mode,
            "target": str(target) if ingestion_mode != "dockerfile" else "<raw_dockerfile>",
            "submitted_by": user.get("username", "unknown"),
            "created_at": now,
            "updated_at": now,
            "progress": {
                "step": ScanStatus.PENDING,
                "percentage": 0,
                "message": "Scan job queued for processing.",
            },
            "findings": [],
            "scores": {},
            "grade": None,
            "error_message": None,
        }

        # Save initial state in MongoDB
        self.db.save_scan_report(initial_report)

        # Dispatch background job
        self.job_executor.submit(
            self._process_scan_job,
            job_id=job_id,
            project_id=project_id,
            ingestion_mode=ingestion_mode,
            target=target,
            selected_engines=selected_engines,
        )

        return initial_report

    def _update_job_status(
        self,
        job_id: str,
        status: str,
        percentage: int,
        message: str,
        error_message: Optional[str] = None,
        extra_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Helper to update scan progress and state in MongoDB."""
        now = datetime.now(timezone.utc)
        update_doc = {
            "job_id": job_id,
            "status": status,
            "updated_at": now,
            "progress": {
                "step": status,
                "percentage": percentage,
                "message": message,
            },
        }
        if error_message:
            update_doc["error_message"] = error_message
        if extra_data:
            update_doc.update(extra_data)

        self.db.save_scan_report(update_doc)

    def _process_scan_job(
        self,
        job_id: str,
        project_id: str,
        ingestion_mode: str,
        target: Any,
        selected_engines: Optional[List[str]] = None,
    ) -> None:
        """Background execution worker for a scan job."""
        workspace_path = None
        is_temporary_workspace = False

        try:
            # 1. State: INGESTING
            self._update_job_status(
                job_id=job_id,
                status=ScanStatus.INGESTING,
                percentage=10,
                message=f"Ingesting project via {ingestion_mode} mode."
            )

            # Ingestion routing
            if ingestion_mode == "archive":
                workspace_path = create_workspace(job_id, base_dir=self.workspace_base_dir)
                is_temporary_workspace = True
                extract_archive_safely(target, workspace_path)

            elif ingestion_mode == "local":
                # Local paths are validated against allowed paths and scanned directly
                workspace_path = validate_local_path(target, self.allowed_local_paths)
                is_temporary_workspace = False

            elif ingestion_mode == "git":
                workspace_path = create_workspace(job_id, base_dir=self.workspace_base_dir)
                is_temporary_workspace = True
                clone_git_repo(target, workspace_path)

            elif ingestion_mode == "dockerfile":
                workspace_path = create_workspace(job_id, base_dir=self.workspace_base_dir)
                is_temporary_workspace = True
                ingest_dockerfile(target, workspace_path)

            else:
                raise ValueError(f"Unknown ingestion mode: '{ingestion_mode}'.")

            # 2. State: SCANNING (Parallel Engine Execution via ThreadPoolExecutor)
            self._update_job_status(
                job_id=job_id,
                status=ScanStatus.SCANNING,
                percentage=30,
                message="Running security engines concurrently."
            )

            # Determine which engines to run
            engines_to_run = {}
            if selected_engines:
                for eng_name in selected_engines:
                    if eng_name in self.engines:
                        engines_to_run[eng_name] = self.engines[eng_name]
            if not engines_to_run:
                engines_to_run = self.engines

            raw_findings = []
            futures = {
                self.engine_executor.submit(engine.scan, workspace_path): name
                for name, engine in engines_to_run.items()
            }

            for future in concurrent.futures.as_completed(futures):
                eng_name = futures[future]
                try:
                    engine_results = future.result()
                    raw_findings.extend(engine_results)
                    logger.info(f"Engine {eng_name} completed for job {job_id} with {len(engine_results)} findings.")
                except Exception as e:
                    logger.error(f"Engine {eng_name} encountered an error: {e}", exc_info=True)

            # 3. State: SCORING (Deduplication, Scoring & Grading)
            self._update_job_status(
                job_id=job_id,
                status=ScanStatus.SCORING,
                percentage=80,
                message="Deduplicating findings, computing weighted risk score and grade."
            )

            score_report = calculate_risk_score(raw_findings)

            # 4. Strict Redaction: Enforce redaction before persistence!
            redacted_findings = redact_findings(score_report["deduplicated_findings"])

            # 5. State: COMPLETED
            final_report = {
                "job_id": job_id,
                "project_id": project_id,
                "status": ScanStatus.COMPLETED,
                "scores": {
                    "raw_score": score_report["raw_score"],
                    "final_score": score_report["final_score"],
                    "total_findings": score_report["total_findings_evaluated"],
                    "unique_findings": score_report["unique_findings_count"],
                    "duplicate_findings": score_report["duplicate_findings_count"],
                    "severity_counts": score_report["severity_counts"],
                },
                "grade": score_report["grade"],
                "findings": redacted_findings,
                "error_message": None,
                "progress": {
                    "step": ScanStatus.COMPLETED,
                    "percentage": 100,
                    "message": "Scan completed successfully.",
                },
            }

            # Persist completed report
            self.db.save_scan_report(final_report)

            # Record finding fingerprints
            self.db.record_finding_fingerprints(project_id, redacted_findings)

            # Record historical metric record
            self.db.save_historical_metrics({
                "project_id": project_id,
                "job_id": job_id,
                "raw_score": score_report["raw_score"],
                "final_score": score_report["final_score"],
                "grade": score_report["grade"],
                "severity_counts": score_report["severity_counts"],
            })

            logger.info(
                f"Scan job {job_id} completed successfully. "
                f"Grade: {score_report['grade']} (Score: {score_report['final_score']}/100)"
            )

        except Exception as e:
            logger.error(f"Scan job {job_id} failed: {e}", exc_info=True)
            self._update_job_status(
                job_id=job_id,
                status=ScanStatus.FAILED,
                percentage=100,
                message="Scan job failed.",
                error_message=str(e),
            )

        finally:
            # Automatic Workspace Cleanup: Guarantee workspace deletion for temporary workspaces
            if is_temporary_workspace and workspace_path:
                try:
                    cleanup_workspace(workspace_path, base_dir=self.workspace_base_dir)
                    logger.info(f"Workspace cleaned up for job {job_id}: {workspace_path}")
                except Exception as cleanup_err:
                    logger.warning(f"Error cleaning up workspace {workspace_path}: {cleanup_err}")

    def shutdown(self) -> None:
        """Gracefully shuts down the thread pool executors."""
        self.engine_executor.shutdown(wait=False)
        self.job_executor.shutdown(wait=False)
