# Local Scan Targets Directory

Place directories here to scan using the Local Path ingestion mode:
`/scan_targets/<your_project>` in the Docker deployment.

## Live dashboard demo

The `demo_vulnerable_project` folder contains deliberately insecure code and
nonfunctional placeholder credentials for demonstrating all four analysis
engines. Sign in to the dashboard with an analyst or admin account, select
**Local path**, use `/scan_targets/demo_vulnerable_project`, and start a scan.
The completed findings show the risk score, grade, and remediation guidance.
Use the **PDF** control to export a redacted executive report; HTML, JSON, and
SARIF 2.1.0 exports are available beside it.

The sample is intentionally vulnerable and must not be used as a real
application or deployed.
