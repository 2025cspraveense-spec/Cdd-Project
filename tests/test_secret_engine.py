
"""Unit tests for the SecretEngine."""

from app.engines.secret_engine import SecretEngine


def test_detects_aws_access_key(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    (project / "settings.py").write_text(
        'AWS_KEY = "AKIA1234567890ABCDEF"\n',
        encoding="utf-8",
    )

    engine = SecretEngine()
    findings = engine.scan(str(project))

    aws_findings = [f for f in findings if f["rule_id"] == "SEC-AWS-001"]

    assert len(aws_findings) == 1
    assert aws_findings[0]["severity"] == "critical"
    assert aws_findings[0]["file_path"] == "settings.py"
    assert aws_findings[0]["line_number"] == 1


def test_detects_generic_password(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    (project / "config.py").write_text(
        'password = "SuperSecret123!"\n',
        encoding="utf-8",
    )

    engine = SecretEngine()
    findings = engine.scan(str(project))

    assert any(f["rule_id"] == "SEC-GEN-001" for f in findings)


def test_returns_standard_finding_structure(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    (project / "app.py").write_text(
       'token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"\n',
        encoding="utf-8",
    )

    engine = SecretEngine()
    findings = engine.scan(str(project))

    assert findings

    required_fields = {
        "engine_name",
        "rule_id",
        "category",
        "severity",
        "file_path",
        "line_number",
        "description",
        "raw_secret",
        "match_content",
        "remediation",
    }

    assert required_fields.issubset(findings[0].keys())
def test_detects_slack_token(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    (project / "config.py").write_text(
        'SLACK_TOKEN = "xoxb-1234567890abcdefghij"\n',
        encoding="utf-8",
    )

    findings = SecretEngine().scan(str(project))

    assert any(f["rule_id"] == "SEC-SLACK-001" for f in findings)


def test_detects_private_key_marker(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    (project / "key.pem").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    findings = SecretEngine().scan(str(project))

    assert any(f["rule_id"] == "SEC-KEY-001" for f in findings)


def test_detects_jwt_token(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.fakeSignature123"
    (project / "auth.py").write_text(
        f'token = "{jwt}"\n',
        encoding="utf-8",
    )

    findings = SecretEngine().scan(str(project))

    assert any(f["rule_id"] == "SEC-JWT-001" for f in findings)
