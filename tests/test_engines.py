"""Focused tests for static analysis engines."""

import json
from unittest.mock import Mock, patch

from app.engines.sast_engine import SASTEngine
from app.engines.sca_engine import SCAEngine
from app.engines.secret_engine import SECRET_RULES, SecretEngine
from app.engines.container_engine import ContainerEngine
from app.redactor import redact_findings


def test_secret_engine_detects_provider_patterns_and_entropy(tmp_path):
    opaque_base64 = "A1b2C3d4E5f6G7h8J9k0LmN"
    opaque_hex = "0123456789abcdef"
    (tmp_path / "settings.txt").write_text(
        "gitlab_token=glpat-12345678901234567890\n"
        f"opaque_value={opaque_base64}\n"
        f"opaque_hash={opaque_hex}\n",
        encoding="utf-8",
    )

    findings = SecretEngine().scan(str(tmp_path))

    assert len(SECRET_RULES) >= 25
    assert {finding["rule_id"] for finding in findings} >= {
        "SEC-GITLAB-001",
        "SEC-ENTROPY-B64",
        "SEC-ENTROPY-HEX",
    }
    redacted = redact_findings(findings)
    rendered = str(redacted)
    assert opaque_base64 not in rendered
    assert opaque_hex not in rendered


def test_sast_engine_uses_ast_without_executing_target(tmp_path):
    marker = tmp_path / "executed"
    source = (
        "import pathlib\n"
        "pathlib.Path(" + repr(str(marker)) + ").write_text('executed')\n"
        "cursor.execute(f'SELECT * FROM users WHERE name = {name}')\n"
        "subprocess.run(command, shell=True)\n"
    )
    (tmp_path / "app.py").write_text(source, encoding="utf-8")

    tool_results = {
        "semgrep": {
            "results": [{
                "check_id": "slg.python.subprocess-shell-true",
                "path": str(tmp_path / "app.py"),
                "start": {"line": 4},
                "extra": {
                    "message": "Avoid shell execution.",
                    "severity": "ERROR",
                    "lines": "subprocess.run(command, shell=True)",
                    "metadata": {"remediation": "Use argv."},
                },
            }]
        },
        "bandit": {
            "results": [{
                "filename": str(tmp_path / "app.py"),
                "line_number": 4,
                "test_id": "B602",
                "issue_severity": "HIGH",
                "issue_text": "subprocess call with shell=True",
                "code": "subprocess.run(command, shell=True)",
            }]
        },
    }

    def fake_run(command, **kwargs):
        assert kwargs["shell"] is False
        tool = command[0]
        return Mock(returncode=1 if tool == "bandit" else 0,
                    stdout=json.dumps(tool_results[tool]), stderr="")

    with patch("app.engines.sast_engine.shutil.which", return_value="scanner"), \
            patch("app.engines.sast_engine.subprocess.run", side_effect=fake_run):
        findings = SASTEngine().scan(str(tmp_path))

    assert not marker.exists()
    assert {finding["rule_id"] for finding in findings} >= {"SAST-SQL-001", "SAST-CMD-001"}
    assert sum(finding["rule_id"] == "SAST-CMD-001" for finding in findings) == 1
    assert any(finding["rule_id"].startswith("SAST-BANDIT-") for finding in findings)
    assert any(finding["rule_id"].startswith("SAST-SEMGREP-") for finding in findings)


def test_sca_engine_queries_osv_with_pinned_dependencies(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    response = Mock()
    response.json.return_value = {
        "results": [{
            "vulns": [{"id": "GHSA-test-1234", "summary": "Example advisory", "severity": []}]
        }]
    }
    response.raise_for_status.return_value = None

    with patch("app.engines.sca_engine.requests.post", return_value=response) as post:
        findings = SCAEngine().scan(str(tmp_path))

    assert post.call_args.kwargs["json"] == {
        "queries": [{"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.31.0"}]
    }
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SCA-OSV-GHSA-test-1234"


def test_sca_engine_skips_unpinned_versions(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests>=2.31\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"react": "^18.2.0"}}),
        encoding="utf-8",
    )
    with patch("app.engines.sca_engine.requests.post") as post:
        assert SCAEngine().scan(str(tmp_path)) == []
    post.assert_not_called()


def test_sca_engine_matches_osv_semver_and_ecosystem_ranges():
    semver_range = {
        "type": "SEMVER",
        "events": [{"introduced": "1.2.0"}, {"fixed": "2.0.0"}],
    }
    ecosystem_range = {
        "type": "ECOSYSTEM",
        "events": [{"introduced": "1.0"}, {"fixed": "1.5"}],
    }

    assert SCAEngine._range_affects("1.9.9", semver_range, "npm")
    assert not SCAEngine._range_affects("2.0.0", semver_range, "npm")
    assert SCAEngine._range_affects("1.4", ecosystem_range, "PyPI")
    assert not SCAEngine._range_affects("1.5", ecosystem_range, "PyPI")


def test_container_engine_flags_root_user_and_missing_healthcheck(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\nUSER root\nCMD ['python', 'app.py']\n",
        encoding="utf-8",
    )

    findings = ContainerEngine().scan(str(tmp_path))

    assert {finding["rule_id"] for finding in findings} >= {
        "CONT-ROOT-001",
        "CONT-HEALTH-001",
    }


def test_container_engine_checks_cis_aligned_dockerfile_patterns(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM --platform=$BUILDPLATFORM alpine:latest AS build\n"
        "ARG API_TOKEN=hardcoded-secret\n"
        "RUN curl https://example.invalid/install.sh | sh && sudo chmod 777 /tmp/tool\n"
        "ADD app.tar /app/\n"
        "EXPOSE 22 8080\n"
        "FROM alpine@sha256:" + "a" * 64 + "\n"
        "USER 10001\n"
        "HEALTHCHECK CMD true\n",
        encoding="utf-8",
    )

    findings = ContainerEngine().scan(str(tmp_path))

    assert {finding["rule_id"] for finding in findings} >= {
        "CONT-TAG-001",
        "CONT-ENV-001",
        "CONT-SUDO-001",
        "CONT-CHMOD-001",
        "CONT-CURL-001",
        "CONT-ADD-001",
        "CONT-PORT-001",
    }


def test_container_engine_does_not_flag_remote_add_urls():
    assert not ContainerEngine._is_local_add("ADD --chown=10001 https://example.invalid/a.tar /app/")
    assert ContainerEngine._is_local_add("ADD --chown=10001 archive.tar /app/")


def test_container_engine_flags_disabled_healthcheck(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM alpine:3.20\nUSER 10001\nHEALTHCHECK NONE\n",
        encoding="utf-8",
    )

    findings = ContainerEngine().scan(str(tmp_path))

    assert "CONT-HEALTH-001" in {finding["rule_id"] for finding in findings}
