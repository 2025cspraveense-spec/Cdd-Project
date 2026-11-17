"""Unit tests for Secure Project Ingestion."""

import io
import os
import tarfile
import tempfile
import zipfile
import pytest
from unittest.mock import patch

from app.ingestion import (
    PathTraversalError,
    SSRFProtectionError,
    ZipSlipError,
    cleanup_workspace,
    create_workspace,
    extract_archive_safely,
    ingest_dockerfile,
    validate_git_url_and_check_ssrf,
    validate_local_path,
)


# ---------------------------------------------------------------------------
# Mode 1: Archive Ingestion & Zip-Slip Defense
# ---------------------------------------------------------------------------

def test_zip_slip_relative_traversal_blocked(tmp_path):
    """Zip-Slip attack with '../' members must raise ZipSlipError and block extraction."""
    malicious_zip = tmp_path / "malicious.zip"
    dest_dir = tmp_path / "extracted"
    dest_dir.mkdir()

    # Create a malicious zip file containing path traversal entries
    with zipfile.ZipFile(malicious_zip, "w") as zf:
        zf.writestr("../../evil_payload.sh", "#!/bin/bash\necho pwned")

    with pytest.raises(ZipSlipError) as exc_info:
        extract_archive_safely(str(malicious_zip), str(dest_dir))

    assert "Zip-Slip path traversal" in str(exc_info.value)
    # Ensure evil file was NEVER written outside
    assert not (tmp_path.parent / "evil_payload.sh").exists()
    assert not (dest_dir / "evil_payload.sh").exists()


def test_tar_slip_relative_traversal_blocked(tmp_path):
    """Tar-Slip attack with traversal members must raise ZipSlipError."""
    malicious_tar = tmp_path / "malicious.tar.gz"
    dest_dir = tmp_path / "extracted_tar"
    dest_dir.mkdir()

    # Create a malicious tar archive
    with tarfile.open(malicious_tar, "w:gz") as tf:
        tarinfo = tarfile.TarInfo(name="../../evil_script.py")
        payload = b"print('exploited')"
        tarinfo.size = len(payload)
        tf.addfile(tarinfo, io.BytesIO(payload))

    with pytest.raises(ZipSlipError) as exc_info:
        extract_archive_safely(str(malicious_tar), str(dest_dir))

    assert "Tar-Slip path traversal" in str(exc_info.value)
    assert not (tmp_path.parent / "evil_script.py").exists()


def test_safe_archive_extraction(tmp_path):
    """Legitimate archives extract successfully without errors."""
    safe_zip = tmp_path / "safe.zip"
    dest_dir = tmp_path / "safe_extracted"
    dest_dir.mkdir()

    with zipfile.ZipFile(safe_zip, "w") as zf:
        zf.writestr("src/main.py", "print('hello world')")
        zf.writestr("README.md", "# Test project")

    extract_archive_safely(str(safe_zip), str(dest_dir))

    assert (dest_dir / "src" / "main.py").exists()
    assert (dest_dir / "README.md").exists()
    assert (dest_dir / "src" / "main.py").read_text() == "print('hello world')"


# ---------------------------------------------------------------------------
# Mode 2: Local Path Ingestion & Directory Traversal Defense
# ---------------------------------------------------------------------------

def test_local_path_within_allowed_base(tmp_path):
    """Permitted directory within allowed bases is accepted."""
    allowed_dir = tmp_path / "projects" / "my_app"
    allowed_dir.mkdir(parents=True)

    result = validate_local_path(str(allowed_dir), allowed_bases=[str(tmp_path)])
    assert os.path.realpath(str(allowed_dir)) == result


def test_local_path_traversal_outside_allowed_base(tmp_path):
    """Attempting to scan outside allowed base must raise PathTraversalError."""
    allowed_dir = tmp_path / "allowed_folder"
    allowed_dir.mkdir()
    secret_dir = tmp_path / "system_secrets"
    secret_dir.mkdir()

    with pytest.raises(PathTraversalError):
        validate_local_path(str(secret_dir), allowed_bases=[str(allowed_dir)])


def test_local_path_nonexistent_or_file(tmp_path):
    """Non-existent path or pointing to a plain file raises PathTraversalError."""
    file_path = tmp_path / "sample.txt"
    file_path.write_text("not a directory")

    with pytest.raises(PathTraversalError):
        validate_local_path(str(file_path), allowed_bases=[str(tmp_path)])

    with pytest.raises(PathTraversalError):
        validate_local_path(str(tmp_path / "missing_folder"), allowed_bases=[str(tmp_path)])


# ---------------------------------------------------------------------------
# Mode 3: Git URL Ingestion & SSRF Protection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("invalid_scheme_url", [
    "http://github.com/repo/sample.git",
    "git://github.com/repo/sample.git",
    "ssh://git@github.com/repo/sample.git",
    "file:///etc/passwd",
    "ftp://ftp.example.com/repo.git",
])
def test_git_url_invalid_schemes_blocked(invalid_scheme_url):
    """Git URLs must strictly use https:// scheme."""
    with pytest.raises(SSRFProtectionError) as exc:
        validate_git_url_and_check_ssrf(invalid_scheme_url)
    assert "scheme" in str(exc.value).lower()


@pytest.mark.parametrize("dangerous_ip", [
    "127.0.0.1",        # IPv4 Loopback
    "127.0.1.1",        # Sub-loopback
    "10.0.0.5",         # RFC 1918 Private
    "172.16.0.1",       # RFC 1918 Private
    "192.168.1.100",    # RFC 1918 Private
    "169.254.169.254",  # AWS/GCP/Azure Metadata (Link-Local)
    "0.0.0.0",          # Unspecified
    "::1",              # IPv6 Loopback
    "::ffff:127.0.0.1", # IPv4-mapped IPv6 loopback
    "::ffff:10.0.0.1",  # IPv4-mapped IPv6 private
    "fc00::1",          # IPv6 Unique Local
    "fe80::1",          # IPv6 Link-Local
])
def test_git_ssrf_private_and_reserved_ips_blocked(dangerous_ip):
    """Hostname resolving to any private, loopback, or metadata IP must be blocked."""
    mock_addrinfo = [(2, 1, 6, "", (dangerous_ip, 443))]

    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        with pytest.raises(SSRFProtectionError) as exc:
            validate_git_url_and_check_ssrf("https://internal-service.local/repo.git")
        assert "restricted ip" in str(exc.value).lower() or "metadata" in str(exc.value).lower()


def test_git_ssrf_metadata_hostnames_blocked():
    """Reserved cloud metadata hostnames are blocked immediately."""
    with pytest.raises(SSRFProtectionError) as exc:
        validate_git_url_and_check_ssrf("https://metadata.google.internal/computeMetadata/v1")
    assert "reserved/metadata" in str(exc.value).lower()


def test_git_url_legitimate_public_ip_allowed():
    """Legitimate public IP address passes SSRF validation."""
    public_ip = "140.82.121.4"  # Public IP (GitHub)
    mock_addrinfo = [(2, 1, 6, "", (public_ip, 443))]

    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        # Should not raise exception
        validate_git_url_and_check_ssrf("https://github.com/legitimate/public-repo.git")


# ---------------------------------------------------------------------------
# Mode 4: Dockerfile Ingestion
# ---------------------------------------------------------------------------

def test_dockerfile_ingestion(tmp_path):
    """Dockerfile content is saved properly into target workspace."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    content = "FROM python:3.12-slim\nUSER appuser\nCMD ['python']"
    df_path = ingest_dockerfile(content, str(workspace))

    assert os.path.exists(df_path)
    assert os.path.basename(df_path) == "Dockerfile"
    with open(df_path, "r") as f:
        assert f.read() == content


# ---------------------------------------------------------------------------
# Workspace Lifecycle & Cleanup
# ---------------------------------------------------------------------------

def test_workspace_creation_and_cleanup(tmp_path):
    """Workspaces are created cleanly and purged safely upon cleanup."""
    job_id = "job-lifecycle-12345"
    base_dir = tmp_path / "workspaces"

    workspace = create_workspace(job_id, base_dir=str(base_dir))
    assert os.path.isdir(workspace)
    assert job_id in workspace

    cleaned = cleanup_workspace(workspace, base_dir=str(base_dir))
    assert cleaned is True
    assert not os.path.exists(workspace)
