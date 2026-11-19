"""Secure Project Ingestion Module for Secret Leak Guard v2.0.

Provides 4 secure ingestion modes:
1. Archive Uploads (.zip, .tar.gz, .tgz) with canonical Zip-Slip path traversal defense.
2. Local Path ingestion with strict directory traversal prevention and allowed roots whitelist.
3. Git URL ingestion with strict scheme validation and SSRF IP blocking (RFC 1918, link-local, loopback, metadata).
4. Dockerfile submission (raw content or file).
"""

import ipaddress
import os
import shutil
import socket
import subprocess
import tarfile
import tempfile
import urllib.parse
import zipfile
from typing import Any, List, Optional, Union


class IngestionError(Exception):
    """Base exception for ingestion errors."""
    pass


class ZipSlipError(IngestionError):
    """Raised when an archive member attempts a path traversal attack."""
    pass


class SSRFProtectionError(IngestionError):
    """Raised when a Git URL hostname resolves to a private, loopback, or reserved IP address."""
    pass


class PathTraversalError(IngestionError):
    """Raised when a local path violates permitted directory boundaries."""
    pass


class InvalidPayloadError(IngestionError):
    """Raised when input parameters or file formats are invalid."""
    pass


def create_workspace(job_id: str, base_dir: Optional[str] = None) -> str:
    """Creates an isolated temporary workspace directory for a scan job.
    
    Args:
        job_id: Unique identifier for the scan job.
        base_dir: Optional base directory; defaults to system temp or /tmp/scanner_workspaces.
        
    Returns:
        The canonical absolute path of the created workspace.
    """
    if not job_id or not str(job_id).isalnum() and not all(c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in str(job_id)):
        raise InvalidPayloadError("Invalid job_id: must contain only alphanumeric characters, dashes, or underscores.")

    if not base_dir:
        base_dir = (
            "/tmp/scanner_workspaces"
            if os.name != "nt"
            else os.path.join(tempfile.gettempdir(), "scanner_workspaces")
        )

    workspace_dir = os.path.realpath(os.path.join(base_dir, str(job_id)))
    os.makedirs(workspace_dir, exist_ok=True)
    return workspace_dir


def cleanup_workspace(workspace_dir: str, base_dir: Optional[str] = None) -> bool:
    """Safely cleans up an isolated temporary workspace directory.
    
    Ensures that the directory being deleted is truly inside the allowed temporary root.
    """
    if not workspace_dir or not os.path.exists(workspace_dir):
        return True

    real_path = os.path.realpath(workspace_dir)

    # Determine acceptable temp roots to prevent catastrophic deletions (e.g. '/' or 'C:\')
    if not base_dir:
        base_dir = (
            "/tmp/scanner_workspaces"
            if os.name != "nt"
            else os.path.join(tempfile.gettempdir(), "scanner_workspaces")
        )
    real_base = os.path.realpath(base_dir)

    # Guard: Workspace must be a subfolder of real_base or system tempdir
    sys_temp = os.path.realpath(tempfile.gettempdir())
    is_safe = (
        (real_path.startswith(real_base + os.sep) and real_path != real_base)
        or (real_path.startswith(sys_temp + os.sep) and real_path != sys_temp)
    )

    if not is_safe:
        raise PathTraversalError(f"Refusing to delete unsafe directory outside temp base: {real_path}")

    shutil.rmtree(real_path, ignore_errors=True)
    return not os.path.exists(real_path)


def extract_archive_safely(archive_path: str, target_dir: str) -> str:
    """Extracts .zip, .tar.gz, .tgz, or .tar archives with strict Zip-Slip protection.
    
    Enforces canonical path validation (os.path.realpath) on EVERY archive member before extraction.
    Throws ZipSlipError if any member resolves outside target_dir.
    """
    real_target_dir = os.path.realpath(target_dir)

    if not os.path.isfile(archive_path):
        raise InvalidPayloadError(f"Archive file does not exist: {archive_path}")

    lower_path = archive_path.lower()

    # Handle ZIP archives
    if lower_path.endswith(".zip"):
        with zipfile.ZipFile(archive_path, "r") as zf:
            for member in zf.infolist():
                member_name = member.filename
                # Construct destination path
                dest_path = os.path.realpath(os.path.join(real_target_dir, member_name))

                # Canonical path verification
                if not (dest_path == real_target_dir or dest_path.startswith(real_target_dir + os.sep)):
                    raise ZipSlipError(
                        f"Zip-Slip path traversal attack detected! Member '{member_name}' resolves to '{dest_path}'."
                    )

                if os.path.commonpath([real_target_dir, dest_path]) != real_target_dir:
                    raise ZipSlipError(
                        f"Zip-Slip path traversal attack detected! Member '{member_name}' resolves outside target."
                    )

                # Safe extraction
                zf.extract(member, path=real_target_dir)

        return real_target_dir

    # Handle TAR archives (.tar, .tar.gz, .tgz)
    elif lower_path.endswith((".tar.gz", ".tgz", ".tar")):
        mode = "r:gz" if lower_path.endswith((".tar.gz", ".tgz")) else "r:"
        with tarfile.open(archive_path, mode) as tf:
            for member in tf.getmembers():
                dest_path = os.path.realpath(os.path.join(real_target_dir, member.name))

                # Canonical path verification
                if not (dest_path == real_target_dir or dest_path.startswith(real_target_dir + os.sep)):
                    raise ZipSlipError(
                        f"Tar-Slip path traversal attack detected! Member '{member.name}' resolves to '{dest_path}'."
                    )

                if os.path.commonpath([real_target_dir, dest_path]) != real_target_dir:
                    raise ZipSlipError(
                        f"Tar-Slip path traversal attack detected! Member '{member.name}' resolves outside target."
                    )

                # Symlink / Hardlink traversal verification
                if member.islnk() or member.issym():
                    link_dest = os.path.realpath(
                        os.path.join(os.path.dirname(dest_path), member.linkname)
                    )
                    if not (link_dest == real_target_dir or link_dest.startswith(real_target_dir + os.sep)):
                        raise ZipSlipError(
                            f"Tar-Slip symlink traversal attack detected! Link '{member.name}' points outside target."
                        )

                # Extract member safely
                if hasattr(tarfile, "data_filter"):
                    tf.extract(member, path=real_target_dir, filter="data")
                else:
                    tf.extract(member, path=real_target_dir)

        return real_target_dir

    else:
        raise InvalidPayloadError(f"Unsupported archive format: {archive_path}")


def validate_local_path(input_path: str, allowed_bases: List[str]) -> str:
    """Validates a local filesystem path against allowed base directory roots.
    
    Prevents path traversal attacks (e.g. '../', null bytes, symlink escapes).
    """
    if not input_path or "\x00" in input_path:
        raise PathTraversalError("Invalid local path provided.")

    real_input = os.path.realpath(os.path.expanduser(input_path.strip()))

    if not os.path.exists(real_input):
        raise PathTraversalError(f"Local path does not exist: {input_path}")

    if not os.path.isdir(real_input):
        raise PathTraversalError(f"Local path must be a directory: {input_path}")

    # Check whether the path is contained within at least one allowed base
    matched_base = False
    for base in allowed_bases:
        real_base = os.path.realpath(os.path.expanduser(base.strip()))
        if real_input == real_base or real_input.startswith(real_base + os.sep):
            matched_base = True
            break

    if not matched_base:
        raise PathTraversalError(
            f"Access denied: Local path '{real_input}' is outside allowed base scan directories: {allowed_bases}"
        )

    return real_input


def validate_git_url_and_check_ssrf(url: str, allowed_schemes: tuple = ("https",)) -> None:
    """Validates a Git repository URL format and blocks SSRF attacks.
    
    Enforces:
    1. Scheme must be 'https://' (rejects file://, git://, ssh://, http://).
    2. Hostname must be present and valid.
    3. Hostname DNS resolution must NOT resolve to private (RFC 1918), loopback,
       link-local, cloud metadata, multicast, or reserved IPs.
    """
    if not url or not isinstance(url, str):
        raise InvalidPayloadError("Git URL is required.")

    parsed = urllib.parse.urlsplit(url.strip())
    if parsed.scheme.lower() not in allowed_schemes:
        raise SSRFProtectionError(
            f"Invalid Git URL scheme: '{parsed.scheme}'. Only 'https://' is permitted."
        )

    hostname = parsed.hostname
    if not hostname:
        raise SSRFProtectionError("Git URL must specify a valid hostname.")
    if parsed.username or parsed.password:
        raise SSRFProtectionError("Git URLs containing embedded credentials are not permitted.")
    try:
        port = parsed.port
    except ValueError as error:
        raise SSRFProtectionError("Git URL contains an invalid port.") from error
    if port not in (None, 443) or parsed.query or parsed.fragment:
        raise SSRFProtectionError("Git URLs must use the default HTTPS port and omit query/fragment data.")

    # Check for known dangerous cloud metadata hostnames directly
    dangerous_hosts = {"metadata.google.internal", "169.254.169.254", "instance-data", "localhost"}
    if hostname.lower() in dangerous_hosts:
        raise SSRFProtectionError(f"SSRF blocked: Hostname '{hostname}' is a reserved/metadata host.")

    # Resolve hostname to all associated IP addresses
    try:
        addr_infos = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise SSRFProtectionError(f"Failed to resolve Git URL hostname '{hostname}': {e}")

    if not addr_infos:
        raise SSRFProtectionError(f"Hostname '{hostname}' did not resolve to any IP address.")

    for addr in addr_infos:
        ip_str = addr[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            raise SSRFProtectionError(f"Resolved invalid IP address: {ip_str}")

        # Check for IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 or ::ffff:10.0.0.1)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped

        # Reject private, loopback, link-local, multicast, or reserved IP ranges
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise SSRFProtectionError(
                f"SSRF protection blocked access: Hostname '{hostname}' resolves to restricted IP '{ip_str}'."
            )


def clone_git_repo(url: str, target_dir: str, timeout_seconds: int = 60) -> str:
    """Clones a remote Git repository into target_dir after passing SSRF checks."""
    validate_git_url_and_check_ssrf(url)
    real_target = os.path.realpath(target_dir)

    cmd = ["git", "clone", "--depth", "1", "--config", "transfer.fsckObjects=true", url, real_target]
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        if result.returncode != 0:
            raise IngestionError(f"Git clone failed: {result.stderr.strip() or result.stdout.strip()}")
    except subprocess.TimeoutExpired:
        raise IngestionError(f"Git clone timed out after {timeout_seconds} seconds.")
    except Exception as e:
        raise IngestionError(f"Failed to clone Git repository: {str(e)}")

    return real_target


def ingest_dockerfile(content: Union[str, bytes], target_dir: str) -> str:
    """Saves submitted Dockerfile content into the isolated workspace."""
    if not content:
        raise InvalidPayloadError("Dockerfile content is empty.")

    real_target = os.path.realpath(target_dir)
    dockerfile_path = os.path.join(real_target, "Dockerfile")

    mode = "wb" if isinstance(content, bytes) else "w"
    encoding = None if isinstance(content, bytes) else "utf-8"

    with open(dockerfile_path, mode, encoding=encoding) as f:
        f.write(content)

    return dockerfile_path
