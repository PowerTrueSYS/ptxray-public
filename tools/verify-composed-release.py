#!/usr/bin/env python3
"""Validate PTxray's checked-in, release-bound public trust evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROOF = ROOT / "site" / "aixray-release-proof.json"
EXPECTED_SCHEMA_VERSION = 1
EXPECTED_COPY_STATUSES = {
    "Next step",
}
APPROVED_COPY_STATUS = "Next step"
EXPECTED_RELEASE_STATUS = "dormant_pending_release_gates"
EXPECTED_RELEASE = {
    "version": "0.1.0",
    "tag": "v0.1.0",
    "tag_commit": "d0587e17bc4fc387c11e8df317cc85e6aa8c2f4a",
    "scanner_sha256": "e098e0b0f617649ba29fbf1626fefb55bcd2b467c09060bdcb4458b1340e5b16",
}
EXPECTED_URLS = {
    "source": "https://github.com/PowerTrueSYS/ptxray-public/tree/v0.1.0",
    "security": "https://github.com/PowerTrueSYS/ptxray-public/blob/v0.1.0/SECURITY.md",
    "verify": "https://github.com/PowerTrueSYS/ptxray-public/blob/v0.1.0/docs/VERIFY.md",
    "catalog": "https://raw.githubusercontent.com/PowerTrueSYS/ptxray-public/v0.1.0/catalog.json",
    "scanner": "https://raw.githubusercontent.com/PowerTrueSYS/ptxray-public/v0.1.0/ptxray-aix.sh",
    "download": "https://github.com/PowerTrueSYS/ptxray-public/releases/download/v0.1.0/ptxray-aix.sh",
}
GITHUB_API_REPO = "https://api.github.com/repos/PowerTrueSYS/ptxray-public"
TAG_REF_REQUEST_URL = (
    f"{GITHUB_API_REPO}/git/ref/tags/{EXPECTED_RELEASE['tag']}"
)
TAG_REF_RESPONSE_URL = (
    f"{GITHUB_API_REPO}/git/refs/tags/{EXPECTED_RELEASE['tag']}"
)
MAX_GITHUB_API_RESPONSE_BYTES = 1024 * 1024
MAX_TAG_PEEL_DEPTH = 4
MAX_DOWNLOAD_BYTES = 32 * 1024 * 1024
DOWNLOAD_CHUNK_BYTES = 64 * 1024
MAX_WORKER_DIAGNOSTIC_CHARS = 4096
LIVE_WORKER_FLAG = "--_live-worker"
RELEASE_PAYLOADS = (
    "aixray-aix.sh",
    "aixray-scan.ksh",
    "ibmi-scan.ksh",
    "ptxray-defs.sh",
    "ptxray-review-pack.sh",
    "ptxray-review-validate.awk",
)
TAGGED_RELEASE_PAYLOADS = RELEASE_PAYLOADS
RELEASE_ASSET_ALIASES = {
    "aixray-aix.sh": "aixray-scan.ksh",
}
VERSIONED_RELEASE_PAYLOADS = {
    "aixray-scan.ksh": ("PTXRAY_RUNNER_VERSION", False),
    "ibmi-scan.ksh": ("PTXRAY_RUNNER_VERSION", False),
    "ptxray-defs.sh": ("PTXRAY_DEFS_VERSION", False),
    "ptxray-review-pack.sh": ("AIXRAY_REVIEW_PACK_VERSION", False),
}
RETIRED_MONOLITH_BASENAMES = frozenset(
    {
        "ptxray-aix.sh",
        "ptxray-ibmi.sh",
    }
)
RELEASE_MANIFEST_NAME = "SHA256SUMS"
RELEASE_SIGNATURE_NAME = "SHA256SUMS.sig"
RELEASE_PUBLIC_KEY_NAME = "POWERTRUE-RELEASE-PUBLIC.pem"
README_REPORT_NAME = "README-REPORT.md"
REPORT_BUNDLE_RUNNERS = {
    "aix": "dist/tools/aixray-scan.ksh",
    "ibmi": "dist/tools/ibmi-scan.ksh",
}
REPORT_BUNDLE_COMPOSE_METADATA = {
    "aix": "dist/compose/group-registry.tsv",
    "ibmi": "dist/compose/ibmi-group-registry.tsv",
}
REPORT_BUNDLE_CHECK_FRAGMENT_PREFIXES = {
    "aix": "dist/tools/ck-",
    "ibmi": "dist/ibmi/tools/ck-",
}
REPORT_BUNDLE_RENDER_PREFIX = "dist/render/"
RELEASE_ASSET_NAMES = {
    *RELEASE_PAYLOADS,
    RELEASE_MANIFEST_NAME,
    RELEASE_SIGNATURE_NAME,
    RELEASE_PUBLIC_KEY_NAME,
}
RELEASE_PUBLIC_KEY_FINGERPRINT = (
    "sha256:c2fa7dc69be3dead5e196eca6a9c48ece42a7105eb9f56ab9f620bd0c6c617bd"
)
OPENSSL = Path("/usr/bin/openssl")


def report_bundle_names(version: str) -> tuple[str, ...]:
    return (
        f"ptxray-report-aix-{version}.tar",
        f"ptxray-report-ibmi-{version}.tar",
    )


def release_payloads_for_version(version: str) -> tuple[str, ...]:
    return (*RELEASE_PAYLOADS, *report_bundle_names(version))


def release_asset_names_for_version(version: str) -> set[str]:
    return set(RELEASE_ASSET_NAMES) | set(report_bundle_names(version))


def report_bundle_kind(bundle_name: str) -> str:
    if bundle_name.startswith("ptxray-report-aix-") and bundle_name.endswith(".tar"):
        return "aix"
    if bundle_name.startswith("ptxray-report-ibmi-") and bundle_name.endswith(".tar"):
        return "ibmi"
    raise ProofError(f"unrecognized report bundle name: {bundle_name}")


def normalized_tar_regular_name(member: tarfile.TarInfo) -> str:
    name = member.name
    if name.startswith("./"):
        name = name[2:]
    if name.endswith("/"):
        name = name[:-1]
    if member.isfile() and name:
        return name
    return ""


def tar_regular_member_payloads(path: Path, label: str) -> dict[str, list[bytes]]:
    require_regular_nonsymlink(path, label)
    import importlib.util
    guard_path = ROOT / "tools/check-no-ibm-redistribution.py"
    require_regular_nonsymlink(guard_path, "IBM redistribution guard")
    guard_spec = importlib.util.spec_from_file_location("ibm_guard", guard_path)
    if guard_spec is None or guard_spec.loader is None:
        raise ProofError("IBM redistribution guard could not be loaded")
    guard = importlib.util.module_from_spec(guard_spec)
    # Verification must not dirty a clean release checkout with __pycache__.
    previous_bytecode = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        guard_spec.loader.exec_module(guard)
    except (OSError, ImportError, SyntaxError) as exc:
        raise ProofError("IBM redistribution guard could not be loaded") from exc
    finally:
        sys.dont_write_bytecode = previous_bytecode
    if not callable(getattr(guard, "blob_reasons", None)):
        raise ProofError("IBM redistribution guard has no blob validator")
    try:
        with tarfile.open(path, mode="r:") as archive:
            payloads: dict[str, list[bytes]] = {}
            for member in archive.getmembers():
                raw = member.name[2:] if member.name.startswith("./") else member.name
                parts = PurePosixPath(raw).parts
                if raw.startswith("/") or ".." in parts or "\\" in raw or raw.rstrip("/") != PurePosixPath(raw).as_posix():
                    raise ProofError(f"{label} contains unsafe member path {member.name}")
                if member.isdir():
                    continue
                if not member.isfile():
                    raise ProofError(f"{label} contains nonregular member {member.name}")
                name = normalized_tar_regular_name(member)
                if not name:
                    raise ProofError(f"{label} contains an empty member name")
                if name.rsplit("/", 1)[-1] in RETIRED_MONOLITH_BASENAMES:
                    raise ProofError(f"{label} contains retired monolith member {name}")
                if (member.mode & 0o111 or name.endswith((".sh", ".ksh", ".awk"))) and not (
                    name == "ptxray-defs.sh" or name.startswith(("dist/tools/", "dist/ibmi/tools/", "dist/compose/", "dist/render/", "dist/lib/"))
                ):
                    raise ProofError(f"{label} contains unexpected executable member {name}")
                handle = archive.extractfile(member)
                if handle is None:
                    raise ProofError(f"{label} member {name} is unreadable")
                content = handle.read()
                # Inspect archive members as well as tracked loose files: a tar
                # must not hide proprietary IBM delivery data from the index guard.
                reasons = guard.blob_reasons(name.encode(), content)
                if reasons:
                    raise ProofError(f"{label} contains IBM delivery data in {name}: {reasons[0]}")
                payloads.setdefault(name, []).append(content)
            return payloads
    except tarfile.TarError as exc:
        raise ProofError(f"{label} is not a readable uncompressed tar") from exc


def tar_regular_member_names(path: Path, label: str) -> set[str]:
    payloads = tar_regular_member_payloads(path, label)
    duplicates = sorted(
        name for name, items in payloads.items() if len(items) > 1
    )
    if duplicates:
        raise ProofError(f"{label} contains duplicate member {duplicates[0]}")
    return set(payloads)


def tar_regular_member_bytes(path: Path, member_name: str, label: str) -> bytes:
    payloads = tar_regular_member_payloads(path, label).get(member_name, [])
    if not payloads:
        raise ProofError(f"{label} is missing {member_name}")
    if len(payloads) > 1:
        raise ProofError(f"{label} contains duplicate member {member_name}")
    return payloads[0]


def validate_report_bundle(path: Path, bundle_name: str) -> None:
    label = f"report bundle {bundle_name}"
    payloads = tar_regular_member_payloads(path, label)
    readmes = payloads.get(README_REPORT_NAME, [])
    if not readmes:
        raise ProofError(
            f"report bundle {bundle_name} is missing {README_REPORT_NAME}"
        )
    for readme in readmes:
        if b"--monolith" in readme:
            raise ProofError(
                f"report bundle {bundle_name} {README_REPORT_NAME} advertises "
                "--monolith"
            )
    duplicates = sorted(
        name for name, items in payloads.items() if len(items) > 1
    )
    if duplicates:
        raise ProofError(f"{label} contains duplicate member {duplicates[0]}")
    names = set(payloads)
    kind = report_bundle_kind(bundle_name)
    runner = REPORT_BUNDLE_RUNNERS[kind]
    if runner not in names:
        raise ProofError(
            f"report bundle {bundle_name} is missing runner {runner}"
        )
    compose_metadata = REPORT_BUNDLE_COMPOSE_METADATA[kind]
    if compose_metadata not in names:
        raise ProofError(
            f"report bundle {bundle_name} is missing {compose_metadata}"
        )
    fragment_prefix = REPORT_BUNDLE_CHECK_FRAGMENT_PREFIXES[kind]
    if not any(
        name.startswith(fragment_prefix) and name.endswith(".ksh")
        for name in names
    ):
        raise ProofError(
            f"report bundle {bundle_name} is missing a "
            f"{fragment_prefix}*.ksh check fragment"
        )
    if not any(name.startswith(REPORT_BUNDLE_RENDER_PREFIX) for name in names):
        raise ProofError(
            f"report bundle {bundle_name} is missing a "
            f"{REPORT_BUNDLE_RENDER_PREFIX}* render entry"
        )
    retired = sorted(
        name
        for name in names
        if name.rsplit("/", 1)[-1] in RETIRED_MONOLITH_BASENAMES
    )
    if retired:
        raise ProofError(
            f"report bundle {bundle_name} contains retired monolith member "
            f"{retired[0]}"
        )


class ProofError(ValueError):
    """A release-proof or referenced-artifact validation failure."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProofError(f"duplicate JSON key: {key!r}")
        value[key] = item
    return value


def require_lowercase_sha(value: Any, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 40
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProofError(f"{label} must be an exact lowercase 40-hex SHA")
    return value


def validate_github_api_url(url: str) -> None:
    if url == TAG_REF_REQUEST_URL:
        return
    tag_object_prefix = f"{GITHUB_API_REPO}/git/tags/"
    if url.startswith(tag_object_prefix):
        require_lowercase_sha(
            url.removeprefix(tag_object_prefix),
            "GitHub tag object URL SHA",
        )
        return
    raise ProofError(f"refusing unexpected GitHub API URL: {url}")


def remaining_live_timeout(deadline: float, action: str) -> float:
    remaining = deadline - time.monotonic()
    if not math.isfinite(remaining) or remaining <= 0:
        raise ProofError(
            f"live verification deadline expired while {action}"
        )
    return remaining


def set_response_read_timeout(response: Any, timeout: float) -> None:
    """Refresh urllib's underlying socket timeout before a blocking read."""
    buffer = getattr(response, "fp", None)
    raw = getattr(buffer, "raw", None)
    socket = getattr(raw, "_sock", None)
    setter = getattr(socket, "settimeout", None)
    if not callable(setter):
        is_closed = getattr(response, "isclosed", None)
        if bool(getattr(response, "closed", False)) or (
            callable(is_closed) and is_closed()
        ):
            return
        raise ProofError("cannot enforce the live verification read deadline")
    try:
        setter(timeout)
    except (OSError, ValueError) as exc:
        raise ProofError(
            "cannot enforce the live verification read deadline"
        ) from exc


def read_live_chunk(
    response: Any,
    size: int,
    deadline: float,
    url: str,
) -> bytes:
    reader = getattr(response, "read1", None)
    if not callable(reader):
        raise ProofError(
            f"live response for {url} has no safe single-read primitive"
        )
    read_timeout = remaining_live_timeout(
        deadline,
        f"reading {url}",
    )
    set_response_read_timeout(response, read_timeout)
    chunk = reader(size)
    remaining_live_timeout(deadline, f"reading {url}")
    if type(chunk) is not bytes:
        raise ProofError(f"live response for {url} returned a non-bytes chunk")
    return chunk


def download_json(url: str, deadline: float) -> dict[str, Any]:
    validate_github_api_url(url)
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "aixray-release-proof-validator/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        request_timeout = remaining_live_timeout(
            deadline,
            f"requesting {url}",
        )
        with urllib.request.urlopen(
            request,
            timeout=request_timeout,
        ) as response:
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    declared_size = int(content_length)
                except ValueError as exc:
                    raise ProofError(
                        f"GitHub API returned an invalid Content-Length for {url}"
                    ) from exc
                if declared_size < 0:
                    raise ProofError(
                        f"GitHub API returned an invalid Content-Length for {url}"
                    )
                if declared_size > MAX_GITHUB_API_RESPONSE_BYTES:
                    raise ProofError(f"GitHub API response is too large for {url}")
            chunks = []
            total = 0
            while True:
                chunk = read_live_chunk(
                    response,
                    min(
                        DOWNLOAD_CHUNK_BYTES,
                        MAX_GITHUB_API_RESPONSE_BYTES + 1 - total,
                    ),
                    deadline,
                    url,
                )
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_GITHUB_API_RESPONSE_BYTES:
                    raise ProofError(
                        f"GitHub API response is too large for {url}"
                    )
                chunks.append(chunk)
            payload = b"".join(chunks)
    except ProofError:
        raise
    except (OSError, TimeoutError, urllib.error.URLError) as exc:
        raise ProofError(f"could not fetch GitHub API URL {url}: {exc}") from exc

    if len(payload) > MAX_GITHUB_API_RESPONSE_BYTES:
        raise ProofError(f"GitHub API response is too large for {url}")
    try:
        parsed = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProofError(f"GitHub API returned malformed JSON for {url}") from exc
    if type(parsed) is not dict:
        raise ProofError(f"GitHub API response must be an object for {url}")
    return parsed


def validate_git_target(
    target: Any,
    label: str,
) -> tuple[str, str]:
    if type(target) is not dict:
        raise ProofError(f"{label} must be an object")
    target_type = target.get("type")
    if target_type not in {"commit", "tag"}:
        raise ProofError(
            f"{label}.type must be commit or tag, got {target_type!r}"
        )
    sha = require_lowercase_sha(target.get("sha"), f"{label}.sha")
    collection = "commits" if target_type == "commit" else "tags"
    expected_url = f"{GITHUB_API_REPO}/git/{collection}/{sha}"
    if target.get("url") != expected_url:
        raise ProofError(f"{label}.url must be exactly {expected_url}")
    return target_type, sha


def resolve_live_tag_commit(
    proof: dict[str, Any],
    deadline: float,
) -> str:
    release = proof["release"]
    tag = release["tag"]
    ref = download_json(TAG_REF_REQUEST_URL, deadline)
    expected_ref = f"refs/tags/{tag}"
    if ref.get("ref") != expected_ref:
        raise ProofError(f"GitHub tag ref must be exactly {expected_ref}")
    if ref.get("url") != TAG_REF_RESPONSE_URL:
        raise ProofError(f"GitHub tag ref URL must be exactly {TAG_REF_RESPONSE_URL}")
    target_type, target_sha = validate_git_target(
        ref.get("object"),
        "GitHub tag ref object",
    )

    seen_tag_objects: set[str] = set()
    while target_type == "tag":
        if target_sha in seen_tag_objects:
            raise ProofError("GitHub annotated tag chain contains a cycle")
        if len(seen_tag_objects) >= MAX_TAG_PEEL_DEPTH:
            raise ProofError(
                f"GitHub annotated tag chain exceeds depth {MAX_TAG_PEEL_DEPTH}"
            )
        seen_tag_objects.add(target_sha)
        tag_url = f"{GITHUB_API_REPO}/git/tags/{target_sha}"
        tag_object = download_json(tag_url, deadline)
        object_sha = require_lowercase_sha(
            tag_object.get("sha"),
            "GitHub annotated tag SHA",
        )
        if object_sha != target_sha:
            raise ProofError(
                "GitHub annotated tag SHA does not match its requested URL"
            )
        if tag_object.get("url") != tag_url:
            raise ProofError(f"GitHub annotated tag URL must be exactly {tag_url}")
        if (
            type(tag_object.get("tag")) is not str
            or not tag_object["tag"]
        ):
            raise ProofError(
                "GitHub annotated tag name must be a non-empty string"
            )
        target_type, target_sha = validate_git_target(
            tag_object.get("object"),
            "GitHub annotated tag object",
        )

    expected_commit = release["tag_commit"]
    if target_sha != expected_commit:
        raise ProofError(
            "live GitHub tag commit does not match release.tag_commit "
            f"(expected {expected_commit}, got {target_sha})"
        )
    return target_sha


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ProofError(f"cannot read {label} {path}: {exc}") from exc
    try:
        value = json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise ProofError(
            f"{label} {path} is not valid JSON: line {exc.lineno}, "
            f"column {exc.colno}: {exc.msg}"
        ) from exc
    if type(value) is not dict:
        raise ProofError(f"{label} root must be a JSON object")
    return value


def require_exact_keys(
    value: dict[str, Any],
    expected: set[str],
    label: str,
) -> None:
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if extra:
            details.append(f"unexpected {', '.join(extra)}")
        raise ProofError(f"{label} keys are invalid: {'; '.join(details)}")


def require_type(value: Any, expected_type: type, label: str) -> None:
    if type(value) is not expected_type:
        raise ProofError(
            f"{label} must be {expected_type.__name__}, "
            f"got {type(value).__name__}"
        )


def validate_url(name: str, value: Any, tag: str) -> None:
    require_type(value, str, f"urls.{name}")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ProofError(f"urls.{name} is malformed: {exc}") from exc
    if parsed.scheme != "https":
        raise ProofError(f"urls.{name} must use https")
    if parsed.hostname not in {"github.com", "raw.githubusercontent.com"}:
        raise ProofError(f"urls.{name} uses a non-official host")
    if (
        parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ProofError(
            f"urls.{name} must not contain credentials, a port, query, or fragment"
        )
    if not parsed.path.startswith("/PowerTrueSYS/ptxray-public/"):
        raise ProofError(
            f"urls.{name} must point into PowerTrueSYS/ptxray-public"
        )
    if "/latest" in parsed.path:
        raise ProofError(f"urls.{name} must not use a moving latest URL")
    if f"/{tag}" not in parsed.path:
        raise ProofError(f"urls.{name} is not bound to release tag {tag}")
    expected = EXPECTED_URLS[name]
    if value != expected:
        raise ProofError(
            f"urls.{name} does not match the pinned release URL; "
            f"expected {expected}"
        )


def validate_proof(proof: dict[str, Any]) -> None:
    require_exact_keys(
        proof,
        {"schema_version", "copy_status", "release_status", "release", "urls"},
        "proof",
    )
    require_type(proof["schema_version"], int, "schema_version")
    if proof["schema_version"] != EXPECTED_SCHEMA_VERSION:
        raise ProofError(
            f"schema_version must be {EXPECTED_SCHEMA_VERSION}, "
            f"got {proof['schema_version']!r}"
        )

    require_type(proof["copy_status"], str, "copy_status")
    if proof["copy_status"] not in EXPECTED_COPY_STATUSES:
        raise ProofError(
            f"copy_status is {proof['copy_status']!r}; "
            f"must be {APPROVED_COPY_STATUS!r}"
        )
    require_type(proof["release_status"], str, "release_status")
    if proof["release_status"] != EXPECTED_RELEASE_STATUS:
        raise ProofError(
            f"release_status must be {EXPECTED_RELEASE_STATUS!r}"
        )

    release = proof["release"]
    require_type(release, dict, "release")
    require_exact_keys(
        release,
        set(EXPECTED_RELEASE) | {"standalone_count"},
        "release",
    )
    for name, expected in EXPECTED_RELEASE.items():
        require_type(release[name], type(expected), f"release.{name}")
        if release[name] != expected:
            raise ProofError(
                f"release.{name} must be {expected!r}, got {release[name]!r}"
            )
    require_type(release["standalone_count"], int, "release.standalone_count")
    if release["standalone_count"] <= 0:
        raise ProofError("release.standalone_count must be a positive integer")
    digest = release["scanner_sha256"]
    if len(digest) != 64 or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise ProofError(
            "release.scanner_sha256 must be 64 lowercase hexadecimal characters"
        )

    urls = proof["urls"]
    require_type(urls, dict, "urls")
    require_exact_keys(urls, set(EXPECTED_URLS), "urls")
    for name, value in urls.items():
        validate_url(name, value, release["tag"])


def validate_catalog(path: Path, release: dict[str, Any]) -> None:
    catalog = load_json(path, "catalog")
    for name, expected_type in (
        ("schema_version", int),
        ("tool_version", str),
        ("check_count", int),
        ("checks", list),
    ):
        if name not in catalog:
            raise ProofError(f"catalog is missing {name}")
        require_type(catalog[name], expected_type, f"catalog.{name}")

    if catalog["schema_version"] != 1:
        raise ProofError(
            f"catalog.schema_version must be 1, got {catalog['schema_version']!r}"
        )
    if catalog["tool_version"] != release["version"]:
        raise ProofError(
            "catalog.tool_version does not match release.version: "
            f"{catalog['tool_version']!r} != {release['version']!r}"
        )
    if catalog["check_count"] != release["standalone_count"]:
        raise ProofError(
            "catalog.check_count does not match release.standalone_count: "
            f"{catalog['check_count']!r} != {release['standalone_count']!r}"
        )
    if len(catalog["checks"]) != catalog["check_count"]:
        raise ProofError(
            "catalog.checks length does not match catalog.check_count: "
            f"{len(catalog['checks'])} != {catalog['check_count']}"
        )

    seen_ids: set[str] = set()
    for index, check in enumerate(catalog["checks"]):
        require_type(check, dict, f"catalog.checks[{index}]")
        check_id = check.get("id")
        require_type(check_id, str, f"catalog.checks[{index}].id")
        if not check_id:
            raise ProofError(f"catalog.checks[{index}].id must not be empty")
        if check_id in seen_ids:
            raise ProofError(f"catalog contains duplicate check id {check_id!r}")
        seen_ids.add(check_id)
        if check.get("read_only") is not True:
            raise ProofError(
                f"catalog check {check_id!r} is not explicitly read_only true"
            )
        if check.get("requires_root") is not True:
            raise ProofError(
                f"catalog check {check_id!r} is not explicitly requires_root true"
            )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(DOWNLOAD_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as exc:
        raise ProofError(f"cannot read scanner {path}: {exc}") from exc
    return digest.hexdigest()


def sha256_release_file(path: Path, label: str) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(DOWNLOAD_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as exc:
        raise ProofError(f"cannot read {label} {path}: {exc}") from exc
    return digest.hexdigest()


def load_release_manifest(
    path: Path,
    expected_payloads: tuple[str, ...],
) -> list[tuple[str, str]]:
    if path.is_symlink() or not path.is_file():
        raise ProofError(
            f"release manifest is not a regular nonsymlink file: {path}"
        )
    try:
        raw = path.read_bytes()
    except (OSError, UnicodeError) as exc:
        raise ProofError(f"cannot read release manifest {path}: {exc}") from exc
    if not raw or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise ProofError("release manifest must be nonempty LF-terminated ASCII")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ProofError("release manifest must be ASCII") from exc

    entries: list[tuple[str, str]] = []
    seen_paths: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        digest, separator, relative = line.partition("  ")
        if (
            not separator
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not relative
        ):
            raise ProofError(
                f"invalid release manifest line {line_number}: {line!r}"
            )
        if relative in seen_paths:
            raise ProofError(f"duplicate release manifest path: {relative}")
        manifest_path = PurePosixPath(relative)
        if (
            manifest_path.is_absolute()
            or relative in {"", "."}
            or ".." in manifest_path.parts
            or "\\" in relative
        ):
            raise ProofError(f"unsafe release manifest path: {relative}")
        seen_paths.add(relative)
        entries.append((relative, digest))
    paths = [relative for relative, _digest in entries]
    if paths != sorted(paths, key=lambda value: value.encode("ascii")):
        raise ProofError("release manifest paths are not sorted bytewise")
    expected_paths = sorted(
        expected_payloads,
        key=lambda value: value.encode("ascii"),
    )
    if paths != expected_paths:
        raise ProofError(
            "release manifest payload paths are not exact; expected "
            + ", ".join(expected_paths)
        )
    return entries


def require_regular_nonsymlink(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise ProofError(f"{label} is not a regular nonsymlink file")


def require_same_bytes(left: Path, right: Path, message: str) -> None:
    try:
        left_bytes = left.read_bytes()
        right_bytes = right.read_bytes()
    except OSError as exc:
        raise ProofError(f"cannot compare signed release files: {exc}") from exc
    if left_bytes != right_bytes:
        raise ProofError(message)


def validate_release_public_key(public_key: Path) -> None:
    require_regular_nonsymlink(public_key, "release public key")
    if OPENSSL.is_symlink() or not OPENSSL.is_file():
        raise ProofError(f"required OpenSSL is unavailable: {OPENSSL}")
    try:
        result = subprocess.run(
            [
                str(OPENSSL),
                "pkey",
                "-pubin",
                "-in",
                str(public_key),
                "-outform",
                "DER",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
    except OSError as exc:
        raise ProofError("could not inspect release public key") from exc
    if result.returncode != 0 or not result.stdout or len(result.stdout) > 4096:
        raise ProofError("release public key is invalid")
    fingerprint = "sha256:" + hashlib.sha256(result.stdout).hexdigest()
    if fingerprint != RELEASE_PUBLIC_KEY_FINGERPRINT:
        raise ProofError(
            "release public key fingerprint mismatch: "
            f"expected {RELEASE_PUBLIC_KEY_FINGERPRINT}, got {fingerprint}"
        )


def validate_release_signature(
    manifest: Path,
    signature: Path,
    public_key: Path,
) -> None:
    require_regular_nonsymlink(signature, "release signature")
    try:
        result = subprocess.run(
            [
                str(OPENSSL),
                "dgst",
                "-sha256",
                "-verify",
                str(public_key),
                "-signature",
                str(signature),
                str(manifest),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
    except OSError as exc:
        raise ProofError("could not verify SHA256SUMS signature") from exc
    if result.returncode != 0:
        raise ProofError("SHA256SUMS signature is invalid")


def validate_tagged_payload_digests(
    recorded: dict[str, str],
    tagged_tree: Path,
    payloads: tuple[str, ...],
) -> None:
    for relative in payloads:
        tagged_path = tagged_tree / relative
        require_regular_nonsymlink(
            tagged_path,
            f"tagged payload {relative}",
        )
        actual = sha256_release_file(tagged_path, f"tagged payload {relative}")
        expected = recorded[relative]
        if actual != expected:
            raise ProofError(
                f"tagged payload SHA-256 mismatch for {relative}: "
                f"expected {expected}, got {actual}"
            )


def payload_version(
    path: Path,
    variable: str,
    *,
    allow_unquoted: bool,
) -> str:
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise ProofError(f"cannot read versioned payload {path}: {exc}") from exc
    try:
        shell_text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProofError(f"versioned payload is not UTF-8: {path.name}") from exc
    shell_text = remove_shell_line_continuations(shell_text)
    lexer = shlex.shlex(
        shell_text,
        posix=True,
        punctuation_chars=";&|()<>",
    )
    lexer.whitespace_split = True
    lexer.commenters = "#"
    assignments = []
    bare_references = 0
    assignment_pattern = re.compile(
        re.escape(variable) + r"(?:\[[^\]\r\n]*\])?\+?=(.*)\Z",
        re.DOTALL,
    )
    try:
        for token in lexer:
            assignment = assignment_pattern.fullmatch(token)
            if assignment is not None:
                assignments.append(assignment.group(1))
            elif token == variable:
                bare_references += 1
    except ValueError as exc:
        raise ProofError(
            f"cannot lex versioned payload {path.name}: {exc}"
        ) from exc
    if len(assignments) != 1 or bare_references:
        raise ProofError(
            f"{path.name} must contain exactly one {variable} assignment"
        )
    quoted = re.findall(
        rb"(?m)^"
        + re.escape(variable.encode("ascii"))
        + rb'=["\']([^"\']+)["\'][ \t]*$',
        content,
    )
    unquoted: list[bytes] = []
    if allow_unquoted:
        unquoted = re.findall(
            rb"(?m)^"
            + re.escape(variable.encode("ascii"))
            + rb"=([0-9][0-9A-Za-z.+-]*)[ \t]*$",
            content,
        )
    matches = quoted + unquoted
    if len(matches) != 1:
        raise ProofError(
            f"{path.name} must contain exactly one {variable} declaration"
        )
    try:
        version = matches[0].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ProofError(
            f"{path.name} contains a non-ASCII {variable} declaration"
        ) from exc
    if assignments[0] != version:
        raise ProofError(
            f"{path.name} {variable} declaration is lexically ambiguous"
        )
    return version


def remove_shell_line_continuations(shell_text: str) -> str:
    """Apply the shell's pre-tokenization backslash-newline removal."""
    output = []
    quote = ""
    comment = False
    word_started = False
    index = 0
    while index < len(shell_text):
        character = shell_text[index]
        following = shell_text[index + 1] if index + 1 < len(shell_text) else ""

        if comment:
            if character == "\\" and following == "\n":
                index += 2
                continue
            output.append(character)
            index += 1
            if character == "\n":
                comment = False
                word_started = False
            continue

        if quote == "'":
            output.append(character)
            index += 1
            if character == "'":
                quote = ""
            continue

        if quote == '"':
            if character == "\\" and following == "\n":
                index += 2
                continue
            output.append(character)
            index += 1
            if character == "\\" and following:
                output.append(following)
                index += 1
            elif character == '"':
                quote = ""
            continue

        if character == "\\" and following == "\n":
            index += 2
            continue
        if character == "\\" and following:
            output.extend((character, following))
            index += 2
            word_started = True
            continue
        if character in "'\"":
            quote = character
            output.append(character)
            index += 1
            word_started = True
            continue
        if character == "#" and not word_started:
            comment = True
            output.append(character)
            index += 1
            continue
        output.append(character)
        index += 1
        if character.isspace() or character in ";&|()<>":
            word_started = False
        else:
            word_started = True
    return "".join(output)


def validate_payload_versions(tag: str, tagged_tree: Path) -> None:
    expected = tag[1:]
    mismatches = []
    for relative, (variable, allow_unquoted) in VERSIONED_RELEASE_PAYLOADS.items():
        version = payload_version(
            tagged_tree / relative,
            variable,
            allow_unquoted=allow_unquoted,
        )
        if version != expected:
            mismatches.append(f"{relative}:{variable}={version}")
    if mismatches:
        raise ProofError(
            f"release tag {tag} does not match payload versions: "
            + ", ".join(mismatches)
        )


def validate_release_manifest_mode(args: argparse.Namespace) -> int:
    if re.fullmatch(r"v[0-9][0-9A-Za-z.+-]*", args.tag) is None:
        raise ProofError(
            "release tag must match v followed by a version"
        )
    if args.release_assets.is_symlink() or not args.release_assets.is_dir():
        raise ProofError("release asset directory is not a real directory")
    if args.tagged_tree.is_symlink() or not args.tagged_tree.is_dir():
        raise ProofError("tagged tree is not a real directory")
    try:
        asset_names = {
            asset.name for asset in args.release_assets.iterdir()
        }
    except OSError as exc:
        raise ProofError(
            f"cannot list release assets {args.release_assets}: {exc}"
        ) from exc
    version = args.tag[1:]
    payloads = release_payloads_for_version(version)
    expected_asset_names = release_asset_names_for_version(version)
    if args.unsigned_preparation:
        expected_asset_names.remove(RELEASE_SIGNATURE_NAME)
    missing_assets = sorted(expected_asset_names - asset_names)
    if missing_assets:
        raise ProofError(
            f"required release asset is missing: {missing_assets[0]}"
        )
    unexpected_assets = sorted(asset_names - expected_asset_names)
    if unexpected_assets:
        raise ProofError(f"unexpected release asset: {unexpected_assets[0]}")
    for asset_name in sorted(expected_asset_names):
        asset_path = args.release_assets / asset_name
        if asset_path.is_symlink() or (
            asset_path.exists() and not asset_path.is_file()
        ):
            raise ProofError(
                "release asset is not a regular nonsymlink file: "
                f"{asset_name}"
            )
    for bundle_name in report_bundle_names(version):
        validate_report_bundle(
            args.release_assets / bundle_name,
            bundle_name,
        )
        validate_report_bundle(
            args.tagged_tree / bundle_name,
            bundle_name,
        )

    tagged_manifest = args.tagged_tree / RELEASE_MANIFEST_NAME
    tagged_public_key = args.tagged_tree / RELEASE_PUBLIC_KEY_NAME
    for path, label in (
        (tagged_manifest, f"tagged {RELEASE_MANIFEST_NAME}"),
        (tagged_public_key, f"tagged {RELEASE_PUBLIC_KEY_NAME}"),
    ):
        require_regular_nonsymlink(path, label)

    asset_manifest = args.release_assets / RELEASE_MANIFEST_NAME
    asset_public_key = args.release_assets / RELEASE_PUBLIC_KEY_NAME
    require_same_bytes(
        args.release_manifest,
        asset_manifest,
        "release manifest argument differs from downloaded SHA256SUMS asset",
    )
    require_same_bytes(
        args.release_manifest,
        tagged_manifest,
        "release manifest differs from tagged SHA256SUMS",
    )
    require_same_bytes(
        asset_public_key,
        tagged_public_key,
        "release public key differs from tagged POWERTRUE-RELEASE-PUBLIC.pem",
    )

    entries = load_release_manifest(args.release_manifest, payloads)
    recorded = dict(entries)
    validate_release_public_key(asset_public_key)
    if args.unsigned_preparation:
        tagged_signature = args.tagged_tree / RELEASE_SIGNATURE_NAME
        if tagged_signature.exists() or tagged_signature.is_symlink():
            raise ProofError(
                "unsigned preparation contains tagged SHA256SUMS.sig"
            )
    else:
        tagged_signature = args.tagged_tree / RELEASE_SIGNATURE_NAME
        require_regular_nonsymlink(
            tagged_signature,
            f"tagged {RELEASE_SIGNATURE_NAME}",
        )
        asset_signature = args.release_assets / RELEASE_SIGNATURE_NAME
        require_same_bytes(
            asset_signature,
            tagged_signature,
            "release signature differs from tagged SHA256SUMS.sig",
        )
        validate_release_signature(
            args.release_manifest,
            asset_signature,
            asset_public_key,
        )
    validate_tagged_payload_digests(recorded, args.tagged_tree, payloads)
    validate_payload_versions(args.tag, args.tagged_tree)

    for relative in payloads:
        expected = recorded[relative]
        actual = sha256_release_file(
            args.release_assets / relative,
            f"release asset {relative}",
        )
        if relative in RELEASE_ASSET_ALIASES:
            target = RELEASE_ASSET_ALIASES[relative]
            if actual != recorded[target]:
                raise ProofError(
                    f"release alias asset {relative} is not a byte copy of {target}: "
                    f"expected {recorded[target]}, got {actual}"
                )
        if actual != expected:
            raise ProofError(
                f"release asset SHA-256 mismatch for {relative}: "
                f"expected {expected}, got {actual}"
            )
    return len(entries)


def validate_scanner(
    path: Path,
    release: dict[str, Any],
    label: str = "scanner",
) -> None:
    actual = sha256_file(path)
    expected = release["scanner_sha256"]
    if actual != expected:
        raise ProofError(
            f"{label} SHA-256 mismatch for {path}: "
            f"expected {expected}, got {actual}"
        )


def download_to(url: str, destination: Path, deadline: float) -> None:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/octet-stream",
            "User-Agent": "aixray-release-proof-validator/1",
        },
    )
    try:
        request_timeout = remaining_live_timeout(
            deadline,
            f"requesting {url}",
        )
        with urllib.request.urlopen(
            request,
            timeout=request_timeout,
        ) as response:
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    declared_size = int(content_length)
                except ValueError as exc:
                    raise ProofError(
                        f"live response for {url} has invalid Content-Length"
                    ) from exc
                if declared_size < 0:
                    raise ProofError(
                        f"live response for {url} has invalid Content-Length"
                    )
                if declared_size > MAX_DOWNLOAD_BYTES:
                    raise ProofError(
                        f"live response for {url} exceeds "
                        f"{MAX_DOWNLOAD_BYTES} bytes"
                    )
            total = 0
            with destination.open("wb") as output:
                while True:
                    chunk = read_live_chunk(
                        response,
                        DOWNLOAD_CHUNK_BYTES,
                        deadline,
                        url,
                    )
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_DOWNLOAD_BYTES:
                        raise ProofError(
                            f"live response for {url} exceeds "
                            f"{MAX_DOWNLOAD_BYTES} bytes"
                        )
                    output.write(chunk)
    except ProofError:
        raise
    except (OSError, TimeoutError, urllib.error.URLError) as exc:
        raise ProofError(f"live download failed for {url}: {exc}") from exc


def validate_live(proof: dict[str, Any], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    remaining_live_timeout(deadline, "starting GitHub tag resolution")
    resolve_live_tag_commit(proof, deadline)
    with tempfile.TemporaryDirectory(prefix="aixray-release-proof-") as directory:
        temporary = Path(directory)
        catalog_path = temporary / "catalog.json"
        scanner_path = temporary / "tag-aixray-aix.sh"
        release_asset_path = temporary / "release-asset-aixray-aix.sh"
        for url, destination, label in (
            (proof["urls"]["catalog"], catalog_path, "catalog download"),
            (proof["urls"]["scanner"], scanner_path, "tag scanner download"),
            (
                proof["urls"]["download"],
                release_asset_path,
                "release asset download",
            ),
        ):
            remaining_live_timeout(deadline, f"starting {label}")
            download_to(url, destination, deadline)
        validate_catalog(catalog_path, proof["release"])
        validate_scanner(scanner_path, proof["release"], "tag scanner")
        validate_scanner(
            release_asset_path,
            proof["release"],
            "release asset",
        )


def build_live_worker_command(
    proof_path: Path,
    timeout: float,
) -> list[str]:
    return [
        sys.executable,
        str(Path(__file__).resolve()),
        "--proof",
        str(proof_path),
        f"--timeout={timeout:.17g}",
        "--live",
        LIVE_WORKER_FLAG,
    ]


def bounded_worker_diagnostic(stdout: str, stderr: str) -> str:
    detail = stderr.strip() or stdout.strip()
    if not detail:
        return "worker exited without a diagnostic"
    if len(detail) > MAX_WORKER_DIAGNOSTIC_CHARS:
        return (
            detail[:MAX_WORKER_DIAGNOSTIC_CHARS]
            + "… [worker diagnostic truncated]"
        )
    return detail


def run_supervised_live(proof_path: Path, timeout: float) -> None:
    started = time.monotonic()
    command = build_live_worker_command(proof_path, timeout)
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as exc:
        raise ProofError(f"could not start live verification worker: {exc}") from exc

    remaining = timeout - (time.monotonic() - started)
    try:
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, timeout)
        stdout, stderr = process.communicate(timeout=remaining)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()
        raise ProofError(
            f"live verification deadline of {timeout:g} seconds expired; "
            "worker was killed and reaped"
        )
    except OSError as exc:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        process.communicate()
        raise ProofError(f"live verification worker I/O failed: {exc}") from exc

    if process.returncode != 0:
        raise ProofError(
            "live verification worker failed: "
            f"{bounded_worker_diagnostic(stdout, stderr)}"
        )
    if stdout.strip() or stderr.strip():
        raise ProofError(
            "live verification worker returned unexpected output: "
            f"{bounded_worker_diagnostic(stdout, stderr)}"
        )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate the pinned PTxray release proof. Network access occurs "
            "only when --live is supplied."
        )
    )
    parser.add_argument(
        "--proof",
        type=Path,
        default=DEFAULT_PROOF,
        help=f"proof JSON path (default: {DEFAULT_PROOF})",
    )
    parser.add_argument(
        "--catalog",
        type=Path,
        help="optional local catalog.json to compare with the proof",
    )
    parser.add_argument(
        "--scanner",
        type=Path,
        help="optional local scanner file to hash and compare with the proof",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help=(
            "explicitly download and validate the immutable tag catalog, "
            "tag scanner, and exact release asset"
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="overall live verification deadline in seconds (default: 15)",
    )
    parser.add_argument(
        "--require-approved-copy",
        action="store_true",
        help="fail unless copy_status records approved John sign-off",
    )
    parser.add_argument(
        "--release-manifest",
        type=Path,
        help="downloaded SHA256SUMS release asset to validate",
    )
    parser.add_argument(
        "--tagged-tree",
        type=Path,
        help="fresh checkout of the published tag",
    )
    parser.add_argument(
        "--release-assets",
        type=Path,
        help="directory containing freshly downloaded release assets",
    )
    parser.add_argument(
        "--tag",
        help="published release tag for manifest-mode diagnostics",
    )
    parser.add_argument(
        "--unsigned-preparation",
        action="store_true",
        help=(
            "validate the exact local ten-file candidate before offline "
            "signing; never valid for publication"
        ),
    )
    parser.add_argument(
        LIVE_WORKER_FLAG,
        action="store_true",
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args(argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be finite and greater than zero")
    if args._live_worker and not args.live:
        parser.error(f"{LIVE_WORKER_FLAG} requires --live")
    manifest_values = (
        args.release_manifest,
        args.tagged_tree,
        args.release_assets,
        args.tag,
    )
    args.manifest_mode = any(value is not None for value in manifest_values)
    if args.manifest_mode and not all(
        value is not None for value in manifest_values
    ):
        parser.error(
            "--release-manifest, --tagged-tree, --release-assets, and --tag "
            "must be supplied together"
        )
    if args.manifest_mode and (
        args.catalog is not None
        or args.scanner is not None
        or args.live
        or args.require_approved_copy
        or args._live_worker
    ):
        parser.error(
            "release-manifest mode cannot be combined with pinned-proof options"
        )
    if args.unsigned_preparation and not args.manifest_mode:
        parser.error("--unsigned-preparation requires release-manifest mode")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.manifest_mode:
        try:
            output_count = validate_release_manifest_mode(args)
        except ProofError as exc:
            print(f"release manifest proof: FAIL: {exc}", file=sys.stderr)
            return 1
        asset_count = len(release_asset_names_for_version(args.tag[1:]))
        if args.unsigned_preparation:
            print(
                "unsigned release preparation: PASS — "
                f"{args.tag}, {output_count} payloads, "
                f"{asset_count - 1} files"
            )
        else:
            print(
                "release manifest proof: PASS — "
                f"{args.tag}, {output_count} signed payloads, "
                f"{asset_count} release assets"
            )
        return 0
    try:
        proof = load_json(args.proof, "release proof")
        validate_proof(proof)
        if args.require_approved_copy and (
            proof["copy_status"] != APPROVED_COPY_STATUS
        ):
            raise ProofError(
                f"copy status is {proof['copy_status']!r}; "
                f"--require-approved-copy requires {APPROVED_COPY_STATUS!r}"
            )
        if args.catalog is not None:
            validate_catalog(args.catalog, proof["release"])
        if args.scanner is not None:
            validate_scanner(args.scanner, proof["release"])
        if args.live:
            if args._live_worker:
                validate_live(proof, args.timeout)
            else:
                run_supervised_live(args.proof, args.timeout)
    except ProofError as exc:
        label = (
            "release proof worker"
            if args._live_worker
            else "release proof"
        )
        print(f"{label}: FAIL: {exc}", file=sys.stderr)
        return 1

    if not args._live_worker:
        print(
            "release proof: PASS — "
            f"{proof['release']['tag']}, "
            f"{proof['release']['standalone_count']} standalone checks, "
            f"scanner SHA-256 {proof['release']['scanner_sha256']}; "
            f"copy {proof['copy_status']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
