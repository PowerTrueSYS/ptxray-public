#!/usr/bin/env python3
"""Render customer-facing release shape from catalog.json."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
import tempfile


COUNT_CLAIM_TARGETS = {
    "README.md": 1,
    "ptxray.jsonld": 1,
    "llms.txt": 1,
    "site/index.html": 2,
}
COUNT_PROPERTY_TARGETS = {
    "ptxray.jsonld": 1,
    "site/index.html": 1,
}
PUBLISHED_VERSION_CLAIM_TARGETS = {
    "README.md": 3,
    "llms.txt": 3,
    "site/index.html": 3,
}
CANDIDATE_VERSION_CLAIM_TARGETS = {
    "README.md": 0,
    "llms.txt": 1,
    "site/index.html": 0,
}
VERSION_PROPERTY_TARGETS = {
    "ptxray.jsonld": 1,
    "site/index.html": 1,
}
COUNT_CLAIM_RE = re.compile(
    r"\b[1-9][0-9]*(?=\s+standalone\b)",
    re.IGNORECASE,
)
COUNT_PROPERTY_RE = re.compile(
    r'("name"\s*:\s*"standaloneCheckCount"\s*,\s*'
    r'"value"\s*:\s*)[1-9][0-9]*'
)
VERSION_VALUE_PATTERN = (
    r"[0-9]+(?:\.[0-9A-Za-z-]+)+"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
VERSION_RE = re.compile(rf"{VERSION_VALUE_PATTERN}\Z")
VERSION_CLAIM_RE = re.compile(
    rf"(\bversion(?:\s*:\s*|\s+)`?){VERSION_VALUE_PATTERN}(`?)",
    re.IGNORECASE,
)
CANDIDATE_VERSION_CLAIM_RE = re.compile(
    rf"(\bcandidate version(?:\s*:\s*|\s+)`?){VERSION_VALUE_PATTERN}(`?)",
    re.IGNORECASE,
)
VERSION_PROPERTY_RE = re.compile(
    r'("softwareVersion"\s*:\s*")[^"\r\n]+(")'
)
CANDIDATE_STATUS_RE = re.compile(
    r'data-release-status="unpublished-([0-9]+\.[0-9]+)-release-candidate"'
)


class ShapeError(Exception):
    """A release-shape input or customer-copy structure is invalid."""


def declared_release_shape(root: Path) -> tuple[int, str]:
    catalog_path = root / "catalog.json"
    try:
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ShapeError(f"cannot read catalog.json: {exc}") from exc
    if not isinstance(catalog, dict):
        raise ShapeError("catalog.json root must be an object")
    count = catalog.get("check_count")
    if type(count) is not int or count < 1:
        raise ShapeError(
            f"catalog.json check_count must be a positive integer; found {count!r}"
        )
    version = catalog.get("tool_version")
    if not isinstance(version, str) or VERSION_RE.fullmatch(version) is None:
        raise ShapeError(
            "catalog.json tool_version must be a dotted version string; "
            f"found {version!r}"
        )
    return count, version


def release_channel(root: Path, version: str) -> str:
    """Return the explicit customer-copy channel for this candidate tree."""
    site_path = root / "site/index.html"
    try:
        site = site_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ShapeError(f"cannot read site/index.html: {exc}") from exc
    candidate_series = CANDIDATE_STATUS_RE.findall(site)
    if not candidate_series:
        return "published"
    if len(candidate_series) != 1:
        raise ShapeError(
            "site/index.html must contain exactly one unpublished-candidate "
            f"status marker; found {len(candidate_series)}"
        )
    declared_series = ".".join(version.split(".", 2)[:2])
    if candidate_series[0] != declared_series:
        raise ShapeError(
            "site/index.html candidate status marker does not match "
            f"catalog.json tool_version ({candidate_series[0]} != "
            f"{declared_series})"
        )
    return "candidate"


def render_customer_copy(
    root: Path,
    count: int,
    version: str,
    channel: str,
) -> dict[Path, tuple[str, str]]:
    rendered: dict[Path, tuple[str, str]] = {}
    for relative, expected_claims in COUNT_CLAIM_TARGETS.items():
        path = root / relative
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise ShapeError(f"cannot read {relative}: {exc}") from exc
        updated, claim_count = COUNT_CLAIM_RE.subn(str(count), source)
        if claim_count != expected_claims:
            raise ShapeError(
                f"{relative} has {claim_count} numeric standalone-count claim(s); "
                f"expected {expected_claims}"
            )
        expected_properties = COUNT_PROPERTY_TARGETS.get(relative, 0)
        updated, property_count = COUNT_PROPERTY_RE.subn(
            lambda match: f"{match.group(1)}{count}",
            updated,
        )
        if property_count != expected_properties:
            raise ShapeError(
                f"{relative} has {property_count} standaloneCheckCount "
                f"property value(s); expected {expected_properties}"
            )
        if channel == "candidate":
            version_targets = CANDIDATE_VERSION_CLAIM_TARGETS
            version_claim_re = CANDIDATE_VERSION_CLAIM_RE
        else:
            version_targets = PUBLISHED_VERSION_CLAIM_TARGETS
            version_claim_re = VERSION_CLAIM_RE
        expected_versions = version_targets.get(relative, 0)
        updated, version_count = version_claim_re.subn(
            lambda match: f"{match.group(1)}{version}{match.group(2)}",
            updated,
        )
        if version_count != expected_versions:
            raise ShapeError(
                f"{relative} has {version_count} numeric version claim(s); "
                f"expected {expected_versions}"
            )
        expected_version_properties = VERSION_PROPERTY_TARGETS.get(relative, 0)
        updated, version_property_count = VERSION_PROPERTY_RE.subn(
            lambda match: f"{match.group(1)}{version}{match.group(2)}",
            updated,
        )
        if version_property_count != expected_version_properties:
            raise ShapeError(
                f"{relative} has {version_property_count} softwareVersion "
                f"property value(s); expected {expected_version_properties}"
            )
        rendered[path] = (source, updated)
    return rendered


def write_atomic(path: Path, content: str) -> None:
    temporary_path: Path | None = None
    try:
        mode = path.stat().st_mode & 0o777
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
        temporary_path.replace(path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "render customer-facing check counts and versions from catalog.json"
        )
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path("."),
        help="candidate public repository root (default: current directory)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if customer files are not already synchronized",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.repo_root
    try:
        count, version = declared_release_shape(root)
        channel = release_channel(root, version)
        rendered = render_customer_copy(root, count, version, channel)
    except ShapeError as exc:
        print(f"release-shape: FAIL: {exc}", file=sys.stderr)
        return 1

    changed = [
        path
        for path, (source, content) in rendered.items()
        if source != content
    ]
    if args.check:
        if changed:
            names = ", ".join(str(path.relative_to(root)) for path in changed)
            print(
                "release-shape: FAIL: customer release-shape copy is out of date: "
                f"{names}; run python3 tools/sync-release-shape.py",
                file=sys.stderr,
            )
            return 1
        print(
            "release-shape: PASS: customer copy matches "
            f"count {count} and {channel} version {version}"
        )
        return 0

    try:
        for path in changed:
            write_atomic(path, rendered[path][1])
    except OSError as exc:
        print(
            f"release-shape: FAIL: cannot update customer copy: {exc}",
            file=sys.stderr,
        )
        return 1
    names = ", ".join(str(path.relative_to(root)) for path in changed) or "no files"
    print(
        f"release-shape: updated {names} from declared count {count} "
        f"and {channel} version {version}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
