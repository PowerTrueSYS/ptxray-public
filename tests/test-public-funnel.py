#!/usr/bin/env python3
"""Offline contract tests for the public PTxray customer funnel."""

from __future__ import annotations

import errno
import hashlib
from html.parser import HTMLParser
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import socketserver
import stat
import subprocess
import tempfile
import threading
import unittest
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
SCANNER = ROOT / "ptxray-aix.sh"
SCANNER_IBMI = ROOT / "ptxray-ibmi.sh"
REVIEW_HELPER = ROOT / "ptxray-review-pack.sh"
FIXTURE_ROOT = os.environ.get("AIXRAY_FIXTURE_ROOT")
FIXTURE = Path(FIXTURE_ROOT) if FIXTURE_ROOT else None
EGRESS_LINTER = ROOT / "tools" / "ci" / "egress-lint.sh"
IBM_DATA_GUARD = ROOT / "tools" / "check-no-ibm-redistribution.py"
RELEASE_INTEGRITY_GATE = ROOT / "tools" / "verify-release-integrity.py"
RELEASE_SHAPE_SYNC = ROOT / "tools" / "sync-release-shape.py"
PUBLIC_WORKFLOW = ROOT / ".github" / "workflows" / "public-checks.yml"
VERIFY_GUIDE = ROOT / "docs" / "VERIFY.md"
RELEASE_NOTES = ROOT / "docs" / "RELEASE-NOTES.md"
SECURITY_POLICY = ROOT / "SECURITY.md"
JSONLD = ROOT / "ptxray.jsonld"
PACKAGE_MANIFEST = ROOT / "package.json"
PACKAGE_LOCK = ROOT / "package-lock.json"
AGENT_INSTRUCTIONS = ROOT / "AGENTS.md"
LEGACY_NAME_ALLOWLIST = ROOT / "docs" / "LEGACY-NAME-ALLOWLIST.md"
DOWNLOAD_PAGE_URL = "https://powertruesystems.com/ptxray/"
CANONICAL_REPOSITORY_URL = "https://github.com/PowerTrueSYS/ptxray-public"
RELEASE_ASSET_URL = (
    "https://github.com/PowerTrueSYS/ptxray-public/releases/latest/download/ptxray-aix.sh"
)
RELEASE_ASSET_URL_IBMI = (
    "https://github.com/PowerTrueSYS/ptxray-public/releases/latest/download/ptxray-ibmi.sh"
)
PUBLISHED_VERSION = "1.4.0"
SIGNED_PAYLOADS = (
    "aixray-aix.sh",
    "ptxray-aix.sh",
    "ptxray-defs.sh",
    "ptxray-ibmi.sh",
    "ptxray-review-pack.sh",
    "ptxray-review-validate.awk",
)
# Tracks the shipped artifact rather than preserving an obsolete response-time
# promise. A free review has no response-time SLA, so this gate pins only the
# wording the public scanner actually prints.
REVIEW_CTA = (
    "Free engineer review: email your report to "
    "review@powertruesystems.com — a principal engineer will review it "
    "personally and follow up."
)
# The safe-send disclosure survived the pseudonymization rework but was
# reworded: the report no longer describes what the helper writes, it tells the
# operator what must not leave the machine. This is the load-bearing sentence
# and it must stay in every report and snapshot footer. Repointed, NOT relaxed
# -- the old wording was pinned to copy that no longer exists.
SAFE_SEND_DISCLOSURE = (
    "never send the local decode key or local manifest."
)
PROGRESS = (
    "[1/9] lifecycle and support…",
    "[2/9] patch and vulnerability currency…",
    "[3/9] storage and capacity…",
    "[4/9] performance and sizing…",
    "[5/9] errors and diagnostics…",
    "[6/9] availability and recovery…",
    "[7/9] security and hardening…",
    "[8/9] configuration hygiene…",
    "[9/9] monitoring and operations…",
)
CUSTOMER_FILES = (
    ROOT / "README.md",
    SITE / "index.html",
    JSONLD,
    ROOT / "llms.txt",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_scanner(*args: str, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    if FIXTURE is None:
        raise RuntimeError("set AIXRAY_FIXTURE_ROOT to run fixture tests")
    env = os.environ.copy()
    env["AIXRAY_FIXTURES"] = f"{FIXTURE}/"
    env["AIXRAY_TODAY"] = "2026-07-01"
    return subprocess.run(
        ["ksh", str(SCANNER), *args],
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def inline_jsonld(site_html: str) -> dict[str, object]:
    match = re.search(
        r'<script\s+type="application/ld\+json">(.*?)</script>',
        site_html,
        flags=re.DOTALL,
    )
    if match is None:
        raise AssertionError("site has no inline JSON-LD block")
    return json.loads(match.group(1))


def verification_python_block() -> str:
    guide = VERIFY_GUIDE.read_text(encoding="utf-8")
    section_marker = "## Verify byte identity and catalog hashes"
    if section_marker not in guide:
        raise AssertionError(f"{VERIFY_GUIDE} has no {section_marker!r} section")
    section = guide.split(section_marker, 1)[1]
    match = re.search(
        r"```sh\npython3 - <<'PY'\n(.*?)\nPY\n```",
        section,
        flags=re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"{VERIFY_GUIDE} has no verification Python block")
    return match.group(1)


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass


class ReportParser(HTMLParser):
    """Collect the post-gate link, top-risk fields, and footer links."""

    def __init__(self) -> None:
        super().__init__()
        self.download_links: list[dict[str, object]] = []
        self.footer_links: list[dict[str, str]] = []
        self.top_risks: list[dict[str, object]] = []
        self.section_text: list[str] = []
        self._ready_depth = 0
        self._footer_depth = 0
        self._footer_link: dict[str, str] | None = None
        self._section_depth = 0
        self._risk: dict[str, object] | None = None
        self._field: str | None = None
        self._field_depth = 0

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        attributes = dict(attrs)
        classes = tuple((attributes.get("class") or "").split())
        if self._ready_depth:
            self._ready_depth += 1
            if tag == "a":
                self.download_links.append(
                    {
                        "href": attributes.get("href"),
                        "download": any(name == "download" for name, _ in attrs),
                    }
                )
        elif attributes.get("id") == "download-ready":
            self._ready_depth = 1

        if self._footer_depth:
            self._footer_depth += 1
            if tag == "a" and attributes.get("href") is not None:
                self._footer_link = {
                    "href": attributes["href"] or "",
                    "text": "",
                }
                self.footer_links.append(self._footer_link)
        elif tag == "footer":
            self._footer_depth = 1

        if self._section_depth:
            self._section_depth += 1
        elif tag == "section" and attributes.get("id") == "start-here":
            self._section_depth = 1

        if not self._section_depth:
            return
        if self._field is not None:
            self._field_depth += 1
            return
        if tag == "li" and "top-risk" in classes:
            statuses = tuple(item for item in classes if item in ("FAIL", "WARN"))
            self._risk = {
                "statuses": statuses,
                "severity": attributes.get("data-severity"),
                # The card names the finding it came from. Matching cards to
                # findings by id rather than by position is what lets the
                # ranking be checked as a contract instead of as a fixed list.
                "finding_id": attributes.get("data-aixray-finding-id"),
                "label": "",
                "rank": "",
                "observed": "",
                "fix": "",
            }
            return
        if self._risk is None:
            return
        for field, class_name in (
            ("label", "top-risk-label"),
            ("rank", "top-risk-rank"),
            ("observed", "top-risk-observed"),
            ("fix", "top-risk-fix"),
        ):
            if class_name in classes:
                self._field = field
                self._field_depth = 1
                break

    def handle_endtag(self, tag: str) -> None:
        if self._field is not None:
            self._field_depth -= 1
            if self._field_depth == 0:
                self._field = None
        elif tag == "li" and self._risk is not None:
            self.top_risks.append(self._risk)
            self._risk = None
        if tag == "a" and self._footer_link is not None:
            self._footer_link = None
        if self._ready_depth:
            self._ready_depth -= 1
        if self._footer_depth:
            self._footer_depth -= 1
        if self._section_depth:
            self._section_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._section_depth:
            self.section_text.append(data)
        if self._risk is not None and self._field is not None:
            self._risk[self._field] = str(self._risk[self._field]) + data
        if self._footer_link is not None:
            self._footer_link["text"] += data


class PublicFunnelTests(unittest.TestCase):
    def run_release_shape_sync(
        self,
        root: Path,
        *,
        check: bool,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            "python3",
            str(RELEASE_SHAPE_SYNC),
            "--repo-root",
            str(root),
        ]
        if check:
            command.append("--check")
        return subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    def copy_verification_inputs(self, destination: Path) -> None:
        (destination / "site").mkdir(parents=True)
        for relative in (
            "README.md",
            "aixray-aix.sh",
            "catalog.json",
            "ptxray-aix.sh",
            "ptxray-defs.sh",
            "ptxray-ibmi.sh",
            "ptxray-review-pack.sh",
            "ptxray-review-validate.awk",
            "SHA256SUMS",
            "site/ptxray-aix.sh",
        ):
            source = ROOT / relative
            if not source.exists() and relative in (
                "ptxray-review-validate.awk",
                "SHA256SUMS",
            ):
                continue
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)

    def write_release_checksums(
        self, candidate: Path, overrides: dict[str, str] | None = None
    ) -> None:
        """Write the exact six-payload signed-release manifest.

        Standalone check digests remain bound by catalog.json; they are not
        separately published release assets. `overrides` plants a specific
        digest for one payload without weakening payload-set membership.
        """
        overrides = overrides or {}
        (candidate / "SHA256SUMS").write_text(
            "".join(
                f"{overrides.get(artifact) or sha256(candidate / artifact)}"
                f"  {artifact}\n"
                for artifact in SIGNED_PAYLOADS
            ),
            encoding="utf-8",
        )

    def run_verification_block(
        self, cwd: Path
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", "-c", verification_python_block()],
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    def test_documented_hash_verification_succeeds_on_current_tree(self) -> None:
        result = self.run_verification_block(ROOT)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("catalog/hash verification OK", result.stdout)

    def test_documented_hash_verification_accepts_declared_shape(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ptxray-verify-declared-shape-"
        ) as temporary:
            candidate = Path(temporary)
            self.copy_verification_inputs(candidate)
            shutil.copytree(ROOT / "checks", candidate / "checks")
            catalog_path = candidate / "catalog.json"
            catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
            original_count = catalog["check_count"]
            removed = catalog["checks"].pop()
            declared_count = original_count - 1
            catalog["check_count"] = declared_count
            catalog_path.write_text(
                json.dumps(catalog, indent=2) + "\n",
                encoding="utf-8",
            )
            shutil.rmtree(candidate / "checks" / removed["id"])
            readme_path = candidate / "README.md"
            readme = readme_path.read_text(encoding="utf-8")
            readme_path.write_text(
                re.sub(
                    rf"\b{re.escape(str(original_count))}\b",
                    str(declared_count),
                    readme,
                ),
                encoding="utf-8",
            )

            result = self.run_verification_block(candidate)

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("catalog/hash verification OK", result.stdout)

    def test_documented_hash_verification_names_missing_artifact(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ptxray-verify-missing-"
        ) as temporary:
            candidate = Path(temporary)
            self.copy_verification_inputs(candidate)
            (candidate / "ptxray-review-pack.sh").unlink()
            result = self.run_verification_block(candidate)

        combined = result.stdout + result.stderr
        self.assertNotEqual(0, result.returncode, combined)
        self.assertIn(
            "artifact verification failed: missing required file "
            "ptxray-review-pack.sh",
            combined,
        )
        self.assertIn(
            "check out the intended release tag or commit and retry with "
            "clean files from that revision",
            combined,
        )
        self.assertNotIn("Traceback", combined)

    def test_documented_hash_verification_names_mismatched_artifacts(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ptxray-verify-mismatch-"
        ) as temporary:
            candidate = Path(temporary)
            self.copy_verification_inputs(candidate)
            with (candidate / "site" / "ptxray-aix.sh").open("ab") as stream:
                stream.write(b"\n# deliberately different test bytes\n")
            result = self.run_verification_block(candidate)

        combined = result.stdout + result.stderr
        self.assertNotEqual(0, result.returncode, combined)
        self.assertIn(
            "artifact verification failed: byte mismatch between "
            "ptxray-aix.sh and site/ptxray-aix.sh",
            combined,
        )
        self.assertIn(
            "check out the intended release tag or commit and retry with "
            "clean files from that revision",
            combined,
        )
        self.assertNotIn("Traceback", combined)

    def test_documented_hash_verification_checks_signed_manifest(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ptxray-verify-v020-manifest-"
        ) as temporary:
            candidate = Path(temporary)
            self.copy_verification_inputs(candidate)
            shutil.copytree(ROOT / "checks", candidate / "checks")
            validator = candidate / "ptxray-review-validate.awk"
            validator.write_text('BEGIN { print "validated" }\n', encoding="utf-8")
            self.write_release_checksums(
                candidate,
                {"ptxray-review-validate.awk": "0" * 64},
            )

            result = self.run_verification_block(candidate)

        combined = result.stdout + result.stderr
        self.assertNotEqual(0, result.returncode, combined)
        self.assertIn(
            "SHA256SUMS digest mismatch for ptxray-review-validate.awk",
            combined,
        )
        self.assertNotIn("Traceback", combined)

    def test_documented_hash_verification_accepts_signed_manifest_docs(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ptxray-verify-v020-manifest-docs-"
        ) as temporary:
            candidate = Path(temporary)
            self.copy_verification_inputs(candidate)
            shutil.copytree(ROOT / "checks", candidate / "checks")
            validator = candidate / "ptxray-review-validate.awk"
            validator.write_text('BEGIN { print "validated" }\n', encoding="utf-8")
            self.write_release_checksums(candidate)
            readme_path = candidate / "README.md"
            stale_digest = "0" * 64
            readme = (
                re.sub(
                    r"\b[0-9A-Fa-f]{64}\b",
                    "",
                    readme_path.read_text(encoding="utf-8"),
                )
                + "\nVerify all release payloads with `SHA256SUMS`.\n"
                + f"Stale pasted digest: `{stale_digest}`.\n"
            )
            readme_path.write_text(readme, encoding="utf-8")

            stale_result = self.run_verification_block(candidate)

            stale_combined = stale_result.stdout + stale_result.stderr
            self.assertNotEqual(0, stale_result.returncode, stale_combined)
            self.assertIn(
                "README.md retains pasted artifact digests instead of using "
                "SHA256SUMS",
                stale_combined,
            )
            readme = readme.replace(stale_digest, "")
            readme_path.write_text(readme, encoding="utf-8")

            result = self.run_verification_block(candidate)

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("catalog/hash verification OK", result.stdout)

    def test_documented_hash_verification_rejects_symlinked_parent(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ptxray-verify-symlink-"
        ) as temporary:
            base = Path(temporary)
            candidate = base / "candidate"
            candidate.mkdir()
            self.copy_verification_inputs(candidate)
            shutil.copytree(ROOT / "checks", candidate / "checks")
            check_directory = candidate / "checks" / "ck-adapter-microcode"
            external_directory = base / "external-check"
            check_directory.rename(external_directory)
            check_directory.symlink_to(
                external_directory,
                target_is_directory=True,
            )
            result = self.run_verification_block(candidate)

        combined = result.stdout + result.stderr
        self.assertNotEqual(0, result.returncode, combined)
        self.assertIn(
            "artifact verification failed: required path "
            "checks/ck-adapter-microcode/ck-adapter-microcode.ksh "
            "traverses symlink component checks/ck-adapter-microcode",
            combined,
        )
        self.assertNotIn("Traceback", combined)

    def test_download_is_frictionless_and_direct(self) -> None:
        site_html = (SITE / "index.html").read_text(encoding="utf-8")

        # The scanner is a direct download from the public GitHub release.
        primary = re.search(
            rf'<a\b(?=[^>]*\bhref="{re.escape(RELEASE_ASSET_URL)}")[^>]*>',
            site_html,
        )
        self.assertIsNotNone(primary, "primary release download link is missing")

        # No email/lead gate fronts the download anymore.
        self.assertNotIn('id="download-form"', site_html)
        self.assertNotIn('id="download-ready"', site_html)
        self.assertNotIn("download-form.js", site_html)
        self.assertFalse(
            (SITE / "download-form.js").exists(),
            "the retired download-gate script must not ship",
        )

        # A soft, non-blocking call to action points at the repo and its issues.
        self.assertIn("https://github.com/PowerTrueSYS/ptxray-public/issues", site_html)

        # The optional notify field exists and is never required to download.
        notify = re.search(
            r'<input\b(?=[^>]*\bid="notify-email")[^>]*>',
            site_html,
        )
        self.assertIsNotNone(notify, "optional notify field is missing")
        if notify is not None:
            self.assertNotRegex(notify.group(0), r"\brequired\b")

        self.assertIn(
            '<input type="hidden" name="_next" '
            f'value="{DOWNLOAD_PAGE_URL}">',
            site_html,
        )
        self.assertNotIn("/ptxray/ready/", site_html)

    def test_download_references_are_direct(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        llms = (ROOT / "llms.txt").read_text(encoding="utf-8")
        site_html = (SITE / "index.html").read_text(encoding="utf-8")
        root_jsonld = json.loads(JSONLD.read_text())
        site_jsonld = inline_jsonld(site_html)

        # The public download page is still the advertised entry point.
        self.assertIn(DOWNLOAD_PAGE_URL, readme)
        self.assertIn(DOWNLOAD_PAGE_URL, llms)
        self.assertNotIn("downloadUrl", root_jsonld)
        self.assertNotIn("downloadUrl", site_jsonld)

        # It links straight to the public release asset — no lead gate.
        self.assertIn(RELEASE_ASSET_URL, site_html)

        # Customer copy must not revive the retired lead-form headline.
        retired_headline = "".join(("Ga", "ted download"))
        self.assertNotIn(retired_headline, readme)
        self.assertNotIn(retired_headline, llms)

    def test_public_identity_is_canonical_ptxray(self) -> None:
        self.assertTrue(JSONLD.is_file(), "ptxray.jsonld is missing")
        self.assertFalse(
            (ROOT / "aixray.jsonld").exists(),
            "legacy JSON-LD filename must not remain",
        )
        if not JSONLD.is_file():
            return

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        llms = (ROOT / "llms.txt").read_text(encoding="utf-8")
        site_html = (SITE / "index.html").read_text(encoding="utf-8")
        audit_guide = (ROOT / "docs" / "auditing-aix.md").read_text(
            encoding="utf-8"
        )
        agent_instructions = AGENT_INSTRUCTIONS.read_text(encoding="utf-8")
        robots = (ROOT / "robots.txt").read_text(encoding="utf-8")
        package = json.loads(PACKAGE_MANIFEST.read_text(encoding="utf-8"))
        package_lock = json.loads(PACKAGE_LOCK.read_text(encoding="utf-8"))
        root_jsonld = json.loads(JSONLD.read_text(encoding="utf-8"))
        site_jsonld = inline_jsonld(site_html)

        self.assertEqual("ptxray-public-tests", package.get("name"))
        self.assertEqual("ptxray-public-tests", package_lock.get("name"))
        self.assertEqual(
            "ptxray-public-tests",
            package_lock.get("packages", {}).get("", {}).get("name"),
        )
        self.assertEqual(CANONICAL_REPOSITORY_URL, package.get("repository", {}).get("url"))
        self.assertEqual(DOWNLOAD_PAGE_URL, package.get("homepage"))
        self.assertRegex((ROOT / "NOTICE").read_text(encoding="utf-8"), r"(?m)^PTxray$")
        self.assertRegex(agent_instructions, r"(?m)^# ptxray-public$")
        self.assertIn(CANONICAL_REPOSITORY_URL, readme)
        self.assertIn(CANONICAL_REPOSITORY_URL, llms)
        self.assertIn(CANONICAL_REPOSITORY_URL, site_html)
        self.assertIn(CANONICAL_REPOSITORY_URL, audit_guide)
        self.assertIn(DOWNLOAD_PAGE_URL, audit_guide)
        self.assertIn(DOWNLOAD_PAGE_URL, robots)
        self.assertNotIn("powertruesystems.com/aixray", robots)
        self.assertIn(
            f'<link rel="canonical" href="{DOWNLOAD_PAGE_URL}">',
            site_html,
        )
        self.assertIn(
            f'<meta property="og:url" content="{DOWNLOAD_PAGE_URL}">',
            site_html,
        )
        for label, metadata in (("root", root_jsonld), ("site", site_jsonld)):
            with self.subTest(metadata=label):
                self.assertEqual("PTxray", metadata.get("name"))
                self.assertEqual(DOWNLOAD_PAGE_URL, metadata.get("url"))
                self.assertEqual(
                    f"{DOWNLOAD_PAGE_URL}#software",
                    metadata.get("@id"),
                )
                self.assertEqual(
                    CANONICAL_REPOSITORY_URL,
                    metadata.get("codeRepository"),
                )
                self.assertNotIn("downloadUrl", metadata)

        for surface, text in (
            ("README.md", readme),
            ("llms.txt", llms),
            ("site/index.html", site_html),
            ("docs/auditing-aix.md", audit_guide),
            ("ptxray.jsonld", JSONLD.read_text(encoding="utf-8")),
            ("AGENTS.md", agent_instructions),
        ):
            with self.subTest(surface=surface, contract="no legacy site identity"):
                self.assertNotIn("powertruesystems.com/aixray", text)
            with self.subTest(surface=surface, contract="no legacy repo identity"):
                self.assertNotIn("PowerTrueSYS/aixray-public", text)

    def test_unpublished_15_candidate_boundary_is_precise(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        security = SECURITY_POLICY.read_text(encoding="utf-8")
        llms = (ROOT / "llms.txt").read_text(encoding="utf-8")
        site_html = (SITE / "index.html").read_text(encoding="utf-8")
        agent_instructions = AGENT_INSTRUCTIONS.read_text(encoding="utf-8")
        root_jsonld = json.loads(JSONLD.read_text(encoding="utf-8"))
        site_jsonld = inline_jsonld(site_html)

        prerequisites = readme.split("## Prerequisites", 1)[1].split("## ", 1)[0]
        self.assertRegex(prerequisites, r"(?i)AIX[^\n.]{0,80}requires? root")
        self.assertRegex(prerequisites, r"(?i)IBM i[^\n.]{0,80}requires?[^\n.]{0,40}QSECOFR")

        candidate_sections = []
        for text, heading in (
            (readme, "## Unpublished PTxray 1.5 release candidate"),
            (security, "## Unpublished PTxray 1.5 release candidate boundary"),
            (llms, "## Unpublished PTxray 1.5 release candidate"),
            (agent_instructions, "## Unpublished 1.5 release candidate boundary"),
        ):
            with self.subTest(heading=heading):
                self.assertIn(heading, text)
                if heading in text:
                    candidate = text.split(heading, 1)[1].split("\n## ", 1)[0]
                    candidate_normalized = " ".join(candidate.split())
                    candidate_sections.append(candidate)
                    self.assertRegex(
                        candidate_normalized,
                        r"(?i)not (?:a )?(?:published )?release",
                    )
                    self.assertRegex(
                        candidate_normalized,
                        r"(?i)AIX[^.]{0,100}\brequires? root\b",
                    )
                    self.assertRegex(
                        candidate_normalized,
                        r"(?i)IBM i[^.]{0,100}\brequires?[^.]{0,80}QSECOFR\b",
                    )
                    self.assertRegex(
                        candidate_normalized,
                        r"(?i)runner[^.]{0,180}(?:invokes?|calls?)"
                        r"[^.]{0,120}(?:separate )?(?:adjacent )?"
                        r"`?ptxray-defs\.sh`?",
                    )

        self.assertIn(
            'data-release-status="unpublished-1.5-release-candidate"',
            site_html,
        )
        site_candidate = site_html.split(
            'data-release-status="unpublished-1.5-release-candidate"', 1
        )[1].split("</section>", 1)[0]
        self.assertRegex(site_candidate, r"(?i)not (?:a )?(?:published )?release")
        self.assertRegex(site_candidate, r"(?i)AIX[^<.]{0,100}\brequires? root\b")
        self.assertRegex(site_candidate, r"(?i)IBM i[^<.]{0,100}\brequires? QSECOFR\b")
        self.assertRegex(site_candidate, r"(?i)VIOS lane remains disabled")
        self.assertIn("network-backed SYSTOOLS", site_html)
        self.assertNotIn(
            "<li>No network calls or telemetry during the assessment</li>",
            site_html,
        )

        for label, metadata in (("root", root_jsonld), ("site", site_jsonld)):
            with self.subTest(metadata=label):
                self.assertEqual("1.5.0", metadata.get("softwareVersion"))
                self.assertNotIn("releaseStatus", metadata)
                self.assertRegex(
                    str(metadata.get("description", "")),
                    r"(?i)unpublished PTxray 1\.5 release candidate",
                )
                requirements = str(metadata.get("softwareRequirements", ""))
                self.assertRegex(requirements, r"AIX requires? root")
                self.assertRegex(requirements, r"IBM i requires? QSECOFR")
                self.assertRegex(requirements, r"VIOS lane is disabled")

        combined = "\n".join(
            (readme, security, llms, site_html, json.dumps(root_jsonld))
        )
        self.assertNotIn("neither assessment will invoke", combined.casefold())
        self.assertNotIn("not invoked by either assessment", combined.casefold())
        self.assertRegex(
            combined,
            r"(?i)default[^\n.]{0,120}(?:download|update|acquire)"
            r"[^\n.]{0,100}(?:latest|current) signed definitions",
        )
        self.assertRegex(
            combined,
            r"(?i)`?--offline`?[^\n.]{0,120}(?:signed )?cache",
        )
        self.assertRegex(
            combined,
            r"(?i)`?--definitions-bundle`?[^\n.]{0,120}local signed",
        )
        self.assertRegex(combined, r"(?i)(?:digest-bound|release-bound)")
        self.assertRegex(combined, r"(?i)(?:age|stale)[^\n.]{0,100}warn")
        self.assertRegex(
            combined,
            r"(?i)definitions cache[^\n.]{0,140}(?:write|writes|written)",
        )
        self.assertRegex(combined, r"(?i)air-gapped (?:assessment|execution|run)")
        self.assertRegex(
            combined,
            r"(?i)assessment[^\n.]{0,100}(?:makes|opens|performs|has) no "
            r"(?:network calls|network connections|network egress)",
        )
        self.assertRegex(
            combined,
            r"(?i)no assessment data[^\n.]{0,100}(?:leaves|is sent|is uploaded)",
        )
        self.assertRegex(combined, r"(?i)(?:do(?:es)? not|no) remediate")
        self.assertRegex(
            combined,
            r"(?i)(?:changes no|does not change) (?:system )?configuration",
        )

        for unsafe in (
            "The tool has zero egress",
            "read-only, zero egress",
            "one inspectable ksh88 file with zero egress",
            "One inspectable ksh88 file.",
        ):
            with self.subTest(contract="no whole-product zero-egress", unsafe=unsafe):
                self.assertNotIn(unsafe.casefold(), combined.casefold())

    def test_security_reporting_channel_is_private_and_honest(self) -> None:
        security = SECURITY_POLICY.read_text(encoding="utf-8")
        lower = security.casefold()
        advisory_url = (
            "https://github.com/PowerTrueSYS/ptxray-public/security/advisories/new"
        )

        self.assertIn("review@powertruesystems.com", security)
        self.assertIn(advisory_url, security)
        self.assertRegex(
            lower,
            r"(?:pending|after|once)[^\n.]{0,120}(?:activation|migration|enabled)",
        )
        self.assertRegex(lower, r"do not (?:open|use)[^\n.]{0,80}public issue")
        self.assertRegex(
            lower,
            r"(?:safe triage|safe to do so|triage safely)[^\n.]{0,160}acknowledg",
        )
        self.assertRegex(lower, r"no (?:fixed |guaranteed )?(?:response )?sla")

    def test_release_notes_mark_candidate_unpublished_and_redirects_active(self) -> None:
        notes = RELEASE_NOTES.read_text(encoding="utf-8")
        prefix = notes.split("## v1.4.0", 1)[0]
        self.assertRegex(prefix, r"(?i)unpublished candidate")
        self.assertRegex(prefix, r"(?is)latest published release.{0,80}1\.4\.0")
        self.assertIn("https://powertruesystems.com/ptxray/", prefix)
        self.assertIn("https://github.com/PowerTrueSYS/ptxray-public", prefix)
        self.assertIn("https://powertruesystems.com/aixray/", prefix)
        self.assertIn("https://github.com/PowerTrueSYS/aixray-public", prefix)
        self.assertRegex(
            prefix.casefold(),
            r"(?s)legacy site.{0,180}(?:active|returns).{0,80}308",
        )
        self.assertRegex(
            prefix.casefold(),
            r"(?s)legacy (?:github )?repository.{0,180}(?:active|returns).{0,80}301",
        )
        self.assertRegex(
            prefix.casefold(),
            r"(?s)(?:key|fingerprint|signature).{0,160}not\s+(?:yet\s+)?published",
        )

    def test_ibmi_candidate_and_published_download_are_distinguished(self) -> None:
        # Candidate source is inspectable in-tree, but releases/latest still
        # serves published 1.4. Do not turn the unpublished 1.5 file into a
        # latest-release claim before the signed release exists.
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        llms = (ROOT / "llms.txt").read_text(encoding="utf-8")
        site_html = (SITE / "index.html").read_text(encoding="utf-8")
        self.assertNotIn(RELEASE_ASSET_URL_IBMI, readme)
        self.assertRegex(readme, r"(?is)1\.5.{0,100}unpublished release candidate")
        self.assertIn(RELEASE_ASSET_URL_IBMI, site_html)
        published_panel = site_html.split(
            "Current published download: PTxray 1.4", 1
        )[1].split("</section>", 1)[0]
        self.assertIn(RELEASE_ASSET_URL_IBMI, published_panel)
        self.assertIn(f"Version {PUBLISHED_VERSION}", published_panel)
        llms_ibmi_download = next(
            line for line in llms.splitlines() if RELEASE_ASSET_URL_IBMI in line
        )
        self.assertRegex(
            llms_ibmi_download,
            r"(?i)releases/latest[^.]{0,100}published 1\.4[^.]{0,100}"
            r"not the unpublished 1\.5 candidate",
        )
        for surface, text in (("README.md", readme), ("site/index.html", site_html)):
            with self.subTest(surface=surface, contract="ibmi hash verification"):
                self.assertIn("SHA256SUMS", text)
            with self.subTest(surface=surface, contract="ibmi scanner named"):
                self.assertIn("ptxray-ibmi.sh", text)

    def test_ibmi_coverage_claim_is_sourced_and_bounded(self) -> None:
        # Only the registry-sourced numbers may be stated, and the coverage
        # claim must be release-scoped to 7.4/7.5. The benchmark identity is
        # BOUND to the shipped binary: its component strings must be present in
        # the real ptxray-ibmi.sh, so the claim is anchored to the bytes that
        # ship, not merely pinned in prose.
        self.assertTrue(
            SCANNER_IBMI.is_file(),
            "the overlaid IBM i scanner ptxray-ibmi.sh is missing",
        )
        ibmi_source = SCANNER_IBMI.read_text(encoding="utf-8")
        for token in ("CIS IBM i", "V7R4M0", "V7R5M0", "Benchmark v2.1.0"):
            with self.subTest(bound_token=token):
                self.assertIn(
                    token,
                    ibmi_source,
                    f"benchmark token {token!r} is not embedded in ptxray-ibmi.sh",
                )

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        llms = (ROOT / "llms.txt").read_text(encoding="utf-8")
        jsonld = JSONLD.read_text(encoding="utf-8")
        # The exact CIS Level 1 coverage counts are computed by the scanner at
        # run time from the registry, not embedded as literals, so they are
        # pinned here as registry-sourced constants (as_of 2026-08-19) and
        # asserted against the customer copy. These are the ONLY IBM i numbers
        # any surface may state.
        for surface, text in (
            ("README.md", readme),
            ("llms.txt", llms),
            ("ptxray.jsonld", jsonld),
        ):
            for fragment in (
                "CIS IBM i V7R4M0 / V7R5M0 Benchmark v2.1.0",
                "76 of 89",
                "73 of 88",
            ):
                with self.subTest(surface=surface, fragment=fragment):
                    self.assertIn(
                        fragment,
                        text,
                        f"{surface} is missing sourced IBM i claim: {fragment}",
                    )
            with self.subTest(surface=surface, contract="ibmi releases"):
                self.assertRegex(text, r"7\.4 and 7\.5|7\.4/7\.5|7\.5.*7\.4")
            with self.subTest(surface=surface, contract="no ibmi stig"):
                self.assertRegex(text, r"(?i)no DISA STIG for IBM i")
            with self.subTest(surface=surface, contract="no unsourced ibmi count"):
                # Guard against any IBM i coverage number other than the two
                # sourced pairs. Every "N of M" claim in the copy must be one of
                # the sanctioned pairs.
                for pair in re.findall(r"\b\d{2,} of \d{2,}\b", text):
                    self.assertIn(
                        pair,
                        {"76 of 89", "73 of 88"},
                        f"{surface} states an unsourced coverage pair: {pair}",
                    )

    def test_license_is_apache_2_0(self) -> None:
        catalog = json.loads((ROOT / "catalog.json").read_text())
        self.assertEqual("Apache-2.0", catalog.get("license"))
        for entry in catalog.get("checks", []):
            with self.subTest(check=entry.get("id")):
                self.assertEqual("Apache-2.0", entry.get("license"))

        license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("Apache License", license_text)
        self.assertIn("Version 2.0, January 2004", license_text)
        self.assertIn("END OF TERMS AND CONDITIONS", license_text)
        self.assertTrue((ROOT / "NOTICE").is_file(), "Apache NOTICE file is missing")

        retired_license_name = "".join(("Poly", "Form"))
        for path in (
            ROOT / "README.md",
            ROOT / "llms.txt",
            JSONLD,
            ROOT / "catalog.json",
            SITE / "index.html",
        ):
            with self.subTest(path=path.name, contract="no retired license reference"):
                self.assertNotIn(
                    retired_license_name,
                    path.read_text(encoding="utf-8"),
                )

    def test_site_serves_the_scanner_directly_over_local_http(self) -> None:
        site_scanner = SITE / "ptxray-aix.sh"
        self.assertTrue(site_scanner.is_file(), "site scanner payload is missing")
        if not site_scanner.is_file():
            return
        self.assertEqual(SCANNER.read_bytes(), site_scanner.read_bytes())

        handler = lambda *args, **kwargs: QuietHandler(  # noqa: E731
            *args, directory=str(SITE), **kwargs
        )
        try:
            server = socketserver.TCPServer(("127.0.0.1", 0), handler)
        except PermissionError as exc:
            if exc.errno not in (errno.EACCES, errno.EPERM):
                raise
            self.skipTest("execution sandbox blocks a loopback listener")
        with server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/ptxray-aix.sh", timeout=5
                ) as response:
                    self.assertEqual(200, response.status)
                    self.assertEqual(site_scanner.read_bytes(), response.read())
            finally:
                server.shutdown()
                thread.join(timeout=5)

    def test_catalog_covers_every_public_artifact_and_scanner(self) -> None:
        catalog = json.loads((ROOT / "catalog.json").read_text())
        checks = catalog.get("checks", [])
        declared_version = catalog.get("tool_version")
        self.assertIsInstance(declared_version, str)
        if isinstance(declared_version, str):
            self.assertRegex(declared_version, r"^[0-9][0-9A-Za-z.+-]*$")
        check_dirs = sorted((ROOT / "checks").glob("ck-*"))
        manifests = sorted((ROOT / "checks").glob("ck-*/manifest.json"))
        declared_count = catalog.get("check_count")
        with self.subTest(contract="declared check count is a positive integer"):
            self.assertIs(type(declared_count), int)
            if type(declared_count) is int:
                self.assertGreater(declared_count, 0)
        with self.subTest(contract="catalog list count"):
            self.assertEqual(declared_count, len(checks))
        with self.subTest(contract="public directory count"):
            self.assertEqual(declared_count, len(check_dirs))
        with self.subTest(contract="manifest count"):
            self.assertEqual(declared_count, len(manifests))

        for entry in checks:
            check_id = entry["id"]
            artifact = ROOT / entry["artifact"]
            manifest = ROOT / "checks" / check_id / "manifest.json"
            with self.subTest(check=check_id, file="artifact"):
                self.assertTrue(artifact.is_file())
                if artifact.is_file():
                    self.assertEqual(entry["sha256"], sha256(artifact))
                    versions = re.findall(
                        r'(?m)^AIXRAY_STANDALONE_VERSION=["\']([^"\']+)["\']'
                        r"[ \t]*$",
                        artifact.read_text(encoding="utf-8"),
                    )
                    self.assertEqual([declared_version], versions)
            with self.subTest(check=check_id, file="manifest"):
                self.assertTrue(manifest.is_file())

        catalog_ids = [entry.get("id") for entry in checks]
        directory_ids = [path.name for path in check_dirs]
        artifact_paths = [entry.get("artifact") for entry in checks]
        self.assertEqual(len(catalog_ids), len(set(catalog_ids)))
        self.assertEqual(len(artifact_paths), len(set(artifact_paths)))
        self.assertEqual(set(directory_ids), set(catalog_ids))
        self.assertEqual(
            {f"checks/{check_id}/{check_id}.ksh" for check_id in directory_ids},
            set(artifact_paths),
        )
        for manifest in manifests:
            manifest_data = json.loads(manifest.read_text())
            self.assertEqual(manifest.parent.name, manifest_data.get("id"))
            entry = next(
                (item for item in checks if item.get("id") == manifest.parent.name),
                None,
            )
            self.assertIsNotNone(entry)
            if entry is not None:
                for key, value in manifest_data.items():
                    with self.subTest(check=manifest.parent.name, metadata=key):
                        self.assertEqual(value, entry.get(key))

        assembled = catalog.get("assembled_scanner")
        self.assertIsInstance(assembled, dict)
        if not isinstance(assembled, dict):
            return
        self.assertEqual("ptxray-aix.sh", assembled.get("artifact"))
        self.assertEqual("site/ptxray-aix.sh", assembled.get("site_artifact"))
        expected = sha256(SCANNER)
        self.assertEqual(expected, assembled.get("sha256"))
        self.assertEqual(expected, sha256(SITE / "ptxray-aix.sh"))

        review_pack = catalog.get("review_pack")
        self.assertIsInstance(review_pack, dict)
        if isinstance(review_pack, dict):
            self.assertEqual(
                "ptxray-review-pack.sh",
                review_pack.get("artifact"),
            )
            self.assertTrue(REVIEW_HELPER.is_file())
            if REVIEW_HELPER.is_file():
                self.assertEqual(
                    sha256(REVIEW_HELPER),
                    review_pack.get("sha256"),
                )

        for artifact, variable in (
            (SCANNER, "VERSION"),
            (REVIEW_HELPER, "AIXRAY_REVIEW_PACK_VERSION"),
        ):
            versions = re.findall(
                rf'(?m)^{variable}=["\']([^"\']+)["\'][ \t]*$',
                artifact.read_text(encoding="utf-8"),
            )
            with self.subTest(artifact=artifact.name, contract="current version"):
                self.assertEqual([declared_version], versions)

    def test_customer_copy_matches_the_declared_check_count(self) -> None:
        catalog = json.loads((ROOT / "catalog.json").read_text())
        declared_count = catalog.get("check_count")
        self.assertIs(type(declared_count), int)
        if type(declared_count) is not int:
            return
        count_claim = re.compile(r"\b([1-9][0-9]*)\s+standalone\b", re.IGNORECASE)
        for path in (
            ROOT / "README.md",
            SITE / "index.html",
            JSONLD,
            ROOT / "llms.txt",
        ):
            text = path.read_text(encoding="utf-8")
            claims = {int(value) for value in count_claim.findall(text)}
            with self.subTest(path=path.name, contract="count claim exists"):
                self.assertTrue(claims, "no numeric standalone-check claim found")
            with self.subTest(path=path.name, contract="all claims are current"):
                self.assertEqual({declared_count}, claims)

        root_jsonld = json.loads(JSONLD.read_text())
        site_jsonld = inline_jsonld((SITE / "index.html").read_text(encoding="utf-8"))
        for label, metadata in (("root", root_jsonld), ("site", site_jsonld)):
            count_values = [
                item.get("value")
                for item in metadata.get("additionalProperty", [])
                if item.get("name") == "standaloneCheckCount"
            ]
            with self.subTest(metadata=label, contract="one current count"):
                self.assertEqual([declared_count], count_values)

    def test_customer_count_copy_is_generated_from_catalog(self) -> None:
        self.assertTrue(
            RELEASE_SHAPE_SYNC.is_file(),
            "missing catalog-driven release-shape sync tool",
        )
        if not RELEASE_SHAPE_SYNC.is_file():
            return

        current = self.run_release_shape_sync(ROOT, check=True)
        self.assertEqual(0, current.returncode, current.stdout + current.stderr)

        with tempfile.TemporaryDirectory(
            prefix="ptxray-release-shape-sync-"
        ) as temporary:
            candidate = Path(temporary)
            for relative in (
                "README.md",
                "catalog.json",
                "ptxray.jsonld",
                "llms.txt",
                "site/index.html",
            ):
                source = ROOT / relative
                target = candidate / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
            catalog_path = candidate / "catalog.json"
            catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
            catalog["check_count"] -= 1
            declared_count = catalog["check_count"]
            catalog_path.write_text(
                json.dumps(catalog, indent=2) + "\n",
                encoding="utf-8",
            )

            stale = self.run_release_shape_sync(candidate, check=True)
            self.assertNotEqual(0, stale.returncode, stale.stdout + stale.stderr)
            updated = self.run_release_shape_sync(candidate, check=False)
            self.assertEqual(0, updated.returncode, updated.stdout + updated.stderr)
            verified = self.run_release_shape_sync(candidate, check=True)
            self.assertEqual(0, verified.returncode, verified.stdout + verified.stderr)

            claim_pattern = re.compile(
                r"\b([1-9][0-9]*)\s+standalone\b",
                re.IGNORECASE,
            )
            for relative in (
                "README.md",
                "ptxray.jsonld",
                "llms.txt",
                "site/index.html",
            ):
                claims = {
                    int(value)
                    for value in claim_pattern.findall(
                        (candidate / relative).read_text(encoding="utf-8")
                    )
                }
                with self.subTest(relative=relative, contract="rendered count"):
                    self.assertEqual({declared_count}, claims)

            root_jsonld = json.loads(
                (candidate / "ptxray.jsonld").read_text(encoding="utf-8")
            )
            site_jsonld = inline_jsonld(
                (candidate / "site/index.html").read_text(encoding="utf-8")
            )
            for label, metadata in (("root", root_jsonld), ("site", site_jsonld)):
                values = [
                    item.get("value")
                    for item in metadata.get("additionalProperty", [])
                    if item.get("name") == "standaloneCheckCount"
                ]
                with self.subTest(metadata=label, contract="rendered property"):
                    self.assertEqual([declared_count], values)

    def test_customer_copy_matches_the_declared_version(self) -> None:
        catalog = json.loads((ROOT / "catalog.json").read_text())
        declared_version = catalog.get("tool_version")
        self.assertIsInstance(declared_version, str)
        if not isinstance(declared_version, str):
            return
        candidate_version_claim = re.compile(
            r"\bcandidate version(?:\s*:\s*|\s+)`?"
            r"([0-9]+(?:\.[0-9A-Za-z-]+)+"
            r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)`?",
            re.IGNORECASE,
        )
        llms = (ROOT / "llms.txt").read_text(encoding="utf-8")
        self.assertEqual([declared_version], candidate_version_claim.findall(llms))

        site_html = (SITE / "index.html").read_text(encoding="utf-8")
        published_panel = site_html.split(
            "Current published download: PTxray 1.4", 1
        )[1].split("</section>", 1)[0]
        self.assertIn(f"Version {PUBLISHED_VERSION}", published_panel)
        self.assertNotIn(f"Version {declared_version}", published_panel)

        root_jsonld = json.loads(JSONLD.read_text())
        site_jsonld = inline_jsonld((SITE / "index.html").read_text(encoding="utf-8"))
        for label, metadata in (("root", root_jsonld), ("site", site_jsonld)):
            with self.subTest(metadata=label, contract="current version"):
                self.assertEqual(declared_version, metadata.get("softwareVersion"))

    def test_customer_version_copy_is_generated_from_catalog(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ptxray-release-version-sync-"
        ) as temporary:
            candidate = Path(temporary)
            for relative in (
                "README.md",
                "catalog.json",
                "ptxray.jsonld",
                "llms.txt",
                "site/index.html",
            ):
                source = ROOT / relative
                target = candidate / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
            catalog_path = candidate / "catalog.json"
            catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
            declared_version = f"{catalog['tool_version']}.999"
            catalog["tool_version"] = declared_version
            catalog_path.write_text(
                json.dumps(catalog, indent=2) + "\n",
                encoding="utf-8",
            )
            original_readme = (candidate / "README.md").read_text(encoding="utf-8")
            original_published_panel = (candidate / "site/index.html").read_text(
                encoding="utf-8"
            ).split("Current published download: PTxray 1.4", 1)[1].split(
                "</section>", 1
            )[0]

            stale = self.run_release_shape_sync(candidate, check=True)
            self.assertNotEqual(0, stale.returncode, stale.stdout + stale.stderr)
            updated = self.run_release_shape_sync(candidate, check=False)
            self.assertEqual(0, updated.returncode, updated.stdout + updated.stderr)
            verified = self.run_release_shape_sync(candidate, check=True)
            self.assertEqual(0, verified.returncode, verified.stdout + verified.stderr)

            candidate_version_claim = re.compile(
                r"\bcandidate version(?:\s*:\s*|\s+)`?"
                r"([0-9]+(?:\.[0-9A-Za-z-]+)+"
                r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)`?",
                re.IGNORECASE,
            )
            llms = (candidate / "llms.txt").read_text(encoding="utf-8")
            self.assertEqual(
                [declared_version],
                candidate_version_claim.findall(llms),
            )
            self.assertEqual(
                original_readme,
                (candidate / "README.md").read_text(encoding="utf-8"),
            )
            rendered_published_panel = (candidate / "site/index.html").read_text(
                encoding="utf-8"
            ).split("Current published download: PTxray 1.4", 1)[1].split(
                "</section>", 1
            )[0]
            self.assertEqual(original_published_panel, rendered_published_panel)
            self.assertIn(f"Version {PUBLISHED_VERSION}", rendered_published_panel)

            root_jsonld = json.loads(
                (candidate / "ptxray.jsonld").read_text(encoding="utf-8")
            )
            site_jsonld = inline_jsonld(
                (candidate / "site/index.html").read_text(encoding="utf-8")
            )
            for label, metadata in (("root", root_jsonld), ("site", site_jsonld)):
                with self.subTest(metadata=label, contract="rendered version"):
                    self.assertEqual(
                        declared_version,
                        metadata.get("softwareVersion"),
                    )

    def test_readme_and_docs_exclude_disallowed_framework_claims(self) -> None:
        disallowed = tuple(
            re.compile(term, flags=re.IGNORECASE)
            for term in ("nc" + "ua", "hi" + "paa")
        )
        paths = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*"))]
        for path in paths:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            for pattern in disallowed:
                with self.subTest(path=path.relative_to(ROOT), term=pattern.pattern):
                    self.assertIsNone(pattern.search(text))

    def test_readme_leads_a_new_customer_through_the_15_candidate_run(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        lower = readme.lower()
        self.assertRegex(readme, r"(?m)^## Prerequisites[ \t]*$")
        prerequisites_match = re.search(
            r"(?ms)^## Prerequisites[ \t]*$\n(.*?)(?=^## )", readme
        )
        self.assertIsNotNone(prerequisites_match)
        prerequisites = prerequisites_match.group(1) if prerequisites_match else ""
        prerequisites_lower = prerequisites.lower()
        self.assertRegex(
            prerequisites, r"AIX\s+7\.2\s*/\s*7\.3|AIX\s+7\.2.*7\.3"
        )
        self.assertIn("VIOS", prerequisites)
        self.assertIn("/bin/sh", prerequisites)
        self.assertRegex(prerequisites_lower, r"standard aix userland")
        self.assertRegex(prerequisites_lower, r"aix[^\n.]{0,80}requires? root")
        self.assertRegex(prerequisites_lower, r"ibm i[^\n.]{0,80}requires?[^\n.]{0,40}qsecofr")
        self.assertRegex(prerequisites_lower, r"several minutes")
        self.assertRegex(prerequisites_lower, r"runtime varies|varies by")
        self.assertRegex(prerequisites_lower, r"system size")
        self.assertRegex(prerequisites_lower, r"flrtvc")
        self.assertRegex(prerequisites_lower, r"no package or agent is installed")
        self.assertRegex(readme, r"(?m)^## Verify what you run\s*$")

        bare = re.search(r"(?m)^\./ptxray-aix\.sh\s*$", readme)
        html_mode = re.search(r"(?m)^\./ptxray-aix\.sh --html\b", readme)
        json_mode = re.search(r"(?m)^\./ptxray-aix\.sh --json\b", readme)
        self.assertIsNotNone(bare, "quickstart has no bare easy run")
        self.assertIsNotNone(html_mode, "advanced HTML stdout mode is missing")
        self.assertIsNotNone(json_mode, "advanced JSON stdout mode is missing")
        if bare is not None and html_mode is not None:
            self.assertLess(bare.start(), html_mode.start())
        self.assertIn("Report ready:", readme)
        self.assertRegex(readme, r"ptxray-<hostname>-<date>\.html")

        scanner_hash = sha256(SCANNER)
        catalog = json.loads((ROOT / "catalog.json").read_text())
        if catalog.get("tool_version") == "0.1.0":
            self.assertIn(scanner_hash, readme)
        else:
            self.assertIn("SHA256SUMS", readme)
            self.assertTrue((ROOT / "SHA256SUMS").is_file())

    def test_readme_documents_safe_send_limits_and_hashes(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        normalized = " ".join(readme.lower().split())
        self.assertIn("ptxray-review-pack.sh", readme)
        self.assertIn("ptxray-review-", readme)
        self.assertIn("ptxray-local-key-", readme)
        self.assertIn("never leaves this machine", normalized)
        self.assertIn("pseudonymized, not anonymized", normalized)
        self.assertIn("undiscovered pure-alphabetic barewords", normalized)
        self.assertIn("inspect the review file before sending", normalized)
        catalog = json.loads((ROOT / "catalog.json").read_text())
        self.assertTrue(REVIEW_HELPER.is_file())
        if catalog.get("tool_version") == "0.1.0":
            self.assertIn(sha256(SCANNER), readme)
            if REVIEW_HELPER.is_file():
                self.assertIn(sha256(REVIEW_HELPER), readme)
        else:
            self.assertIn("SHA256SUMS", readme)
            self.assertTrue((ROOT / "ptxray-review-validate.awk").is_file())
            self.assertTrue((ROOT / "SHA256SUMS").is_file())
            self.assertNotRegex(readme, r"\b[0-9A-Fa-f]{64}\b")

    def test_candidate_output_names_and_legacy_allowlist_are_narrow(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        verify = VERIFY_GUIDE.read_text(encoding="utf-8")
        audit_guide = (ROOT / "docs" / "auditing-aix.md").read_text(
            encoding="utf-8"
        )
        site_html = (SITE / "index.html").read_text(encoding="utf-8")
        for surface, text in (
            ("README.md", readme),
            ("docs/VERIFY.md", verify),
            ("docs/auditing-aix.md", audit_guide),
        ):
            with self.subTest(surface=surface, output="report"):
                self.assertIn("ptxray-<hostname>-<date>.html", text)
        self.assertIn("ptxray-review-*.html", readme)
        self.assertIn("ptxray-local-key-*.map", readme)
        self.assertIn("ptxray-review-*.html", verify)
        self.assertIn("ptxray-local-key-*.map", verify)
        self.assertIn("ptxray-&lt;hostname&gt;-&lt;date&gt;.html", site_html)

        current_surfaces = "\n".join((readme, verify, audit_guide, site_html, (ROOT / "llms.txt").read_text(encoding="utf-8")))
        for retired in (
            "aixray-<hostname>-<date>.html",
            "aixray-&lt;hostname&gt;-&lt;date&gt;.html",
            "aixray-review-*.html",
            "aixray-local-key-*.map",
        ):
            with self.subTest(retired=retired):
                self.assertNotIn(retired, current_surfaces)

        allowlist = LEGACY_NAME_ALLOWLIST.read_text(encoding="utf-8")
        self.assertIn("aixray-aix.sh", allowlist)
        self.assertIn("byte-identical", allowlist)
        self.assertIn("data-aixray-*", allowlist)
        self.assertIn("AIXRAY_*", allowlist)
        self.assertIn("docs/RELEASE-NOTES.md", allowlist)
        self.assertTrue((ROOT / "aixray-aix.sh").is_file())
        for retired_path in (
            ROOT / "aixray-review-pack.sh",
            ROOT / "aixray-review-validate.awk",
            SITE / "aixray-aix.sh",
        ):
            with self.subTest(retired_path=retired_path):
                self.assertFalse(retired_path.exists())

    def test_v010_release_note_records_exact_tag_asset_discrepancy(self) -> None:
        self.assertTrue(RELEASE_NOTES.is_file())
        if not RELEASE_NOTES.is_file():
            return
        note = RELEASE_NOTES.read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for exact_value in (
            "d0587e17bc4fc387c11e8df317cc85e6aa8c2f4a",
            "ed854a50801a050ebf9932ac99af522f76caa4a6",
            "e098e0b0f617649ba29fbf1626fefb55bcd2b467c09060bdcb4458b1340e5b16",
            "6829bd1aa6d24648c8c142287afc0aef730cc081716250d7eb79297c61ebaf52",
            "8291000be2093176fc43164905958964d1e7bf9e197974abb54a25eabaab1ff4",
        ):
            with self.subTest(exact_value=exact_value):
                self.assertIn(exact_value, note)
        self.assertIn("aixray-review-pack.sh` is absent", note)
        self.assertIn(
            "[`v0.1.0` release-integrity note](docs/RELEASE-NOTES.md"
            "#v010-release-integrity-note)",
            readme,
        )
        self.assertIn("artifacts in this repository revision", readme)

    def test_report_keeps_marketing_hooks_and_safe_send_footer(self) -> None:
        source = SCANNER.read_text(encoding="utf-8")
        self.assertEqual(1, source.count("MITIGATE_CTA='"))
        self.assertEqual(1, source.count("BOOK_CTA='"))
        self.assertIn('WL="$WL$MITIGATE_CTA"', source)
        self.assertIn('CATBLOCKS="$CATBLOCKS$MITIGATE_CTA"', source)
        self.assertEqual(2, source.count(".cta,.mitigate{display:none}"))

        footer_blocks = re.findall(
            r'<footer>.*?</footer>\s*<div class="cta".*?</div>',
            source,
            flags=re.DOTALL,
        )
        self.assertEqual(2, len(footer_blocks))
        for footer in footer_blocks:
            with self.subTest(footer=footer[:80]):
                self.assertIn("${BOOK_CTA}", footer)
                self.assertIn("ptxray-review-pack.sh", footer)
                self.assertIn(SAFE_SEND_DISCLOSURE, footer)
                self.assertIn(
                    'href="mailto:review@powertruesystems.com"',
                    footer,
                )

    def test_stig_gated_row_is_literal_and_honestly_documented(self) -> None:
        for artifact in (SCANNER, SITE / "ptxray-aix.sh"):
            source = artifact.read_text(encoding="utf-8")
            rows = [
                tuple(line.split("|"))
                for line in source.splitlines()
                if line.startswith("V-215358|")
            ]
            with self.subTest(artifact=artifact.relative_to(ROOT)):
                self.assertEqual([("V-215358", "rctcp", "gated")], rows)
                self.assertIn(
                    '"gated" is the AIX routing daemon service name',
                    source,
                )

    def test_public_standards_claims_are_source_derived_and_bounded(self) -> None:
        source = SCANNER.read_text(encoding="utf-8")
        families = {
            "R_FILEPERM": ("eval_fileperms", "stig_fileperms", 5),
            "R_SECATTR": ("eval_secattr", "stig_secattr", 6),
            "R_NETTUNE": ("eval_nettune", "stig_nettune", 5),
            "R_SVCOFF": ("eval_svcoff", "stig_svcoff", 3),
        }
        security = re.search(
            r"^function checks_security \{\n(.*?)^\}\n\n# eval_fileperms",
            source,
            flags=re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(security, "checks_security body is missing")
        if security is None:
            return
        self.assertEqual(
            1,
            len(re.findall(r"(?m)^checks_security$", source)),
            "checks_security is not invoked exactly once by the main scan path",
        )
        stig_ids: list[str] = []
        evaluator_bodies: list[str] = []
        for table, (evaluator, finding, field_count) in families.items():
            block = re.search(
                rf'^{table}="\n(.*?)\n"$',
                source,
                flags=re.MULTILINE | re.DOTALL,
            )
            self.assertIsNotNone(block, f"{table} rule table is missing")
            if block is None:
                continue
            rows = [
                line.split("|")
                for line in block.group(1).splitlines()
                if line
            ]
            for row in rows:
                self.assertEqual(field_count, len(row), f"malformed {table} row")
                self.assertRegex(row[0], r"^V-[0-9]+$")
                if table == "R_FILEPERM":
                    self.assertTrue(row[1].startswith("/"))
                    self.assertTrue(any(row[2:]))
                    for value in row[2:]:
                        self.assertRegex(value, r"^(?:[0-9]+)?$")
                elif table == "R_SECATTR":
                    self.assertTrue(row[1].startswith("/"))
                    self.assertTrue(row[2] and row[3])
                    self.assertIn(row[4], ("eq", "ge", "le"))
                    self.assertRegex(row[5], r"^-?[0-9]+$")
                elif table == "R_NETTUNE":
                    self.assertIn(row[1], ("no", "nfso"))
                    self.assertTrue(row[2])
                    self.assertIn(row[3], ("eq", "ge", "le"))
                    self.assertRegex(row[4], r"^-?[0-9]+$")
                else:
                    self.assertIn(row[1], ("inetd", "lssrc", "rctcp"))
                    self.assertRegex(row[2], r"^[A-Za-z0-9_.-]+$")
            family_ids = [row[0] for row in rows]
            self.assertEqual(
                len(family_ids),
                len(set(family_ids)),
                f"{table} repeats a V-ID",
            )
            evaluator_body = re.search(
                rf"^function {evaluator} \{{\n(.*?)^\}}$",
                source,
                flags=re.MULTILINE | re.DOTALL,
            )
            self.assertIsNotNone(
                evaluator_body,
                f"{evaluator} implementation is missing",
            )
            if evaluator_body is None:
                continue
            body = evaluator_body.group(1)
            self.assertIn(f'"${table}"', body)
            self.assertIn('print "stig:" R_id[i]', body)
            self.assertRegex(body, rf"\badd security {finding}\b")
            self.assertEqual(
                1,
                len(re.findall(rf"(?m)^  {evaluator}$", security.group(1))),
                f"{evaluator} is not dispatched exactly once by checks_security",
            )
            evaluator_bodies.append(body)
            stig_ids.extend(family_ids)

        self.assertEqual(
            len(stig_ids),
            len(set(stig_ids)),
            "a V-ID appears in more than one evaluated rule table",
        )
        self.assertIsNone(
            re.search(r"(?i)\bALL\s+[0-9]+\s+STIG rules\b", source),
            "scanner prose must not supply a public STIG denominator",
        )
        self.assertFalse(
            "V-IDs/values stable" in source,
            "scanner must not claim rule-set stability across releases",
        )

        crosswalk = re.search(
            r"^cis_l1_map='(.*?)\n'$",
            source,
            flags=re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(crosswalk, "numeric CIS L1 crosswalk is missing")
        if crosswalk is None:
            return
        cis_rows = [
            tuple(line.split("|"))
            for line in crosswalk.group(1).splitlines()
            if line
        ]
        # The crosswalk is many-to-many in BOTH directions and always was:
        # several checks can contribute to one control, and one check that
        # evaluates two directives can satisfy two controls. ck-ssh-ignore-rhosts
        # is the latter -- it requires IgnoreRhosts yes AND
        # HostbasedAuthentication no, so finding:ssh_ignore_rhosts legitimately
        # maps to both 4.6.3.8 and 4.6.3.7. An earlier source-uniqueness
        # assertion only held while the crosswalk was small enough for no such
        # check to exist, and it forbade one direction while silently
        # permitting the other (22 controls already have more than one source).
        # What actually guards against double-counting is PAIR uniqueness.
        self.assertEqual(
            len(cis_rows),
            len(set(cis_rows)),
            "numeric CIS L1 crosswalk repeats a (source, control) pair",
        )
        # The guarantee is that no crosswalk row credits a CIS control to a
        # finding the scanner never emits -- a phantom source would inflate
        # coverage. It is NOT that every crosswalk source is a `security`
        # finding raised by checks_security: finding:firmware is emitted by the
        # lifecycle section and finding:system_config_capture_cron by the config
        # section, and both are legitimate CIS L1 sources (7.2 and 2.1). The
        # category was never load-bearing here, so search the whole scanner for
        # a real emitter and keep the category open. Still an emitter check --
        # `add <category> <id>` must appear, so a bare mention in a comment or a
        # crosswalk row does not satisfy it.
        emitters = set(
            re.findall(r"\b(?:add|nr_warn) [a-z_]+ ([a-z0-9_]+)\b", source)
        )
        for source_id, control in cis_rows:
            self.assertRegex(source_id, r"^(?:finding:[a-z0-9_]+|stig:V-[0-9]+)$")
            self.assertRegex(control, r"^[0-9]+(?:\.[0-9]+)+$")
            if source_id.startswith("stig:"):
                self.assertIn(source_id.removeprefix("stig:"), stig_ids)
            else:
                finding = source_id.removeprefix("finding:")
                self.assertIn(
                    finding,
                    emitters,
                    f"crosswalk control {control} credits finding:{finding}, "
                    "which the scanner never emits",
                )
        cis_renderer = re.search(
            r"^function cis_l1_verdicts \{.*?\n(.*?)^\}$",
            source,
            flags=re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(cis_renderer, "CIS L1 verdict resolver is missing")
        if cis_renderer is not None:
            self.assertIn('"$cis_l1_map"', cis_renderer.group(1))
            self.assertIn('"${F_RULES[$CIS_INDEX]}"', cis_renderer.group(1))
        ctl_match = re.search(
            r"^  function ctl_match \{.*?\n(.*?)^  \}$",
            source,
            flags=re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(ctl_match, "compliance control resolver is missing")
        if ctl_match is not None:
            self.assertIn('cis_l1_verdicts "$1"', ctl_match.group(1))
        self.assertGreaterEqual(
            source.count("$(ctl_match $i)"),
            1,
            "compliance renderer does not invoke ctl_match",
        )

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        llms = (ROOT / "llms.txt").read_text(encoding="utf-8")
        jsonld = JSONLD.read_text(encoding="utf-8")
        stig_claim = (
            "DISA STIG for IBM AIX 7.x coverage is partial: "
            f"{len(stig_ids)} distinct rule V-IDs receive an engine verdict"
        )
        claim_fragments = (
            stig_claim,
            f"{len(cis_rows)} CIS L1-aligned checks",
        )
        for artifact, text in (
            ("README.md", readme),
            ("llms.txt", llms),
            ("ptxray.jsonld", jsonld),
        ):
            with self.subTest(artifact=artifact):
                for claim in claim_fragments:
                    self.assertTrue(
                        claim in text,
                        f"{artifact} is missing source-derived claim: {claim}",
                    )
                for limit in (
                    "V-215399",
                    "package-commit condition",
                    "V-215429",
                    "not counted",
                    "not a single-release coverage fraction",
                ):
                    self.assertIn(limit, text)
                self.assertRegex(text, r"(?i)\bpartial\b")
                self.assertTrue(
                    "not a claim of completeness" in text
                    or "not a completeness claim" in text
                    or "alignment only" in text
                )
                for banned in (
                    r"(?i)\b(?:ffiec|ncua|hipaa)\b",
                    r"(?i)\blinux\b",
                    (
                        r"(?i)CIS Benchmark coverage|certified|accredited|"
                        r"fully compliant"
                    ),
                    (
                        r"(?i)(?:\b[0-9]+\s+of\s+[0-9]+\b[^\n.]*"
                        r"\bDISA STIG\b|\bDISA STIG\b[^\n.]*"
                        r"\b[0-9]+\s+of\s+[0-9]+\b)"
                    ),
                ):
                    self.assertIsNone(
                        re.search(banned, text),
                        f"{artifact} contains banned public wording: {banned}",
                    )

        included = readme.index("## What is included?")
        standards = readme.index("## Standards coverage")
        proof = readme.index("## Why can a cautious AIX administrator inspect it first?")
        self.assertLess(included, standards)
        self.assertLess(standards, proof)
        for table in families:
            self.assertIn(table, readme)
        for area in (
            "NFS exports",
            "password hashing",
            "file ownership and permissions",
            "network tunables",
        ):
            self.assertIn(area, readme)
        self.assertIn("V-215399", readme)

    def test_scanner_audit_map_names_only_public_paths(self) -> None:
        header = "\n".join(SCANNER.read_text(encoding="utf-8").splitlines()[:30])
        audit = re.search(
            r"# Audit map \(repository paths\):\n((?:#   .*\n){3})",
            header + "\n",
        )
        self.assertIsNotNone(audit, "three-line audit map is missing")
        if audit is None:
            return
        paths = tuple(
            line.removeprefix("#   ").split(" — ", 1)[0]
            for line in audit.group(1).splitlines()
        )
        self.assertEqual(
            ("checks/", "catalog.json", "README.md#verify-what-you-run"),
            paths,
        )
        self.assertTrue((ROOT / "checks").is_dir())
        self.assertTrue((ROOT / "catalog.json").is_file())
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertRegex(readme, r"(?m)^## Verify what you run\s*$")
        for dev_only in (
            "docs/HOW-TO-AUDIT.md",
            "docs/ASSEMBLE.md",
            "tools.d/checks",
        ):
            self.assertNotIn(dev_only, header)

    @unittest.skipUnless(
        os.environ.get("AIXRAY_FIXTURE_ROOT"),
        "set AIXRAY_FIXTURE_ROOT to run fixture tests",
    )
    def test_bare_run_completes_the_newcomer_drill(self) -> None:
        assert FIXTURE is not None
        self.assertTrue(FIXTURE.is_dir(), f"fixture is missing: {FIXTURE}")
        with tempfile.TemporaryDirectory(prefix="aixray-public-newcomer-") as temp:
            cwd = Path(temp)
            result = run_scanner(cwd=cwd)
            reports = sorted(cwd.glob("aixray-*-2026-07-01.html"))
            self.assertEqual(0, result.returncode, result.stderr)
            with self.subTest(contract="quiet stdout"):
                self.assertEqual("", result.stdout)
            with self.subTest(contract="one report"):
                self.assertEqual(1, len(reports))
            lines = result.stderr.splitlines()
            progress = tuple(line for line in lines if re.match(r"^\[[^]]+\]", line))
            with self.subTest(contract="ordered progress"):
                self.assertEqual(PROGRESS, progress)
            with self.subTest(contract="completion"):
                completions = [line for line in lines if line.startswith("Report ready:")]
                self.assertEqual(1, len(completions))
            with self.subTest(contract="review CTA"):
                self.assertEqual(1, lines.count(REVIEW_CTA))
            if len(reports) != 1:
                return
            report = reports[0]
            self.assertRegex(
                report.name, r"^aixray-[A-Za-z0-9._-]+-2026-07-01\.html$"
            )
            self.assertEqual(0o600, stat.S_IMODE(report.stat().st_mode))
            expected_completion = (
                f"Report ready: ./{report.name} — open it in your browser. "
                "To save a PDF: Print -> Save as PDF."
            )
            self.assertIn(expected_completion, lines)
            document = report.read_text(encoding="utf-8")
            self.assertTrue(document.rstrip().endswith("</html>"))
            self.assertIn('id="start-here"', document)
            score_at = document.find('class="score"')
            start_at = document.find('id="start-here"')
            self.assertGreaterEqual(score_at, 0)
            self.assertGreater(start_at, score_at)
            category_at = document.find('class="cathead"')
            self.assertGreater(category_at, start_at)
            footer = re.search(r"<footer>.*?</footer>", document, flags=re.DOTALL)
            self.assertIsNotNone(footer)
            if footer is not None:
                self.assertIn(REVIEW_CTA, footer.group(0))
            parser = ReportParser()
            parser.feed(document)
            linked_ctas = [
                {
                    "href": link["href"],
                    "text": " ".join(link["text"].split()),
                }
                for link in parser.footer_links
            ]
            self.assertIn(
                {
                    "href": "mailto:review@powertruesystems.com",
                    "text": REVIEW_CTA,
                },
                linked_ctas,
            )

            structured = run_scanner("--json")
            self.assertEqual(0, structured.returncode, structured.stderr)
            findings = json.loads(structured.stdout)["findings"]
            by_id = {finding["id"]: finding for finding in findings}

            # Severity priority, worst first. This is the ONLY part of the
            # ranking this test models, and deliberately so: within a
            # (status, severity) bucket the scanner orders by CVE action tier,
            # then by descending framework corroboration, then by finding id,
            # and caps any one category at two entries on a first pass before
            # relaxing the cap on a second. Re-implementing that here would
            # make the test a copy of the code it is supposed to check, and it
            # would pass for a reimplementation that is wrong in the same way.
            # So assert the properties the ranking must have instead.
            priority = {
                (status, severity): rank
                for rank, (status, severity) in enumerate(
                    (status, severity)
                    for status in ("FAIL", "WARN")
                    for severity in ("high", "med", "low")
                )
            }
            actionable = [
                finding
                for finding in findings
                if (finding["status"], finding["severity"]) in priority
            ]

            self.assertGreaterEqual(len(parser.top_risks), 1)
            self.assertEqual(min(5, len(actionable)), len(parser.top_risks))

            rendered_ids = [risk["finding_id"] for risk in parser.top_risks]
            self.assertNotIn(None, rendered_ids, "a top-risk card names no finding")
            self.assertEqual(
                len(set(rendered_ids)),
                len(rendered_ids),
                f"a finding occupies more than one of the five slots: {rendered_ids}",
            )

            for rendered in parser.top_risks:
                source = by_id.get(rendered["finding_id"])
                self.assertIsNotNone(
                    source,
                    f"top-risk card names {rendered['finding_id']}, which is "
                    "absent from --json",
                )
                if source is None:
                    continue
                # Every visible value on the card must be the value of the
                # finding the card names -- a card that renders another
                # finding's evidence is a false accusation against the box.
                self.assertEqual((source["status"],), rendered["statuses"])
                self.assertEqual(source["severity"], rendered["severity"])
                self.assertEqual(source["label"], str(rendered["label"]).strip())
                self.assertEqual(
                    f"{source['status']} · {source['severity']}",
                    str(rendered["rank"]).strip(),
                )
                self.assertEqual(
                    f"Observed: {source['observed']}",
                    " ".join(str(rendered["observed"]).split()),
                )
                # INVERTED, not hollowed out. This assertion used to require
                # `Fix: <text>` in the top-risk card. AIXray reports gaps and
                # says nothing about remediation, so the card no longer renders
                # a fix span at all -- and the guard that used to prove the
                # span was present now proves it is absent. The parser still
                # collects a "top-risk-fix" element into rendered["fix"]
                # precisely so this can fail if the span ever comes back; the
                # collector is the mechanism of the guard, not a leftover.
                self.assertEqual(
                    "",
                    str(rendered["fix"]).strip(),
                    "the top-risk card rendered remediation text; AIXray "
                    "reports findings and does not tell the operator how to "
                    "fix them",
                )
                # The JSON `fix` field is a separate surface and stays this
                # release, so the fixture still supplies one. Asserting that
                # keeps the two surfaces from being conflated: a non-empty
                # source fix must still not reach the HTML card.
                self.assertNotEqual("", str(source["fix"]).strip())

            # The two invariants that make "top risks" an honest heading.
            shown_ranks = [
                priority[(by_id[fid]["status"], by_id[fid]["severity"])]
                for fid in rendered_ids
            ]
            self.assertEqual(
                sorted(shown_ranks),
                shown_ranks,
                "the cards are out of severity order -- a less severe finding "
                f"is shown above a more severe one: {rendered_ids}",
            )
            # Nothing worse than the worst card may be left out. The scanner
            # drains a whole (status, severity) bucket before moving to the
            # next -- the category cap only reorders within a bucket, it never
            # defers a bucket -- so an omitted finding may tie the last card
            # but must never outrank it. This is the assertion that would
            # catch "the top five are not the five worst".
            worst_shown = max(shown_ranks)
            for finding in actionable:
                if finding["id"] in rendered_ids:
                    continue
                self.assertGreaterEqual(
                    priority[(finding["status"], finding["severity"])],
                    worst_shown,
                    f"{finding['id']} ({finding['status']}/"
                    f"{finding['severity']}) outranks a rendered top risk but "
                    "was left out of the five",
                )

    @unittest.skipUnless(
        os.environ.get("AIXRAY_FIXTURE_ROOT"),
        "set AIXRAY_FIXTURE_ROOT to run fixture tests",
    )
    def test_start_here_renders_honest_zero_actionable_guidance(self) -> None:
        assert FIXTURE is not None
        source = SCANNER.read_text(encoding="utf-8")
        needle = '\nSTART_HERE_ITEMS=""\n'
        self.assertEqual(1, source.count(needle))
        if source.count(needle) != 1:
            return
        force_no_actionable = """
i=0
while [ "$i" -lt "$NFIND" ]; do
  F_ST[$i]=NOT_ASSESSED
  i=$((i+1))
done
START_HERE_ITEMS=""
"""
        instrumented = source.replace(needle, f"\n{force_no_actionable}", 1)
        with tempfile.TemporaryDirectory(prefix="aixray-public-no-action-") as temp:
            temp_root = Path(temp)
            scanner = temp_root / "aixray-aix.sh"
            scanner.write_text(instrumented, encoding="utf-8")
            env = os.environ.copy()
            env["AIXRAY_FIXTURES"] = f"{FIXTURE}/"
            env["AIXRAY_TODAY"] = "2026-07-01"
            result = subprocess.run(
                ["ksh", str(scanner), "--html"],
                cwd=temp_root,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        self.assertEqual(0, result.returncode, result.stderr)
        parser = ReportParser()
        parser.feed(result.stdout)
        self.assertEqual([], parser.top_risks)
        guidance = " ".join("".join(parser.section_text).split())
        self.assertIn("No actionable FAIL or WARN finding", guidance)
        self.assertIn("NOT_ASSESSED", guidance)

    @unittest.skipUnless(
        os.environ.get("AIXRAY_FIXTURE_ROOT"),
        "set AIXRAY_FIXTURE_ROOT to run fixture tests",
    )
    def test_explicit_html_remains_a_stdout_mode(self) -> None:
        result = run_scanner("--html")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(result.stdout.startswith("<!doctype html>"))
        self.assertTrue(result.stdout.rstrip().endswith("</html>"))

    def test_public_shell_and_metadata_syntax(self) -> None:
        # AIX /bin/sh is ksh; these artifacts intentionally use ksh88 syntax.
        # Ubuntu's dash is not part of the supported shell contract.
        ksh = shutil.which("ksh")
        self.assertIsNotNone(
            ksh,
            "ksh is required for the AIX shell contract syntax check",
        )
        assert ksh is not None
        for artifact in (SCANNER, REVIEW_HELPER):
            result = subprocess.run(
                [ksh, "-n", str(artifact)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            with self.subTest(shell="ksh", artifact=artifact.name):
                self.assertEqual(0, result.returncode, result.stderr)
        json.loads((ROOT / "catalog.json").read_text())
        json.loads(JSONLD.read_text())
        inline_jsonld((SITE / "index.html").read_text(encoding="utf-8"))

    def test_public_ci_runs_all_release_guards(self) -> None:
        self.assertTrue(PUBLIC_WORKFLOW.is_file())
        self.assertTrue(IBM_DATA_GUARD.is_file())
        self.assertTrue(RELEASE_INTEGRITY_GATE.is_file())
        if not PUBLIC_WORKFLOW.is_file():
            return
        workflow = PUBLIC_WORKFLOW.read_text(encoding="utf-8")
        self.assertRegex(workflow, r"(?m)^on:\s*$")
        self.assertRegex(workflow, r"(?m)^\s+pull_request:\s*$")
        self.assertRegex(workflow, r"(?m)^\s+push:\s*$")
        self.assertRegex(workflow, r"(?m)^\s+branches:\s*\[master\]\s*$")
        self.assertRegex(
            workflow,
            r'(?m)^\s+tags:\s*\["v\*"\]\s*$',
        )
        self.assertRegex(workflow, r"(?m)^\s+release:\s*$")
        self.assertRegex(
            workflow,
            r"(?m)^\s+types:\s*\[published, edited, released\]\s*$",
        )
        self.assertIn("fetch-depth: 0", workflow)
        self.assertEqual(
            2,
            workflow.count(
                "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
            ),
        )
        self.assertNotIn("actions/checkout@v", workflow)
        self.assertGreaterEqual(workflow.count("persist-credentials: false"), 2)
        self.assertIn("sudo apt-get install -y ksh", workflow)
        self.assertIn("python3 tools/sync-release-shape.py --check", workflow)
        self.assertIn("sh tests/run-tests.sh", workflow)
        self.assertIn(
            "set -- ptxray-aix.sh ptxray-ibmi.sh ptxray-review-pack.sh "
            "checks/*/*.ksh",
            workflow,
        )
        self.assertIn(
            "ptxray-defs.sh is intentionally excluded",
            workflow,
        )
        self.assertIn("if [ -f ptxray-review-validate.awk ]; then", workflow)
        self.assertIn('set -- "$@" ptxray-review-validate.awk', workflow)
        self.assertIn('sh tools/ci/egress-lint.sh "$@"', workflow)
        self.assertIn(
            "python3 tools/check-no-ibm-redistribution.py",
            workflow,
        )
        self.assertIn(
            'python3 tools/verify-release-integrity.py --tag "$RELEASE_TAG"',
            workflow,
        )
        self.assertIn("openssl version", workflow)
        self.assertIn('gh release download "$RELEASE_TAG"', workflow)
        self.assertIn(
            '--assets-dir "$RUNNER_TEMP/release-assets"',
            workflow,
        )
        self.assertIn(
            "startsWith(github.event.release.tag_name, 'v')",
            workflow,
        )
        verify_guide = VERIFY_GUIDE.read_text(encoding="utf-8")
        self.assertIn(
            "python3 tools/verify-release-integrity.py --tag v0.1.0",
            verify_guide,
        )
        self.assertIn(
            '--assets-dir release-assets',
            verify_guide,
        )

    def test_verify_guide_prepares_signature_first_without_fake_fingerprint(self) -> None:
        guide = VERIFY_GUIDE.read_text(encoding="utf-8")
        signature_heading = "## Verify the signed manifest first"
        self.assertIn(signature_heading, guide)
        self.assertLess(guide.index(signature_heading), guide.index("## Pin the public revision"))
        signature_section = guide.split(signature_heading, 1)[1].split("## ", 1)[0]

        for artifact in (
            "ptxray-aix.sh",
            "ptxray-ibmi.sh",
            "ptxray-defs.sh",
            "ptxray-review-pack.sh",
            "ptxray-review-validate.awk",
            "aixray-aix.sh",
            "SHA256SUMS",
            "SHA256SUMS.sig",
            "POWERTRUE-RELEASE-PUBLIC.pem",
        ):
            with self.subTest(artifact=artifact):
                self.assertIn(artifact, signature_section)
        self.assertIn(
            "openssl pkey -pubin -in POWERTRUE-RELEASE-PUBLIC.pem -outform DER",
            signature_section,
        )
        self.assertIn(
            "openssl dgst -sha256 -verify POWERTRUE-RELEASE-PUBLIC.pem "
            "-signature SHA256SUMS.sig SHA256SUMS",
            signature_section,
        )
        self.assertRegex(signature_section, r"(?s)RSA-3072.*SHA-256.*PKCS#1 v1\.5")
        self.assertRegex(signature_section.casefold(), r"not\s+(?:yet\s+)?published")
        self.assertIn("independent", signature_section.casefold())
        self.assertIn("fingerprint", signature_section.casefold())
        self.assertNotRegex(signature_section, r"(?i)expected fingerprint\s*:")

    def test_scanner_has_no_egress_command_primitive(self) -> None:
        self.assertTrue(EGRESS_LINTER.is_file(), f"missing linter: {EGRESS_LINTER}")

        def lint(path: Path) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["sh", str(EGRESS_LINTER), str(path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )

        for artifact in (SCANNER, REVIEW_HELPER):
            clean = lint(artifact)
            with self.subTest(clean_artifact=artifact.name):
                self.assertEqual(
                    0,
                    clean.returncode,
                    clean.stdout + clean.stderr,
                )
        probes = (
            'x="$(curl https://example.invalid)"',
            "command curl https://example.invalid",
            "env curl https://example.invalid",
            "/usr/bin/curl https://example.invalid",
            "host example.invalid",
            "command nslookup example.invalid",
            "tftp example.invalid",
            "sftp example.invalid",
            "rcp local-file example.invalid:/tmp/remote-file",
            "rsh example.invalid true",
            "rexec example.invalid true",
            "socat TCP:example.invalid:443 -",
            "ping example.invalid",
            "traceroute example.invalid",
            "sendmail recipient@example.invalid",
            "exec 3<>/dev/tcp/example.invalid/443",
            "exec 4<>/dev/udp/example.invalid/53",
        )
        source = SCANNER.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix="aixray-public-egress-") as temp:
            temp_root = Path(temp)
            for index, probe in enumerate(probes):
                candidate = temp_root / f"probe-{index}.sh"
                candidate.write_text(f"{source}\n{probe}\n", encoding="utf-8")
                result = lint(candidate)
                with self.subTest(probe=probe):
                    self.assertEqual(1, result.returncode, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
