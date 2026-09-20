#!/usr/bin/env python3
"""Offline contract tests for the public PTxray customer funnel."""

from __future__ import annotations

import errno
import hashlib
import http.server
import json
from pathlib import Path
import re
import shutil
import socketserver
import subprocess
import tempfile
import threading
import unittest
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
SCANNER = ROOT / "aixray-scan.ksh"
SCANNER_IBMI = ROOT / "ibmi-scan.ksh"
REVIEW_HELPER = ROOT / "ptxray-review-pack.sh"
EGRESS_LINTER = ROOT / "tools" / "ci" / "egress-lint.sh"
RELEASE_INTEGRITY_GATE = ROOT / "tools" / "verify-release-integrity.py"
RELEASE_SHAPE_SYNC = ROOT / "tools" / "sync-release-shape.py"
PUBLIC_WORKFLOW = ROOT / ".github" / "workflows" / "public-checks.yml"
VERIFY_GUIDE = ROOT / "docs" / "VERIFY.md"
RELEASE_NOTES = ROOT / "docs" / "RELEASE-NOTES.md"
SECURITY_POLICY = ROOT / "SECURITY.md"
JSONLD = ROOT / "ptxray.jsonld"
DOWNLOAD_PAGE_URL = "https://powertruesystems.com/ptxray/"
CANONICAL_REPOSITORY_URL = "https://github.com/PowerTrueSYS/ptxray-public"
PUBLISHED_VERSION = json.loads((ROOT / "catalog.json").read_text())["tool_version"]
REPORT_BUNDLE_AIX = f"ptxray-report-aix-{PUBLISHED_VERSION}.tar"
REPORT_BUNDLE_IBMI = f"ptxray-report-ibmi-{PUBLISHED_VERSION}.tar"
SIGNED_PAYLOADS = (
    "aixray-aix.sh",
    "aixray-scan.ksh",
    "ptxray-defs.sh",
    "ibmi-scan.ksh",
    "ptxray-review-pack.sh",
    "ptxray-review-validate.awk",
    REPORT_BUNDLE_AIX,
    REPORT_BUNDLE_IBMI,
)
CUSTOMER_FILES = (
    ROOT / "README.md",
    SITE / "index.html",
    JSONLD,
    ROOT / "llms.txt",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def inline_jsonld(site_html: str):
    match = re.search(r'<script\s+type="application/ld\+json">(.*?)</script>', site_html, re.DOTALL)
    if match is None: raise AssertionError("site has no inline JSON-LD block")
    return json.loads(match.group(1))

class PublicFunnelTests(unittest.TestCase):
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
        self.assertEqual("aixray-scan.ksh", assembled.get("artifact"))
        expected = sha256(SCANNER)
        self.assertEqual(expected, assembled.get("sha256"))

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
            (SCANNER, "PTXRAY_RUNNER_VERSION"),
            (REVIEW_HELPER, "AIXRAY_REVIEW_PACK_VERSION"),
        ):
            versions = re.findall(
                rf'(?m)^{variable}=["\']([^"\']+)["\'][ \t]*$',
                artifact.read_text(encoding="utf-8"),
            )
            with self.subTest(artifact=artifact.name, contract="current version"):
                self.assertEqual([declared_version], versions)

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

    @classmethod
    def setUpClass(cls):
        import tarfile
        cls.bundle_members = {}
        for platform in ('aix', 'ibmi'):
            with tarfile.open(ROOT / f'ptxray-report-{platform}-{PUBLISHED_VERSION}.tar') as archive:
                cls.bundle_members[platform] = {
                    m.name.removeprefix('./'): archive.extractfile(m).read()
                    for m in archive if m.isfile()
                }

    def test_current_release_signed_tree(self):
        result = subprocess.run(['python3', str(RELEASE_INTEGRITY_GATE), '--repo-root', str(ROOT), '--tag', 'v'+PUBLISHED_VERSION], capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stdout+result.stderr)

    def test_manifest_exact_eight_payloads(self):
        entries = {}
        for line in (ROOT/'SHA256SUMS').read_text().splitlines():
            digest, name = line.split('  ', 1)
            self.assertNotIn(name, entries)
            self.assertRegex(digest, r'^[0-9a-f]{64}$')
            entries[name] = digest
        self.assertEqual(set(SIGNED_PAYLOADS), set(entries))
        for name, digest in entries.items():
            self.assertEqual(digest, sha256(ROOT/name), name)

    def test_downloads_are_complete_direct_bundles(self):
        html = (SITE/'index.html').read_text()
        readme = (ROOT/'README.md').read_text()
        for platform in ('aix','ibmi'):
            filename = f'ptxray-report-{platform}-{PUBLISHED_VERSION}.tar'
            self.assertIn(filename, html)
            self.assertIn(filename, readme)
            self.assertRegex(html, r'https://github.com/PowerTrueSYS/ptxray-public/releases/(?:download/v'+re.escape(PUBLISHED_VERSION)+r'|latest/download)/'+re.escape(filename))
        self.assertNotRegex(html, r'(?is)<form[^>]*>[^<]*(?:download|report bundle)')
        self.assertNotRegex(html, r'(?i)(?:href|action)=["\'][^"\']*(?:ptxray-aix\.sh|ptxray-ibmi\.sh)')
        self.assertIn('--compliance all', readme)
        self.assertIn('dist/tools/aixray-scan.ksh', readme)
        self.assertIn('dist/tools/ibmi-scan.ksh', readme)

    def test_customer_identity_version_count_and_license(self):
        catalog = json.loads((ROOT/'catalog.json').read_text())
        standalone = json.loads(JSONLD.read_text())
        self.assertEqual(standalone, inline_jsonld((SITE/'index.html').read_text()))
        self.assertEqual('PTxray', standalone['name'])
        self.assertEqual(PUBLISHED_VERSION, standalone['softwareVersion'])
        self.assertEqual(DOWNLOAD_PAGE_URL, standalone['url'])
        self.assertEqual(CANONICAL_REPOSITORY_URL, standalone['codeRepository'])
        self.assertIn('apache.org/licenses/LICENSE-2.0', standalone['license'])
        for path in CUSTOMER_FILES:
            text = path.read_text()
            with self.subTest(surface=path.name):
                self.assertIn(PUBLISHED_VERSION, text)
                self.assertIn(str(catalog['check_count']), text)
                self.assertNotRegex(text, r'https://(?:github.com/PowerTrueSYS/aixray-public|powertruesystems.com/aixray)')
                self.assertNotRegex(text, r'(?i)(?:100%|full|complete) (?:CIS|STIG|benchmark) (?:coverage|compliance)')
                self.assertNotRegex(text, r'(?i)\b(?:66|209|76|89) (?:controls|recommendations|checks)\b')
                self.assertNotRegex(text, r'(?i)(?:single[- ]file|one[- ]file) (?:scanner|assessment|product)')

    def test_claims_preserve_acquisition_assessment_boundary(self):
        for path in CUSTOMER_FILES:
            text = ' '.join(path.read_text().lower().split())
            with self.subTest(surface=path.name):
                self.assertIn('assessment', text)
                self.assertIn('before assessment', text)
                self.assertIn('no remediation', text) if path.suffix=='.html' else self.assertRegex(text, r'(?:no|without|perform no) remediation')
                self.assertRegex(text, r'(?:no network calls|without network calls|no-egress assessment)')
                self.assertRegex(text, r'(?:no assessment data|assessment-data upload|no assessment-data|no assessment telemetry)')
                self.assertIn('vios', text)
                self.assertIn('disabled', text)
        readme = (ROOT/'README.md').read_text().lower()
        for required in ('ksh93', 'openssl', 'unzip', 'qsecofr', '--offline', 'pseudonym'):
            self.assertIn(required, readme)
        self.assertRegex(readme, r'(?s)review.*helper.*reject.*current.*composed')
        privacy = SECURITY_POLICY.read_text().lower()
        self.assertRegex(privacy, r'not guaranteed anonym|not anonym')
        self.assertRegex(privacy, r'(?:review|inspect).*before sharing')
        self.assertRegex(privacy, r'(?:never|do not) share.*key')

    def test_signature_first_guide_and_independent_fingerprint(self):
        guide = VERIFY_GUIDE.read_text()
        sig = 'openssl dgst -sha256 -verify POWERTRUE-RELEASE-PUBLIC.pem -signature SHA256SUMS.sig SHA256SUMS'
        self.assertIn(sig, guide)
        self.assertIn('openssl pkey -pubin -in POWERTRUE-RELEASE-PUBLIC.pem -outform DER', guide)
        self.assertIn('sha256:c2fa7dc69be3dead5e196eca6a9c48ece42a7105eb9f56ab9f620bd0c6c617bd', guide)
        self.assertIn('independent', guide.lower())
        self.assertLess(guide.index(sig), guide.index('python3 tools/verify-release-integrity.py'))
        for name in (*SIGNED_PAYLOADS, 'SHA256SUMS', 'SHA256SUMS.sig', 'POWERTRUE-RELEASE-PUBLIC.pem'):
            self.assertIn(name, guide)
        self.assertIn('private', SECURITY_POLICY.read_text().lower())
        self.assertIn('https://github.com/PowerTrueSYS/ptxray-public/security/advisories/new', SECURITY_POLICY.read_text())
        self.assertRegex(SECURITY_POLICY.read_text(), r'mailto:[^\s)]+@powertruesystems\.com')

    def test_bundle_runners_are_exact_release_copies(self):
        self.assertEqual((ROOT/'aixray-aix.sh').read_bytes(), SCANNER.read_bytes())
        for platform, runner in [('aix',SCANNER),('ibmi',SCANNER_IBMI)]:
            members = self.bundle_members[platform]
            self.assertEqual(runner.read_bytes(), members['dist/tools/'+runner.name])
            self.assertEqual((ROOT/'ptxray-defs.sh').read_bytes(), members['ptxray-defs.sh'])
            self.assertIn('README-REPORT.md', members)
            self.assertNotIn(b'--monolith', members['README-REPORT.md'])

    def test_registered_checks_are_shipped_and_catalogued(self):
        catalog = {entry['id']:entry for entry in json.loads((ROOT/'catalog.json').read_text())['checks']}
        for platform, registry, prefix in [('aix','dist/compose/group-registry.tsv','dist/tools/'), ('ibmi','dist/compose/ibmi-group-registry.tsv','dist/ibmi/tools/')]:
            members = self.bundle_members[platform]
            rows = [line.split('\t') for line in members[registry].decode().splitlines() if line and not line.startswith('#')]
            ids = [row[0] for row in rows]
            self.assertEqual(len(ids), len(set(ids)))
            self.assertGreater(len(ids), 0)
            if platform == 'aix':
                self.assertEqual(set(ids), {check for check, entry in catalog.items() if not entry.get('pared')})
            else:
                self.assertEqual(set(ids), {name.rsplit('/', 1)[-1][:-4] for name in members if name.startswith(prefix+'ck-') and name.endswith('.ksh')})
            for row in rows:
                check, findings, tags = row
                with self.subTest(platform=platform, check=check):
                    self.assertIn(prefix+check+'.ksh', members)
                    source = members[prefix+check+'.ksh'].decode()
                    self.assertIn(f'AIXRAY_STANDALONE_VERSION="{PUBLISHED_VERSION}"', source)
                    if platform == 'ibmi':
                        for finding in findings.split(','):
                            self.assertIn(finding, source)
                    if platform == 'aix':
                        self.assertIn(check, catalog)
                        self.assertEqual(set(findings.split(',')), set(catalog[check]['finding_ids']))
                        self.assertEqual(set(tags.split(',')) - {'ops', '-'}, set(catalog[check]['tags']) - {'ops'})
                        self.assertEqual(members[prefix+check+'.ksh'], (ROOT/catalog[check]['artifact']).read_bytes())
            tagset = {tag for row in rows for tag in row[2].split(',')}
            self.assertTrue({'cis-l1','cis-l2','ops'}.issubset(tagset))

    def test_reports_preserve_missing_evidence_and_privacy(self):
        for platform, members in self.bundle_members.items():
            render = b'\n'.join(content for name, content in members.items() if name.startswith('dist/render/'))
            with self.subTest(platform=platform):
                for status in (b'PASS',b'FAIL',b'WARN',b'NOT_ASSESSED',b'NOT_APPLICABLE'):
                    self.assertIn(status, render)
                self.assertIn(b'aixray-privacy-schema', render)
                self.assertIn(b'data-aixray-field', render)
                self.assertIn(b'data-aixray-location', render)
                self.assertIn(b'name="aixray-privacy-schema" content="1"', render)

    def test_no_unrendered_build_placeholders(self):
        for name in ('ptxray-review-pack.sh','aixray-scan.ksh','ibmi-scan.ksh','ptxray-defs.sh'):
            self.assertNotRegex((ROOT/name).read_bytes(), rb'@@[A-Z][A-Z0-9_]+@@', name)
        for platform, members in self.bundle_members.items():
            for name, content in members.items():
                if name.endswith(('.sh','.ksh','.awk')) or content.startswith(b'#!'):
                    with self.subTest(platform=platform, member=name):
                        self.assertNotRegex(content, rb'@@(?:PTXRAY|AIXRAY)_[A-Z0-9_]+@@')

    def test_shell_syntax_of_public_entrypoints(self):
        for path in (SCANNER,SCANNER_IBMI,REVIEW_HELPER,ROOT/'ptxray-defs.sh'):
            result = subprocess.run(['ksh','-n',str(path)],capture_output=True,text=True)
            self.assertEqual(0,result.returncode,result.stderr)

    def test_ci_preserves_all_release_gates(self):
        workflow = PUBLIC_WORKFLOW.read_text()
        for gate in ('tests/run-tests.sh','tools/sync-release-shape.py --check','tests/check-packaged-egress.py','tools/check-no-ibm-redistribution.py','tools/verify-release-integrity.py','--assets-dir','persist-credentials: false'):
            self.assertIn(gate, workflow)
        self.assertNotRegex(workflow,r'uses: actions/checkout@(?:v\d|main|master)\b')
        self.assertNotIn('continue-on-error: true',workflow)

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

    def test_review_helper_retains_safe_send_transaction_guards(self):
        source = REVIEW_HELPER.read_text()
        for literal in ('DO NOT SEND', 'REVIEW REQUIRED', 'privacy schema 2', '0600', 'source report changed', 'ptxray-local-key-', 'ptxray-review-'):
            self.assertIn(literal, source)
        self.assertNotRegex(source, r'(?m)^\s*(?:curl|wget|scp|ssh|sendmail)\s')

    def test_same_package_downloader_digest_and_runtime_are_shipped(self):
        for platform, members in self.bundle_members.items():
            with self.subTest(platform=platform):
                self.assertIn('dist/lib/flrtvc-runtime.ksh', members)
                pin = members['dist/data/definitions-downloader.sha256'].decode().strip()
                self.assertRegex(pin, r'^[0-9a-f]{64}$')
                self.assertEqual(pin, hashlib.sha256(members['ptxray-defs.sh']).hexdigest())
                runner = members['dist/tools/'+('aixray-scan.ksh' if platform=='aix' else 'ibmi-scan.ksh')]
                self.assertIn(b'fv_stage_downloader', runner)
                self.assertNotIn(b'command -v ptxray-defs.sh', runner)

    def test_aix_full_runner_requires_completed_offline_flrtvc(self):
        members = self.bundle_members['aix']
        runner = members['dist/tools/aixray-scan.ksh']
        adapter = members['dist/tools/flrtvc-run.ksh']
        for literal in (b'flrtvc-run', b'--validate-clean', b'--currency-state', b'--highest-cvss'):
            self.assertIn(literal, runner)
        self.assertIn(b'./engine.ksh -s -f ./apar.csv -l ./lslpp-input -e ./emgr', adapter)
        self.assertIn('dist/data/flrtvc-pin.txt', members)
        # IBM bytes are acquisition inputs; they must not become bundle members.
        self.assertFalse(any(name.rsplit('/',1)[-1] in ('flrtvc.ksh','apar.csv') for name in members))

    def test_documented_public_audit_paths_resolve(self):
        readme = (ROOT/'README.md').read_text()
        for relative in ('catalog.json','checks/','docs/VERIFY.md','SECURITY.md','LICENSE'):
            self.assertIn(relative, readme)
            self.assertTrue((ROOT/relative).exists())
        for private_path in ('tools.d/checks','src/ptxray-aix.sh.in','docs/ASSEMBLE.md'):
            self.assertNotIn(private_path, readme)

    def test_generated_copy_rejects_and_repairs_count_and_version_drift(self):
        with tempfile.TemporaryDirectory(prefix='ptxray-copy-test-') as temp:
            candidate = Path(temp)
            for path in (*CUSTOMER_FILES, ROOT/'catalog.json'):
                target = candidate/path.relative_to(ROOT); target.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(path,target)
            command = ['python3',str(RELEASE_SHAPE_SYNC),'--repo-root',str(candidate)]
            clean = subprocess.run(command+['--check'],capture_output=True,text=True)
            self.assertEqual(0,clean.returncode,clean.stdout+clean.stderr)
            original = (candidate/'README.md').read_text()
            count = str(json.loads((ROOT/'catalog.json').read_text())['check_count'])
            for old,new in ((count,str(int(count)+1)),(PUBLISHED_VERSION,'9.9.9')):
                (candidate/'README.md').write_text(original.replace(old,new))
                drift = subprocess.run(command+['--check'],capture_output=True,text=True)
                self.assertNotEqual(0,drift.returncode)
                fixed = subprocess.run(command,capture_output=True,text=True)
                self.assertEqual(0,fixed.returncode,fixed.stdout+fixed.stderr)
                recheck = subprocess.run(command+['--check'],capture_output=True,text=True)
                self.assertEqual(0,recheck.returncode,recheck.stdout+recheck.stderr)

    def test_bundle_bytes_survive_direct_http_download(self):
        class QuietHandler(http.server.SimpleHTTPRequestHandler):
            def log_message(self,*args): pass
        handler = lambda *args,**kwargs: QuietHandler(*args,directory=str(ROOT),**kwargs)
        try:
            server = socketserver.TCPServer(('127.0.0.1',0),handler)
        except PermissionError as exc:
            if exc.errno not in (errno.EACCES,errno.EPERM): raise
            self.skipTest('execution sandbox blocks a loopback listener')
        with server:
            thread = threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                name = REPORT_BUNDLE_AIX
                with urllib.request.urlopen(f'http://127.0.0.1:{server.server_address[1]}/{name}',timeout=5) as response:
                    self.assertEqual(200,response.status)
                    self.assertEqual(sha256(ROOT/name),hashlib.sha256(response.read()).hexdigest())
            finally:
                server.shutdown();thread.join(timeout=5)

if __name__ == '__main__':
    unittest.main(verbosity=2)
