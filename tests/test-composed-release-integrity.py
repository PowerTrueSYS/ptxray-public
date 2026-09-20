#!/usr/bin/env python3
"""Exercise composed CLI validation with a signed isolated synthetic release."""
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT/'tools/verify-release-integrity.py'
VERSION = '1.8.1'
PAYLOADS = ('aixray-aix.sh','aixray-scan.ksh','ibmi-scan.ksh','ptxray-defs.sh','ptxray-review-pack.sh','ptxray-review-validate.awk','ptxray-report-aix-1.8.1.tar','ptxray-report-ibmi-1.8.1.tar')
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
class ComposedReleaseIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keytmp = tempfile.TemporaryDirectory()
        cls.key = Path(cls.keytmp.name)/'key.pem'
        subprocess.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:3072','-out',str(cls.key)],check=True,capture_output=True)
        # A private fixture trust root exercises signature negatives without
        # requiring the vendor signing key or changing the production verifier.
        der = subprocess.run(['openssl','pkey','-in',str(cls.key),'-pubout','-outform','DER'],check=True,capture_output=True).stdout
        pin = 'sha256:' + hashlib.sha256(der).hexdigest()
        cls.tools = Path(cls.keytmp.name)/'tools'; cls.tools.mkdir()
        for name in ('verify-release-integrity.py','verify-composed-release.py','check-no-ibm-redistribution.py'):
            content = (ROOT/'tools'/name).read_text()
            if name == 'verify-composed-release.py':
                content = content.replace('sha256:c2fa7dc69be3dead5e196eca6a9c48ece42a7105eb9f56ab9f620bd0c6c617bd',pin)
            (cls.tools/name).write_text(content)
    @classmethod
    def tearDownClass(cls): cls.keytmp.cleanup()
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)/'tree'; self.root.mkdir()
        self.assets = Path(self.tmp.name)/'assets'
        for name, variable in [('aixray-scan.ksh','PTXRAY_RUNNER_VERSION'),('ibmi-scan.ksh','PTXRAY_RUNNER_VERSION'),('ptxray-defs.sh','PTXRAY_DEFS_VERSION'),('ptxray-review-pack.sh','AIXRAY_REVIEW_PACK_VERSION')]:
            (self.root/name).write_text(f'#!/bin/ksh\n{variable}="{VERSION}"\nexit 0\n')
        shutil.copyfile(self.root/'aixray-scan.ksh',self.root/'aixray-aix.sh')
        (self.root/'ptxray-review-validate.awk').write_text('BEGIN { exit 0 }\n')
        check = self.root/'checks/ck-example/ck-example.ksh'; check.parent.mkdir(parents=True)
        check.write_text(f'#!/bin/ksh\nAIXRAY_STANDALONE_VERSION="{VERSION}"\nexit 0\n')
        (self.root/'catalog.json').write_text(json.dumps({'tool_version':VERSION,'check_count':1,'checks':[{'id':'ck-example','artifact':'checks/ck-example/ck-example.ksh','sha256':sha(check)}]}))
        catalog = json.loads((self.root/'catalog.json').read_text())
        for field,name in [('assembled_scanner','aixray-scan.ksh'),('review_pack','ptxray-review-pack.sh'),('review_validator','ptxray-review-validate.awk')]:
            catalog[field] = {'artifact':name,'sha256':sha(self.root/name)}
        (self.root/'catalog.json').write_text(json.dumps(catalog))
        for platform in ('aix','ibmi'):
            with tarfile.open(self.root/f'ptxray-report-{platform}-{VERSION}.tar','w') as archive:
                for name in ('README-REPORT.md',f'dist/tools/{"aixray" if platform=="aix" else "ibmi"}-scan.ksh',f'dist/compose/{"" if platform=="aix" else "ibmi-"}group-registry.tsv',f'dist/{"" if platform=="aix" else "ibmi/"}tools/ck-example.ksh','dist/render/compose/run.ksh'):
                    info=tarfile.TarInfo(name); content=b'synthetic fixture\n'; info.size=len(content); archive.addfile(info,io.BytesIO(content))
        subprocess.run(['openssl','pkey','-in',str(self.key),'-pubout','-out',str(self.root/'POWERTRUE-RELEASE-PUBLIC.pem')],check=True,capture_output=True)
        self.sign()
    def sign(self):
        (self.root/'SHA256SUMS').write_text(''.join(f'{sha(self.root/name)}  {name}\n' for name in sorted(PAYLOADS)))
        subprocess.run(['openssl','dgst','-sha256','-sign',str(self.key),'-out',str(self.root/'SHA256SUMS.sig'),str(self.root/'SHA256SUMS')],check=True,capture_output=True)
        self.assets.mkdir(exist_ok=True)
        for name in (*PAYLOADS,'SHA256SUMS','SHA256SUMS.sig','POWERTRUE-RELEASE-PUBLIC.pem'): shutil.copyfile(self.root/name,self.assets/name)
    def gate(self, tree_only=False):
        args=['python3',str(self.tools/'verify-release-integrity.py'),'--tag','v'+VERSION,'--repo-root',str(self.root)]
        if not tree_only: args += ['--assets-dir',str(self.assets)]
        return subprocess.run(args,capture_output=True,text=True)
    def accepted(self, **kwargs):
        result=self.gate(**kwargs); self.assertEqual(0,result.returncode,result.stdout+result.stderr)
    def refused(self, reason):
        result=self.gate(); self.assertEqual(1,result.returncode,result.stdout+result.stderr); self.assertIn(reason,result.stderr)
    def test_valid_signed_composed_release(self): self.accepted()
    def test_tree_only(self): self.accepted(tree_only=True)
    def test_production_verifier_rejects_fixture_trust_root(self):
        result = subprocess.run(['python3', str(GATE), '--tag', 'v'+VERSION, '--repo-root', str(self.root), '--assets-dir', str(self.assets)], capture_output=True, text=True)
        self.assertEqual(1, result.returncode)
        self.assertIn('public key fingerprint mismatch', result.stderr)
    def test_catalog_runner_metadata_tamper(self):
        path = self.root/'catalog.json'; data = json.loads(path.read_text())
        data['assembled_scanner']['sha256'] = '0'*64; path.write_text(json.dumps(data))
        self.refused('catalog assembled_scanner digest mismatch')
    def test_missing_payload(self):
        (self.assets/'aixray-scan.ksh').unlink(); self.refused('missing')
    def test_unexpected_asset(self):
        (self.assets/'extra.sh').write_text('bad'); self.refused('unexpected release asset')
    def test_tampered_payload(self):
        (self.assets/'aixray-scan.ksh').write_text('bad'); self.refused('mismatch')
    def test_signature_tamper(self):
        (self.root/'SHA256SUMS.sig').write_bytes(b'invalid'); shutil.copyfile(self.root/'SHA256SUMS.sig',self.assets/'SHA256SUMS.sig'); self.refused('signature')
    def test_manifest_tamper(self):
        for parent in (self.root,self.assets):
            with (parent/'SHA256SUMS').open('a') as f: f.write('0'*64+'  unknown.sh\n')
        self.refused('paths are not exact')
    def test_alias_drift_even_when_signed(self):
        (self.root/'aixray-aix.sh').write_text('alias differs'); self.sign(); self.refused('byte copy')
    def test_payload_version_even_when_signed(self):
        p=self.root/'ibmi-scan.ksh';p.write_text(p.read_text().replace(VERSION,'1.9.0'));self.sign();self.refused('versions')
    def test_later_runtime_version_override(self):
        with (self.root/'ibmi-scan.ksh').open('a') as f:f.write('PTXRAY_RUNNER_VERSION="9.9.9"\n')
        self.sign();self.refused('exactly one PTXRAY_RUNNER_VERSION')
    def test_catalog_digest_tamper(self):
        (self.root/'checks/ck-example/ck-example.ksh').write_text('bad');self.refused('catalog digest')
    def test_catalog_version_mismatch(self):
        p=self.root/'catalog.json';c=json.loads(p.read_text());c['tool_version']='1.7.0';p.write_text(json.dumps(c));self.refused('catalog version')
    def test_symlinked_catalog_parent(self):
        source=self.root/'checks/ck-example'; dest=self.root/'relocated';source.rename(dest);source.symlink_to(dest,target_is_directory=True);self.refused('symlink')
    def test_symlinked_release_payload(self):
        source=self.root/'aixray-scan.ksh'; dest=self.root/'relocated';source.rename(dest);source.symlink_to(dest);self.refused('nonsymlink')
if __name__=='__main__':unittest.main(verbosity=2)
