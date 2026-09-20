#!/usr/bin/env python3
"""Lint every packaged assessment executable, including renderers and libraries.

The exact root downloader is the only exclusion: acquisition precedes assessment.
No archive extraction occurs before the archive shape has been validated.
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import sys
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('proof', ROOT/'tools/verify-composed-release.py')
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)

def main():
    version = json.loads((ROOT/'catalog.json').read_text())['tool_version']
    with tempfile.TemporaryDirectory(prefix='ptxray-packaged-egress-') as temp:
        directory = Path(temp)
        paths = []
        seen = set()
        for platform in ('aix','ibmi'):
            name = f'ptxray-report-{platform}-{version}.tar'
            proof.validate_report_bundle(ROOT/name, name)
            for member, contents in proof.tar_regular_member_payloads(ROOT/name, name).items():
                content = contents[0]
                if member == 'ptxray-defs.sh':
                    continue
                if not (member.endswith(('.sh','.ksh','.awk')) or content.startswith(b'#!')):
                    continue
                # Identical shared programs in the two bundles need one lint pass.
                if content in seen: continue
                seen.add(content)
                path = directory/platform/member
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(content)
                paths.append(path)
        paths.extend(ROOT/name for name in ('aixray-aix.sh','aixray-scan.ksh','ibmi-scan.ksh','ptxray-review-pack.sh','ptxray-review-validate.awk'))
        paths.extend(sorted((ROOT/'checks').glob('*/*.ksh')))
        # Public checks and bundled checks must be byte-identical (funnel gate).
        # Deduplicate here as well, keeping every distinct shipped program.
        unique = []; seen.clear()
        for path in paths:
            content = path.read_bytes()
            if content not in seen: unique.append(path); seen.add(content)
        result = subprocess.run(['sh',str(ROOT/'tools/ci/egress-lint.sh'),*[str(p) for p in unique]],capture_output=True,text=True)
        if result.returncode:
            print(result.stdout,end=''); print(result.stderr,end='',file=sys.stderr)
        else:
            print(f'packaged-egress: PASS ({len(unique)} distinct assessment/review programs)')
        return result.returncode

if __name__ == '__main__':
    try: raise SystemExit(main())
    except (proof.ProofError,OSError,ValueError,KeyError) as exc:
        print(f'packaged-egress: FAIL: {exc}',file=sys.stderr); raise SystemExit(1)
