#!/usr/bin/env python3
"""Composed release archive rejection tests; historical tests remain separate."""
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("proof", ROOT / "tools/verify-composed-release.py")
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)

class ComposedBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "ptxray-report-aix-1.8.0.tar"
        self.members = {
            "README-REPORT.md": b"Run dist/tools/aixray-scan.ksh",
            "dist/tools/aixray-scan.ksh": b"#!/bin/ksh\nexit 0\n",
            "dist/compose/group-registry.tsv": b"ck-example\texample\tops\n",
            "dist/tools/ck-example.ksh": b"#!/bin/ksh\nexit 0\n",
            "dist/render/compose/run.ksh": b"#!/bin/ksh\nexit 0\n",
        }
    def write(self, extra=None):
        with tarfile.open(self.path, "w") as archive:
            for name, content in self.members.items():
                info = tarfile.TarInfo(name); info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
            if extra:
                info, content = extra
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
    def validate(self):
        proof.validate_report_bundle(self.path, self.path.name)
    def test_valid_composed_bundle(self):
        self.write(); self.validate()
    def test_missing_required_members(self):
        for name in tuple(self.members):
            with self.subTest(name=name):
                saved = self.members.pop(name); self.write()
                with self.assertRaises(proof.ProofError): self.validate()
                self.members[name] = saved
    def test_unsafe_paths(self):
        for name in ("../outside", "/tmp/outside", "dist/../../outside", "dist/../outside", "dist/./tools/x", "dist//tools/x", "dist\\outside"):
            with self.subTest(name=name):
                self.write((tarfile.TarInfo(name), b"x"))
                with self.assertRaisesRegex(proof.ProofError, "unsafe member"): self.validate()
    def test_links_and_special_files(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE):
            with self.subTest(kind=kind):
                info = tarfile.TarInfo("dist/link"); info.type = kind; info.linkname = "/tmp/outside"
                self.write((info, b""))
                with self.assertRaisesRegex(proof.ProofError, "nonregular member"): self.validate()
    def test_duplicate_members(self):
        self.write((tarfile.TarInfo("README-REPORT.md"), b"duplicate"))
        with self.assertRaisesRegex(proof.ProofError, "duplicate member"): self.validate()
    def test_retired_monolith(self):
        self.write((tarfile.TarInfo("dist/tools/ptxray-aix.sh"), b"retired"))
        with self.assertRaisesRegex(proof.ProofError, "retired monolith"): self.validate()
    def test_unexpected_root_executable(self):
        for name, mode in (("install.sh", 0o644), ("unknown", 0o755), ("data/install.ksh", 0o644)):
            info = tarfile.TarInfo(name); info.mode = mode
            self.write((info, b"#!/bin/sh\nexit 0\n"))
            with self.subTest(name=name), self.assertRaisesRegex(proof.ProofError, "unexpected executable"): self.validate()
    def test_ibm_raw_filenames(self):
        for name in ("data/apar.csv", "dist/tools/flrtvc.ksh"):
            self.write((tarfile.TarInfo(name), b"IBM delivery payload"))
            with self.subTest(name=name), self.assertRaisesRegex(proof.ProofError, "IBM delivery data"): self.validate()
    def test_renamed_ibm_engine_signature(self):
        self.write((tarfile.TarInfo("dist/tools/renamed.ksh"), b'#!/bin/ksh93\nVERSION="1.0"\nparseLSLPP parseEFIX\n'))
        with self.assertRaisesRegex(proof.ProofError, "IBM delivery data"): self.validate()
    def test_filled_delivery_embed_slot(self):
        self.write((tarfile.TarInfo("dist/tools/bundled.ksh"), b"flrtvc_" + b"ksh_b64='payload'\n"))
        with self.assertRaisesRegex(proof.ProofError, "IBM delivery data"): self.validate()
    def test_legitimate_shared_runtime_path(self):
        self.write((tarfile.TarInfo("dist/lib/flrtvc-runtime.ksh"), b"fv_example() { :; }\n"))
        self.validate()

if __name__ == "__main__": unittest.main(verbosity=2)
