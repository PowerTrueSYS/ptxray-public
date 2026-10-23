#!/usr/bin/env python3
"""Fail closed if IBM-derived data, a definitions bundle, or banned claims are committed.

PTxray's data principle (docs/DESIGN-PRINCIPLES.md): a scan fetches the latest
IBM and CISA data itself at run time. PowerTrue hosts, signs and ships no
IBM-derived data and no definitions bundle. This guard enforces that on:

  (a) the complete Git index (honors GIT_INDEX_FILE, so it works as a
      pre-commit hook and in CI): IBM-derived data files, bundle envelopes,
      bundle/signature file names, and base64-wrapped copies of any of them
      (decoded, and gunzipped when wrapped), plus gzip-wrapped blobs;
  (b) a release asset list (--asset-list FILE, one name per line) and/or an
      assets directory (--assets-dir DIR, names and contents);
  (c) current docs: the banned phrases and the hosted definitions URL must not
      come back. Historical records (release notes, build notes, superpowers
      plans, decomposition and evidence logs, research) are exempt.

It reports only paths and reasons, never the prohibited bytes.

Usage:
  check-no-ibm-defs-distribution.py [--assets-only] [--asset-list FILE]
                                    [--assets-dir DIR]
Exit 0 clean, 1 violations, 2 could not inspect.
"""

import argparse
import base64
import binascii
import fnmatch
import os
import re
import subprocess
import sys
import zlib

# A real bundle starts with its magic line, carries payload records and ends with an END-BUNDLE line.
# Source code that merely names the magic does not match.
BUNDLE_MAGIC_RE = re.compile(rb"(?m)^(?:PTXRAY|AIXRAY)-DEFINITION-BUNDLE\|[0-9]+[ \t\r]*$")
BUNDLE_END_RE = re.compile(rb"(?m)^END-BUNDLE\|[^\r\n]*$")
# A real payload record has a numeric size, then base64 lines. A format
# description with <placeholders> does not.
BUNDLE_PAYLOAD_RE = re.compile(rb"(?m)^BEGIN-PAYLOAD\|[a-z0-9-]+\|[0-9]+[ \t\r]*\n[A-Za-z0-9+/=]{16,}")
# The APAR CSV header on its own line, then data rows. Code and tests that quote
# the header, or synthetic fixtures with a handful of rows, do not match.
APAR_HEADER_RE = re.compile(
    rb"(?m)^type,product,versions,abstract,apars,fixedIn,ifixes,bulletinUrl,"
    rb"filesets,issued,updated,siblings,download,cvss,reboot[ \t\r]*$"
)
APAR_ROW_RE = re.compile(rb"(?m)^[a-z]+,[A-Za-z0-9._ -]+,[^\r\n]*,[^\r\n]*,[^\r\n]*,[^\r\n]*$")
APAR_MIN_ROWS = 25  # synthetic fixtures have a handful of rows; the real feed has ~1500
FIXTURE_TABLE_MIN_LINES = 25
FLRTVC_VERSION_RE = re.compile(rb'(?m)^VERSION="[0-9][^"\r\n]*"\s*$')
KEV_MIN_ENTRIES = 25
FLRT_MIN_ENTRIES = 25
PSP_MIN_ENTRIES = 25
MAX_DECODE_BYTES = 256 * 1024 * 1024
MAX_CANDIDATES = 4000
MAX_DEPTH = 4

# File names that are never allowed anywhere (tree or release assets).
BANNED_NAME_GLOBS = (
    "flrtvc.ksh",
    "apar.csv",
    "aixray-aix.bundled.sh",
    "hiper_security.csv",
    "*.ptxray-defs",
    "*.aixray-defs",
    "*.ptxray-defs.sig",
    "*.aixray-defs.sig",
    "*-defs.sig",
    "*.defs.sig",
    "latest.*defs*",
    "definitions.bundle",
    "definitions.bundle.sig",
)
# Bundle member table names: banned by name, except tiny synthetic test fixtures.
MEMBER_TABLE_NAMES = (
    "ibm-apar-csv.csv", "ibmi-psp-group-levels.tsv", "ibm-flrt-firmware.tsv",
    "cisa-kev.json",
)
FIXTURE_PATH_MARKERS = ("/fixtures/", "/test/")
# Additional release-asset-only rules: a release ships payloads, never data.
ASSET_NAME_RES = (
    re.compile(r"(^|[-_.])apar([-_.]|$)", re.I),
    re.compile(r"(^|[-_.])flrt(vc)?([-_.]|$)", re.I),
    re.compile(r"(^|[-_.])psp([-_.]|$)", re.I),
    re.compile(r"(^|[-_.])definitions?([-_.]|$)", re.I),
    re.compile(r"(^|[-_.])defs?([-_.]|$)", re.I),
    re.compile(r"(^|[-_.])kev([-_.]|$)", re.I),
)
ASSET_SAFE = {"ptxray-defs.sh"}  # legacy helper script, removed by the implementation PR

BANNED_PHRASES = (
    ("banned phrase: never phone IBM", re.compile(r"never\s+phones?\s+ibm|must\s+never\s+phone", re.I)),
    (
        "banned phrase: zero network calls",
        re.compile(
            r"zero[\s-]+network[\s-]+calls?\b"
            r"(?![\s-]+(?:during|in|by|at)[\s-]+(?:the[\s-]+)?(?:assessment|probe))",
            re.I,
        ),
    ),
    (
        "hosted definitions URL",
        re.compile(r"powertruesystems\.com/ptxray/definitions|latest\.(ptxray|aixray)-defs", re.I),
    ),
)
DOC_SCOPE_FILES = {
    "README.md", "PROJECT.md", "AGENTS.md", "CLAUDE.md", "SECURITY.md",
    "CONTRIBUTING.md", "CONTEXT.md", "STATUS.md", "llms.txt", "ptxray.jsonld",
}
DOC_SCOPE_PREFIXES = ("docs/", "site/", "mcp/README")
DOC_EXEMPT_PREFIXES = (
    "docs/superpowers/", "docs/decomposition/", "docs/lab-acceptance/",
    "docs/release-evidence/", "docs/research/", "docs/RELEASE-NOTES",
    "docs/report-reference/",
)
DOC_EXTS = (".md", ".txt", ".html", ".htm", ".json", ".jsonld", ".yml", ".yaml")

B64_LONG_RE = re.compile(rb"[A-Za-z0-9+/]{120,}={0,2}")
B64_LINE_RE = re.compile(rb"^[A-Za-z0-9+/]{16,}={0,2}$")
LINE_TRIM = b" \t\r\\\"'+;,()"


def git_bytes(*args):
    try:
        proc = subprocess.run(["git", *args], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError("could not inspect the Git index") from exc
    return proc.stdout


def decode_b64(text):
    text = re.sub(rb"[^A-Za-z0-9+/=]", b"", text)
    text = text.rstrip(b"=")
    if len(text) < 200:
        return None
    text += b"=" * (-len(text) % 4)
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None


def plain_reasons(blob):
    reasons = []
    if (BUNDLE_MAGIC_RE.search(blob) and BUNDLE_END_RE.search(blob)
            and BUNDLE_PAYLOAD_RE.search(blob)):
        reasons.append("contains a definitions-bundle envelope")
    head = APAR_HEADER_RE.search(blob)
    if head and len(APAR_ROW_RE.findall(blob, head.end())) >= APAR_MIN_ROWS:
        reasons.append("contains an IBM APAR CSV feed")
    if (b"ksh93" in blob[:512] and FLRTVC_VERSION_RE.search(blob)
            and b"parseLSLPP" in blob and b"parseEFIX" in blob):
        reasons.append("contains IBM flrtvc.ksh")
    if blob.count(b'"cveID"') >= KEV_MIN_ENTRIES:
        reasons.append("contains a CISA KEV catalog snapshot")
    if b'"flrtReport"' in blob and blob.count(b'"eosps"') >= FLRT_MIN_ENTRIES:
        reasons.append("contains an IBM FLRT firmware dump")
    if b"<all_psps>" in blob and blob.count(b"<psp>") >= PSP_MIN_ENTRIES:
        reasons.append("contains an IBM i PSP dump")
    return reasons


def unwrap(blob):
    """Yield blob plus decompressed forms of it (gzip/zlib), bounded."""
    out = [blob]
    if blob[:2] == b"\x1f\x8b":
        try:
            out.append(zlib.decompress(blob, 31, MAX_DECODE_BYTES))
        except zlib.error:
            pass
    elif blob[:1] == b"\x78" and blob[1:2] in (b"\x01", b"\x5e", b"\x9c", b"\xda"):
        try:
            out.append(zlib.decompress(blob, 15, MAX_DECODE_BYTES))
        except zlib.error:
            pass
    return out


def b64_candidates(blob):
    seen = 0
    for match in B64_LONG_RE.finditer(blob):
        seen += 1
        if seen > MAX_CANDIDATES:
            return
        yield match.group(0)
    group = []
    for line in blob.split(b"\n"):
        stripped = line.strip(LINE_TRIM)
        if B64_LINE_RE.match(stripped):
            group.append(stripped)
            continue
        if len(group) >= 3:
            seen += 1
            if seen > MAX_CANDIDATES:
                return
            yield b"".join(group)
        group = []
    if len(group) >= 3:
        yield b"".join(group)


def content_reasons(blob, depth=0, via=""):
    reasons = []
    for form in unwrap(blob):
        label = via + (" (gzip-wrapped)" if form is not blob else "")
        reasons.extend(r + label for r in plain_reasons(form))
        if depth < MAX_DEPTH:
            for cand in b64_candidates(form):
                decoded = decode_b64(cand)
                if decoded is None:
                    continue
                reasons.extend(content_reasons(decoded, depth + 1, via + " (base64-wrapped)"))
        if reasons:
            break
    return reasons


def name_reasons(path, strict_assets=False, blob=None):
    base = os.path.basename(path).lower()
    reasons = []
    for glob in BANNED_NAME_GLOBS:
        if fnmatch.fnmatchcase(base, glob):
            reasons.append("prohibited file name (%s)" % glob)
            break
    if base in MEMBER_TABLE_NAMES:
        marked = "/" + path.lower().replace("\\", "/")
        if strict_assets or not any(m in marked for m in FIXTURE_PATH_MARKERS):
            reasons.append("prohibited file name (bundle member table %s)" % base)
        elif blob is not None and not base.endswith(".json") and blob.count(b"\n") >= FIXTURE_TABLE_MIN_LINES:
            reasons.append("fixture named like a bundle member table is too large to be synthetic")
    if strict_assets and base not in ASSET_SAFE:
        for rx in ASSET_NAME_RES:
            if rx.search(base):
                reasons.append("release asset name looks like IBM/definitions data")
                break
    return reasons


def doc_in_scope(path):
    if path.startswith(DOC_EXEMPT_PREFIXES) or os.path.basename(path).startswith("BUILD-NOTES"):
        return False
    if not path.lower().endswith(DOC_EXTS):
        return False
    return path in DOC_SCOPE_FILES or path.startswith(DOC_SCOPE_PREFIXES)


def doc_reasons(path, blob):
    if not doc_in_scope(path):
        return []
    text = re.sub(r"\s+", " ", blob.decode("utf-8", "replace"))
    return [reason for reason, rx in BANNED_PHRASES if rx.search(text)]


def index_blobs():
    """Yield (path, blob) for every index entry, via one cat-file process."""
    out = git_bytes("ls-files", "-s", "-z")
    entries = []
    for rec in out.split(b"\0"):
        if not rec:
            continue
        meta, _, path = rec.partition(b"\t")
        mode, oid, _stage = meta.split(b" ")
        if mode == b"160000":
            continue  # gitlink
        entries.append((path, oid))
    try:
        proc = subprocess.Popen(["git", "cat-file", "--batch"], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE)
    except OSError as exc:
        raise RuntimeError("could not inspect the Git index") from exc
    for path, oid in entries:
        proc.stdin.write(oid + b"\n")
        proc.stdin.flush()
        header = proc.stdout.readline().split()
        if len(header) != 3:
            raise RuntimeError("could not read Git object for an index entry")
        size = int(header[2])
        blob = proc.stdout.read(size)
        proc.stdout.read(1)
        yield path, blob
    proc.stdin.close()
    proc.wait()


def scan_index():
    violations = []
    for raw, blob in index_blobs():
        path = raw.decode("utf-8", "surrogateescape")
        label = raw.decode("utf-8", "backslashreplace")
        reasons = name_reasons(path, blob=blob)
        reasons += content_reasons(blob)
        reasons += doc_reasons(path, blob)
        for reason in reasons:
            violations.append((label, reason))
    return violations


def scan_asset_list(list_path):
    violations = []
    with open(list_path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            name = line.strip()
            if not name or name.startswith("#"):
                continue
            for reason in name_reasons(name, strict_assets=True):
                violations.append(("asset-list:" + name, reason))
    return violations


def scan_assets_dir(root):
    violations = []
    for dirpath, _dirs, files in os.walk(root):
        for fname in sorted(files):
            full = os.path.join(dirpath, fname)
            rel = os.path.relpath(full, root)
            reasons = name_reasons(rel, strict_assets=True)
            try:
                with open(full, "rb") as handle:
                    reasons += content_reasons(handle.read())
            except OSError:
                raise RuntimeError("could not read asset %s" % rel)
            for reason in reasons:
                violations.append(("assets:" + rel, reason))
    return violations


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--asset-list", help="file with one release asset name per line")
    parser.add_argument("--assets-dir", help="directory of release assets to scan")
    parser.add_argument("--assets-only", action="store_true",
                        help="do not scan the Git index, only the given assets")
    args = parser.parse_args(argv)
    try:
        violations = []
        if not args.assets_only:
            violations += scan_index()
        if args.asset_list:
            violations += scan_asset_list(args.asset_list)
        if args.assets_dir:
            violations += scan_assets_dir(args.assets_dir)
    except (RuntimeError, OSError) as exc:
        print("no-IBM-defs-distribution: FAIL — %s" % exc, file=sys.stderr)
        return 2
    if violations:
        print("no-IBM-defs-distribution: FAIL — prohibited content:", file=sys.stderr)
        for path, reason in violations:
            print("  %s: %s" % (path, reason), file=sys.stderr)
        print("PowerTrue hosts, signs and ships no IBM-derived data or definitions "
              "bundle; see docs/DESIGN-PRINCIPLES.md.", file=sys.stderr)
        return 1
    print("no-IBM-defs-distribution OK: no IBM-derived data, definitions bundle, "
          "or banned claim found")
    return 0


if __name__ == "__main__":
    sys.exit(main())
