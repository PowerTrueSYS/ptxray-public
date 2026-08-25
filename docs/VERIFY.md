# How to verify PTxray is safe

No single grep, digest, test, or trace proves arbitrary code safe. This
checklist gives a skeptical administrator repeatable evidence about one exact
public revision of the `ptxray-aix.sh` and `ptxray-ibmi.sh` runners, the
separate `ptxray-defs.sh` downloader, and the offline `ptxray-review-pack.sh`
helper. Read the evidence scopes in
[`SECURITY.md`](../SECURITY.md) before treating any pass as broader than it
is.

Run checkout code only in a disposable, credential-free review VM or a
locked-down container without sensitive mounts, host sockets, tokens, or
production data. Until review is complete, assume the revision could egress.
Do not run it first on a production AIX/VIOS target.

## Verify the signed manifest first

This is the verification order for the unpublished PTxray 1.5 release
candidate. That release,
its release public key, and its authoritative fingerprint are not yet
published. Until the release ceremony publishes the real fingerprint through
an independent PowerTrue Systems channel, stop here: candidate files are not a
release, and a public key downloaded beside a payload cannot authenticate
itself.

The designed release asset set is exactly:

```text
ptxray-aix.sh
ptxray-ibmi.sh
ptxray-defs.sh
ptxray-review-pack.sh
ptxray-review-validate.awk
aixray-aix.sh
SHA256SUMS
SHA256SUMS.sig
POWERTRUE-RELEASE-PUBLIC.pem
```

`aixray-aix.sh` is the only legacy-named compatibility asset and must be
byte-identical to `ptxray-aix.sh`. `SHA256SUMS` must contain exactly six
basename entries: the five `ptxray-*` payloads above and the compatibility
asset. It does not hash itself, its signature, or the public key. Repository or
tag metadata is not an additional release asset.

On a trusted review workstation with OpenSSL, print the downloaded key's
SPKI-DER SHA-256 fingerprint:

```sh
openssl pkey -pubin -in POWERTRUE-RELEASE-PUBLIC.pem -outform DER \
  | openssl dgst -sha256
```

Compare that value with the authoritative fingerprint obtained through the
independent channel. Do not compare it only with another file or page from the
same download location. No expected fingerprint is printed here because no
authoritative 1.5 fingerprint exists yet.

Only after the independent fingerprint matches, verify the RSA-3072 / SHA-256
/ PKCS#1 v1.5 signature over the exact `SHA256SUMS` bytes:

```sh
openssl dgst -sha256 -verify POWERTRUE-RELEASE-PUBLIC.pem -signature SHA256SUMS.sig SHA256SUMS
```

Require `Verified OK`, then verify all six payload digests before running a
payload:

```sh
sha256sum -c SHA256SUMS
cmp ptxray-aix.sh aixray-aix.sh
```

## Pin the public revision

```sh
git clone https://github.com/PowerTrueSYS/ptxray-public
cd ptxray-public
git rev-parse HEAD
git status --short
```

Record the commit ID. The status command should print nothing. For a release,
check out the trusted release tag or commit before continuing; every digest and
result below is revision-specific.

## Run the release-integrity gate

Before pushing a release tag, run the tree-only gate from the committed
candidate revision:

```sh
python3 tools/verify-release-integrity.py --tag v1.5.0
```

For `v1.0.0` through the current published 1.4 line, use that release's
documented asset set. The 1.5 candidate uses the nine assets listed in the
signature-first section above; the renderer, release public key, signed
manifest, and signature ceremony must land before that candidate can pass the
final gate.
The immutable `v0.1.0` release retains its historical two-asset contract
(`ptxray-aix.sh` and `ptxray-review-pack.sh`):

```sh
python3 tools/verify-release-integrity.py --tag v0.1.0 \
  --assets-dir release-assets
```

The gate checks the required tree paths, catalog digests, root/site scanner
identity, artifact version declarations, the exact versioned release asset
set, the signed checksum manifest, and asset bytes. The unpublished candidate
cannot pass its final release check until the renderer produces the exact 1.5
payloads and the signing ceremony signs their manifest. Any `FAIL` line blocks
a release.

## Verify byte identity and catalog hashes

The publisher derives every mechanical customer-facing release-version claim
from `catalog.json.tool_version` and every numeric standalone-count claim from
`catalog.json.check_count`. After generating a release catalog, run the renderer
once; committed candidates and CI use check mode so stale copy cannot pass:

```sh
python3 tools/sync-release-shape.py
python3 tools/sync-release-shape.py --check
```

First require the root and site scanner payloads to be byte-identical:

```sh
cmp ptxray-aix.sh site/ptxray-aix.sh
```

`cmp` should print nothing and exit zero. Then validate the catalog,
README, every standalone artifact, and the declared sorted-check schema from the
repository root:

```sh
python3 - <<'PY'
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

root = Path(".")
resolved_root = root.resolve(strict=False)
guidance = (
    "check out the intended release tag or commit and retry with clean files "
    "from that revision"
)

def fail(message):
    raise SystemExit(f"artifact verification failed: {message}; {guidance}")

def require_file(relative):
    candidate = PurePosixPath(relative)
    if (
        candidate.is_absolute()
        or ".." in candidate.parts
        or relative in ("", ".")
    ):
        fail(f"unsafe required path {relative!r}")
    path = root
    components = []
    for part in candidate.parts:
        path /= part
        components.append(part)
        try:
            is_symlink = path.is_symlink()
        except OSError as exc:
            fail(f"could not inspect required path {relative}: {exc}")
        if is_symlink:
            component = PurePosixPath(*components).as_posix()
            fail(
                f"required path {relative} traverses symlink component "
                f"{component}"
            )
    try:
        resolved_path = path.resolve(strict=False)
        resolved_path.relative_to(resolved_root)
    except ValueError:
        fail(f"required path {relative} resolves outside the repository")
    except (OSError, RuntimeError) as exc:
        fail(f"could not resolve required path {relative}: {exc}")
    if not path.is_file():
        fail(f"missing required file {relative}")
    return path

def read_bytes(relative):
    path = require_file(relative)
    try:
        return path.read_bytes()
    except OSError as exc:
        fail(f"could not read {relative}: {exc}")

def read_text(relative):
    content = read_bytes(relative)
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"{relative} is not valid UTF-8: {exc}")

def sha256(relative):
    return hashlib.sha256(read_bytes(relative)).hexdigest()

def require_equal(actual, expected, message):
    if actual != expected:
        fail(message)

try:
    catalog = json.loads(read_text("catalog.json"))
except json.JSONDecodeError as exc:
    fail(f"catalog.json is not valid JSON: {exc}")
if not isinstance(catalog, dict):
    fail("catalog.json root is not an object")
readme = read_text("README.md")

scanner = sha256("ptxray-aix.sh")
review = sha256("ptxray-review-pack.sh")
site_scanner = sha256("site/ptxray-aix.sh")
require_equal(
    site_scanner,
    scanner,
    "byte mismatch between ptxray-aix.sh and site/ptxray-aix.sh "
    f"(sha256 {scanner} != {site_scanner})",
)

expected_scanner = {
    "artifact": "ptxray-aix.sh",
    "site_artifact": "site/ptxray-aix.sh",
    "sha256": scanner,
}
require_equal(
    catalog.get("assembled_scanner"),
    expected_scanner,
    "catalog.json assembled_scanner does not match ptxray-aix.sh and "
    f"site/ptxray-aix.sh; expected {expected_scanner!r}, "
    f"found {catalog.get('assembled_scanner')!r}",
)

expected_review = {
    "artifact": "ptxray-review-pack.sh",
    "sha256": review,
}
require_equal(
    catalog.get("review_pack"),
    expected_review,
    "catalog.json review_pack does not match ptxray-review-pack.sh; "
    f"expected {expected_review!r}, found {catalog.get('review_pack')!r}",
)

legacy_release = catalog.get("tool_version") == "0.1.0"
release_digests = {}
if not legacy_release:
    # v0.1.0 shipped three top-level payloads. Every release since also ships
    # one standalone tool per catalog check, so this set is DERIVED from
    # catalog.json rather than written out: the previous hard-coded triple
    # silently became wrong the moment the standalone tools joined the release,
    # and rejected a correct v1.0.0 SHA256SUMS covering 327 payloads.
    catalog_checks = catalog.get("checks")
    if not isinstance(catalog_checks, list):
        fail("catalog.json checks is not a list")
    check_artifacts = []
    for entry in catalog_checks:
        if not isinstance(entry, dict):
            fail("catalog.json contains a check entry that is not an object")
        artifact_path = entry.get("artifact")
        if not isinstance(artifact_path, str) or not artifact_path:
            fail(f"catalog check {entry.get('id')!r} has no artifact path")
        check_artifacts.append(artifact_path)
    payloads = (
        "ptxray-aix.sh",
        "ptxray-ibmi.sh",
        "ptxray-review-pack.sh",
        "ptxray-review-validate.awk",
    ) + tuple(check_artifacts)
    checksum_source = read_text("SHA256SUMS")
    for line_number, line in enumerate(checksum_source.splitlines(), start=1):
        match = re.fullmatch(r"([0-9A-Fa-f]{64})[ \t]+\*?(\S+)", line)
        if match is None:
            fail(
                f"SHA256SUMS line {line_number} is malformed; expected a "
                "SHA-256 digest and a release artifact path"
            )
        digest, relative = match.groups()
        if relative in release_digests:
            fail(f"SHA256SUMS contains duplicate entry: {relative}")
        release_digests[relative] = digest.lower()
    require_equal(
        set(release_digests),
        set(payloads),
        "SHA256SUMS payload set does not match the release payloads declared "
        "by catalog.json",
    )
    for relative in payloads:
        actual = sha256(relative)
        expected = release_digests[relative]
        require_equal(
            actual,
            expected,
            f"SHA256SUMS digest mismatch for {relative} "
            f"(manifest sha256 {expected}, file sha256 {actual})",
        )
if legacy_release:
    if scanner not in readme:
        fail(f"README.md does not contain the ptxray-aix.sh digest {scanner}")
    if review not in readme:
        fail(
            "README.md does not contain the ptxray-review-pack.sh digest "
            f"{review}"
        )
elif "SHA256SUMS" not in readme:
    fail("README.md does not direct readers to the SHA256SUMS manifest")
elif re.search(r"\b[0-9A-Fa-f]{64}\b", readme):
    fail(
        "README.md retains pasted artifact digests instead of using "
        "SHA256SUMS"
    )

checks = catalog.get("checks")
if not isinstance(checks, list):
    fail("catalog.json checks is not a list")
declared_count = catalog.get("check_count")
if type(declared_count) is not int or declared_count < 1:
    fail(
        "catalog.json check_count is not a positive integer "
        f"({declared_count!r})"
    )
require_equal(
    declared_count,
    len(checks),
    "catalog.json check_count does not match the checks list "
    f"({declared_count} != {len(checks)})",
)
if not all(isinstance(entry, dict) for entry in checks):
    fail("catalog.json contains a check entry that is not an object")
ids = [entry.get("id") for entry in checks]
if not all(isinstance(check_id, str) for check_id in ids):
    fail("catalog.json contains a check without a string id")
require_equal(
    ids,
    sorted(ids),
    "catalog.json checks are not sorted by id",
)
check_root = root / "checks"
directory_ids = sorted(
    path.name for path in check_root.glob("ck-*") if path.is_dir()
)
manifest_ids = sorted(
    path.parent.name for path in check_root.glob("ck-*/manifest.json")
)
require_equal(
    directory_ids,
    ids,
    "checks/ directory IDs do not match catalog.json checks",
)
require_equal(
    manifest_ids,
    ids,
    "checks/ manifest IDs do not match catalog.json checks",
)
copy_counts = {
    int(value)
    for value in re.findall(
        r"\b([1-9][0-9]*)\s+standalone\b",
        readme,
        flags=re.IGNORECASE,
    )
}
require_equal(
    copy_counts,
    {declared_count},
    "README.md standalone-check count claims do not match "
    f"catalog.json check_count ({sorted(copy_counts)!r} != {declared_count})",
)
for entry in checks:
    artifact = entry.get("artifact")
    if not isinstance(artifact, str) or not artifact:
        fail(f"catalog check {entry.get('id')!r} has no artifact path")
    expected = entry.get("sha256")
    actual = sha256(artifact)
    require_equal(
        actual,
        expected,
        f"catalog digest mismatch for {artifact} "
        f"(catalog sha256 {expected!r}, file sha256 {actual})",
    )

print("scanner", scanner)
print("review", review)
if release_digests:
    print("validator", release_digests["ptxray-review-validate.awk"])
    print("SHA256SUMS", sha256("SHA256SUMS"))
print("catalog/hash verification OK")
PY
```

The program prints the revision-specific artifact digests it actually verifies;
there is no second hand-maintained digest list in this guide.

The published `v0.1.0` assets have a documented tag/asset discrepancy. See the
[`v0.1.0` release-integrity note](RELEASE-NOTES.md#v010-release-integrity-note)
before comparing that release.

A digest identifies the reviewed bytes. It becomes an authenticity check only
when compared with a digest obtained through an independently trusted release
channel.

## Inspect and test the assessment no-network boundary

Start with a deliberately broad source search against the scanner, review
helper, and companion validator when present:

```sh
set -- ptxray-aix.sh ptxray-ibmi.sh ptxray-review-pack.sh
[ ! -f ptxray-review-validate.awk ] || set -- "$@" ptxray-review-validate.awk
git grep -n -E '(^|[^[:alnum:]_])(curl|wget|ftp|tftp|telnet|nc|socat|ssh|scp|sftp|rcp|rsh|rexec|ping|traceroute|sendmail|host|nslookup|dig)([^[:alnum:]_]|$)|/dev/(tcp|udp)|socket[[:space:]]*\(|connect[[:space:]]*\(' -- "$@" || true
```

This is a review aid, not a pass/fail gate. The artifacts contain network words
in comments, local-configuration reads, report text, and remediation text.
Review every hit. An unexplained executable client or socket call is a failure.
Do not add `ptxray-defs.sh` to this no-egress set: it is the separately named
network-capable downloader. Inspect it independently and require its executable
network surface to be limited to the two disclosed fixed HTTPS GET endpoints:

```sh
git grep -n -E 'curl|https://' -- ptxray-defs.sh
```

Connected mode is the default before assessment and writes a verified cache
generation. `--offline` must select only the signed cache;
`--definitions-bundle SIGNED_FILE` must verify the local signed bundle and
adjacent `SIGNED_FILE.sig`. In every mode, require the runner to validate the
adjacent downloader's same-release digest before invocation and require an old
or stale definitions age warning.

Run the shipped command-position lint against those exact sources:

```sh
set -- ptxray-aix.sh ptxray-ibmi.sh ptxray-review-pack.sh
[ ! -f ptxray-review-validate.awk ] || set -- "$@" ptxray-review-validate.awk
sh tools/ci/egress-lint.sh "$@"
```

The command must exit zero. An artifact with no candidate references reports
`egress-lint: PASS`; reviewed scanner text can instead produce explicit
`ALLOWED` lines. Any `FAIL` line or nonzero exit is a failure. The lint
catches direct and wrapped network-client forms. It is a static tripwire, not a
complete shell parser or live AIX runtime trace. Its limits—including inherited
descriptors, other address families, cooperating daemons, and network-mounted
output paths—are described in
[`SECURITY.md`](../SECURITY.md#how-the-assessment-network-boundary-is-enforced).

## Inspect the read-only and local-write boundary

Search for commands that deserve special attention when shell runs as root:

```sh
git grep -n -E '(^|[^[:alnum:]_])(installp|rpm|dnf|yum|chdev|chsec|chuser|startsrc|stopsrc|reboot|shutdown|mkdir|mktemp|tee|rm|rmdir|mv|ln|cp|chmod|chown)([^[:alnum:]_]|$)' -- ptxray-aix.sh ptxray-review-pack.sh || true

git grep -n -E 'REPORT_TMP|FLRT_|FV_|SCRATCH|HTML_(TMP|OUT)|MAP_(TMP|OUT)|--flrt-export|--out' -- ptxray-aix.sh ptxray-review-pack.sh || true
```

The first search is intentionally noisy: most mutating command names in the
scanner are remediation prose that is never evaluated. The second highlights
the current local writer variables. Inspect each actual `mkdir`, `cp`,
`chmod`, `ln`, `rm`, `mv`, and redirection operand. Scanner
writes must remain confined to operator-selected report/export paths, private
FLRTVC scratch, or the protected `/var/ptxray/definitions` cache written
through the separate verified downloader. Review-helper writes must remain beside the selected report,
inside private scratch or the final mode-`0600` review/map paths. Neither
grep proves read-only behavior by itself.

Also inspect each check's `commands`, `read_only`, and
`requires_root` fields in [`catalog.json`](../catalog.json), then read
the paired shell file under [`checks/`](../checks/).

## Verify the review-pack boundary

The helper must be executable and valid under both available shell parsers:

```sh
test -x ptxray-review-pack.sh
sh -n ptxray-review-pack.sh
ksh -n ptxray-review-pack.sh
```

For a report you own, run:

```sh
./ptxray-review-pack.sh ptxray-<hostname>-<date>.html
```

Success creates one owner-only `ptxray-review-*.html` and one owner-only
`ptxray-local-key-*.map`. Open the review HTML and inspect it. Send only
the review HTML. The map starts with a DO-NOT-SEND warning and contains the
local token-to-identifier mapping; keep it mode `0600` and local. A
successful pseudonymization is not a claim of anonymity. A nonzero exit with no
final review HTML is the helper's fail-closed behavior, not permission to send
the raw report.

## Confirm IBM delivery data is not bundled

Reject prohibited raw delivery filenames and the bundled-artifact name:

```sh
if git ls-files | grep -E '(^|/)(apar\.csv|flrtvc\.ksh|aixray-aix\.bundled\.sh)$'; then
  echo 'FAIL: prohibited IBM delivery filename is tracked' >&2
  exit 1
else
  echo 'OK: no prohibited IBM delivery filename is tracked'
fi
```

Run the content-aware Git-index guard:

```sh
python3 tools/check-no-ibm-redistribution.py
```

Expected result:

```text
no-IBM-redistribution OK: tracked index contains no raw IBM FLRTVC data or filled scanner slots
```

The guard checks the exact filenames, protected empty scanner slots, and the
specific script/feed signatures documented in
[`SECURITY.md`](../SECURITY.md#ibm-flrtvc-delivery-data). It is not a
general IBM-content classifier. Perform the broader candidate-name review too:

```sh
git ls-files | grep -Ei '(^|/).*apar.*\.csv$|(^|/).*flrtvc.*$' || true
```

Review every result rather than assuming a renamed file is harmless.

## Run the public regression suite

With `ksh` and Python 3 available:

```sh
PYTHONDONTWRITEBYTECODE=1 sh tests/run-tests.sh
```

Require a zero exit status plus both `public funnel launch contracts OK` and
`outbound review-pack redaction profile OK`. Without an explicitly supplied
AIX scanner-fixture directory, fixture-dependent scanner cases may report
`skipped`; all seven portable review-pack tests must pass. Passing tests
complement source review and do not expand the claims made by the tests.
