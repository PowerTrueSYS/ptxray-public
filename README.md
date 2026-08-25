# PTxray: read-only IBM AIX and IBM i health, risk, and security assessment

PTxray is an open-source IBM AIX and IBM i health check and posture assessment for administrators who need evidence before they change a system. The published PTxray 1.5.0 release uses inspectable ksh runners for AIX `/bin/sh` and IBM i PASE ksh plus a separate signed-definitions downloader. Assessment probes read system state, change no system configuration, make no network calls, send no assessment data or telemetry away from the host, and do not remediate findings.

> **Release status:** The current published release is PTxray 1.5.0. Download
> the complete asset set from `releases/latest`, verify the signed checksum
> manifest, and confirm the release-key fingerprint through the independent
> PowerTrue security channel before privileged execution.

**Official page:** [powertruesystems.com/ptxray](https://powertruesystems.com/ptxray/)

**Download:** [powertruesystems.com/ptxray/](https://powertruesystems.com/ptxray/)

Version: 1.5.0

**Direct release downloads:** [AIX runner](https://github.com/PowerTrueSYS/ptxray-public/releases/latest/download/ptxray-aix.sh) · [IBM i runner](https://github.com/PowerTrueSYS/ptxray-public/releases/latest/download/ptxray-ibmi.sh) · [signed checksums](https://github.com/PowerTrueSYS/ptxray-public/releases/latest/download/SHA256SUMS)

**Source:** [github.com/PowerTrueSYS/ptxray-public](https://github.com/PowerTrueSYS/ptxray-public)

**Guide:** [How to audit an IBM AIX system](docs/auditing-aix.md) — a complete, vendor-honest checklist of what to check, why it matters, and what "good" looks like.

## What is PTxray?

PTxray answers: **“What is measurably true about this AIX or IBM i system right now?”**

It inspects lifecycle and support levels, patch currency, storage and capacity, performance signals, error history, resilience, security configuration, configuration hygiene, and monitoring readiness. The assembled assessment produces HTML, JSON, or supported compliance views. The separate downloader can update a local signed-definitions cache before assessment begins; the probes themselves neither reach the network nor change system configuration.

PTxray is useful for:

- IBM AIX health checks and pre-change evidence
- IBM i posture and operational-readiness assessments
- IBM Power posture reviews
- AIX security audit preparation and configuration review
- storage, paging, mirror, MPIO, error-log, dump, and backup checks
- machine-readable assessment workflows that need explicit unknown states

## What is included?

- `ptxray-aix.sh` — the AIX assessment runner. PTxray 1.5 requires root before definitions selection or assessment begins. Its VIOS lane remains disabled pending live VIOS acceptance.
- `ptxray-ibmi.sh` — the IBM i assessment runner, graded against the CIS IBM i V7R4M0 / V7R5M0 Benchmark v2.1.0 on IBM i 7.4 and 7.5. PTxray 1.5 requires both the signed-on and system user to be QSECOFR.
- `ptxray-defs.sh` — the separate, adjacent signed-definitions downloader and verifier. It is the only assessment component permitted to make a network request.
- [`ptxray-review-pack.sh`](ptxray-review-pack.sh) — the offline helper that creates a pseudonymized review copy and a separate local decoding key
- `aixray-aix.sh` — a release-asset-only compatibility name that must be byte-identical to `ptxray-aix.sh`. It is not a second implementation, product name, report prefix, or documentation namespace.
- [`checks/`](checks/) — 387 standalone ksh check tools, each paired with its `manifest.json`
- [`catalog.json`](catalog.json) — the generated, sorted manifest catalog with SHA-256 hashes and the declared check count
- [`SECURITY.md`](SECURITY.md) and [`docs/VERIFY.md`](docs/VERIFY.md) — the trust boundary, caveats, and repeatable public-repository verification commands
- [`site/index.html`](site/index.html) — the public download page for `powertruesystems.com/ptxray/`
- [`ptxray.jsonld`](ptxray.jsonld), [`llms.txt`](llms.txt), and [`robots.txt`](robots.txt) — machine and crawler discovery metadata

The standalone tools are independently callable check modules. Their inventory count is not a numerical claim about every finding produced by the larger assembled assessment.

## PTxray 1.5 release

PTxray 1.5.0 is the current published release. The AIX runner requires root, and
the IBM i runner requires QSECOFR. Before assessment probes begin,
the runner verifies and invokes the separate, adjacent, same-release
digest-bound `ptxray-defs.sh`; a missing, replaced, or mismatched downloader is
not executed.

In a non-interactive run, connected mode is the default and attempts to
download the current signed definitions. In an interactive run, the menu
prompts the operator to update, use the last valid signed cache, import a local
signed bundle, or continue without definitions. `--offline` selects the signed
cache without a network request. `--definitions-bundle SIGNED_FILE` verifies a
local signed bundle and its adjacent `SIGNED_FILE.sig` before it becomes the
current cache generation. Old or stale definitions produce an explicit age
warning; they are not silently described as current.

The network and write boundaries are deliberately separated. Before a
connected update, `ptxray-defs.sh` discloses its two fixed HTTPS GET requests,
the destination, and the metadata visible to ordinary DNS/TLS infrastructure.
It sends no request body or assessment data. Verified definitions are written
to the protected `/var/ptxray/definitions` cache. Once selection finishes, the
assessment probes make no network calls, send no assessment data or telemetry,
change no system configuration, and perform no remediation. This supports an
air-gapped assessment run with a previously populated signed cache or a locally
transferred signed bundle.

## Standards coverage

PTxray evaluates selected controls against observed system state. Coverage is partial: a `PASS` applies only to the implemented rule and available evidence, not to the standard as a whole.

| Claim | Proof |
|---|---|
| **DISA STIG for IBM AIX 7.x coverage is partial: 66 distinct rule V-IDs receive an engine verdict.** This count is not a single-release coverage fraction. | The live `R_FILEPERM`, `R_SECATTR`, `R_NETTUNE`, and `R_SVCOFF` tables in [`ptxray-aix.sh`](ptxray-aix.sh) contain 66 distinct V-IDs. `checks_security` calls all four evaluators, and each emits per-rule `PASS`, `FAIL`, or `NA` evidence in JSON `rules[]`. `V-215399` is counted for its `clean_partial_conns` tunable verdict; the package-commit condition in that rule is not checked. Deferred `V-215429` is not in a live table and is not counted. |
| **Partial: 260 CIS L1-aligned checks** resolve to 209 distinct Level 1 control numbers of the CIS IBM AIX 7 Benchmark v1.2.0, which has 212 Level 1 controls. Their scope spans NFS exports, password hashing, file ownership and permissions, and network tunables, plus login policy, auditing, cron and at, home directories, system accounts, and the r-command services. The three controls with no mapping — 5.1.4, 5.1.5 and 7.1 — are not claimed. A mapping is not a verdict: a mapped control whose evidence is unreadable or absent renders `NOT_ASSESSED`, never `PASS`. This is an alignment cross-check, not a claim of completeness against CIS. | The numeric-only `cis_l1_map` in [`ptxray-aix.sh`](ptxray-aix.sh) names each source finding or STIG rule the cross-check reads, one per line as `source\|control`. Count its rows and its distinct control numbers directly from the file. The 212 denominator is the Level 1 control count of the benchmark itself; the benchmark PDF is licensed by CIS and is deliberately not redistributed here. The renderer resolves the mappings from the run's actual verdicts and emits no verdict for a control whose evidence is unavailable. |
| **Level 2 is reachable as `--compliance cis-l2`.** Its scope is narrower than Level 1 and is not summarised as a fraction here. | `--compliance cis-l2` is accepted by the argument parser in [`ptxray-aix.sh`](ptxray-aix.sh) and renders the same evidence-backed verdict states, `NOT_ASSESSED` included. |
| **IBM i coverage is bounded and release-scoped.** Graded against the CIS IBM i V7R4M0 / V7R5M0 Benchmark v2.1.0: on IBM i 7.5, 76 of 89 CIS Level 1 controls receive an automated verdict; on IBM i 7.4, 73 of 88. Uncovered Level 1 controls are CIS-manual or not-yet-implemented and are disclosed by the scanner, not silently dropped. There is no DISA STIG for IBM i. | [`ptxray-ibmi.sh`](ptxray-ibmi.sh) reads system values and IFS state through IBM i services and grades them against the benchmark it declares, emitting `NOT_ASSESSED` when a probe is determinate-absent. Its embedded rule authorities cite `CIS IBM i … Benchmark v2.1.0`; the Level 1 coverage counts are registry-sourced (as_of 2026-08-19). |

## Why can a cautious AIX administrator inspect it first?

| Claim | Proof |
|---|---|
| Read-only assessment probes | The assembled runner declares its capture boundary at the top of `ptxray-aix.sh`. Every public manifest records `"read_only": true` and lists the commands its standalone tool may run. Requested reports, definitions-cache generations, and protected temporary scratch data are documented local writes; none is remediation or a system-configuration change. |
| No network during assessment | The runner can invoke the separate downloader before assessment. After definitions selection, assessment probes do not fetch definitions, open network connections, send telemetry, or transmit results. Review the runner and downloader as separate command surfaces before running either. |
| Inspectable ksh programs | The AIX assessment engine remains one inspectable ksh88-compatible runner under AIX `/bin/sh`; IBM i uses PASE ksh. The release also supplies the separate adjacent `ptxray-defs.sh`, which the runner authenticates by its same-release digest before invoking it. Bash, Python, GNU userland, and package installation are not assessment runtime requirements. |
| No fabricated assessment result | `NOT_ASSESSED` is a first-class output state. Missing, unreadable, malformed, ambiguous, or unsupported evidence is reported as unavailable rather than silently converted to `PASS`. Search the assembled source for `NOT_ASSESSED` to inspect each branch. |
| Declared standalone inventory | [`catalog.json`](catalog.json) records `check_count`; each entry resolves to one paired script and manifest under [`checks/`](checks/), and the public tests require all three counts to agree. |
| Exact artifact identity | Each catalog entry carries the SHA-256 digest of its referenced standalone shell artifact. The catalog is sorted by check ID for deterministic review. |
| Signed published release | PTxray 1.5.0 publishes the exact nine-asset allowlist, including six payloads, `SHA256SUMS`, its detached signature, and the release public key. [`docs/VERIFY.md`](docs/VERIFY.md) gives the signature-first verification order and independently published key fingerprint. |

“Read-only” describes the assessment probes' effect on target system
configuration. PTxray still writes output explicitly requested by the operator,
uses bounded private scratch space for documented local-input workflows, and
can write verified definitions to `/var/ptxray/definitions` before assessment.
The no-network boundary applies to the assessment probes, not to the initial
software download, a connected definitions update, or an operator's transfer
of local inputs.

## Prerequisites

- IBM AIX 7.2 or 7.3; the IBM i assessment runs on IBM i 7.4 or 7.5 through PASE. The VIOS lane remains disabled pending live acceptance.
- AIX `/bin/sh` and standard AIX userland; bash, Python, GNU userland, and package installation are not required
- PTxray 1.5 AIX requires root; the runner refuses before definitions selection or assessment when that requirement is not met.
- PTxray 1.5 IBM i requires both `SESSION_USER=QSECOFR` and `SYSTEM_USER=QSECOFR`.
- Keep the same-release `ptxray-defs.sh` adjacent to the runner. Signed-definitions verification needs OpenSSL at a supported fixed path; connected updates also need curl at a supported fixed path.
- Plan for several minutes; runtime varies by system size and optional locally supplied FLRTVC data
- No package or agent is installed. The downloader may create the documented persistent definitions cache. Assessment probes make no network calls, and no assessment data or telemetry leaves the host. Use `--offline` with a valid signed cache or `--definitions-bundle` with a transferred signed bundle for an air-gapped assessment run.

## How do I run PTxray?

Download the complete signed 1.5 release asset set from
the [download page](https://powertruesystems.com/ptxray/), verify it, and keep
`ptxray-aix.sh` and `ptxray-defs.sh` together. The bare run uses the interactive
definitions menu when a terminal is available; otherwise it attempts a
connected signed-definitions update before assessment:

```sh
chmod 700 ptxray-aix.sh
./ptxray-aix.sh
```

The bare run writes `ptxray-<hostname>-<date>.html` in the current directory and prints this completion message:

```text
Report ready: ./ptxray-<hostname>-<date>.html — open it in your browser. To save a PDF: Print -> Save as PDF.
```

Open the named report in a browser. Use **Print → Save as PDF** when you need a PDF copy. To write the named HTML report somewhere else, use `./ptxray-aix.sh --out DIR`.

For advanced, explicit stdout output, redirect HTML or JSON yourself:

```sh
./ptxray-aix.sh --html > ptxray-report.html
./ptxray-aix.sh --json > ptxray-report.json
```

For a supported compliance view on stdout:

```sh
./ptxray-aix.sh --compliance stig > ptxray-stig.html
```

For an air-gapped run using a previously populated signed cache:

```sh
./ptxray-aix.sh --offline
```

To verify and import a locally transferred bundle, keep its detached signature
beside it as `SIGNED_FILE.sig`:

```sh
./ptxray-aix.sh --definitions-bundle /secure/path/current.ptxray-defs
```

On IBM i, use the same definitions options with `ptxray-ibmi.sh` under PASE ksh.

## Send a report safely for review

Before sending a generated HTML report, run the offline review helper beside
the report:

```sh
./ptxray-review-pack.sh ptxray-<hostname>-<date>.html
```

The v1.0.0-and-later release bundle also supplies
`ptxray-review-validate.awk`; keep it beside `ptxray-review-pack.sh` when you
transfer or run the helper. The historical v0.1.0 helper is self-contained.

The helper produces a sendable `ptxray-review-*.html` review file and a
separate mode-`0600` `ptxray-local-key-*.map` decoding key that never leaves
this machine. Its output is pseudonymized, not anonymized: undiscovered
pure-alphabetic barewords are the documented residual. Inspect the review file
before sending it; never send the local decoding key. See the exact boundary
in [`SECURITY.md`](SECURITY.md#review-pack-sharing-boundary) and the review steps in
[`docs/VERIFY.md`](docs/VERIFY.md).

## Verify what you run

SHA-256 values for the artifacts in this repository revision are published in
[`SHA256SUMS`](SHA256SUMS), one line per released file, rather than pasted into
this page where they would rot. Verify every release payload against it.

When verifying a full repository tree (a `git clone` or tag archive), use:

```sh
sha256sum -c SHA256SUMS
```

When verifying only downloaded release assets, use:

```sh
sha256sum -c --ignore-missing SHA256SUMS
```

The `--ignore-missing` flag verifies only the files present in the directory;
it skips any `SHA256SUMS` entry whose file is absent without reporting it as a
failure.

On AIX, `csum -h SHA256 <file>` produces the same digest for a single file.

The top-level `assembled_scanner` entry in [`catalog.json`](catalog.json)
binds the root and site scanner copies to the scanner's `SHA256SUMS` line. The
top-level `review_pack` entry binds the review helper to its line. Each sorted
`checks[]` entry records its standalone artifact and SHA-256; `check_count`
must match that list and the paired files under `checks/`.

The published `v0.1.0` assets do not match its immutable tag. See the
[`v0.1.0` release-integrity note](docs/RELEASE-NOTES.md#v010-release-integrity-note)
for the exact commits and published-asset digests.

On a review workstation with `jq`, `rg`, and SHA-256 tooling:

```sh
jq '.tool_version, .check_count, .license' catalog.json
python3 tools/sync-release-shape.py --check
find checks -name manifest.json | wc -l
jq -e 'all(.checks[]; .read_only == true and .license == "Apache-2.0")' catalog.json
version=$(jq -r '.tool_version' catalog.json)
set -- ptxray-aix.sh ptxray-ibmi.sh ptxray-review-pack.sh
[ ! -f ptxray-defs.sh ] || set -- "$@" ptxray-defs.sh
rg -n -F -e "VERSION=\"${version}\"" -e "PTXRAY_DEFS_VERSION=\"${version}\"" -e "PTXRAY_VERSION=${version}" -e "AIXRAY_REVIEW_PACK_VERSION=\"${version}\"" -e "AIXRAY_STANDALONE_VERSION=\"${version}\"" "$@" checks --glob '*.ksh'
rg -n 'NOT_ASSESSED' ptxray-aix.sh
cmp ptxray-aix.sh site/ptxray-aix.sh
set -- ptxray-aix.sh ptxray-ibmi.sh ptxray-review-pack.sh checks/*/*.ksh
[ ! -f ptxray-review-validate.awk ] || set -- "$@" ptxray-review-validate.awk
sh tools/ci/egress-lint.sh "$@"
python3 tools/check-no-ibm-redistribution.py
sh tests/run-tests.sh
```

To verify a standalone artifact, compare its digest with the `sha256` value in its catalog entry. To audit behavior, inspect its manifest’s declared commands and then read the paired ksh file; both are adjacent by design.

## Output honesty and limitations

PTxray reports observable posture; it does not prove that a system is secure, compliant, recoverable, or free of defects. A `PASS` applies only to the evidence and rule implemented by that check. PTxray does not perform remediation. A backup record is not a restore test, and a configuration assessment is not a penetration test.

Reference data has a declared vintage in the assembled script. Review that value when deciding whether the result is current enough for your use.

## License

PTxray is open source under the [Apache License 2.0](LICENSE). Use, modification, and redistribution are permitted under the license's terms, including the patent grant. See the [NOTICE](NOTICE) file for attribution.

Machine-readable license expression: `Apache-2.0`.

The assembled report includes IBM Plex font data under the SIL Open Font License 1.1. See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

Copyright © 2026 CJDM LLC, doing business as PowerTrue Systems.
