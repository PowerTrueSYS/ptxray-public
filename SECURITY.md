# Security and trust model

PTxray is intended to be inspected before it is run. The published 1.4 AIX and
VIOS assessment is best run as root, but an unprivileged run continues with
root-only checks degraded to `WARN` or `NOT_ASSESSED`. The security boundary is
the exact revision of the program for the selected platform, not a brand claim
or a download page.

This document covers the assembled [`ptxray-aix.sh`](ptxray-aix.sh) and
[`ptxray-ibmi.sh`](ptxray-ibmi.sh) assessments. Current 1.4 assessment
execution is self-contained with respect to the network; locally supplied
inputs are transferred under the operator's normal controls.

## Assessment security contract

For `ptxray-aix.sh` and `ptxray-ibmi.sh`:

- **Read-only means no assessed-system mutation.** The scanner reads posture
  evidence and renders a report. It does not remediate findings.
- **Assessment execution has no network egress.** The assessment must not open
  an outbound network connection, perform a live DNS lookup, fetch reference
  data, send telemetry, upload a report, or send any assessment data away from
  the host.
- **Outputs remain local.** PTxray writes only the report or export path chosen
  by the operator and, for a locally supplied FLRTVC run, a private temporary
  scratch directory. It removes that directory on normal exit and handled
  signals; abrupt termination can leave private scratch debris.
- **Missing evidence is not clean evidence.** Unavailable evidence is never
  promoted to `PASS`. Most unread or incomplete sources are surfaced as
  `NOT_ASSESSED` in the completeness model; some legacy or control-shaped rows
  retain `WARN` with explicit “needs root” wording. One known exception is the
  root-crontab `backup_job` row, which is omitted after an unprivileged read
  failure because separate backup evidence is reported elsewhere.

These are deliberately narrower statements than “the process has no side
effects.” Producing a report is a filesystem write, as is the bounded FLRTVC
scratch workflow described below.

## What it reads

The scanner uses standard AIX read or query commands and fixed,
reviewable configuration paths to inspect:

- host identity, AIX TL/SP, and firmware levels, filesets, interim fixes,
  and locally supplied vulnerability evidence;
- filesystems, volume groups, logical volumes, disks, paths, paging, CPU,
  memory, and performance counters;
- `errpt`, dump, boot, backup, availability, and monitoring posture;
- network interfaces, routes, listeners, resolver configuration, SSH,
  services, account/password/audit policy, scheduled work, and bounded file
  metadata checks.

The public check catalog is in [`docs/CHECK-CATALOG.md`](docs/CHECK-CATALOG.md),
and [`docs/HOW-TO-AUDIT.md`](docs/HOW-TO-AUDIT.md) maps the shipped artifact to
its smaller source units and command contracts.

## What it writes

The scanner can write only the following local artifacts:

- HTML, JSON, or compliance output sent to stdout or redirected by the
  operator;
- an HTML report under a directory explicitly selected with `--out` (the
  zero-argument convenience run selects the current directory), using a hidden
  same-directory temporary file before the final `mv`;
- two inventory files under a directory explicitly selected with
  `--flrt-export`. A private `umask` protects newly created files, but does not
  repair permissions on pre-existing files, and shell redirection can follow a
  pre-positioned symlink. Use a new, operator-owned, otherwise empty export
  directory; and
- when authorized FLRTVC inputs are supplied locally, private scratch files
  under `${TMPDIR:-/tmp}`. PTxray creates its scratch directory mode 700,
  restricts the input copies, and makes a best-effort removal on normal exit or
  a handled signal. An abrupt termination, including one during final cleanup,
  can leave the private directory behind for manual removal.

It does not execute a write to AIX configuration, ODM device configuration,
filesets, service state, security policy, accounts, boot state, or remediation
changes. The preserved real-AIX drill observed diagnostic ODM-class mtimes
advance without any corresponding scanner-tree open/write syscall and could not
attribute that housekeeping. PTxray therefore does not claim that no metadata
anywhere on a live system can move while read utilities run.

## What it never executes

The scan does not install, update, or remove software; edit configuration or
security policy; change device attributes; start, stop, or restart services;
create, lock, or delete users; or reboot or shut down the system. Commands such
as `chdev`, `chsec`, `chuser`, `chmod`, and `installp` appear in finding
remediation text because the report tells an administrator what they may choose
to do later. That prose is data; it is not executed by the scan.

## How the assessment network boundary is enforced

The zero-egress requirement is backed by layered, reviewable gates in
[`network-boundary.yml`](.github/workflows/network-boundary.yml), which runs on
every pull request and on pushes to `master`:

1. [`egress-lint.sh`](tools/ci/egress-lint.sh) rejects network-client command
   references in executable positions. Its regression suite includes the exact
   former `aix host_self host "$HOST"` invocation that once caused a live DNS
   lookup.
2. [`network-denial-check.sh`](tools/ci/network-denial-check.sh) compares
   successful fixture scans with and without a Linux network namespace. This
   proves no network dependency; it does not, by itself, prove no attempted
   egress.
3. [`egress-trace.sh`](tools/ci/egress-trace.sh) runs the scanner under
   `strace -f -e trace=network` and fails on an observed `AF_INET` or
   `AF_INET6`-family syscall in the traced process tree. CI installs `strace`
   and treats a missing tracer as a failure.

The scopes matter. The static lint is intentionally a tripwire, not a shell
parser. Both dynamic CI jobs set `AIXRAY_FIXTURES`; in that mode, `aix`, `aixv`,
and related wrappers replay repository files instead of executing their live
AIX query commands. The jobs therefore exercise the fixture-mode scanner
control flow, not the live AIX command tree. This is why the former wrapped
`host` resolver was not executed by those jobs; the real-AIX trace found it and
the static lint now carries its exact regression.

The Linux trace also does not cover inherited connected descriptors,
`AF_PACKET` or every other address family, a separate daemon acting through an
`AF_UNIX` request, or writes to a network-mounted filesystem. The harness
documents these limits in [`tools/ci/README.md`](tools/ci/README.md); source
review and a real-AIX trace remain part of the evidence.

The repository also preserves the
[`2026-07-14 real-AIX truss record`](docs/lab-acceptance/2026-07-14-zero-egress-lab-acceptance.md).
That record is intentionally a failed pre-fix drill: it found and attributed a
real DNS call. The current scanner replaced the live lookup with static
`/etc/hosts` evidence, and the static-lint regression prevents the former
command from returning. The failed record is not represented as a current
post-fix AIX pass. For the strongest assurance, repeat its documented AIX
`truss` method against the exact revision and AIX release you intend to run.

## Read-only enforcement and assembly identity

[`assembly-gate.yml`](.github/workflows/assembly-gate.yml) rebuilds the public
scanner, requires byte identity with the committed `ptxray-aix.sh`, and runs the
per-tool read-only command-contract gates. This makes review of the smaller
source units relevant to the exact shipped bytes. Shared monolith control flow
and its bounded report/scratch writes still require source review; the command
allowlist is not presented as a universal proof.

See [`docs/VERIFY.md`](docs/VERIFY.md) for exact commands to inspect likely
network and mutating primitives, run the egress and command-contract gates,
reassemble the scanner, and compare SHA-256 digests.

## Published 1.4 platform and privilege scope

- IBM AIX 7.2 and 7.3, including the VIOS assessment surface, are best run as
  root for intended coverage.
- A non-root AIX or VIOS run is supported but incomplete. Root-only reads
  degrade to explicit `WARN` or `NOT_ASSESSED` results rather than causing a
  privilege refusal.
- For IBM i 7.4 and 7.5, inspect the exact artifact's signed-on and system-user
  identity gate before running it; do not generalize that boundary to AIX.

Required patch, dump, boot, account, audit, service, security, and platform
evidence may be inaccessible in a non-root AIX or VIOS run. The report must
retain those unavailable states rather than presenting them as clean evidence.

## Unpublished 1.5 privilege and definitions design

This is a candidate design, not a published release. In PTxray 1.5, AIX and
VIOS will require root and IBM i will require QSECOFR. Its separate
downloader will attempt to acquire current signed definitions by default;
assessment execution will consume locally available, verified definitions and
will not contact a definitions service. An air-gapped operator will be able to
perform the download and verification on a connected administration system,
then transfer the definitions bundle to the target.

## Release-signing boundary

Release signatures authenticate the exact `SHA256SUMS` bytes. The manifest
then binds named release payloads to their SHA-256 digests. This does not make
the release signing key self-authenticating: obtain its SPKI-DER SHA-256
fingerprint through an independent PowerTrue Systems channel before trusting
the downloaded public key.

The PTxray 1.5 release, release public key, and authoritative fingerprint have
not been published. No fingerprint is stated here until the release ceremony
produces and independently publishes the real value. Candidate files are not a
release and must not be treated as one.

## IBM FLRTVC delivery data

The public scanner does not fetch or contain IBM's `flrtvc.ksh` or full
`apar.csv`. Its six delivery embed slots are empty. An authorized connected
admin system may fetch and verify those inputs and side-load them for an
offline target run; that local delivery artifact is ignored and must not be
committed or publicly redistributed.

[`tools/check-no-ibm-redistribution.py`](tools/check-no-ibm-redistribution.py)
fails CI if the Git index contains the case-insensitive basenames `flrtvc.ksh`
or `apar.csv`, a tracked `aixray-aix.bundled.sh`, a non-empty protected embed
slot assignment, the specific FLRTVC structure it checks (`ksh93` in the first
line, a version assignment, `parseLSLPP`, and `parseEFIX`), or its full-feed
signature (at least 100 lines, the exact header, and a vintage row). It is not a
general classifier for all IBM-derived content. Its exact scope, and a broader
candidate-file audit that remains necessary, are documented in
[`docs/VERIFY.md`](docs/VERIFY.md#confirm-that-ibm-delivery-data-is-not-bundled).

## Review-pack sharing boundary

> **Public copy:** An
> `ptxray-review-pack.sh` review file is **pseudonymized, not anonymized**. It
> can still contain operational and configuration details. Inspect the review
> file locally before deciding whether to share it. The separate local decoding
> key must not be sent with the review file. Creating either file performs no
> upload or send; sharing remains a deliberate user action.

The current helper writes its `aixray-review-*.html`,
`aixray-local-key-*.map`, and `aixray-local-removals-*.txt` outputs beside the
input report through a private scratch directory. Keep the key and removals
manifest local. This optional local transformation does not broaden
the scanner's assessed-system read-only boundary or its zero-egress boundary.
It is not proof that a review file is free of all identifying or sensitive
information.

## Reporting a security issue

Do not open a public issue for a suspected vulnerability. Email the tested
mailbox [`review@powertruesystems.com`](mailto:review@powertruesystems.com)
with the subject **PTxray security report**. The intended private-advisory URL
is
[`https://github.com/PowerTrueSYS/ptxray-public/security/advisories/new`](https://github.com/PowerTrueSYS/ptxray-public/security/advisories/new),
but private advisory reporting remains pending activation after the repository
migration and settings review. Until activation is confirmed, use the mailbox,
not that form. Include:

- the exact Git commit or release tag;
- platform and release, effective user or profile, and any privilege warning
  or refusal emitted by the assessment;
- the invocation and the smallest reproduction that demonstrates the issue;
  and
- the observed impact and any relevant lint or trace evidence.

After safe triage is possible, PowerTrue Systems will acknowledge the report.
There is no fixed response SLA. Do not attach a production scan, credentials,
host identifiers, or other
sensitive system data to a vulnerability report unless a secure transfer method
has been agreed first. The generated report separately offers optional engineer
review at the same mailbox; that offer is not permission to send an unsanitized
production report. Sanitize it first, or email without the attachment to agree
a transfer method. Do not use a public GitHub issue for security reports.
