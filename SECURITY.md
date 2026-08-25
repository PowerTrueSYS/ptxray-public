# Security and trust model

PTxray is intended to be inspected before it is run. The unpublished PTxray 1.5
release candidate requires root for AIX and QSECOFR for IBM i. The VIOS lane
remains disabled pending live VIOS acceptance. The
security boundary is the exact, verified release asset set for the selected
platform, not a brand claim or a download page. Candidate files are not a
release, and PTxray 1.5 is not available from `releases/latest` yet.

This document covers the `ptxray-aix.sh` and `ptxray-ibmi.sh` runners, the
separate adjacent `ptxray-defs.sh` downloader, and the offline
`ptxray-review-pack.sh` helper in the 1.5 candidate.

## Assessment security contract

For `ptxray-aix.sh` and `ptxray-ibmi.sh`:

- **Read-only describes the assessment probes.** They read posture evidence and
  render a report. They do not remediate findings or change system
  configuration.
- **Assessment execution has no network egress.** The assessment must not open
  an outbound network connection, perform a live DNS lookup, fetch reference
  data, send telemetry, upload a report, or send any assessment data away from
  the host.
- **Writes are local and named.** PTxray can write the report or export path
  chosen by the operator, a protected definitions cache, and private temporary
  scratch data for documented local-input workflows. It removes scratch data
  on normal exit and handled signals; abrupt termination can leave private
  scratch debris.
- **Missing evidence is not clean evidence.** Unavailable evidence is never
  promoted to `PASS`. Most unread or incomplete sources are surfaced as
  `NOT_ASSESSED` in the completeness model. Stale definitions are explicitly
  identified and cannot silently support a current-data `PASS`.

These are deliberately narrower statements than “the process has no side
effects.” Producing a report, publishing a verified definitions-cache
generation, and using bounded scratch space are filesystem writes.

## What it reads

The runners use standard platform read or query commands and fixed, reviewable
configuration paths to inspect:

- host identity, AIX TL/SP, and firmware levels, filesets, interim fixes,
  and locally supplied vulnerability evidence;
- filesystems, volume groups, logical volumes, disks, paths, paging, CPU,
  memory, and performance counters;
- `errpt`, dump, boot, backup, availability, and monitoring posture;
- network interfaces, routes, listeners, resolver configuration, SSH,
  services, account/password/audit policy, scheduled work, and bounded file
  metadata checks.

The public check inventory and command declarations are in
[`catalog.json`](catalog.json) and the adjacent `manifest.json` files under
[`checks/`](checks/). The operator-focused scope is described in
[`docs/auditing-aix.md`](docs/auditing-aix.md).

## What it writes

The candidate can write only the following local artifacts:

- HTML, JSON, or compliance output sent to stdout or redirected by the
  operator;
- an HTML report under a directory explicitly selected with `--out` (the
  zero-argument convenience run selects the current directory), using a hidden
  same-directory temporary file before the final `mv`;
- two owner-only inventory files under a directory explicitly selected with
  `--flrt-export`. PTxray resolves and validates the directory ancestry, writes
  through exclusive owner-only temporary files, refuses existing destinations,
  checks both capture return codes, and publishes with no-clobber hard links; and
- when authorized FLRTVC inputs are supplied locally, private scratch files
  under `${TMPDIR:-/tmp}`. PTxray creates its scratch directory mode 700,
  restricts the input copies, and makes a best-effort removal on normal exit or
  a handled signal. An abrupt termination, including one during final cleanup,
  can leave the private directory behind for manual removal; and
- verified, immutable definitions generations under
  `/var/ptxray/definitions`, plus the protected current-generation pointer and
  bounded temporary files used during verification. A connected update is a
  pre-assessment downloader operation, not an assessment probe.

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

[`public-checks.yml`](.github/workflows/public-checks.yml) runs
[`egress-lint.sh`](tools/ci/egress-lint.sh) over the assessment runners, review
helper, validator, and standalone checks. It deliberately excludes
`ptxray-defs.sh`, because the downloader is the one network-capable component.
The lint rejects network-client commands in executable positions and carries a
regression for the former wrapped `host` lookup.

Static lint is a review tripwire, not a shell parser or proof of arbitrary-code
behavior. Inspect the exact runner and downloader sources and repeat a network
trace on the AIX or IBM i release you intend to assess. Keep the downloader out
of an assessment-only trace, or account for its disclosed pre-assessment HTTPS
requests separately.

## Read-only enforcement and assembly identity

[`verify-release-integrity.py`](tools/verify-release-integrity.py) requires
root/site artifact identity, validates catalog and release-manifest digests,
and checks the exact release asset set. Public CI does not rebuild the private
engine. Shared runner control flow and its bounded local writes still require
source review; a command allowlist is not presented as a universal proof.

See [`docs/VERIFY.md`](docs/VERIFY.md) for exact commands to inspect likely
network and mutating primitives, run the public gates, and compare SHA-256
digests.

## Unpublished PTxray 1.5 release candidate boundary

This candidate is not a published release. AIX requires root, and IBM
i requires both `SESSION_USER=QSECOFR` and `SYSTEM_USER=QSECOFR`. The privilege
gate runs before definitions selection, so an unprivileged invocation neither
starts a scan nor reaches the network.

The runner invokes the separate adjacent `ptxray-defs.sh` only after validating
its ownership, mode, and embedded same-release SHA-256 digest. Connected mode
attempts to download the current signed definitions by default. `--offline` uses only the signed
cache. `--definitions-bundle SIGNED_FILE` imports a local signed bundle and its
adjacent `SIGNED_FILE.sig`. The interactive menu exposes update, signed cache,
local signed bundle, and continue-without-definitions choices; a prompt timeout
or end-of-file cancels without running the assessment.

Before a connected update, the downloader identifies the two fixed public
HTTPS GET requests, the cache destination, and the source-IP, host/path, time,
TLS, and fixed-user-agent metadata visible to PowerTrue and ordinary DNS/TLS
infrastructure. It disables redirects and inherited proxies and sends no
request body or assessment data. It verifies signatures and schema before
publishing an immutable generation under `/var/ptxray/definitions`. A failed
update can use the last valid signed cache; old or stale definitions produce an
explicit age warning. Assessment probes begin only after selection and remain
no-egress, read-only on system configuration, and non-remediating. An
air-gapped assessment uses `--offline` with a valid cache or a locally
transferred signed bundle.

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

The 1.5 candidate helper writes its `ptxray-review-*.html`,
`ptxray-local-key-*.map`, and `ptxray-local-removals-*.txt` outputs beside the
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
