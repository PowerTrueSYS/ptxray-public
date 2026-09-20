# Security and trust model

PTxray 1.8.1 is an inspectable assessment for AIX and IBM i. The product entry points are the runners inside the complete signed report bundles. AIX requires root; IBM i requires QSECOFR as session and effective user. VIOS assessment is disabled pending live acceptance.

## Assessment boundary

Assessment probes read local evidence, change no system configuration, perform no remediation, make no network calls, and send no assessment data or telemetry away from the host. Acquisition and assessment are separate operations. The adjacent `ptxray-defs.sh` helper may make disclosed requests before assessment; it sends no assessment data.

Read-only does not mean that no files are written. Reports, explicitly requested exports, private scratch directories, and verified definition-cache generations are local writes. The helper discloses the cache location. Normal exit and handled signals remove temporary scratch; abrupt termination can leave private scratch behind.

Missing, malformed, unsupported, stale, or ambiguous evidence is not clean evidence. A completed run may contain `FAIL`, `WARN`, `NOT_ASSESSED`, and `NOT_APPLICABLE`. Read the findings and coverage disclosures. PTxray does not prove security, compliance, recoverability, or absence of defects.

## Verify the complete release

Follow [docs/VERIFY.md](docs/VERIFY.md) before privileged execution. The release contains eleven assets: eight payloads, `SHA256SUMS`, its detached `SHA256SUMS.sig`, and `POWERTRUE-RELEASE-PUBLIC.pem`. The manifest binds the bundles, runner copies, definitions helper, and review tools. Checks and data inside the bundles are covered by their bundle hashes; the separate public catalog is cross-checked by the verifier. Verify the manifest signature before trusting its checksums, then verify the tagged tree and downloaded assets.

Confirm the release public-key fingerprint independently with PowerTrue Systems. SHA-256 of the DER SubjectPublicKeyInfo is:

```text
sha256:c2fa7dc69be3dead5e196eca6a9c48ece42a7105eb9f56ab9f620bd0c6c617bd
```

An attacker who replaces both code and an unverified public key can defeat a checksum-only procedure. A fingerprint delivered by the same untrusted download is not independent authentication. Private signing keys are not stored in this repository or in a report bundle.

Keep the extracted bundle in a trusted directory with its files intact. The runners verify the definitions helper's ownership, permissions, physical path ancestry and SHA-256 against a trusted same-package pin, stage a private copy, and execute only that verified copy. The public release signature authenticates the package including its pin. The top-level runner files are not self-contained and must not be run alone.

## Definitions and IBM FLRTVC

The helper verifies RSA-signed data before parsing it and protects cache generation integrity and its rollback floor. An invalid signature or corrupt generation is rejected. `--offline` uses verified cache without acquisition requests; a local signed bundle must include its adjacent `.sig`. Stale data remains explicitly marked rather than being silently restamped.

On AIX, the helper separately acquires IBM FLRTVC and validates its pinned SHA-256. The assessment adapter rechecks the private engine copy and executes it offline with captured fileset/interim-fix inventory and APAR data. The engine requires native ksh93. Required inputs, engine completion, and the complete compact output are validated before the report is accepted. A truncated engine response is not a completed assessment, and stale APAR data cannot establish a clean vulnerability result.

Public report bundles do not contain IBM's executable engine or APAR CSV. The redistribution guard checks those names and content signatures, including bundle contents. It is a targeted guard, not a license classifier for every possible IBM-derived byte. Vendor input acquisition and use remain subject to the applicable vendor terms.

## Runtime and local evidence

AIX requires native platform commands, KornShell/ksh93 and supported fixed-path OpenSSL. Connected engine acquisition additionally needs supported curl and unzip. IBM i uses PASE ksh and documented SQL services; see its bundle README for service and tool requirements. PTxray does not install missing packages or change authority settings to obtain evidence.

Checks read platform identity, software/patch levels, system values, local configuration, storage and performance summaries, event/error records, and security settings. Inspect the exact code and adjacent command manifests before running it. Recommendations are explanatory text; PTxray does not execute remediation commands.

## Review-pack sharing

`ptxray-review-pack.sh` rejects current composed reports because their privacy annotations do not meet its strict contract. Review and remove sensitive details manually before sharing a full report. Its legacy supported format produces a pseudonymized copy, not guaranteed anonymity; never share a decoding key. The helper performs no upload or send. Sharing is a separate user action.

## Report a vulnerability privately

Do not open a public issue containing a suspected vulnerability or assessment data. Email [review@powertruesystems.com](mailto:review@powertruesystems.com) with the subject **PTxray security report**, or use [GitHub private vulnerability reporting](https://github.com/PowerTrueSYS/ptxray-public/security/advisories/new).

Include the release tag, platform, invocation, minimal reproduction, and observed impact. Do not attach production reports, credentials, private keys, or sensitive system data unless a secure transfer method has been agreed. Optional service/contact links are separate from acquisition and from security reporting.
