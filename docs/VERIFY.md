# Verify PTxray 1.8.1 before privileged execution

The product is the complete report bundle for your platform. A top-level runner alone lacks its tool tree. Verify the exact signed release before extracting the bundle or executing any of its programs. The commands below run on an administration workstation with Git, GitHub CLI, Python 3 and OpenSSL; they are not assessment-host runtime requirements.

## Signature first

Obtain the release key's fingerprint independently from PowerTrue Systems. The expected SHA-256 of its DER SubjectPublicKeyInfo is:

```text
sha256:c2fa7dc69be3dead5e196eca6a9c48ece42a7105eb9f56ab9f620bd0c6c617bd
```

Download the tagged source and release assets into new directories:

```sh
git clone --depth 1 --branch v1.8.1 https://github.com/PowerTrueSYS/ptxray-public.git ptxray-1.8.1
mkdir ptxray-1.8.1-assets
gh release download v1.8.1 --repo PowerTrueSYS/ptxray-public --dir ptxray-1.8.1-assets
cd ptxray-1.8.1-assets
openssl pkey -pubin -in POWERTRUE-RELEASE-PUBLIC.pem -outform DER | openssl dgst -sha256
```

Stop if the fingerprint does not match the independently confirmed value. A fingerprint supplied only through the same untrusted download does not authenticate that download.

```sh
openssl dgst -sha256 -verify POWERTRUE-RELEASE-PUBLIC.pem -signature SHA256SUMS.sig SHA256SUMS
```

Require `Verified OK` and exit code 0. Do not execute downloaded code before this signature and the relevant payload checksums have been verified.

The signed manifest records the eight release payloads, including the complete bundles. Verify all eight checksums in the assets directory (on macOS, use `shasum -a 256 -c SHA256SUMS`):

```sh
sha256sum -c SHA256SUMS
```

Require every entry to pass. The following additional repository verifier cross-checks the tagged tree, separate catalog, and downloaded assets. Its source is obtained through GitHub; it is not itself authenticated by the payload manifest:

```sh
cd ../ptxray-1.8.1
python3 tools/verify-release-integrity.py --tag v1.8.1 --repo-root "$PWD" --assets-dir "$PWD/../ptxray-1.8.1-assets"
```

Inspect that verifier before executing it. It checks the trusted signature, exact manifest/tree/asset hashes, version declarations, runner alias identity, catalog identity, and required bundle contents. It rejects missing or tampered payloads and unsafe archive members. A successful verifier does not establish that the program is free of defects; inspect the code and its declared command surface too.

## Exact release assets

The v1.8.1 release has eleven assets:

- `ptxray-report-aix-1.8.1.tar`
- `ptxray-report-ibmi-1.8.1.tar`
- `aixray-scan.ksh`
- `aixray-aix.sh` (byte-identical compatibility name for the AIX runner)
- `ibmi-scan.ksh`
- `ptxray-defs.sh`
- `ptxray-review-pack.sh`
- `ptxray-review-validate.awk`
- `SHA256SUMS`
- `SHA256SUMS.sig`
- `POWERTRUE-RELEASE-PUBLIC.pem`

The first eight are payloads recorded in the manifest. The signature authenticates the manifest, and the independently authenticated public key verifies the signature. The top-level runner copies require the complete extracted bundle. Retired `ptxray-aix.sh` and `ptxray-ibmi.sh` monoliths are not part of this release.

## Extract and run

After verification, copy the matching bundle to the assessment host, extract it in a trusted directory, and follow its `README-REPORT.md`. Preserve the libraries, data, definitions helper, pin files, checks, and renderers together. Inspect those components before privileged execution. AIX requires root and native ksh93/OpenSSL; connected acquisition also needs curl/unzip. IBM i requires PASE ksh and QSECOFR plus the documented SQL services.

Create an output directory and use `--compliance all` for the full available catalog. Narrower CIS selections do not verify the complete catalog. `--offline` requires verified cached inputs; offline AIX additionally requires the separately staged pinned IBM engine. Missing required input must fail explicitly, never be bypassed to obtain a report.

## Assessment and redistribution boundaries

Assessment probes must change no system configuration, perform no remediation, make no network calls, and send no assessment data or telemetry away from the host. The separate downloader makes disclosed acquisition requests before assessment. Report generation and protected cache/scratch writes are local filesystem effects.

Public bundles must not redistribute IBM FLRTVC or its APAR CSV. The repository guard and archive inspection check known names/content signatures; they do not replace license review for newly introduced content. Inspect both extracted bundles, including libraries and auxiliary scripts, when reviewing a release.

## Review copies and limitations

A full report may expose hostnames, addresses, account names and operational context. The review-pack helper rejects current composed reports: their privacy annotations do not meet its strict contract. Full reports require manual review and removal of sensitive details before sharing. For any supported review copy, pseudonymization is not anonymity; never share a local decoding key. No report is uploaded automatically.

Keep `NOT_ASSESSED`, `NOT_APPLICABLE`, warnings, source ages and coverage gaps intact. A successful scan or release verification is not proof that the host is secure, compliant, recoverable, or defect-free. Report security concerns privately as described in [SECURITY.md](../SECURITY.md).
