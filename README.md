# PTxray — understand the health and security of your IBM Power systems

**Free, open-source assessment for IBM AIX and IBM i.** PTxray turns local system evidence into a readable report of security risks, software and patch currency, operational health, and resilience. See what needs attention, the evidence behind each finding, and recommended next steps.

It runs read-only checks and keeps the results on your host. **No configuration changes. No remediation. No assessment-data uploads or telemetry.**

[Get PTxray](#get-ptxray) · [Safe, local assessment](#designed-for-safe-local-assessment) · [Open-source code](#open-source-and-inspectable) · [Product page](https://powertruesystems.com/ptxray/)

## What you can learn

| Question | What PTxray examines |
| --- | --- |
| Where are the security gaps? | Account and password policies, privileged access, service settings, file permissions, and checks aligned with applicable security benchmarks. |
| Which software or patches need attention? | OS and software levels, known vulnerability evidence, AIX FLRTVC exposure findings, and IBM i PTF evidence. |
| Is the system current and supported? | OS support status, firmware and patch currency against available reference data. |
| What could affect reliability? | Storage and capacity, selected performance indicators, configuration health, and recorded errors. |
| What needs review before a recovery event? | Available backup, redundancy, and recovery configuration evidence. |

Checks and available evidence differ by platform. The report makes those boundaries visible so you can distinguish an identified problem from something that still needs manual review.

## A report you can act on

- **Understand the findings:** open a local HTML report with results, supporting evidence, and recommended actions.
- **Plan the follow-up:** use the findings to inform patching, configuration reviews, maintenance, and recovery-readiness discussions. You decide which actions to take.
- **Bring evidence to a review:** use benchmark mappings and explicit coverage disclosures to support security and audit work.
- **Use the results in your workflow:** retain JSON findings and structured assessment data alongside the human-readable report.

Results distinguish `PASS`, `FAIL`, `WARN`, `NOT_APPLICABLE`, and `NOT_ASSESSED`. Missing evidence is never silently counted as a pass. An assessment supports decisions; it does not certify compliance or prove that a system is secure or recoverable.

## Designed for safe, local assessment

- **Reads and reports:** assessment probes change no system configuration and perform no remediation. PTxray does not install missing packages or change authority settings.
- **Keeps assessment local:** probes make no network calls and send no assessment data or telemetry away from the host. PTxray does not upload your report.
- **Separates downloads from assessment:** before assessment, the separate definitions helper can download signed reference data and, on AIX, the pinned IBM FLRTVC engine. These disclosed requests send no assessment data. Use `--offline` with verified, staged inputs when the host must stay disconnected.
- **Lets you verify what you run:** releases include signed manifests and checksums. [Verify the release](docs/VERIFY.md) and inspect the code before privileged execution.

Read-only assessment still writes local reports and private temporary files; acquisition writes a protected local cache. AIX runs as root and IBM i as QSECOFR, so review the prerequisites and choose a suitable execution window. Large assessments can take tens of minutes and consume system resources. See [SECURITY.md](SECURITY.md) for the full trust model.

Reports contain sensitive system details. The bundled review-copy helper rejects the current composed report format; it does not currently produce a pseudonymized copy of these reports. Review and remove sensitive details manually before sharing.

## Open source and inspectable

PTxray's published assessment code is **open source under [Apache-2.0](LICENSE)**. Download and run it without an email address, form, or registration. You can inspect the shell code and the commands it uses before running it.

The public AIX catalog contains 585 standalone check tools with adjacent command manifests in [`checks/`](checks/). [`catalog.json`](catalog.json) records the inventory and exact SHA-256 hashes. The IBM i report bundle contains its own 134-check catalog. These are tool counts, not counts of findings or benchmark controls.

IBM FLRTVC and IBM's APAR feed are separately acquired vendor inputs, not redistributed in the report bundles; their use remains subject to the applicable vendor terms.

## Get PTxray

Version: 1.8.0

Download the complete signed [PTxray v1.8.0 release](https://github.com/PowerTrueSYS/ptxray-public/releases/tag/v1.8.0) for your platform:

- [AIX report bundle](https://github.com/PowerTrueSYS/ptxray-public/releases/download/v1.8.0/ptxray-report-aix-1.8.0.tar)
- [IBM i report bundle](https://github.com/PowerTrueSYS/ptxray-public/releases/download/v1.8.0/ptxray-report-ibmi-1.8.0.tar)

Follow [the verification guide](docs/VERIFY.md) before extracting or running code with privileges. Keep the complete bundle intact: the top-level runner copies require its tool tree, helpers, libraries, and data.

## Run a complete AIX assessment

AIX 7.2 or 7.3 requires root, KornShell including native ksh93 for IBM FLRTVC, and supported fixed-path OpenSSL. Connected acquisition also requires supported curl and unzip. PTxray does not install packages or change host configuration.

After verifying the release:

```sh
mkdir ptxray-aix
cd ptxray-aix
tar -xf ../ptxray-report-aix-1.8.0.tar
mkdir report
ksh dist/tools/aixray-scan.ksh --html --pdf --json --compliance all --out report
```

The runner acquires signed definitions and the pinned IBM FLRTVC engine before assessment, captures fileset and interim-fix inventory, runs IBM FLRTVC offline, and includes the completed exposure results in HTML and JSON. It retains IBM's complete compact report as `report/flrtvc-report.txt`. An incomplete engine run does not produce a completed assessment report. Stale or unverified definitions cannot support a clean vulnerability conclusion.

The separate `ptxray-defs.sh` downloader makes disclosed HTTPS requests before assessment and writes a protected local cache. It sends no assessment data. IBM's engine and APAR feed are acquired separately; they are not redistributed inside these bundles.

## Run a complete IBM i assessment

IBM i 7.4 or 7.5 requires PASE ksh and QSECOFR as both session and effective user. Read the bundle's `README-REPORT.md` for the required IBM i SQL services and runtime tools.

```sh
mkdir ptxray-ibmi
cd ptxray-ibmi
tar -xf ../ptxray-report-ibmi-1.8.0.tar
mkdir report
ksh dist/tools/ibmi-scan.ksh --html --json --compliance all --out report
```

The full catalog includes security, operational health, capacity, resilience, and currency checks. IBM i uses its own native evidence and PTF data; IBM FLRTVC is an AIX tool. Explicit `cis-l1` and `cis-l2` selections are available for narrower assessments. Coverage and unsupported evidence are disclosed in the report; running every available check does not establish full compliance with a benchmark.

## Reports and offline use

Open `report/report.html` in a browser. JSON findings are in `report/report.json`, and `report/scan.ptx` carries the structured report data. AIX `--pdf` also writes `report-print.html` for the browser's Print → Save as PDF command. IBM i additionally writes `ptxray-ibmi.json` for Blueprint workflows.

Use `--offline` to consume verified cached inputs without acquisition requests. An air-gapped AIX host also needs the pinned IBM engine staged through the helper's `--flrtvc-local` mode. A local signed definitions bundle must travel with its adjacent `.sig` file. See each bundle's `README-REPORT.md` for staging commands and exact prerequisites. Missing or invalid required inputs produce an explicit refusal.

## Scope and support

PTxray reports evidence and recommended actions; it does not remediate the host or prove security, compliance, or recoverability. Standards tags are alignment information, not certification. VIOS assessment remains disabled pending live acceptance. No unsupported platform coverage is implied by IBM Power branding.

See [SECURITY.md](SECURITY.md) for the trust boundary and private vulnerability-reporting channel, and [docs/auditing-aix.md](docs/auditing-aix.md) for the audit guide. Use [GitHub issues](https://github.com/PowerTrueSYS/ptxray-public/issues) for ordinary bug reports; do not include sensitive assessment data.

## Release history

For changes in each version, see the [release notes](docs/RELEASE-NOTES.md) and [GitHub releases](https://github.com/PowerTrueSYS/ptxray-public/releases).
