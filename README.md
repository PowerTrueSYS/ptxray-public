# PTxray: IBM AIX and IBM i assessment

PTxray produces a local HTML risk report and JSON findings from read-only checks of IBM AIX and IBM i. Assessment probes change no system configuration, perform no remediation, make no network calls, and send no assessment data or telemetry away from the host.

Version: 1.8.0

**Download the complete signed release:** [PTxray v1.8.0](https://github.com/PowerTrueSYS/ptxray-public/releases/tag/v1.8.0). The report bundles are the product entry points. Verify the signed manifest and bundle checksums using [docs/VERIFY.md](docs/VERIFY.md) before extracting or running code with privileges.

- [AIX report bundle](https://github.com/PowerTrueSYS/ptxray-public/releases/download/v1.8.0/ptxray-report-aix-1.8.0.tar)
- [IBM i report bundle](https://github.com/PowerTrueSYS/ptxray-public/releases/download/v1.8.0/ptxray-report-ibmi-1.8.0.tar)
- [Source and issue tracker](https://github.com/PowerTrueSYS/ptxray-public)
- [Official product page](https://powertruesystems.com/ptxray/)

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

The full AIX selection can take tens of minutes on a small partition, especially while scanning the filesystem for Trusted Execution and rendering detailed findings. Findings distinguish `PASS`, `FAIL`, `WARN`, `NOT_APPLICABLE`, and `NOT_ASSESSED`; unavailable evidence is never silently counted as a pass.

## Inspectable components

The AIX catalog contains 585 standalone check tools with adjacent command manifests in [`checks/`](checks/). [`catalog.json`](catalog.json) records the inventory and exact SHA-256 hashes. IBM i has a separate 134-check catalog inside its report bundle. The tool counts are not counts of findings or benchmark controls.

The top-level `aixray-scan.ksh`, its compatibility name `aixray-aix.sh`, and `ibmi-scan.ksh` are copies of the bundled runners. They require the extracted tool tree and do not run as standalone files. Keep the complete bundle intact, including its definitions helper, libraries, and data.

The bundled review-copy helper rejects the current composed report format because it does not yet satisfy its strict privacy contract. Do not treat a full report as pseudonymized. Review and remove sensitive host, account, address, and operational details manually before sharing. PTxray does not upload the report.

## Scope and support

PTxray reports evidence and recommended actions; it does not remediate the host or prove security, compliance, or recoverability. Standards tags are alignment information, not certification. VIOS assessment remains disabled pending live acceptance. No unsupported platform coverage is implied by IBM Power branding.

See [SECURITY.md](SECURITY.md) for the trust boundary and private vulnerability-reporting channel, [docs/auditing-aix.md](docs/auditing-aix.md) for the audit guide, and [LICENSE](LICENSE) for Apache-2.0 terms. No email address, form, or registration is required to download or run PTxray.
