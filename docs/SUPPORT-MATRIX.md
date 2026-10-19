# PTxray support matrix

This page lists which platforms PTxray supports, from which release, on which OS levels, how to run each one, and the known limits. It covers PTxray 1.8.4.

| Platform | Status | Since | Supported OS levels | How to run (release asset) | Known limits |
| --- | --- | --- | --- | --- | --- |
| AIX | Shipped | 0.1.0 | AIX 7.2 and 7.3 | As root, from the extracted bundle: `ksh dist/tools/aixray-scan.ksh --html --pdf --json --compliance all --out report` (in `ptxray-report-aix-<version>.tar`) | See [AIX](#aix) |
| VIOS | Shipped | 1.8.2 | Not documented (see [VIOS](#vios)) | From the padmin shell run `oem_setup_env`, then as root, from the extracted AIX bundle: `ksh ptxray-vios.sh --html --pdf --json --compliance all --out report` (in `ptxray-report-aix-<version>.tar`) | See [VIOS](#vios) |
| IBM i | Shipped | 1.3.0 | IBM i 7.4 and 7.5 | As QSECOFR (session and effective user), in PASE, from the extracted bundle: `ksh dist/tools/ibmi-scan.ksh --html --json --compliance all --out report` (in `ptxray-report-ibmi-<version>.tar`) | See [IBM i](#ibm-i) |
| Linux | Planned | Not shipped | Not documented | None. No current release includes a Linux scanner. | See [Linux](#linux) |

`<version>` is the release version, for example `ptxray-report-aix-1.8.4.tar`. Verify the release first ([docs/VERIFY.md](VERIFY.md)), and keep the extracted bundle intact. `--out` must be an existing directory. Every platform's assessment is read-only: it changes no configuration, performs no remediation, and sends no assessment data away from the host.

## AIX

- Needs root, KornShell including native ksh93 (for IBM FLRTVC), and supported fixed-path OpenSSL. Connected acquisition also needs supported curl and unzip. PTxray does not install missing packages.
- Before the assessment starts, the separate `ptxray-defs.sh` helper downloads signed definitions and IBM's pinned FLRTVC engine. On a host with no network route, stage those inputs first and add `--offline`; the bundle's `README-REPORT.md` has the exact steps. If a required input is missing or invalid, PTxray refuses and does not write a report.
- IBM FLRTVC and IBM's APAR feed are acquired separately and are not included in the bundles. Their use is subject to IBM's terms.
- Standards tags show alignment, not certification. A completed run does not prove compliance, security, or recoverability.
- The full selection can take tens of minutes on a small partition.
- The review-copy helper rejects the current report format. Remove sensitive details by hand before sharing a report.

## VIOS

- VIOS uses the AIX report bundle. `ptxray-vios.sh` checks that it is running as root and that `/usr/ios/cli/ioscli` exists, then runs the AIX runner. The full AIX catalog runs, plus checks specific to the VIOS. The assessment is read-only and does not change VIOS configuration.
- VIOS checks cover:
  - the VIOS level, compared with IBM's support lifecycle
  - Shared Ethernet Adapter failover setup, bridge mode, link status, and related settings
  - whether the VIOS is a single point of failure
  - virtual Fibre Channel (NPIV) login state and adapter redundancy
  - virtual SCSI mappings, backing devices, and reservation policy
  - vNIC mappings
  - Shared Storage Pool cluster health, free space, alert thresholds, and node upgrade status
  - VIOS configuration backups
  - extra login accounts and logins that bypass the restricted shell
  - viosecure firewall and hardening level
- Supported VIOS levels are not documented. The bundled lifecycle data rates VIOS 4.1 as supported and VIOS 3.1 as end of support from 2026-04-30.
- There is no CIS VIOS benchmark. PTxray does not claim CIS VIOS certification. Ordinary AIX, STIG, CIS, and vulnerability findings still apply on a VIOS.
- If a VIOS has no Shared Ethernet Adapter, NPIV, virtual SCSI, or Shared Storage Pool configured, the report shows those areas as not present. It does not treat that as a tested redundant setup.
- The checks for configured Shared Ethernet Adapter failover, NPIV, virtual SCSI, and Shared Storage Pools were built from IBM's documented command output and test data. They have not yet been run against a live VIOS that has those features configured.
- If the command output can't be read, the result is a warning or "not assessed", never a pass.
- A scan sees only the VIOS it runs on. It cannot confirm the partner VIOS in a dual-VIOS setup.
- The AIX limits above also apply. For a VIOS with no network route, stage the inputs and add `--offline` as described in the bundle's `README-REPORT.md`.

## IBM i

- Needs PASE ksh, with QSECOFR as both the session and the effective user, plus the IBM i SQL services and tools listed in the bundle's `README-REPORT.md`.
- IBM i uses its own native evidence and PTF data. IBM FLRTVC is an AIX tool and is not used on IBM i.
- The assessment does not use network-backed SQL services. Evidence that cannot be read locally is reported as "not assessed".
- The IBM i run writes HTML and JSON reports. The `--pdf` print form is documented for AIX only.
- There is no DISA STIG for IBM i, so none is claimed. Running every check does not mean full benchmark compliance; partial and manual coverage is shown in the report.

## Linux

- Not shipped. No current PTxray release includes a Linux scanner or a Linux bundle. The repository keeps an old Linux demo script, but it is frozen and is not part of the product.
- Supported Linux distributions and a release version are not documented.

## How this is maintained

This file is the single source of truth for PTxray platform support. The README, release notes, the PTxray web page, and marketing material should cite this file rather than repeat its contents. Update it in the same change that ships, adds, or retires a platform, and check it at every release.

## Sources

Every cell above comes from these sources:

- **AIX row.**
  - OS levels, root, ksh93, OpenSSL, curl/unzip, and the run command: [README.md](../README.md), "Run a complete AIX assessment", and the bundle's `README-REPORT.md`.
  - Since 0.1.0: the v0.1.0 GitHub release and the "v0.1.0 release-integrity note" in [RELEASE-NOTES.md](RELEASE-NOTES.md).
  - Run time and review-helper limits: [README.md](../README.md) and [SECURITY.md](../SECURITY.md).
  - FLRTVC/APAR boundary: [README.md](../README.md), "Open source and inspectable".
- **VIOS row.**
  - Since 1.8.2: [RELEASE-NOTES.md](RELEASE-NOTES.md) v1.8.2. `ptxray-vios.sh` is in `ptxray-report-aix-1.8.2.tar` and later, and not in `ptxray-report-aix-1.8.1.tar`.
  - Command and `oem_setup_env`: the AIX bundle's `README-REPORT.md` ("On VIOS, after `oem_setup_env`, as root").
  - Wrapper behaviour: `ptxray-vios.sh` in the AIX bundle.
  - Check coverage: `checks/ck-vios-*`, `ck-viosecure-*`, `ck-sea-*`, `ck-npiv-*`, `ck-vscsi-*`, `ck-vnic-maps`, and `ck-ssp-*` manifests in [checks/](../checks/), plus RELEASE-NOTES v1.8.3 and v1.8.4.
  - Lifecycle data: `EOS_VIOS` in `dist/tools/ck-vios-level.ksh` in the AIX bundle.
  - No CIS VIOS benchmark, the not-present behaviour, and the live-test limit: RELEASE-NOTES v1.8.2, v1.8.3, and v1.8.4.
  - Unreadable output never passes: [README.md](../README.md) ("Missing evidence is never silently counted as a pass") and the VIOS check manifests (for example `ck-npiv-maps`: "A failed lsmap is not assessed").
  - Built from IBM's documented command output, and the single-VIOS limit: PTxray's VIOS coverage notes (`docs/COVERAGE.md`, "VIOS role checks", in the private source repository), together with the live-test statements in RELEASE-NOTES v1.8.3 and v1.8.4.
- **IBM i row.**
  - OS levels, QSECOFR, PASE ksh, the run command, and native PTF evidence: [README.md](../README.md), "Run a complete IBM i assessment".
  - Since 1.3.0: RELEASE-NOTES v1.3.0 ("PTxray joins the IBM i platform").
  - No network-backed SQL services: RELEASE-NOTES v1.8.0.
  - No DISA STIG for IBM i: RELEASE-NOTES v1.3.0.
  - `--pdf` documented for AIX only: [README.md](../README.md), "Reports and offline use".
- **Linux row.**
  - The [v1.8.4 GitHub release](https://github.com/PowerTrueSYS/ptxray-public/releases/tag/v1.8.4) has eleven assets and none of them is a Linux scanner or bundle.
  - The frozen Linux demo: the project changelog ("Linux reference ... frozen demo").
  - Planned status: product decision. No release version or distribution list is documented.
