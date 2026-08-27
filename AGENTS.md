# ptxray-public

The **public, open-source** face of PTxray and the site content behind
`powertruesystems.com/ptxray/`. Everything here is customer- and search-visible. This file
carries the working rules for this repository.

## This repo is public

**Anything committed here is public immediately and permanently.** No client data, no lab
hostnames, no internal pricing, no roadmap, no internal decision references. A hostname, IP, or
serial that looks like a customer estate is a stop-and-escalate.

**The private engine lives outside this public repository.** This repo carries the
distributed artifact and the public documentation, not the build system.

## Repo-specific rules

**The product claims here are load-bearing.** "Runs as a single ksh88 file under AIX `/bin/sh`",
"makes zero network calls during assessment execution", "reports findings without remediating
the host", "changes no system configuration and sends no assessment data away from the host" —
these are commitments a customer relies on and a competitor will test. Never widen a claim to
make copy read better, and never let a claim drift ahead of what the shipped artifact does.

**The network boundary applies to assessment execution.** The assessment must not reach the
network or send assessment data or telemetry away from the host.

**A published or downloadable version number in the copy must match the shipped artifact.**
Unpublished-candidate copy must say that status explicitly and must not imply the candidate is
available from the published download channel.

**No remediation.** PTxray reads and reports. Any change that mutates a host contradicts the
product.

## Published 1.6 release boundary

PTxray 1.6.0 is the current published release and is available from `releases/latest` as an
exact signed eleven-asset set: eight payloads recorded in `SHA256SUMS` — the six 1.5 artifacts
plus `ptxray-report-aix-1.6.0.tar` and `ptxray-report-ibmi-1.6.0.tar` — that manifest, its
detached signature, and the release public key. The report runners inside the two bundles are
the product entry points; the one-file scripts remain for compatibility and do not produce the
report. Its AIX runner requires root, and its IBM i runner
requires QSECOFR. Before assessment probes begin, each runner verifies and invokes the separate,
adjacent, same-release digest-bound `ptxray-defs.sh`. Connected mode attempts a signed-definitions
update by default; `--offline` selects the signed cache, and `--definitions-bundle` imports a local
signed bundle and its adjacent signature. The interactive menu presents the same choices.

Only the downloader may use the network or write `/var/ptxray/definitions`; its disclosure occurs
before any request. The assessment probes remain read-only, perform no remediation, make no
network calls, and send no assessment data away from the host. A report or explicitly requested
export is still a local write. Keep this distinction intact on every customer-visible surface.

IBM i firmware, PTF group, and Security/HIPER group currency are `NOT_ASSESSED` in 1.6; the
`--allow-ibm-lookup` opt-in arrives in 1.7. Do not describe that currency as measured.

The VIOS lane remains disabled pending live VIOS acceptance. Do not describe
the published 1.6 release as VIOS-capable.
