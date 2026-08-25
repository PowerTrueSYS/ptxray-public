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

## Published 1.5 release boundary

PTxray 1.5.0 is the current published release and is available from `releases/latest` as an
exact signed asset set. Its AIX runner requires root, and its IBM i runner
requires QSECOFR. Before assessment probes begin, each runner verifies and invokes the separate,
adjacent, same-release digest-bound `ptxray-defs.sh`. Connected mode attempts a signed-definitions
update by default; `--offline` selects the signed cache, and `--definitions-bundle` imports a local
signed bundle and its adjacent signature. The interactive menu presents the same choices.

Only the downloader may use the network or write `/var/ptxray/definitions`; its disclosure occurs
before any request. The assessment probes remain read-only, perform no remediation, make no
network calls, and send no assessment data away from the host. A report or explicitly requested
export is still a local write. Keep this distinction intact on every customer-visible surface.

The VIOS lane remains disabled pending live VIOS acceptance. Do not describe
the published 1.5 release as VIOS-capable.
