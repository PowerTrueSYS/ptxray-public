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

**Published 1.4 privilege claims follow the artifact.** AIX and VIOS are best run as root, but
a non-root run is supported with root-only checks degraded to `WARN` or `NOT_ASSESSED`. Do not
describe that current behavior as a privilege refusal.

**A version number in the copy must match the shipped artifact.** Documentation that describes
a version we have not published is a false claim on a public page.

**No remediation.** PTxray reads and reports. Any change that mutates a host contradicts the
product.

## Unpublished 1.5 design boundary

This design is not a published release or current inventory. In 1.5, AIX and VIOS require root
and IBM i requires QSECOFR. Its separate downloader attempts to acquire current signed
definitions by default and is not invoked by either assessment. Keep those future claims in an
explicitly unpublished 1.5 section until the renderer-owned refusing programs and downloader
ship.
