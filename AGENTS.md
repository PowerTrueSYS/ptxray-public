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

**The product claims here are load-bearing.** "Ships complete inspectable KornShell report bundles",
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

## Published 1.8 release boundary

PTxray 1.8.1 ships exactly eleven signed-release assets: eight payloads in
`SHA256SUMS`, that manifest, its detached signature, and the release public key.
The report bundles contain the product entry points and their complete tool trees.
Top-level runner copies require the extracted bundle; retired one-file scanners
are not shipped. AIX requires root and native ksh93 for IBM FLRTVC. IBM i requires
PASE ksh and QSECOFR. Follow each bundle's runtime prerequisites.

Before assessment, each runner verifies its same-package definitions helper and
its digest pin. The separate helper acquires signed definitions and, on AIX, the
pinned IBM FLRTVC engine. IBM delivery inputs are acquired separately and must not
be redistributed inside the report bundles. Offline runs require verified local
inputs and cannot bypass missing evidence to manufacture a complete result.

Only the separate acquisition helper may make download requests or write the
protected definitions cache; disclosure occurs before a request. Assessment
probes perform no remediation, change no system configuration, make no network
calls, and send no assessment data away. Report and scratch files are local writes.

The complete IBM i selection runs every registered check. This is not a claim of
complete automated benchmark coverage: partial and manual evidence gaps remain
explicit. Do not use network-backed SQL services during assessment.

The review-copy helper refuses current composed reports because their privacy
annotations do not satisfy its strict contract. Manual privacy review is required
before sharing a full report; never present a refusal as pseudonymization success.
VIOS remains disabled pending live acceptance.
