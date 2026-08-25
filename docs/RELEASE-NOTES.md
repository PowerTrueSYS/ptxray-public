# Release notes

## Unpublished candidate status

The latest published release remains version 1.4.0. PTxray 1.5.0 is an
unpublished release candidate, not a release. Its exact rendered programs,
catalog, source registry, checksums, signature, public key, and independently
published fingerprint must all come from the release renderer and signing
ceremony before a versioned 1.5 release section can be added.

The candidate AIX and VIOS runners require root; the IBM i runner requires
QSECOFR. Each runner authenticates and invokes the separate adjacent
`ptxray-defs.sh` before assessment. Connected mode attempts a signed-definitions
update by default, while `--offline` uses a signed cache and
`--definitions-bundle` accepts a local signed bundle. Assessment probes remain
no-egress, read-only on system configuration, and non-remediating. These facts
do not make 1.5 available from `releases/latest`.

The canonical site is `https://powertruesystems.com/ptxray/` and the canonical
repository is `https://github.com/PowerTrueSYS/ptxray-public`. The legacy site
URL `https://powertruesystems.com/aixray/` has an active HTTP 308 redirect to
the canonical site, which returns HTTP 200. The legacy GitHub repository URL
`https://github.com/PowerTrueSYS/aixray-public` has an active HTTP 301 redirect
to the canonical repository, which returns HTTP 200. These redirect facts do
not publish the 1.5 candidate. The release public key, fingerprint, and
signature are not yet published.

## v1.4.0

If you downloaded v1.3.0, download v1.4.0 and run it again. This release
rewrites what a scan hands you. The checks still read the same box the same
read-only way; the report they produce is new, and 25 checks that could only
ever report an inventory or a refusal have been taken out of the compliance
groups rather than left padding the count.

Two things this release does not do, stated up front so you can plan around
them: the currency producer lane is not in this release, and the currency
section of a scan says so in as many words instead of implying a clean result.

### IBM i edition

`ptxray-ibmi.sh` ships unchanged from v1.3.0 apart from its declared version: same
CIS IBM i V7R4M0 / V7R5M0 Benchmark v2.1.0 grading on IBM i 7.4 and 7.5, same read-only
PASE run. The report rewrite above is the AIX edition's; the IBM i report is the v1.3.0 form.

### What changed for you

**The report is new.** A scan now produces one structured document and renders
every view from it — the HTML report, the print form and the terminal
snapshot are three views of one document, never three separate calculations.
That is the whole point of the rewrite: a number in the printed page and the
same number on your terminal cannot disagree, because neither one computed it.

The page is three things, top to bottom, and nothing else:

- **The hero.** A five-ring aperture, one ring per pillar, each ring labelled
  with its score and its name and each label a link into that pillar's
  section. The middle carries the overall score, the hostname and the scan
  date — or `NOT SCORED` and an `n OF m ASSESSED` line when coverage is too
  thin to grade honestly.
- **The pillar sections.** One collapsed section per pillar. The summary row
  carries a gauge, the pillar name, the context that pillar is judged in
  (the AIX level, the firmware level, the standards you selected), a
  one-line statement of how the score was derived, and a proportional
  FAIL/WARN/PASS bar. Opening a section lists its controls, worst first, each
  with its verdict, what was found, and the command and captured output the
  verdict came from.
- **The Blueprint box.** The last element on the page.

**The report carries findings and evidence. It does not carry remediation.**
No fix text, no cost estimate, no outage window appears on any row. That is a
deliberate line: the report is the X-ray, and a remediation plan for your box
is a separate piece of work that starts from it.

**A refusal reads as a refusal.** A control PTxray could not assess renders
the word `NOT ASSESSED`, a box saying why it could not be assessed, and the
severity that control would have carried — as `ck-sec-apars` does on our lab
box, rendering `NOT ASSESSED`, `The probe ran but produced no output to
assess.` and a `high` exposure — so an unassessed critical control
cannot sit on the page wearing the same shape as a passing one. It groups
with the warnings and it counts as a warning in the pillar score. It is never
folded into the passes.

**A print form.** The report converts to a page-broken print layout you send
to Print → Save as PDF in any browser. Page one is the hero plus a one-line
index of every pillar; each pillar then expands onto its own page, opened, so
a printed copy carries the same evidence a clicked-open browser copy does.
There is no PDF binary, no font download and no network call anywhere in that
path.

**A terminal snapshot.** Add `--tty` alongside `--out` and the same document
also renders as a compact ASCII headline on stderr — host, platform, OS level,
scan date and the overall score — so a scripted run can log the verdict without
parsing HTML. It is a modifier on the report, not a mode of its own: the report
is still written to `--out`, and the snapshot goes to stderr so it never mixes
into piped output.

**A provenance stamp on every report, not only when something is wrong.**
Each definitions source renders its id, whether it was bundled or fetched,
its `as_of` date, its origin, and its age in whole days — with `STALE` when
that age exceeds 30 days. You can tell at a glance how old the data behind a
verdict is, on a clean report as much as on a bad one.

### The pare: 25 checks out of the groups

Twenty-five checks are flagged `pared` and no longer appear in any compliance
group. Eight were refusal-only or inventory-only — they reported what is
installed, or reported that they could not judge, without ever rendering a
verdict. Seventeen were performance and housekeeping tuning checks that do
not belong in a security-and-currency posture scan.

The check directories stay: several remain useful as fact emitters and the
history is preserved. What changes is that they stop inflating a compliance
denominator they were never going to answer.

One customer-visible coverage change: the **FFIEC group drops from 34 to 31
controls**. `ck-fs-lv-slack`, `ck-jfs-legacy` (`II.C.11`) and `ck-savevg`
(`II.C.21`) were the only pared checks carrying compliance tags. CIS Level 1
and Level 2 and STIG coverage are unchanged.

The backup checks in the pared set are not lost work — the questions they
tried to answer from inside an LPAR are better answered by asking you during
onboarding, which is where they are going.

### Under the hood: one control, one tool

The scanner is built from per-tool modules rather than one script with
everything inlined. The runner's job is to run doors and pass their output
along; it does not contain a check body, a probe or an HTML row. Every
hardware and OS fact on the report — the machine, the AIX level, the firmware
level, CPU, memory, paging, filesystems, storage and recovery posture — now
comes from a probe captured on your box and handed to a pure transformer that
parses it and invents nothing.

### Currency: an honest refusal, not a clean result

**The currency producer lane is not in this release. It lands after 1.4.**

PTxray's currency evaluation needs producer records describing which
definition sources are loaded. Those producers are not built yet. Rather than
render a currency section that looks fine because it had nothing to judge,
the currency lane refuses and says so. On a completely healthy box, on a
completely broken box, the answer today is the same refusal — that is the
correct behaviour for a component that cannot see its inputs, and it is
called out here so nobody reads a quiet currency panel as a pass.

The definitions lane is a different mechanism and its evaluator does work.
Supply a `.aixray-defs` bundle and PTxray reads every source in it offline,
with no network call: on our lab box a current bundle evaluated to
`UNVERIFIED` because one source was 42 days old against a 30-day threshold — a
real verdict on real data, which is exactly what the currency lane cannot yet
give you.

**How to supply the bundle.** `--html` requires `--definitions-bundle`, and
that is the path we test and ship: the bundle's sources are evaluated offline
and stamped into the report's provenance block. Passing
`--definitions-bundle` *without* `--html`, to get the standalone acquisition
block on its own, does not complete in this build — the tool that produces
that block's input does not exist in the tree yet. Use the bundle through the
report.

### What did not change

PTxray is still a read-only assessment. It does not remediate findings,
install or remove software, change configuration, restart services, alter
accounts, or reboot the system.

The on-box scanner is still honest about air-gapped operation: it does not
phone home, fetch reference data, upload a report, perform a live DNS lookup,
or open an outbound network connection. The new report is a single
self-contained HTML file — no external stylesheet, no external script, no
remote font, no remote image. Reports stay local unless you choose to
transfer them.

### Release process note

The `sec-14-review` gate was skipped for this release by operator ruling on
2026-08-23. It is recorded here rather than left out of the record.

### Already fixed for 1.4.1

Four things are known and scheduled rather than silently carried:

- **The print form drops the provenance stamp.** `report.html` carries the
  definition-source block; `report-print.html` does not.
- **Checks describe their reasons in prose.** When a control is `NOT ASSESSED`
  or `N/A`, PTxray infers a typed reason by pattern-matching the sentence the
  check wrote. Unrecognised wording now degrades to "Reason not typed by the
  check." rather than failing the report, but the durable fix is for checks to
  emit a typed reason field alongside the prose.
- **A single non-conforming row can still cost the whole report.** The
  renderer validates the document before it renders and refuses outright on a
  uniqueness violation. It should degrade the offending row instead: a report
  with one under-typed row is worth more than no report.
- **The currency producer lane.** See above.

### Known limitations

The v1.2.0 known limitations all still apply:

- Run as root for the intended coverage. A non-root run is supported but
  incomplete because several patch, dump, boot, account, audit, SSH, and
  service-policy reads require privilege.
- The public scanner neither fetches nor bundles IBM's `flrtvc.ksh` or full
  `apar.csv`. A complete current CVE sweep requires an authorized, locally
  supplied FLRTVC report or inputs. Without them, source-dependent clean
  results remain incomplete.
- This is a point-in-time, bounded posture scan, not continuous monitoring or
  an exhaustive filesystem/application audit. Workload-specific tuning and
  controls outside a read-only in-LPAR view still require administrator
  review.
- A review-pack file is pseudonymized, not anonymized. It can retain
  operational detail and must be inspected locally before sharing; never send
  its separate decoding key with it.
- Producing a report writes the operator-selected output. Locally supplied
  FLRTVC inputs also use a private temporary directory; an abrupt termination
  can leave that directory for manual removal. Neither operation changes
  assessed AIX/VIOS configuration or state.

And two new to this release:

- The currency lane refuses on every box until the producer lane ships. See
  above.
- `--definitions-bundle` used *without* `--html` exits 2 at the
  acquisition-rendering step and leaves a zero-byte `acquisition.html` behind.
  Delete that file; it carries no meaning. With `--html` — the shipped path —
  the bundle is consumed by the report and this does not arise.
- Scan history and compare-to-last-run are designed for in the document
  contract but not built. Every scan is independent.

## v1.3.0

PTxray joins the IBM i platform and takes its production name. This release
renames the project from AIXray to **PTxray** and adds a dedicated IBM i
edition alongside the existing AIX assessment.

### IBM i edition

`ptxray-ibmi.sh` is a new read-only IBM i assessment that runs from PASE
(`/QOpenSys/usr/bin/ksh`). On IBM i 7.4 and 7.5 it is graded against the CIS
IBM i V7R4M0 / V7R5M0 Benchmark v2.1.0: 76 of 89 CIS Level 1 controls receive
an automated verdict on 7.5, and 73 of 88 on 7.4. Uncovered Level 1 controls
are CIS-manual or not-yet-implemented and are disclosed by the scanner rather
than dropped (registry as_of 2026-08-19); on other releases it reports the
release-independent evidence it can assess and omits borrowed control numbers.
Like the AIX edition it
changes nothing, installs nothing, and makes no network calls during
assessment, and it reports `NOT_ASSESSED` when evidence is unavailable rather
than inventing a result. There is no DISA STIG for IBM i, so none is claimed.

### PTxray rename

The AIX assessment is now `ptxray-aix.sh`, and the review helpers are
`ptxray-review-pack.sh` and `ptxray-review-validate.awk`. For continuity, each
release also publishes `aixray-aix.sh` as a byte-identical alias so download
links and report footers minted before the rename keep resolving; the alias
will be retired at a future major release.

### Download

The release assets are `ptxray-aix.sh`, `ptxray-ibmi.sh`,
`ptxray-review-pack.sh`, `ptxray-review-validate.awk`, the `aixray-aix.sh`
alias, and `SHA256SUMS`. Download the assets, verify them against
`SHA256SUMS`, and run the edition for your platform.

## v1.2.0

A reference-data and inventory release. The standalone check-module count grows
from 324 to 387; the public package is the assembled monolith, the two
review-pack helpers, and those 387 modules — 390 build outputs in all. If you
downloaded v1.1.0, download v1.2.0, verify it against `SHA256SUMS`, and run it
again.

### Security APAR seed

A current AIX 7.3 TL4 (7300-04) system can now be judged against bundled
security APAR rows. v1.1.0 carried no 7300-04 seed row, so `ck-sec-apars`
refused with "no bundled security APAR rows apply". v1.2.0 adds `IJ59563`
(7300-04) and the sibling TL rows `IJ59564` (7300-03), `IJ59565` (7300-02) and
`IJ59566` (7200-05), all carrying CVE-2026-16923 (`bos.mp64` local privilege
escalation). The check still refuses when `instfix` cannot read the fix
database; that is evidence handling, not a missing table row.

Three HIPER rows for IBM node 7278066
(`devices.pciex.7710612214105006.com`) are now in the same seed: `IJ57378`
(7300-04), `IJ57303` (7300-03), `IJ57855` (7200-05). IBM publishes no CVE for
that node, so the display field carries the non-CVE token `HIPER-7278066`.

### Firmware floor table

The firmware floor table is now keyed on the full machine-type-model, so current
Power10 E1050 (`9043-*`) and E1080 (`9080-HEX`) systems resolve to a bundled
family instead of falling out of the type-only lookup. Power9 E980 (`9080-M9S`)
is listed. Scale-out 9105 and 9009 rows are globbed (`9105-*`, `9009-*`).

### Check inventory

Standalone check modules grow from 324 to 387. Each new module is a
self-contained `ck-*` tool; the public tag carries all 387 plus the assembled
monolith and the two review-pack helpers, which is the 390 build outputs above.
This is an inventory change, not a change of shape — AIXray is still one
inspectable script you read before it runs, with the standalone tools published
alongside it.

CIS Level 1 demonstrated coverage is unchanged from v1.1.0 at 208 of 212
controls (209 mapped); `4.1.1.19` remains mapped but has
never rendered a determinate verdict on a committed fixture. The CIS Level 2
surface and the published count basis are otherwise unchanged.

### Reference data

Reference-data `as_of` dates advance to 2026-08-18 for the IBM AIX lifecycle,
IBM security advisory, and CIS IBM AIX reference sources. The DISA STIG for IBM
AIX source stays at 2026-06-15 — that is DISA's publisher benchmark date, not a
curator stamp.

The 30-day lifecycle and security-advisory freshness thresholds start from
2026-08-18. A default installation renders those sources STALE after 2026-09-17
unless a later refresh ships.

Two post-vintage IBM advisories remain documented gaps, the same class as in
v1.1.0: IBM publishes no AIX Level→APAR table for them, so both stay on the
operator-supplied FLRTVC path.

### What did not change

**No remediation of findings, no configuration change.** AIXray reads and
reports. It does not remediate a host, install or remove software, change
configuration, restart services, alter accounts, or reboot the system.

**Zero network calls during assessment execution.** The scanner does not phone
home, fetch reference data, upload a report, perform a live DNS lookup, or open
an outbound network connection. Reports stay local unless an operator chooses to
transfer them. Obtaining the script is, as always, a separate download.

**The download is still the monolith plus the standalone `ck-*` tools.**

### Known limitations

AIXray v1's known limitations, unchanged since v1.0.0:

- Run as root for the intended coverage. A non-root run is supported but
  incomplete, because several patch, dump, boot, account, audit, SSH and
  service-policy reads require privilege.
- The public scanner neither fetches nor bundles IBM's `flrtvc.ksh` or full
  `apar.csv`. A complete current CVE sweep requires an authorized, locally
  supplied FLRTVC report or inputs. Without them, source-dependent clean results
  remain incomplete.
- This is a point-in-time, bounded posture scan, not continuous monitoring or an
  exhaustive filesystem or application audit. Workload-specific tuning and
  controls outside a read-only in-LPAR view still require administrator review.
- A review-pack file is pseudonymized, not anonymized. It can retain operational
  detail and must be inspected locally before sharing; never send its separate
  decoding key with it.
- Producing a report writes the operator-selected output. Locally supplied
  FLRTVC inputs also use a private temporary directory; an abrupt termination
  can leave that directory for manual removal. Neither operation changes
  assessed AIX/VIOS configuration or state.

## v1.1.0

A defect-fix release. Zero new checks: the check-module count stays 324,
unchanged from v1.0.0. If you downloaded v1.0.0, download v1.1.0, verify it
against `SHA256SUMS`, and run it again.

### SRC parser fixes

The parser fixes are all in the shared SRC (`lssrc -a`) capture fragment consumed
by the 16 SRC/rctcpip service checks — writesrv, dt, piobe, qdaemon, and the 12
rc.tcpip subserver checks. Two parser defects are closed:

**Right-anchored SRC status parse.** The v1.0.0 parser accepted only two exact
`lssrc -a` row shapes: a four-field row ending in `active` and a three-field row
ending in `inoperative`. Subsystem rows without a group column — present in real
inventories, proven by live captures from two AIX boxes — fit neither shape, and
the parser fails closed: a single rejected row discarded the entire SRC
inventory, so the affected checks refused with `NOT_ASSESSED` rather than assess.
No wrong verdict was emitted. The status field is now right-anchored against the
known status vocabulary, and groupless rows are retained.

**Open SRC status vocabulary.** Transitional states `stopping` and `starting` now
classify as running; previously an unrecognized state — `stopping` was captured
live — discarded the whole inventory the same way, withholding SRC evidence from
all 16 checks.

In practical terms for a v1.0.0 operator: on systems whose `lssrc -a` inventory
contains a groupless or transitional-state row, the affected service checks
reported `NOT_ASSESSED`; v1.1.0 assesses them.

### Review-copy pseudonymizer fix

The `discover_after` extractor could not match identity labels ending in `=`;
the fail-closed layers held — no observed leak in eight probes, not an
exhaustive proof — and the fix restores the intended coverage.

### Reference data

The reference-data `as_of` advances to 2026-08-11 after a live-feed curation
review. Table content (lifecycle rows, security-advisory rows, the embedded
strict-seed APAR catalogue) is unchanged. Two post-vintage IBM security
advisories — for curl (maximum CVSS 9.8, eight CVEs) and for BIND (CVSS 7.5) —
remain documented gaps: IBM publishes no AIX Level→APAR table for either, so
both stay on the operator-supplied FLRTVC path, same as in v1.0.0.

### What did not change

**No remediation of findings, no configuration change.** AIXray reads and
reports; it does not remediate a host or alter its configuration.

**Zero network calls during assessment execution.** The assessment logic and
reference data are local to the script. Reports stay local unless the operator
transfers them. Obtaining the script is, as always, a separate download.

## v1.0.0

The first stable release. `catalog.json` declares `tool_version` `1.0.0` and
the assembled scanner reports `VERSION="1.0.0"`.

### What ships

Four release assets, up from two at `v0.1.0`:

```text
aixray-aix.sh              the assembled scanner
aixray-review-pack.sh      the review-copy helper
aixray-review-validate.awk the independent validator the helper runs
SHA256SUMS                 digests for every payload catalog.json declares
```

`SHA256SUMS` now covers the three top-level payloads **and** every standalone
check tool, not just the top-level files. `docs/VERIFY.md` derives the payload
set from `catalog.json`, so the documented verification recipe stays correct as
the catalog grows.

The repository ships 324 standalone check tools under `checks/<id>/`, each with
its own manifest, alongside the assembled single-file scanner. Every catalog
entry declares `read_only: true`; 88 of the 324 declare `requires_root`.

### Standards

Checks carry the standard tags they are written against. At this release the
catalog tag census is:

```text
cis-l1   252 checks
cis-l2    20 checks
ffiec      14 checks across II.C.11, II.C.15, II.C.22
stig        7 checks across V-245557 .. V-245569
```

A tag records which standard a check was written against. It is not a coverage
claim: consult the report's own auditor coverage table for what a given scan
actually assessed, including the controls it could not assess.

### Reporting posture

AIXray reports what it found. It does not tell you how to fix it — remediation
text is out of the report entirely, in `--html` and `--compliance` alike. The
executive summary opens with **Start here: top risks**, the five highest-impact
`FAIL`/`WARN` findings ranked by status then severity, each shown with the
evidence that produced it.

`NOT_ASSESSED` is a refusal, not a pass. Refusals are rendered, counted, and
carried into the auditor coverage table rather than folded into a clean bill.

### Review copies

The review helper produces a pseudonymized copy of a report for sharing, and an
independent validator (`aixray-review-validate.awk`) must clear it before any
artifact is written. A report now carries a privacy schema marker and a
per-field privacy annotation on every assessment cell; the validator refuses to
publish when a field cannot be proved de-identified.

When it refuses, the reason is written to a local
`aixray-local-pseudonymize-failed-*.txt` manifest, not to stderr — a reason
quotes the offending value, and that value must not leave the machine through a
terminal transcript or a CI log. stderr carries only the `NOT READY TO SHARE`
banner and a pointer to the manifest.

## v0.1.0 release-integrity note

The immutable `v0.1.0` tag points to commit
`d0587e17bc4fc387c11e8df317cc85e6aa8c2f4a`. The files attached to the
GitHub `v0.1.0` release are byte-identical to the same paths at the later
master commit `ed854a50801a050ebf9932ac99af522f76caa4a6`, which was the
master tip when the assets were uploaded. They are not byte-identical to the
tagged tree.

At that tagged revision, `aixray-review-pack.sh` is absent and
`aixray-aix.sh` has SHA-256
`e098e0b0f617649ba29fbf1626fefb55bcd2b467c09060bdcb4458b1340e5b16`.
The attached `v0.1.0` assets have these SHA-256 values:

```text
aixray-aix.sh
6829bd1aa6d24648c8c142287afc0aef730cc081716250d7eb79297c61ebaf52

aixray-review-pack.sh
8291000be2093176fc43164905958964d1e7bf9e197974abb54a25eabaab1ff4
```

### Text for the GitHub v0.1.0 release body

```text
Release-integrity note: the files attached to this release correspond to
commit ed854a50801a050ebf9932ac99af522f76caa4a6, not to the immutable
v0.1.0 tag at d0587e17bc4fc387c11e8df317cc85e6aa8c2f4a. The attached
aixray-aix.sh SHA-256 is
6829bd1aa6d24648c8c142287afc0aef730cc081716250d7eb79297c61ebaf52;
the attached aixray-review-pack.sh SHA-256 is
8291000be2093176fc43164905958964d1e7bf9e197974abb54a25eabaab1ff4.
The review helper is absent from the tagged tree, whose aixray-aix.sh
SHA-256 is
e098e0b0f617649ba29fbf1626fefb55bcd2b467c09060bdcb4458b1340e5b16.
```
