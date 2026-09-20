# PTxray legacy-name allowlist

PTxray 1.8 uses `ptxray-*` for customer-facing programs, reports, review
outputs, documentation, URLs, and repository identity. A legacy `aixray`
string is permitted only in the narrow compatibility or historical surfaces
below. A new occurrence outside this list is a release blocker.

## Allowed compatibility surfaces

- `aixray-scan.ksh` is the maintained AIX runner name. `aixray-aix.sh` is
  its byte-identical compatibility alias; both require the extracted bundle.
  The retired `ptxray-aix.sh` monolith is not a release payload.
- Existing versioned report internals such as `data-aixray-*`, schema IDs, and
  stable machine keys remain compatible. Renaming them would break consumers
  without changing the customer-visible product identity.
- Existing environment and embedded build-contract names in the `AIXRAY_*`
  family remain compatible until a separately versioned interface replaces
  them. They must not appear as current branding or output filenames.
- Defensive checks may name a prohibited historical filename, such as the
  rejected bundled-delivery artifact, when the string is data rather than an
  artifact that ships.

## Allowed history

[`docs/RELEASE-NOTES.md`](RELEASE-NOTES.md) may preserve old product names,
filenames, URLs, and immutable release facts inside historical release notes.
The redirect notice at the top may name the legacy site and GitHub repository
only to document their redirects to the canonical PTxray locations.

Current report instructions use `report.html`, `report.json`, and `scan.ptx`
in the selected output directory. Legacy supported review copies retain
`ptxray-review-*.html`, `ptxray-local-key-*.map`, and
`ptxray-local-removals-*.txt`; the helper refuses current composed reports.
