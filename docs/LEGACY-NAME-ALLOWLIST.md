# PTxray legacy-name allowlist

PTxray 1.5 uses `ptxray-*` for customer-facing programs, reports, review
outputs, documentation, URLs, and repository identity. A legacy `aixray`
string is permitted only in the narrow compatibility or historical surfaces
below. A new occurrence outside this list is a release blocker.

## Allowed compatibility surfaces

- `aixray-aix.sh` is the sole legacy-named release asset. It must be
  byte-identical to `ptxray-aix.sh`; it is not a separate implementation.
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

Current instructions must use `ptxray-<hostname>-<date>.html`,
`ptxray-review-*.html`, `ptxray-local-key-*.map`, and
`ptxray-local-removals-*.txt`. The old report and review-output prefixes are
not compatibility interfaces in PTxray 1.5.
