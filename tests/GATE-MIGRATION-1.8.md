# Composed release gate migration

The 1.8 release is a pair of complete report bundles. The previous public
funnel tests described retired monolithic scanners and a fixed 1.6 release.
These tests now inspect the shipped runners, registered checks, libraries,
renderers and data inside the versioned bundles.

This is a gate change, separate from product implementation. No signature,
checksum, no-assessment-network or IBM redistribution requirement is waived.

| Previous assertion | Current evidence |
| --- | --- |
| Fixed 1.6 monolith download URLs and root/site mirror | Catalog-derived version, direct complete-bundle URLs, bundle/top-level runner byte identity, signed alias identity, local HTTP byte identity |
| Inline README checksum verifier and missing/tampered file probes | Documented signature-first workflow, exact eight signed payloads and eleven release assets, production pinned key, composed integrity mutation tests |
| Historical integrity validation | All existing historical release-integrity tests retained; composed releases use a separate version route |
| Catalog count, versions, hashes and manifests | Exact public check directory/catalog parity, per-artifact digests and versions, adjacent manifest metadata, generated copy drift/repair tests |
| Monolith's fixed benchmark coverage fractions | AIX active registry equals catalog minus explicitly pared checks; IBM i registry equals shipped IBM i checks; registered findings/tags checked against their source; no unsupported full-coverage claim |
| Single-file syntax and egress checks | Four public entrypoint syntax checks; all distinct bundled assessment/review scripts, AWK, renderers and libraries scanned; only the separate root definitions downloader excluded; all 17 network primitive injection negatives retained |
| Optional monolith fixture modes | Current bundled renderer exercised portably; current schema-1 report explicitly refused by the strict review helper with no output or input mutation; native assessment acceptance remains a release validation task |
| Pseudonymization and planted-identifier tests | Existing identifier-removal, diagnostic-preservation, private-file, random-name, input-immutability and adversarial tests retained; supported input fixtures updated to schema 2 with the required exact theme script |
| Report marketing CTA and named monolith footer | Retired because those elements are not part of the composed renderer; no-upload, private decode-key and inspect-before-sharing protections retained in supported helper behavior and documentation |
| Public license, identity, private security channel and historical release discrepancy | Retained using current metadata and public paths; the exact historical v0.1.0 integrity record remains checked |

Additional archive negatives reject traversal, noncanonical paths, links,
special files, duplicate members, unexpected root/data executable scripts,
retired monoliths, raw IBM delivery filenames, renamed IBM engine signatures
and filled delivery embed slots. This directory/type check is not a complete
program-safety proof. Signed bytes and source review remain necessary.

The signed composed fixture tests generate a temporary test key and adjust
only an isolated copied verifier's key fingerprint. The production verifier
continues to require the independently pinned PowerTrue release key. No test
signing key or trust override is distributed with the runtime.

Current composed reports remain unsupported by the review-copy helper. The
public documentation and tests preserve that explicit limitation. A helper
refusal must never be presented as a successful pseudonymization.

Suggested commit trailer:

    GATE-CHANGE: Migrate retired monolith assertions to signed composed bundles; retain historical integrity and privacy negatives and expand archive and assessment-egress coverage.
