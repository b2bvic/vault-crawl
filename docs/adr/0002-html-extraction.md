# ADR 0002: isolate HTML extraction behind golden fixtures

Status: accepted boundary, implementation deferred to Phase 1

## Decision

Use a standards-based HTML parser for DOM inventory and a replaceable primary
content extractor behind one internal interface. Evaluate `scraper`/`html5ever`
for the DOM layer and `dom_smoothie` against the committed golden corpus before
locking the primary extractor.

## Reason

Metadata, links, tables, forms, JSON-LD, and source evidence need a stable DOM
representation. Primary-content algorithms differ on navigation-heavy,
malformed, multilingual, and duplicate-heading pages. The fixture output must
choose the implementation, not package familiarity.

## Consequences

No HTML extraction dependency appears in Phase 0 and no extraction-quality
claim is made. Phase 1 will record the selected package version, license,
fixture diffs, parser version, and replacement boundary.

