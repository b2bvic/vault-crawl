# ADR 0003: portable Rust PDF path with a host-tool oracle

Status: accepted boundary, implementation deferred to Phase 1

## Decision

The promoted PDF path must run without `pdftotext`. A maintained Rust parser
will be selected after text, scanned, encrypted, malformed, and multi-page
fixtures establish output and resource behavior. `pdftotext` may serve as an
optional comparison oracle on hosts where it is installed.

## Reason

Host environments vary in whether `pdftotext` is installed. Making the host
tool primary would create deployment mismatches. Selecting a Rust crate before
hostile-document fixtures exist would hide parser and resource-limit risk.

## Consequences

Phase 1 must record page boundaries, file hash, parser and version, OCR-needed
state, and failure type. Host tools must use fixed argument arrays, no shell,
no inherited secrets or network, an isolated task directory, and a timeout.
Phase 0 ships no PDF parser and claims no PDF support.
