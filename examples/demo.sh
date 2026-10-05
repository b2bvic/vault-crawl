#!/usr/bin/env bash
# Isolated, synthetic demonstration. Does not install hooks or contact a model.
set -euo pipefail
REPO_ROOT=$(CDPATH="" cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
demo_root=$(mktemp -d)
trap 'rm -rf "$demo_root"' EXIT
cd "$REPO_ROOT"
cargo run --quiet --locked -p vault-crawl-cli -- --project example --state-root "$demo_root/state" --receipt-root "$demo_root/receipts" parse fixtures/http/article.html --source-url https://example.com/article --content-type text/html --json
