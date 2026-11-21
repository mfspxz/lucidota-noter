#!/usr/bin/env bash
# Noter observe runner: re-run the full workspace test suite on change.
# Exit 0 = green (silent), exit 2 = suite failed (eventd emits
# devloop.observe-fail; the eventd-alerts hook wakes an agent).
# Appends every run to dev-loop/observe.log.
set -u
export PATH="$HOME/.cargo/bin:$PATH"
cd "$(dirname "$0")/.."
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
if CARGO_BUILD_JOBS=2 cargo test --workspace --offline >/tmp/devloop-noter-observe.out 2>&1; then
  PASSED=$(grep -oE '[0-9]+ passed' /tmp/devloop-noter-observe.out | awk '{s+=$1} END {print s}')
  echo "$TS OBSERVE-OK workspace $PASSED passed 0 failed" >> dev-loop/observe.log
  exit 0
else
  echo "$TS OBSERVE-FAIL workspace suite failed (see /tmp/devloop-noter-observe.out)" >> dev-loop/observe.log
  exit 2
fi
