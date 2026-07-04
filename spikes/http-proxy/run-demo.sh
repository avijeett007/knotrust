#!/usr/bin/env bash
# SPIKE — convenience wrapper. From spikes/http-proxy/: ./run-demo.sh
# (run `npm install` once first — this is a standalone install, NOT part of
# the pnpm workspace; see README.md).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
node src/run-demo.mjs
