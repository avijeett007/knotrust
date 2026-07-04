#!/usr/bin/env bash
# scripts/check-core-boundary.sh
#
# Repo-level half of the MCP-import ban (invariant §4.1; P0-E2-T1 ruling 5b).
# This is NOT a mirror of packages/core/scripts/check-boundaries.mjs (the
# package-local AST-based `lint:boundaries` gate) and the two are not
# required to "agree" before either is trusted. They are two overlapping
# gates with different blind spots: this one is a plain grep across
# packages/core/src for the two banned substrings — no syntax awareness, but
# no dependency on TypeScript parsing succeeding either — and it is the one
# wired into .github/workflows/ci.yml. The design property that matters is
# that the UNION of the two gates covers every realistic accidental import;
# only deliberate obfuscation of the specifier (e.g. building the string at
# runtime) could evade both.
#
# The match is anchored to a *quoted* occurrence (`'@modelcontextprotocol...'`
# / `"...proxy-stdio..."`), not a bare substring anywhere in the file. A
# plain substring grep would also fire on contract.ts's own mandated header
# comment — `/** @knotrust/core — no dependency on @modelcontextprotocol/sdk
# anywhere in this file. */` — which legitimately *names* the banned package
# in prose to warn readers off it. Import/export/require/dynamic-import
# specifiers are always quoted string literals, so anchoring on the quote
# keeps the gate mechanical while not permanently red on compliant code.
#
# P0-E2-T5 (ruling R18) extends the banned substring list with the pdp
# package specifier: the PdpAdapter port TYPES live in @knotrust/core
# (pdp-port.ts) precisely so @knotrust/pdp can depend on @knotrust/core (for
# these types, and for evaluatePrecedence in the built-in L0 adapter)
# without a package cycle. That direction only holds if core never imports
# pdp back — see ADR-0018 (docs/05-decisions/adr/adr-0018-pdp-adapter-boundary.md).
set -euo pipefail

TARGET_DIR="packages/core/src"

if [[ ! -d "$TARGET_DIR" ]]; then
  echo "check-core-boundary: '$TARGET_DIR' not found (run from the repo root)." >&2
  exit 1
fi

PATTERN="[\"'][^\"']*(@modelcontextprotocol|proxy-stdio|@knotrust/pdp)[^\"']*[\"']"

if grep -rnE --include='*.ts' --include='*.tsx' "$PATTERN" "$TARGET_DIR"; then
  echo "" >&2
  echo "check-core-boundary: FAILED — $TARGET_DIR imports @modelcontextprotocol, proxy-stdio, or @knotrust/pdp." >&2
  echo "@knotrust/core must not import @modelcontextprotocol/*, any packages/proxy-* path, or @knotrust/pdp (invariant §4.1, ADR-0018)." >&2
  exit 1
fi

echo "check-core-boundary: OK — no @modelcontextprotocol, proxy-stdio, or @knotrust/pdp import specifiers under $TARGET_DIR."
