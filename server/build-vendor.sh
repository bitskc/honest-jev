#!/bin/sh
# Builds ./vendor from the upstream jkudish/jev-mcp (MIT) at a pinned commit, then patches the one
# Node-only line (createRequire of package.json) so it runs in a Worker. vendor/ is generated: do not commit it.
#   JEV_MCP_REF=<commit-or-tag> ./build-vendor.sh      # override the pin
#   JEV_MCP_SRC=/path/to/local/jev-mcp ./build-vendor.sh   # use an existing checkout instead of cloning
set -e
cd "$(dirname "$0")"
REF="${JEV_MCP_REF:-4a9b331509752b1f23b3a73c4f274521d4a16020}"   # jkudish/jev-mcp v0.14.6
case "$REF" in
  ""|-*|*[!A-Za-z0-9._/-]*)
    echo "build-vendor.sh: refusing JEV_MCP_REF: use a commit SHA or a tag/branch of [A-Za-z0-9._/-] (no newline, no leading '-')" >&2
    exit 1 ;;
esac
if [ -n "${JEV_MCP_SRC:-}" ]; then
  SRC="$JEV_MCP_SRC"
else
  SRC=".build/jev-mcp"
  rm -rf "$SRC" && mkdir -p .build
  git clone --quiet https://github.com/jkudish/jev-mcp "$SRC"
  git -C "$SRC" checkout --quiet "$REF"
  (cd "$SRC" && npm ci --silent && npm run build --silent)
fi
rm -rf vendor && mkdir -p vendor
cp "$SRC"/dist/*.js vendor/
VER=$(node -p "require('$PWD/$SRC/package.json').version" 2>/dev/null || node -p "require('$SRC/package.json').version")
sed -i "s|^import { createRequire } from \"node:module\";||; s|^const { version: packageVersion } = .*|const packageVersion = \"$VER\";|" vendor/server.js
grep -n "packageVersion =" vendor/server.js
# Provenance stamp: the upstream commit this bundle was built from. The clone path stamps the pin
# (resolved by the checkout). A JEV_MCP_SRC checkout stamps its HEAD when it is a git repo; a non-git
# JEV_MCP_SRC has no provable revision, so it is stamped unknown rather than the default pin.
# server/scripts/gen-tools-doc.mjs reads the stamp for the docs/TOOLS.md header.
if [ -n "${JEV_MCP_SRC:-}" ]; then
  RESOLVED=$(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo "unknown (local JEV_MCP_SRC)")
else
  RESOLVED=$(git -C "$SRC" rev-parse HEAD)
fi
printf '\n// vendorRef: %s (stamped by server/build-vendor.sh)\n' "$RESOLVED" >> vendor/server.js
grep -n "vendorRef" vendor/server.js
