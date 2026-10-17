#!/bin/bash
# Build, test, smoke-check and publish foxhole-vpn to npm.
# Bump "version" in package.json first (the update check compares against it).
# Arguments go to npm publish, e.g. ./publish.sh --dry-run  or  ./publish.sh --otp 123456
set -euo pipefail
cd "$(dirname "$0")"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

npm ci --no-audit --no-fund                # the locked TypeScript toolchain
npm test                                   # build + the proxy/global/dns/update suites
npm pack --pack-destination "$T"           # runs prepack: clean dist/, compile, chmod +x dist/cli.js
TGZ=$(echo "$T"/foxhole-vpn-*.tgz)

# Install the tarball the way users get it and run it: proves the files list,
# bin link, shebang and exec bit all work from a real global install.
npm install --global --prefix "$T/global" --no-audit --no-fund "$TGZ" >/dev/null
"$T/global/bin/foxhole-vpn" --version

npm publish "$TGZ" "$@"                     # the exact tarball tested above (no rebuild on publish)
