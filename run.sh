#!/bin/sh
# TRUST404 Track 1 entry point:  ./run.sh <dir>   -> JSON array on stdout, logs on stderr, exit 0
# Requires: node >= 18 and a prior `npm install && npm run build` (or use the Dockerfile).
DIR="$(cd "$(dirname "$0")" && pwd)"
exec node "$DIR/dist/cli.js" judge "$@"
