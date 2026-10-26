#!/usr/bin/env bash
# Shortcut for stopping the NetGuard AI servers.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$ROOT/start.sh" stop
