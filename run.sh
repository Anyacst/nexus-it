#!/usr/bin/env sh
# NEXUS-IoT launcher for macOS/Linux. Usage: ./run.sh [command] [args...]  (default: serve)
set -e
cd "$(dirname "$0")"
if [ "$#" -eq 0 ]; then set -- serve; fi
exec python3 -m nexus_iot "$@"
