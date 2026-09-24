#!/usr/bin/env bash
# run_gui.sh — open the IDS dashboard in your browser.
#
# Starts a small local web server (Python standard library only, nothing to
# install) and opens the dashboard. From there you can generate the dataset,
# train the model, and run the detector in simulation / PCAP / live mode.
#
# The server listens on 127.0.0.1 only — it is never reachable from the
# network it is watching. Ctrl-C to stop it.
#
# Usage:  bash run_gui.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# Prefer the project venv's python if it exists, else fall back to python3.
if [ -x "./.venv/bin/python" ]; then
    PY="./.venv/bin/python"
else
    PY="python3"
fi

exec "$PY" src/webgui.py "$@"
