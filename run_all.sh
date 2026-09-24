#!/usr/bin/env bash
# run_all.sh — run the whole pipeline end to end.
#   1. generate the dataset
#   2. preprocess + train + evaluate + save the model
#   3. run the real-time detector in synthetic-demo mode
#
# Usage:  bash run_all.sh
set -euo pipefail

# Resolve the project root (directory this script lives in) so it works from anywhere.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# Prefer the project venv's python if it exists, else fall back to python3.
if [ -x "./.venv/bin/python" ]; then
    PY="./.venv/bin/python"
else
    PY="python3"
fi

echo "==> [1/3] Generating dataset ..."
"$PY" src/generate_dataset.py

echo
echo "==> [2/3] Preprocessing + training model ..."
"$PY" src/train_model.py

echo
echo "==> [3/3] Real-time detector (simulation mode) ..."
"$PY" src/realtime_detector.py --mode sim

echo
echo "==> Done. See models/ and outputs/ for artefacts, docs/ for the write-up."
