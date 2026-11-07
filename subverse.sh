#!/usr/bin/env bash
# Subverse launcher. Runs the tool using the project's own virtualenv (.venv)
# if present, so you don't have to activate anything. Works from any directory;
# file arguments you pass are resolved against YOUR current directory as usual.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -x "$here/.venv/bin/python" ]; then
    py="$here/.venv/bin/python"
else
    py="$(command -v python3 || command -v python || true)"
fi
[ -n "${py:-}" ] || { echo "subverse: no python interpreter found" >&2; exit 1; }

# Put the package on the import path without needing `pip install -e .`,
# while leaving the working directory alone so relative paths still work.
exec env PYTHONPATH="$here${PYTHONPATH:+:$PYTHONPATH}" "$py" -m subverse "$@"
