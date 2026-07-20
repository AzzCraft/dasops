#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
python3 - <<'PY'
from pathlib import Path
import importlib

root = Path.cwd()
assert (root / "pyproject.toml").is_file()
assert (root / "dasops" / "__init__.py").is_file()
mod = importlib.import_module("dasops")
assert hasattr(mod, "__all__")
PY
printf '{"task":"DAS-03-005","scenario":"dasops wheel install","status":"ok"}\n'
