#!/usr/bin/env bash
set -euo pipefail

# Usage: bash scripts/ci-run.sh <TARGET_ROOT> [FUZZ_HOURS]
# Env:
#   OPENAI_API_KEY  - required for LLM-backed generation (unless using --llm-cmd externally)
#   CI_PROJECT_DIR  - set by GitLab runner; used for absolute path resolution

TARGET_ROOT="${1:-${TARGET_ROOT:-}}"
FUZZ_HOURS="${2:-${FUZZ_HOURS:-5}}"

if [[ -z "${TARGET_ROOT}" ]]; then
  echo "[error] TARGET_ROOT not provided. Usage: bash scripts/ci-run.sh <TARGET_ROOT> [FUZZ_HOURS]" >&2
  exit 2
fi

echo "=== ReachForge CI Runner ==="
echo "[info] CWD: $(pwd)"
echo "[info] TARGET_ROOT (raw): ${TARGET_ROOT}"
echo "[info] FUZZ_HOURS: ${FUZZ_HOURS}"

# Resolve absolute path for TARGET_ROOT
if [[ "${TARGET_ROOT}" = /* ]]; then
  ABS_ROOT="${TARGET_ROOT}"
else
  BASE="${CI_PROJECT_DIR:-$(pwd)}"
  ABS_ROOT="$(realpath -m "${BASE}/${TARGET_ROOT}")"
fi
echo "[info] TARGET_ROOT (abs): ${ABS_ROOT}"

if [[ ! -d "${ABS_ROOT}" ]]; then
  echo "[error] TARGET_ROOT directory not found: ${ABS_ROOT}" >&2
  exit 2
fi

# Check AFL++ availability
RUN_FUZZ="--run-fuzz"
if ! command -v afl-fuzz >/dev/null 2>&1; then
  echo "[warn] afl-fuzz not found on PATH; will skip fuzzing stage"
  RUN_FUZZ="--no-run-fuzz"
fi

# Prefer running as a package (-m) if importable; fallback to direct script
RUN_AS_PACKAGE=0
python3 - <<'PY' || RUN_AS_PACKAGE=1
import importlib, sys
try:
    importlib.import_module("reachforge")
    print("[ok] reachforge package importable; will run with -m reachforge.cli")
except Exception:
    sys.exit(1)
PY

set -x
if [[ "${RUN_AS_PACKAGE}" -eq 0 ]]; then
  # Run from the parent of the package so -m resolves correctly
  PARENT="$(dirname "$(pwd)")"
  cd "${PARENT}" || true
  python3 -m reachforge.cli main2fuzz --root "${ABS_ROOT}" --fuzz-hours "${FUZZ_HOURS}" ${RUN_FUZZ}
else
  # Run as a plain script from repo root (dual-imports supported in cli.py)
  cd "${CI_PROJECT_DIR:-$(pwd)}" || true
  python3 cli.py main2fuzz --root "${ABS_ROOT}" --fuzz-hours "${FUZZ_HOURS}" ${RUN_FUZZ}
fi
set +x

# Summarize outputs if present
OUT_DIR="${ABS_ROOT}/reachforge2_out"
if [[ -d "${OUT_DIR}" ]]; then
  echo "[info] Output directory: ${OUT_DIR}"
  ls -l "${OUT_DIR}" || true
  echo "[info] DriverSpec:"
  sed -n '1,120p' "${OUT_DIR}/specs/driver_spec.json" 2>/dev/null || true
  echo "[info] Crash report:"
  sed -n '1,200p' "${OUT_DIR}/crash_report.txt" 2>/dev/null || true
else
  echo "[warn] Output directory not found: ${OUT_DIR}"
fi

echo "=== ReachForge CI Runner complete ==="
