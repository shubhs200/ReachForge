#!/usr/bin/env bash
set -euo pipefail

echo "=== ReachForge CI Validation ==="
echo "[info] Python: $(python3 --version || true)"
echo "[info] CWD: $(pwd)"

# Check for AFL++ (optional at this stage)
if command -v afl-fuzz >/dev/null 2>&1; then
  echo "[ok] afl-fuzz found: $(command -v afl-fuzz)"
else
  echo "[warn] afl-fuzz not found on PATH (will attempt install in CI before_script)"
fi

# Check LLM credentials (not strictly required if using --llm-cmd)
if [[ -n "${OPENAI_API_KEY:-}" ]] || [[ -n "${OPENAI_API_TOKEN:-}" ]]; then
  echo "[ok] LLM API key detected in environment"
else
  echo "[warn] OPENAI_API_KEY not set; LLM-backed stages may fail unless --llm-cmd provided"
fi

# Verify core files exist
python3 - <<'PY'
import os, sys, json
required = [
  "cli.py",
  "compiler.py",
  "generator.py",
  "llm_runner.py",
  "poller_index.py",
  "prompt_main2fuzz.py",
  "prompt_seeds.py",
  "schema.py",
  "seeds_schema.py",
  "config/llm.json",
  "config/compile_command.py",
]
missing = [p for p in required if not os.path.exists(p)]
if missing:
    print(f"[error] Missing required files: {', '.join(missing)}")
    sys.exit(1)
else:
    print("[ok] Core files present")

# Requirements file (for internal LLM adapter)
if not os.path.exists("requirements.txt"):
    print("[warn] requirements.txt not found (requests needed for internal LLM adapter)")
else:
    print("[ok] requirements.txt present")

print("=== Validation complete ===")
PY
