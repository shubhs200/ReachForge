ReachForge4 (self-contained CI bundle)

Overview
- Purpose: Generate a single-shot fuzz driver (DriverSpec -> driver source -> binary) and 10 seeds (SeedsSpec) for a given C/C++ project rooted at --root.
- This folder contains everything needed to run RF4 in a pipeline without depending on modules outside reachforge4/.

What’s bundled here
- Core:
  - cli.py: main entrypoint (python3 -m reachforge4.cli main2fuzz ...)
  - generator.py, compiler.py, schema.py, source_index.py
  - prompt_main2fuzz.py, prompt_seeds.py, poller_index.py
  - llm_runner.py (prefers internal LLM adapter, falls back to legacy if present)
- Config:
  - config/llm.json: default model/api config (override via CLI/env)
  - config/compile_command.py: compile command templates (bundled template used by default)
- LLM adapter (internal):
  - llm_adapters/openai.py: minimal JSON-only chat wrapper via requests
  - llm_adapters/__init__.py
- Requirements:
  - requirements.txt: only requests is needed for LLM HTTP calls

External expectations (CI image/job)
- Toolchain:
  - AFL++ compilers (afl-clang-fast / afl-clang-fast++) or adjust compile_command.py to your compiler/sanitizers.
  - Any app-specific headers/libs referenced in compile_command.py (e.g., build/vcpkg_installed/... paths).
- Environment variables:
  - OPENAI_API_KEY (or OPENAI_API_TOKEN) for the internal LLM adapter.
  - Optional: REACHFORGE2_MAX_ROUNDS (e.g., 8–12 for complex projects).
- Python:
  - Python 3.10+ recommended
  - pip install -r reachforge4/requirements.txt

Running in CI (example steps)
1) Install deps
   - pip install -r reachforge4/requirements.txt
   - Ensure AFL++ and your app’s libs/headers are available on PATH and filesystem.
2) Configure model (either):
   - Set environment: export OPENAI_API_KEY=...
   - Or edit reachforge4/config/llm.json (driver/seeds/default model/api_base).
3) Run for an application (examples):
   - Analyze Image:
     python3 -m reachforge4.cli main2fuzz --root analyze-image
   - MQTT server:
     python3 -m reachforge4.cli main2fuzz --root mqtt-server
4) Outputs:
   - <root>/reachforge2_out/
     - context/prompt.main2fuzz.md (and prompt.seeds.md)
     - specs/driver_spec.json
     - drivers/<app>/<driver_filename>
     - compile.log.txt
     - seeds/spec.json and seeds/<app>/[10 seed files] (by default unless disabled)

CLI flags (subset)
- --root <path>: application root containing app/src or src (required).
- --out <path>: output directory (default: <root>/reachforge2_out).
- --workdir <path>: working directory for compile commands (default: root).
- Driver agent model:
  - --driver-model, --driver-api-base (override config/env)
- Seeds agent model:
  - --seeds-model, --seeds-api-base (override config/env)
- Vulnerabilities:
  - --include-vulns (default on) / --no-include-vulns
- Seed generation:
  - --generate-seeds (default on) / --no-generate-seeds
- Retry attempts on compile failure:
  - --max-attempts N (default 2)

How model/config resolution works
- Priority for model/api_base per agent:
  1) CLI flags
  2) Env vars: REACHFORGE4_DRIVER_MODEL / REACHFORGE4_DRIVER_API_BASE (seeds equivalents), or legacy REACHFORGE2_MODEL / REACHFORGE2_API_BASE
  3) reachforge4/config/llm.json (driver / seeds / default sections)

Compile command template resolution
- compiler.py prefers the bundled:
  - reachforge4/config/compile_command.py
- Legacy fallback:
  - ReachForge/config/compile_command.py (if present)
- Edit the bundled template to match your CI paths (include/lib/toolchain choices). Placeholders:
  {src} {binary} {harness_dir} {name} {lang} {cmake_snippet} {out_dir} {workdir}

Poller and vulnerabilities (optional)
- If <root>/poller/poller.py or sample inputs exist, RF4 summarizes them to bias realistic harness/seed choices (HTTP/multipart/MQTT patterns).
- If vulnerabilities.json exists (root or app/), RF4 biases toward impacted files/functions.

Notes
- The driver generation is source-first and single-shot: no sockets/servers/threads/RNG/time.
- RF4 can auto-add extra_sources based on undefined symbols and lift helper functions from the entry translation unit if needed.

Troubleshooting
- “missing LLM adapter”: Set OPENAI_API_KEY and ensure requests is installed, or provide an external --llm-cmd.
- “exhausted retrieval rounds without valid JSON”: Ensure OPENAI_API_KEY is set; optionally raise REACHFORGE2_MAX_ROUNDS (e.g., 8–12) or pass a different model via CLI.
- Compile path issues: Adjust reachforge4/config/compile_command.py include/lib paths for your CI environment.

License
- This folder contains only the RF4 tooling and configs. Your app code and third-party libs remain under their respective licenses.
