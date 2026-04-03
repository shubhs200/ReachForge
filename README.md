# ReachForge

LLM-powered fuzzing harness generator for C/C++ library vulnerabilities.
Automatically generates targeted fuzz harnesses and seed inputs using LLVM IR
call-graph analysis and LLM assistance within OSS-Fuzz containers.

---

## Architecture

```
vulnerabilities.json + library source
         │
         ▼
┌──────────────────┐
│  build_capture    │  Intercepts compiler commands, generates LLVM IR
│  rf-cc / rf-cxx   │  (ASAN + UBSAN + fuzzer-no-link instrumentation)
└────────┬─────────┘
         ▼
┌──────────────────┐
│  cve_enrichment   │  Queries NVD, OSV, GitHub Advisory APIs
│                    │  Retrieves: description, CVSS, fix patches, refs
│                    │  Cached in out/enrichment_cache/
└────────┬─────────┘
         ▼
┌──────────────────┐
│  harness_plan     │  LLVM IR callgraph → BFS from sink to public API
│                    │  vuln_analyzer + contract_inference + stage_retrieval
│                    │  Selects entry point, extracts parameter roles,
│                    │  builds execution/trigger/construction plans
└────────┬─────────┘
         ▼
┌──────────────────┐
│  prompt_harness   │  Builds structured LLM prompt with:
│                    │  - CVE description + fix patch diffs (from enrichment)
│                    │  - Vulnerability-directed strategy synthesis
│                    │  - Call-path semantic analysis
│                    │  - Forbidden patterns
└────────┬─────────┘
         ▼
┌──────────────────┐
│  LLM (OpenAI)    │  3 prompt variants → best candidate selection
│                    │  gpt-5.4, temperature=0.2, JSON response
└────────┬─────────┘
         ▼
┌──────────────────┐
│  harness_runner   │  ORCHESTRATOR — the main entry point
│                    │  validate → repair → compile → seed → fuzz
│                    │  Up to 3 repair attempts per failure mode:
│                    │    semantic fix → compile fix → runtime fix
└──────────────────┘
         │
    ┌────┼────────┐
    ▼    ▼        ▼
 compile  seed    fuzz
 harness  gen     runner
```

**Entry point**: `python3 harness_runner.py`

All other pipeline files are invoked by `harness_runner.py` via subprocess
calls or direct imports. There is no separate CLI; `harness_runner.py` IS
the CLI.

---

## Quick Start

```bash
# 1. Start an OSS-Fuzz container with the target library
docker run -it --rm \
  -e OPENAI_API_KEY="$OPENAI_API_KEY" \
  -v /path/to/ReachForge_tailored:/src/reachforge \
  gcr.io/oss-fuzz/<library> \
  /bin/bash

# 2. Inside the container, run the pipeline
python3 /src/reachforge/harness_runner.py \
  --root /src/<library> \
  --cve-id CVE-XXXX-XXXXX \
  --package <library-name> \
  --out /out/reachforge
```

You only need the CVE ID and package name. The tool automatically retrieves
the vulnerability description, CWE classification, affected function, affected
file, and fix patches from NVD/OSV/GitHub APIs.

Alternatively, provide a `vulnerabilities.json` for more control:

```bash
python3 /src/reachforge/harness_runner.py \
  --root /src/<library> \
  --vulns /src/<library>/vulnerabilities.json \
  --cve-id CVE-XXXX-XXXXX \
  --out /out/reachforge
```

### Example: libpng

```bash
docker run -it --rm \
  -e OPENAI_API_KEY="$OPENAI_API_KEY" \
  -v ~/ReachForge_tailored:/src/reachforge \
  gcr.io/oss-fuzz/libpng \
  python3 /src/reachforge/harness_runner.py \
    --root /src/libpng \
    --cve-id CVE-2025-64505 \
    --package libpng \
    --out /out/reachforge
```

---

## Requirements

- Python 3.8+
- libclang (available in OSS-Fuzz containers)
- OpenAI API key (set as `OPENAI_API_KEY` environment variable)
- Docker with pre-built OSS-Fuzz images

### Available Docker Images

cjson, curl, expat, harfbuzz, libarchive, libpng, libtiff, libwebp,
libxml2, sqlite3, zlib

---

## vulnerabilities.json Format (Optional)

When using `--vulns`, each target library needs a `vulnerabilities.json` file:

```json
{
  "vulnerabilities": [
    {
      "cve-id": "CVE-2025-64505",
      "package-name": "libpng",
      "package-version": "1.6.50",
      "cwe-id": "CWE-125",
      "affected-file": "pngrtran.c",
      "affected-function": "png_do_quantize",
      "description": "Optional: CVE advisory text for better LLM guidance"
    }
  ]
}
```

**Required fields**: `cve-id`, `package-name`
**Auto-derived fields** (populated from CVE enrichment if not provided):
`cwe-id` (from NVD), `affected-function` (parsed from CVE description),
`affected-file` (parsed from patch diff)
**Optional fields**: `description` (auto-retrieved by CVE enrichment, or
manually provided), `package-version`

---

## Configuration

### LLM (`config/llm.json`)

```json
{
  "default": { "model": "gpt-5.4", "api_base": "https://api.openai.com/v1" },
  "driver":  { "model": "gpt-5.4", "api_base": "https://api.openai.com/v1" },
  "seeds":   { "model": "gpt-5.4", "api_base": "https://api.openai.com/v1" }
}
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | OpenAI API key (required) |
| `LIB_FUZZING_ENGINE` | Path to fuzzer runtime library (set by OSS-Fuzz) |
| `GITHUB_TOKEN` | GitHub token for higher API rate limits (optional) |

---

## Pipeline Steps (what harness_runner.py does)

1. **Build Capture** — Runs the library's build system with `rf-cc`/`rf-cxx` as
   CC/CXX, logging compile commands to JSONL and generating LLVM IR (`.ll` files)
   with ASAN/UBSAN/fuzzer-no-link instrumentation.

2. **CVE Enrichment** — Queries NVD, OSV.dev, and GitHub Advisory APIs to
   automatically retrieve CVE descriptions, CVSS scores, fix commit hashes,
   and patch diffs. Results cached in `out/enrichment_cache/`. Auto-populates
   missing fields: `cwe-id` from NVD, `affected-function` from CVE description
   parsing, `affected-file` from patch diff. Use `--no-enrich` to skip.

3. **Harness Planning** — Builds an LLVM IR callgraph (including indirect calls
   via function pointer dispatch tables), finds all public APIs that reach the
   vulnerable function via BFS, selects the best entry point using taint-based
   scoring, and produces a detailed plan with parameter roles, execution hints,
   trigger conditions, and construction plans.

4. **Prompt Building** — Constructs a structured LLM prompt with CVE description,
   fix patch diffs (from enrichment), call-path semantic analysis, a vulnerability-directed
   strategy synthesis section that forces the LLM to reason about what specific
   inputs trigger the bug, annotated source snippets, contract obligations, and
   forbidden anti-patterns.

5. **LLM Harness Generation** — Sends 3 prompt variants to the LLM (temperature
   0.2), validates each candidate statically (100-point scoring with ~20 check
   categories), selects the best one.

6. **Compilation** — Compiles the harness against the instrumented library,
   auto-detects extra link libraries (zlib, lzma, etc.) via `nm --undefined-only`.

7. **Repair Loop** — Up to 3 attempts per failure mode:
   - Semantic validation failure → LLM fix prompt with specific violations
   - Compile failure → LLM fix prompt with compiler errors
   - Runtime smoke failure → LLM fix prompt with crash/timeout info

8. **Seed Generation** — LLM generates targeted seed inputs based on the
   vulnerability type, function source, and fix patch context.

9. **Fuzzing** — Runs the compiled harness with the generated seed corpus.

---

## Project Structure

```
ReachForge_tailored/
├── harness_runner.py      # Entry point — end-to-end orchestrator (733 lines)
│
├── cve_enrichment.py      # CVE enrichment via NVD/OSV/GitHub APIs (310)
├── build_capture.py       # Build interception, sets CC/CXX to rf-cc/rf-cxx (94)
├── harness_plan.py        # Callgraph BFS, parameter roles, planning (2385)
├── prompt_harness.py      # LLM prompt builder with strategy synthesis (886)
├── compile_harness.py     # Harness compilation, auto link-lib detection (825)
├── harness_validator.py   # Static validation + runtime smoke tests (1011)
├── seed_generator.py      # Seed generation via LLM (256)
├── fuzz_runner.py         # Seed corpus creation and fuzzer execution (325)
│
├── llvm_callgraph.py      # LLVM IR callgraph with function pointer resolution (868)
├── public_api.py          # libclang-based public API extraction (756)
├── vuln_analyzer.py       # Sink analysis: params, state, conditions, roles (2238)
├── contract_inference.py  # Semantic contract recovery (507)
├── stage_retrieval.py     # Source snippet retrieval for deferred stages (370)
│
├── rf-cc                  # C compiler wrapper (instrumentation + IR)
├── rf-cxx                 # C++ compiler wrapper (instrumentation + IR)
├── vulnerabilities.json   # CVE definitions for target libraries
├── Dockerfile.ci          # CI container definition
├── requirements.txt       # Python dependencies
├── __init__.py            # Package marker
│
├── config/
│   └── llm.json           # LLM model and API configuration
├── llm_adapters/
│   ├── __init__.py
│   └── openai.py          # Raw urllib OpenAI wrapper with retry logic (142)
├── tests/                 # 103 tests across 6 files
│   ├── conftest.py
│   ├── test_cve_enrichment.py
│   ├── test_harness_runner.py
│   ├── test_llvm_callgraph_context.py
│   ├── test_contract_inference.py
│   ├── test_setup_state_ranking.py
│   └── test_vuln_analyzer_semantics.py
└── oss-fuzz/              # OSS-Fuzz project definitions (used for Docker builds)
```

**Total**: ~11,700 lines of pipeline code, ~3,100 lines of tests, 103 tests passing.

---

## Running Tests

```bash
cd /path/to/ReachForge_tailored
python3 -m pytest tests/ -v
```

---

## Key Design Decisions

- **LLVM IR over AST**: Callgraph built from `.ll` files, not source AST. This
  resolves indirect calls through function pointer dispatch tables (struct field
  GEP tracking) and handles all compiler-resolved overloads.

- **3-variant prompting**: Three prompt variants sent to LLM with different
  emphasis; best candidate selected by static validation score.

- **100-point validation**: ~20 check categories including: correct includes,
  no forbidden patterns (threads, sockets, RNG), proper memory management,
  stdin/file reading patterns, fuzz target signature, etc.

- **Runtime smoke test**: Compiled harness run with 3 probe files, -runs=3,
  timeout=20s. Evidence classification: sink-hit (100), sink-adjacent (80),
  entry-reached (50).

- **Auto link-lib detection**: `nm --undefined-only` on the compiled object,
  pattern-matched against known libraries (zlib via deflate/inflate, lzma via
  lzma_* prefixes, etc.).

- **No hardcoded patterns**: Everything derived from static analysis of the
  actual library source and LLVM IR. No CWE-specific rules — the LLM infers
  the correct testing strategy from the CVE description, fix patch, source code,
  state fields, and call-path semantics.

- **CVE enrichment (RAG)**: Automatic retrieval of CVE descriptions, CVSS scores,
  fix patch diffs, and references from NVD/OSV/GitHub. Auto-populates missing
  vulnerability fields (`cwe-id`, `affected-function`, `affected-file`) so only
  `cve-id` and `package-name` are truly required. The patch diff is the
  highest-value signal — it shows the LLM exactly which code paths were vulnerable
  and what input conditions trigger the bug.

- **Vulnerability-directed strategy synthesis**: The prompt includes a dedicated
  section that combines the CVE description, static-analysis state fields, field
  conditions, and trigger relations, forcing the LLM to reason step-by-step about
  what specific input structure triggers the vulnerability before generating code.

---

## Known Limitations

- **Local-only sink analysis**: `vuln_analyzer.py` reads only the sink function
  body. It cannot trace how parameters are derived from callers (no inter-function
  data flow).

- **Build system auto-detection**: Supports cmake and autotools. Other build
  systems need `--build-script`.

- **Model dependency**: Uses raw `urllib` to call OpenAI API (no SDK). Rate
  limit retry: fixed 30s wait. Connection error retry: linear backoff.

- **Enrichment requires network**: CVE enrichment needs outbound HTTPS to
  NVD, OSV, and GitHub APIs. Use `--no-enrich` if running without network
  access. Patch diff fetching requires GitHub commit URLs.
