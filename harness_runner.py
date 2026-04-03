#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def extract_generated_code(fuzzer_src: Path):
    """Extract plain C/C++ code if the LLM returned a JSON wrapper."""
    try:
        raw = fuzzer_src.read_text(encoding="utf-8").strip()
        if raw.startswith("{"):
            parsed = json.loads(raw)
            code = (parsed.get("fuzzer.cc") or
                    parsed.get("content") or
                    parsed.get("code") or
                    parsed.get("harness") or
                    parsed.get("fileContent") or "")
            if code:
                fuzzer_src.write_text(code, encoding="utf-8")
                print("Extracted " + str(len(code)) + " bytes from JSON wrapper")
    except Exception as e:
        print("Warning: could not extract from JSON: " + str(e), file=sys.stderr)


def _load_repair_plan_excerpt(plan_path: Path):
    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return {
        'public_api_name': plan.get('public_api_name'),
        'wrapper_path': plan.get('wrapper_path', []),
        'execution_plan': plan.get('execution_plan', {}),
        'trigger_plan': plan.get('trigger_plan', {}),
        'construction_plan': plan.get('construction_plan', {}),
    }


def _build_repair_directives(details):
    directives = []
    text = ' '.join(details.get('violations', []) + details.get('warnings', [])).lower()
    if 'structured input shaping' in text or 'structured container' in text or 'raw data/size directly' in text:
        directives.append('Rewrite the harness so it synthesizes a minimally valid structured container before calling the entry API; do not pass raw data, data + offset, or ConsumeRemainingBytes directly into a parser-style public API.')
    if 'incremental' in text or 'chunked' in text or 'feed or update' in text:
        directives.append('If the plan indicates incremental processing, preserve bounded repeated feed or update ordering instead of one opaque bulk call.')
    if 'support object' in text or 'null placeholders' in text:
        directives.append('Use real support objects, buffers, palettes, histograms, or config state and populate them from bounded fuzz bytes when the active data plan says they are high-value mutable regions.')
    if 'work unit' in text or 'row' in text or 'block' in text or 'decoded' in text:
        directives.append('Ensure fuzz entropy reaches produced rows, blocks, frames, or equivalent work units rather than being spent only on trailing bytes that never influence sink-adjacent state.')
    if 'constant' in text and ('table' in text or 'config' in text or 'palette' in text):
        directives.append('Do not keep high-value support tables or configuration permanently constant; fuzz them within valid bounds while preserving consistency constraints.')
    if 'deadly signal' in text or 'abnormally' in text or 'null callback placeholders' in text or 'error recovery' in text or 'abort' in text:
        directives.append('If the library exposes callback-based, setjmp-style, or other recoverable error signaling, install harness-local non-fatal error containment instead of relying on default fatal behavior.')
    if not directives:
        directives.append('Treat the harness as a full rewrite task if needed; preserve only the documented public API family and required lifecycle, not the current code structure.')
    return directives[:6]


def build_semantic_fix_prompt(out: Path, attempt: int, reason: str, details, current_code: str, plan_path: Path):
    """Build a prompt asking the LLM to repair semantic harness weaknesses."""
    fix_prompt_path = out / "context" / ("semantic_fix_prompt_" + str(attempt) + ".md")
    plan_excerpt = _load_repair_plan_excerpt(plan_path)
    directives = _build_repair_directives(details)
    prompt_lines = [
        "The previous harness is semantically weak for the selected vulnerability target. Rewrite it so it follows the execution plan more accurately.",
        "",
        "## Reason:",
        reason,
        "",
        "## Execution Plan Excerpt:",
        "```json",
        json.dumps(plan_excerpt, indent=2),
        "```",
        "",
        "## Semantic Validation Details:",
        "```json",
        json.dumps(details, indent=2),
        "```",
        "",
        "## Previous Harness Code:",
        "```c++",
        current_code,
        "```",
        "",
        "## Repair Directives:",
    ]
    for item in directives:
        prompt_lines.append("- " + item)
    prompt_lines.extend([
        "",
        "## Requirements:",
        "1. Preserve valid public API usage and compilability.",
        "2. Fix the semantic problems called out above even if that requires rewriting major parts of the harness.",
        "3. Follow the execution plan, milestone plan, and active data plan rather than patching the current raw-input structure.",
        "4. If the current harness passes raw fuzzer bytes directly into a parser-style public API, replace it with a synthesized structured input flow.",
        "5. Output ONLY the corrected C++ code, no JSON wrapper, no explanation.",
        "",
        "Generate the corrected fuzzer.cc:"
    ])
    fix_prompt_path.write_text("\n".join(prompt_lines), encoding="utf-8")
    return fix_prompt_path


def build_prompt_variants(base_prompt: Path, out: Path):
    """Create a small set of prompt variants to avoid a single weak local optimum."""
    base_text = base_prompt.read_text(encoding="utf-8")
    variants = [
        ('milestone-first', 'Prioritize satisfying milestone states in order before spending entropy on deeper sink-adjacent bytes.'),
        ('active-data-first', 'Prioritize the active data plan after milestone satisfaction: keep stabilized regions valid and place most entropy in the highest-value mutable regions.'),
        ('support-object-first', 'Prioritize valid support objects and bounded transform configuration, then drive sink-relevant mutable regions without breaking lifecycle correctness.'),
    ]
    prompt_dir = out / 'context' / 'candidate_prompts'
    prompt_dir.mkdir(parents=True, exist_ok=True)
    prompt_paths = []
    for name, instruction in variants:
        path = prompt_dir / ('prompt.' + name + '.md')
        path.write_text('## Candidate Strategy\n' + instruction + '\n\n' + base_text, encoding='utf-8')
        prompt_paths.append((name, path))
    return prompt_paths


def run_seed_corpus_validation(harness_binary: Path, out_dir: Path, plan_path: Path):
    """Run the harness against generated seeds and classify early crashes before fuzzing."""
    from fuzz_runner import create_corpus_from_seeds
    from harness_validator import classify_runtime_evidence

    out_dir = Path(out_dir)
    seeds_json = out_dir / 'seeds.json'
    corpus_dir = out_dir / 'corpus'
    if not seeds_json.exists():
        return {
            'ok': True,
            'issue': '',
            'output': '',
            'evidence': {},
            'seed_count': 0,
        }

    if corpus_dir.exists():
        import shutil
        shutil.rmtree(str(corpus_dir))

    seed_count = create_corpus_from_seeds(seeds_json, corpus_dir)
    validation_runs = max(seed_count, 1)

    env = os.environ.copy()
    env['ASAN_OPTIONS'] = 'abort_on_error=1:detect_leaks=0'
    env['UBSAN_OPTIONS'] = 'abort_on_error=1'

    try:
        result = subprocess.run(
            [
                str(harness_binary),
                '-runs={}'.format(validation_runs),
                '-timeout=5',
                str(corpus_dir),
            ],
            cwd=str(out_dir),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=max(30, validation_runs + 10),
        )
    except subprocess.TimeoutExpired:
        return {
            'ok': False,
            'issue': 'Generated-seed validation timed out before completing the initial corpus run.',
            'output': '',
            'evidence': {},
            'seed_count': seed_count,
        }
    except Exception as exc:
        return {
            'ok': False,
            'issue': 'Generated-seed validation failed to execute: {}'.format(exc),
            'output': '',
            'evidence': {},
            'seed_count': seed_count,
        }

    combined = (result.stdout or '') + '\n' + (result.stderr or '')
    evidence = classify_runtime_evidence(plan_path, combined, result.returncode)
    if result.returncode != 0:
        # A crash that reaches the sink or sink-adjacent functions means the
        # harness *successfully triggered the vulnerability* — that is not a
        # harness defect, so treat it as a pass.
        ev_score = evidence.get('score', 0) if evidence else 0
        if ev_score >= 80:
            return {
                'ok': True,
                'issue': '',
                'output': combined[:6000],
                'evidence': evidence,
                'seed_count': seed_count,
                'vulnerability_triggered': True,
            }
        return {
            'ok': False,
            'issue': 'Harness crashed or exited abnormally on generated targeted seeds.',
            'output': combined[:6000],
            'evidence': evidence,
            'seed_count': seed_count,
        }

    return {
        'ok': True,
        'issue': '',
        'output': combined[:2000],
        'evidence': evidence,
        'seed_count': seed_count,
    }


def select_best_candidate(plan_path: Path, candidates_dir: Path, variants, model: str, api_base: str):
    """Generate several candidates and keep the one with the strongest semantic validation score."""
    from llm_adapters.openai import run_openai_json
    from harness_validator import validate_harness_source

    candidates_dir.mkdir(parents=True, exist_ok=True)
    reports = []
    for name, prompt_path in variants:
        candidate_src = candidates_dir / ('fuzzer.' + name + '.cc')
        ok, msg = run_openai_json(str(prompt_path), str(candidate_src), model=model, api_base=api_base)
        if not ok:
            reports.append({
                'name': name,
                'ok': False,
                'error': msg,
                'score': 0,
                'path': str(candidate_src),
            })
            continue
        extract_generated_code(candidate_src)
        semantic_report = validate_harness_source(plan_path, candidate_src)
        reports.append({
            'name': name,
            'ok': semantic_report.get('ok', False),
            'score': semantic_report.get('score', 0),
            'violations': semantic_report.get('violations', []),
            'warnings': semantic_report.get('warnings', []),
            'relation_diagnostics': semantic_report.get('relation_diagnostics', []),
            'path': str(candidate_src),
        })

    reports.sort(
        key=lambda item: (
            item.get('ok', False),
            item.get('score', 0),
            sum(1 for rel in item.get('relation_diagnostics', []) if rel.get('ok')),
            -len(item.get('violations', [])),
            -len(item.get('warnings', []))
        ),
        reverse=True
    )
    return reports

def detect_build_system(root: Path) -> str:
    """Detect the build system used by the project.
    Prefers autotools if cmake is not available.
    """
    import shutil
    
    has_cmake = shutil.which("cmake") is not None
    has_autoreconf = shutil.which("autoreconf") is not None or (root / "configure").exists()
    
    # Prefer autotools if cmake is not available
    if (root / "configure").exists() and (not has_cmake or (root / "configure.ac").exists() or (root / "configure.in").exists()):
        return "autotools"
    if (root / "CMakeLists.txt").exists() and has_cmake:
        return "cmake"
    if (root / "Makefile").exists():
        return "make"
    if (root / "meson.build").exists():
        return "meson"
    if (root / "configure").exists():
        return "autotools"
    # Recognise autotools projects that have configure.ac/configure.in but
    # no pre-generated configure script (needs autoreconf / bootstrap first).
    if (root / "configure.ac").exists() or (root / "configure.in").exists():
        return "autotools"
    return "unknown"

def build_manual_autotools(root: Path, log_path: Path, script_dir: Path) -> int:
    """Manually build an autotools project with instrumentation."""
    import os
    
    print("No ossfuzz.sh found, using manual autotools build...")
    
    # Set up environment with instrumentation
    env = os.environ.copy()
    env["RF_BUILD_LOG"] = str(log_path)
    env["REAL_CC"] = env.get("CC", "clang")
    env["REAL_CXX"] = env.get("CXX", "clang++")
    env["CC"] = str(script_dir / "rf-cc")
    env["CXX"] = str(script_dir / "rf-cxx")
    env["CFLAGS"] = "-fsanitize=address,undefined -fsanitize=fuzzer-no-link -fno-omit-frame-pointer -g"
    env["CXXFLAGS"] = env["CFLAGS"]
    # Disable leak detection during build — build tools (parser generators,
    # code generators, etc.) commonly leak memory and ASAN would otherwise
    # abort the build.  This mirrors standard oss-fuzz practice.
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    
    # Run configure - skip autoreconf if configure already exists
    configure_script = root / "configure"
    if not configure_script.exists():
        # Need to generate configure first
        if (root / "autogen.sh").exists():
            print("Running autogen.sh...")
            result = subprocess.run(["bash", "./autogen.sh"], cwd=str(root), env=env)
            if result.returncode != 0:
                return result.returncode
        elif (root / "bootstrap").exists():
            print("Running bootstrap...")
            result = subprocess.run(["bash", "./bootstrap"], cwd=str(root), env=env)
            if result.returncode != 0:
                return result.returncode
        elif (root / "buildconf").exists():
            print("Running buildconf...")
            result = subprocess.run(["bash", "./buildconf"], cwd=str(root), env=env)
            if result.returncode != 0:
                return result.returncode
        elif os.path.exists("/usr/bin/autoreconf"):
            print("Running autoreconf...")
            result = subprocess.run(["autoreconf", "-fvi"], cwd=str(root), env=env)
            if result.returncode != 0:
                return result.returncode
    
    # Run configure with --disable-shared for static-only builds (preferred
    # for fuzzing — avoids DSO linking issues and produces self-contained
    # harness binaries).
    configure_args = ["./configure", "--disable-shared"]
    if configure_script.exists():
        print("Running: " + " ".join(configure_args))
        result = subprocess.run(configure_args, cwd=str(root), env=env)
        if result.returncode != 0:
            # Fall back to plain configure without --disable-shared
            print("configure --disable-shared failed, retrying without it...")
            result = subprocess.run(["./configure"], cwd=str(root), env=env)
            if result.returncode != 0:
                return result.returncode
    
    # Build with make
    make_cmd = ["make", "-j4"]
    print("Running: " + " ".join(make_cmd))
    result = subprocess.run(make_cmd, cwd=str(root), env=env)
    return result.returncode


def build_manual_cmake(root: Path, log_path: Path, script_dir: Path, vulns_file: Path = None, cve_id: str = None) -> int:
    """Manually build a CMake project with instrumentation."""
    import os
    import json
    
    print("No ossfuzz.sh found, using manual CMake build...")
    
    # Detect if cJSON_Utils is needed based on vulnerability file
    enable_cjson_utils = False
    if vulns_file and vulns_file.exists():
        try:
            vulns_data = json.loads(vulns_file.read_text(encoding="utf-8"))
            for vuln in vulns_data.get("vulnerabilities", []):
                if vuln.get("cve-id") == cve_id:
                    affected_file = vuln.get("affected-file", "")
                    if "Utils" in affected_file or "cJSON_Utils" in affected_file:
                        enable_cjson_utils = True
                        print("Detected cJSON_Utils vulnerability, enabling Utils build...")
                    break
        except Exception:
            pass
    
    # Clean and create build directory
    build_dir = root / "build"
    if build_dir.exists():
        import shutil
        shutil.rmtree(str(build_dir))  # Python 3.5 needs string
    build_dir.mkdir(parents=True, exist_ok=True)
    
    # Set up environment with instrumentation
    env = os.environ.copy()
    env["RF_BUILD_LOG"] = str(log_path)
    env["REAL_CC"] = env.get("CC", "clang")
    env["REAL_CXX"] = env.get("CXX", "clang++")
    env["CC"] = str(script_dir / "rf-cc")
    env["CXX"] = str(script_dir / "rf-cxx")
    # Disable leak detection during build (see build_manual_autotools).
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    
    # CMake configure with instrumentation flags
    cflags = "-fsanitize=address,undefined -fsanitize=fuzzer-no-link -fno-omit-frame-pointer -g"
    cmake_cmd = [
        "cmake", "..",
        "-DCMAKE_C_FLAGS=" + cflags,
        "-DCMAKE_CXX_FLAGS=" + cflags,
        "-DCMAKE_BUILD_TYPE=Debug",
        "-DBUILD_TESTING=OFF",
        "-DBUILD_SHARED_LIBS=OFF",
    ]
    
    # Enable cJSON_Utils if needed
    if enable_cjson_utils:
        cmake_cmd.append("-DENABLE_CJSON_UTILS=On")
        cmake_cmd.append("-DBUILD_CJSON_UTILS=On")
    
    print("Running: " + " ".join(cmake_cmd))
    result = subprocess.run(cmake_cmd, cwd=str(build_dir), env=env)
    if result.returncode != 0:
        return result.returncode
    
    # Build
    make_cmd = ["make", "-j4"]
    print("Running: " + " ".join(make_cmd))
    result = subprocess.run(make_cmd, cwd=str(build_dir), env=env)
    if result.returncode != 0:
        # Partial-build fallback: if the library .a was produced, treat as success
        import glob
        static_libs = glob.glob(str(build_dir / "**" / "lib*.a"), recursive=True)
        if static_libs:
            print("WARNING: make failed (rc=" + str(result.returncode) + ") but static library found: " + static_libs[0])
            print("Treating as partial build success (non-library targets may have failed).")
            return 0
        return result.returncode
    return result.returncode

def main():
    p = argparse.ArgumentParser(description="Standalone harness generator for OSS-Fuzz library vulnerabilities")
    p.add_argument("--root", required=True, help="Project root under $SRC")
    p.add_argument("--build-script", required=False, help="Build script to run")
    p.add_argument("--vulns", required=False, help="Path to vulnerabilities.json (optional if --cve-id and --package are provided)")
    p.add_argument("--cve-id", required=True, help="CVE ID to target")
    p.add_argument("--package", required=False, help="Package name (required when --vulns is not provided)")
    p.add_argument("--out", required=True, help="Output directory for harness artifacts")
    p.add_argument("--no-enrich", action="store_true",
                   help="Skip automatic CVE enrichment from NVD/OSV/GitHub")
    args = p.parse_args()

    # Build or load vulnerability entry
    if args.vulns:
        vulns_file = Path(args.vulns)
    else:
        # No vulnerabilities.json — construct a minimal entry from CLI args
        if not args.package:
            p.error("--package is required when --vulns is not provided")
        minimal_entry = {"cve-id": args.cve_id, "package-name": args.package}
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        generated_vulns = out / "vulnerabilities.json"
        generated_vulns.write_text(
            json.dumps({"vulnerabilities": [minimal_entry]}, indent=2),
            encoding="utf-8"
        )
        args.vulns = str(generated_vulns)
        vulns_file = generated_vulns
        print("[harness_runner] Generated minimal vulnerabilities.json from --cve-id and --package")

    root = Path(args.root).resolve()
    out = Path(args.out)
    # Create directory first before resolving (needed for Python 3.5)
    out.mkdir(parents=True, exist_ok=True)
    out = out.resolve()
    log_path = out / "rf_build_commands.jsonl"

    script_dir = Path(__file__).resolve().parent
    
    # Parse vulnerabilities file for build detection
    vulns_file = Path(args.vulns)
    
    # Determine build approach
    build_script = args.build_script
    if not build_script:
        # Try to detect build system
        build_system = detect_build_system(root)
        if build_system == "cmake":
            # Use manual CMake build
            rc = build_manual_cmake(root, log_path, script_dir, vulns_file, args.cve_id)
            if rc != 0:
                sys.exit(rc)
        elif build_system == "autotools":
            # Use manual autotools build
            rc = build_manual_autotools(root, log_path, script_dir)
            if rc != 0:
                sys.exit(rc)
        else:
            print("Error: Cannot auto-detect build system. Please provide --build-script")
            sys.exit(1)
    else:
        # Check for ossfuzz.sh - if it doesn't exist, try manual build
        ossfuzz_sh = root / "fuzzing" / "ossfuzz.sh"
        if build_script == "bash /src/build.sh" and not ossfuzz_sh.exists():
            print("ossfuzz.sh not found, falling back to manual CMake build...")
            build_system = detect_build_system(root)
            if build_system == "cmake":
                rc = build_manual_cmake(root, log_path, script_dir, vulns_file, args.cve_id)
                if rc != 0:
                    sys.exit(rc)
            else:
                # Try the provided build script anyway
                rc = subprocess.run([
                    sys.executable, str(script_dir / "build_capture.py"),
                    "--root", str(root),
                    "--build-script", build_script,
                    "--log", str(log_path)
                ], cwd=str(root))
                if rc.returncode != 0:
                    sys.exit(rc.returncode)
        else:
            # 1) Capture compile/link commands using build script
            rc = subprocess.run([
                sys.executable, str(script_dir / "build_capture.py"),
                "--root", str(root),
                "--build-script", build_script,
                "--log", str(log_path)
            ], cwd=str(root))
            if rc.returncode != 0:
                sys.exit(rc.returncode)

    # 1.5) CVE enrichment — query NVD/OSV/GitHub for descriptions, patches, CVSS
    effective_vulns = args.vulns
    if not args.no_enrich:
        try:
            from cve_enrichment import enrich_vulnerability
            vulns_data = json.loads(Path(args.vulns).read_text(encoding="utf-8"))
            vulns_list = vulns_data.get("vulnerabilities", vulns_data.get("vulns", []))
            target_entry = next((v for v in vulns_list if v.get("cve-id") == args.cve_id), None)
            if target_entry:
                cache_dir = out / "enrichment_cache"
                enriched_entry = enrich_vulnerability(target_entry, cache_dir=cache_dir)
                # Replace the target entry in the list
                enriched_list = []
                for v in vulns_list:
                    if v.get("cve-id") == args.cve_id:
                        enriched_list.append(enriched_entry)
                    else:
                        enriched_list.append(v)
                enriched_vulns_path = out / "enriched_vulnerabilities.json"
                enriched_vulns_path.write_text(
                    json.dumps({"vulnerabilities": enriched_list}, indent=2),
                    encoding="utf-8"
                )
                effective_vulns = str(enriched_vulns_path)
                print("[enrichment] Enriched vulnerabilities written to {}".format(enriched_vulns_path))
        except Exception as exc:
            print("[enrichment] Warning: CVE enrichment failed ({}), proceeding with original data".format(exc),
                  file=sys.stderr)

    # 2) Generate harness plan
    plan_path = out / "harness_plan.json"
    subprocess.run([
        sys.executable, str(script_dir / "harness_plan.py"),
        "--root", str(root),
        "--vulns", effective_vulns,
        "--cve-id", args.cve_id,
        "--log", str(log_path),
        "--out", str(plan_path)
    ], cwd=str(root), check=True)

    # 3) Build LLM prompt
    subprocess.run([
        sys.executable, str(script_dir / "prompt_harness.py"),
        "--root", str(root),
        "--plan", str(plan_path),
        "--out", str(out)
    ], cwd=str(root), check=True)

    # 4) Invoke LLM to generate fuzzer.cc
    prompt_md = out / "context" / "prompt.harness.md"
    fuzzer_src = out / "fuzzer.cc"
    from llm_adapters.openai import run_openai_json
    from harness_validator import validate_harness_source, run_runtime_smoke
    # Load model from config
    cfg_path = script_dir / "config" / "llm.json"
    model = "gpt-4o"  # default
    api_base = "https://api.openai.com/v1"
    try:
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        model = cfg.get("default", {}).get("model") or cfg.get("model") or model
        api_base = cfg.get("default", {}).get("api_base") or cfg.get("api_base") or api_base
    except Exception:
        pass
    prompt_variants = build_prompt_variants(prompt_md, out)
    candidate_reports = select_best_candidate(plan_path, out / 'candidates', prompt_variants, model, api_base)
    if not candidate_reports:
        print('LLM error: no harness candidates were generated', file=sys.stderr)
        sys.exit(1)
    (out / 'context' / 'candidate_reports.json').write_text(json.dumps(candidate_reports, indent=2), encoding='utf-8')
    best_candidate = next((item for item in candidate_reports if item.get('path') and Path(item.get('path')).exists()), None)
    if not best_candidate:
        print('LLM error: candidate generation failed', file=sys.stderr)
        sys.exit(1)
    best_candidate_path = Path(best_candidate['path'])
    fuzzer_src.write_text(best_candidate_path.read_text(encoding='utf-8'), encoding='utf-8')
    print('Selected candidate {} with semantic score {}'.format(best_candidate.get('name'), best_candidate.get('score', 0)))

    # 5) Compile generated harness with retry on failure
    max_retries = 3
    binary_name = "vuln_fuzzer"
    
    for attempt in range(max_retries):
        semantic_report = validate_harness_source(plan_path, fuzzer_src)
        if not semantic_report.get('ok'):
            current_code = fuzzer_src.read_text(encoding="utf-8")
            print("Semantic validation failed (attempt " + str(attempt+1) + "/" + str(max_retries) + "), asking LLM to repair the harness...")
            fix_prompt_path = build_semantic_fix_prompt(
                out,
                attempt,
                "Static semantic validation found violations against the execution plan.",
                semantic_report,
                current_code,
                plan_path
            )
            ok, msg = run_openai_json(str(fix_prompt_path), str(fuzzer_src), model=model, api_base=api_base)
            if ok:
                extract_generated_code(fuzzer_src)
                semantic_report = validate_harness_source(plan_path, fuzzer_src)
                if not semantic_report.get('ok'):
                    if attempt < max_retries - 1:
                        continue
                    print("Semantic validation failed after all retries:", file=sys.stderr)
                    print(json.dumps(semantic_report, indent=2), file=sys.stderr)
                    sys.exit(1)
                # LLM repair succeeded and validation now passes
                print("LLM semantic repair succeeded (attempt " + str(attempt+1) + ")")
            else:
                print("LLM semantic repair failed: " + msg)
                if attempt < max_retries - 1:
                    continue
                print("All semantic repair attempts exhausted", file=sys.stderr)
                sys.exit(1)

        result = subprocess.run([
            sys.executable, str(script_dir / "compile_harness.py"),
            "--log", str(log_path),
            "--harness-src", str(fuzzer_src),
            "--out-binary", binary_name
        ], cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        
        if result.returncode == 0:
            # Find the compiled binary
            harness_binary = None
            possible_locations = [
                root / "build" / binary_name,
                root / binary_name,
                out / binary_name,
                Path(binary_name),
            ]
            for loc in possible_locations:
                if loc.exists():
                    harness_binary = loc
                    break
            
            if not harness_binary:
                # Search for it
                import glob
                found = glob.glob(str(root / "**" / binary_name), recursive=True)
                if found:
                    harness_binary = Path(found[0])
            
            if harness_binary:
                # Copy to output directory
                import shutil
                dest_binary = out / binary_name
                if harness_binary != dest_binary:
                    shutil.copy2(str(harness_binary), str(dest_binary))
                    print("Harness copied to: " + str(dest_binary))
                else:
                    print("Harness generated and compiled at: " + str(harness_binary))
            else:
                print("Compilation reported success, but the harness binary could not be located.", file=sys.stderr)
                if attempt < max_retries - 1:
                    continue
                sys.exit(1)

            runtime_target = out / binary_name if (out / binary_name).exists() else harness_binary
            runtime_report = run_runtime_smoke(runtime_target, out, plan_path)
            (out / 'context' / 'runtime_smoke_report.json').write_text(json.dumps(runtime_report, indent=2), encoding='utf-8')
            if runtime_report.get('vulnerability_triggered'):
                ev = runtime_report.get('evidence', {})
                print('Smoke test triggered the vulnerability ({}, score={}) -- harness is correct, skipping repair.'.format(
                    ev.get('classification', 'unknown'), ev.get('score', 0)))
            if not runtime_report.get('ok'):
                if attempt < max_retries - 1:
                    current_code = fuzzer_src.read_text(encoding="utf-8")
                    print("Runtime smoke validation failed (attempt " + str(attempt+1) + "/" + str(max_retries) + "), asking LLM to repair the harness...")
                    fix_prompt_path = build_semantic_fix_prompt(
                        out,
                        attempt,
                        runtime_report.get('issue', 'Runtime smoke validation failed.'),
                        runtime_report,
                        current_code,
                        plan_path
                    )
                    ok, msg = run_openai_json(str(fix_prompt_path), str(fuzzer_src), model=model, api_base=api_base)
                    if ok:
                        extract_generated_code(fuzzer_src)
                        continue
                    print("LLM runtime repair failed: " + msg)
                else:
                    print("Runtime smoke validation failed after all retries:", file=sys.stderr)
                    print(runtime_report.get('output', ''), file=sys.stderr)
                    sys.exit(1)
            
            evidence = runtime_report.get('evidence', {})
            print("Harness generated and compiled")
            if evidence:
                print("Runtime evidence: {} (score={})".format(
                    evidence.get('classification', 'unknown'),
                    evidence.get('score', 0)
                ))
            
            # 6) Generate seeds
            print("Generating targeted seeds...")
            seeds_path = None
            try:
                from seed_generator import generate_seeds
                seeds_path = generate_seeds(root, out, model=model)
                if seeds_path:
                    print("Seeds generated at: " + str(seeds_path))
            except Exception as e:
                print("Warning: seed generation failed: " + str(e), file=sys.stderr)

            if seeds_path:
                seed_report = run_seed_corpus_validation(runtime_target, out, plan_path)
                (out / 'context' / 'seed_runtime_report.json').write_text(json.dumps(seed_report, indent=2), encoding='utf-8')
                if seed_report.get('vulnerability_triggered'):
                    ev = seed_report.get('evidence', {})
                    print('Seeds triggered the vulnerability ({}, score={}) -- harness is correct, skipping repair.'.format(
                        ev.get('classification', 'unknown'), ev.get('score', 0)))
                if not seed_report.get('ok'):
                    if attempt < max_retries - 1:
                        current_code = fuzzer_src.read_text(encoding='utf-8')
                        print('Generated-seed validation failed (attempt ' + str(attempt+1) + '/' + str(max_retries) + '), asking LLM to repair the harness...')
                        fix_prompt_path = build_semantic_fix_prompt(
                            out,
                            attempt,
                            seed_report.get('issue', 'Generated-seed validation failed.'),
                            seed_report,
                            current_code,
                            plan_path
                        )
                        ok, msg = run_openai_json(str(fix_prompt_path), str(fuzzer_src), model=model, api_base=api_base)
                        if ok:
                            extract_generated_code(fuzzer_src)
                            continue
                        print('LLM generated-seed repair failed: ' + msg)
                    else:
                        print('Generated-seed validation failed after all retries:', file=sys.stderr)
                        print(seed_report.get('output', ''), file=sys.stderr)
                        sys.exit(1)
            
            # 7) Run fuzzer with generated seeds
            print("\nStarting fuzzing...")
            try:
                from fuzz_runner import create_corpus_from_seeds
                
                harness_binary = out / binary_name
                seeds_json = out / "seeds.json"
                corpus_dir = out / "corpus"
                
                # Create corpus from seeds
                seed_count = create_corpus_from_seeds(seeds_json, corpus_dir)
                print("Created corpus with " + str(seed_count) + " seeds")
                
                # Run fuzzer
                print("\nRunning: " + str(harness_binary) + " " + str(corpus_dir))
                print("-" * 60)
                
                import os
                env = os.environ.copy()
                env["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=0"
                env["UBSAN_OPTIONS"] = "abort_on_error=1"
                
                result = subprocess.run(
                    [str(harness_binary), str(corpus_dir)],
                    cwd=str(out),
                    env=env
                )
                
                print("-" * 60)
                if result.returncode != 0:
                    print("\nFuzzer exited with code " + str(result.returncode))
                    # Check for crash files
                    for f in out.iterdir():
                        if f.name.startswith("crash-") or f.name.startswith("timeout-"):
                            print("CRASH FILE: " + str(f))
                            break
                else:
                    print("\nFuzzing completed normally")
                    
            except Exception as e:
                print("Warning: fuzzing failed: " + str(e), file=sys.stderr)
            
            return
        
        # Compilation failed - try to fix with LLM
        if attempt < max_retries - 1:
            error_msg = result.stderr or result.stdout
            
            # Read the current (failed) harness code
            current_code = fuzzer_src.read_text(encoding="utf-8")
            
            print("Compilation failed (attempt " + str(attempt+1) + "/" + str(max_retries) + "), asking LLM to fix...")
            print("DEBUG: Compilation error details:", file=sys.stderr)
            print("-" * 60, file=sys.stderr)
            print(error_msg, file=sys.stderr)
            print("-" * 60, file=sys.stderr)
            print("DEBUG: Current harness code:", file=sys.stderr)
            print("-" * 60, file=sys.stderr)
            print(current_code[:500] + "..." if len(current_code) > 500 else current_code, file=sys.stderr)
            print("-" * 60, file=sys.stderr)
            
            # Build a fix prompt
            fix_prompt_path = out / "context" / ("fix_prompt_" + str(attempt) + ".md")
            fix_prompt = [
                "The previous harness code failed to compile. Please fix it.",
                "",
                "## Compilation Error:",
                "```",
                error_msg[:2000],
                "```",
                "",
                "## Previous Harness Code:",
                "```c++",
                current_code,
                "```",
                "",
                "## Requirements:",
                "1. Fix ALL compilation errors",
                "2. Ensure all required headers are included",
                "3. Do NOT call internal/static functions - use the public API",
                "4. Output ONLY the corrected C++ code, no JSON wrapper, no explanation",
                "",
                "Generate the corrected fuzzer.cc:"
            ]
            fix_prompt_path.write_text("\n".join(fix_prompt), encoding="utf-8")
            
            # Call LLM to fix
            ok, msg = run_openai_json(str(fix_prompt_path), str(fuzzer_src), model=model, api_base=api_base)
            if ok:
                extract_generated_code(fuzzer_src)
                print("LLM provided fixed harness, retrying compilation...")
            else:
                print("LLM fix failed: " + msg)
        else:
            print("Compilation failed after all retries:", file=sys.stderr)
            print(result.stderr or result.stdout, file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()