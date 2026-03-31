#!/usr/bin/env python3
"""
Build capture that intercepts compiler commands and adds instrumentation flags.
Ensures the library is built with ASAN/UBSAN and fuzzer coverage instrumentation.
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path
import shlex

def run_build_capture(root: str, build_script: str, log_path: str) -> int:
    # Ensure wrappers are executable
    script_dir = Path(__file__).resolve().parent
    wrapper_cc = str(script_dir / "rf-cc")
    wrapper_cxx = str(script_dir / "rf-cxx")
    for w in (wrapper_cc, wrapper_cxx):
        try:
            os.chmod(w, 0o755)
        except Exception:
            pass

    # Prepare environment
    env = os.environ.copy()
    env["RF_BUILD_LOG"] = log_path

    # Add instrumentation flags to CFLAGS/CXXFLAGS if not already present
    # These flags are needed for coverage-guided fuzzing
    instrumentation_flags = "-fsanitize=address,undefined -fsanitize=fuzzer-no-link -fno-omit-frame-pointer -gline-tables-only"
    
    existing_cflags = env.get("CFLAGS", "")
    if "-fsanitize" not in existing_cflags:
        env["CFLAGS"] = f"{instrumentation_flags} {existing_cflags}".strip()
    
    existing_cxxflags = env.get("CXXFLAGS", "")
    if "-fsanitize" not in existing_cxxflags:
        env["CXXFLAGS"] = f"{instrumentation_flags} {existing_cxxflags}".strip()

    # Ensure LIB_FUZZING_ENGINE is properly configured
    cur = env.get("LIB_FUZZING_ENGINE", "")
    if cur:
        path_part = cur.split()[0] if cur else ""
        if path_part and not os.path.exists(path_part):
            candidates = [
                "/usr/local/lib/clang/22/lib/x86_64-unknown-linux-gnu/libclang_rt.fuzzer.a",
                "/usr/local/lib/clang/22/lib/x86_64-unknown-linux-gnu/libclang_rt.fuzzer_no_main.a",
            ]
            for cand in candidates:
                if os.path.exists(cand):
                    rest = cur[len(path_part):] if cur.startswith(path_part) else ""
                    cur = cand + rest
                    break
        if "libclang_rt.fuzzer" in cur and "-pthread" not in cur:
            cur = cur + " -pthread"
        env["LIB_FUZZING_ENGINE"] = cur

    # Preserve original compiler
    env["REAL_CC"] = env.get("CC", "clang")
    env["REAL_CXX"] = env.get("CXX", "clang++")
    # Use wrappers
    env["CC"] = wrapper_cc
    env["CXX"] = wrapper_cxx

    # Run the build script from the target library root
    build_script_cmd = build_script
    try:
        bs_path = Path(build_script)
        if bs_path.exists() and bs_path.is_file() and not os.access(str(bs_path), os.X_OK):
            build_script_cmd = f"bash {shlex.quote(str(bs_path))}"
    except Exception:
        pass

    print(f"[build_capture] Building with instrumentation: {instrumentation_flags}")
    build_cmd = ["/bin/bash", "-lc", build_script_cmd]
    proc = subprocess.run(build_cmd, cwd=root, env=env)
    return proc.returncode

def main():
    p = argparse.ArgumentParser(
        description="Capture compile/link commands during build with instrumentation"
    )
    p.add_argument("--root", required=True, help="Project root directory")
    p.add_argument("--build-script", required=True, help="Build script to run (e.g. './build.sh')")
    p.add_argument("--log", required=False, default="rf_build_commands.jsonl",
                   help="Path to append captured commands (JSONL)")
    args = p.parse_args()

    rc = run_build_capture(args.root, args.build_script, args.log)
    if rc != 0:
        print(f"[build_capture] build script exited with code {rc}", file=sys.stderr)
    sys.exit(rc)

if __name__ == "__main__":
    main()