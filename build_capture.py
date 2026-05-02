#!/usr/bin/env python3
"""
Build capture that intercepts compiler commands and adds instrumentation flags.
Ensures the library is built with ASAN/UBSAN and fuzzer coverage instrumentation.
"""
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
import shlex


def _installed_automake_version():
    """Return the installed Automake version as a tuple of ints, or None."""
    try:
        out = subprocess.run(
            ["automake", "--version"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=5,
        ).stdout.splitlines()
        if not out:
            return None
        # First line is like "automake (GNU automake) 1.15.1"
        m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", out[0])
        if not m:
            return None
        parts = [int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)]
        return tuple(parts)
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        return None


def _preflight_source_repair(root: str) -> None:
    """Generic, library-agnostic source-tree repairs run BEFORE the build.

    Two known incompatibilities between OSS-Fuzz legacy base images and
    pinned vulnerable source revisions:

    1. ``AM_INIT_AUTOMAKE([X.Y.Z ...])`` in ``configure.ac`` requires a
       newer Automake than the container ships (e.g. libxml2 master needs
       1.16.3, but Ubuntu 16.04 base ships 1.15). The Automake version
       requirement is purely advisory — projects almost never use features
       only the latest version provides — so downgrading the requirement
       to the installed version lets the build proceed.

    2. The container's ``build.sh`` invokes ``make`` directly assuming a
       prebuilt Makefile, but the pinned source ships only ``configure.ac``
       (no committed ``configure``/``Makefile``). Running ``autoreconf -fvi``
       once produces them. We do this opportunistically when ``configure.ac``
       exists and ``configure`` is missing.

    Both repairs are idempotent and project-agnostic.
    """
    root_path = Path(root)
    if not root_path.exists():
        return

    # Repair 1: downgrade AM_INIT_AUTOMAKE version requirements.
    installed = _installed_automake_version()
    if installed is not None:
        installed_str = ".".join(str(x) for x in installed)
        pat = re.compile(
            r"(AM_INIT_AUTOMAKE\s*\(\s*\[?)(\d+\.\d+(?:\.\d+)?)",
            re.IGNORECASE,
        )
        for cfg in root_path.rglob("configure.ac"):
            try:
                txt = cfg.read_text(errors="replace")
            except Exception:
                continue
            def _rewrite(m):
                want = tuple(int(x) for x in m.group(2).split("."))
                if want > installed:
                    return f"{m.group(1)}{installed_str}"
                return m.group(0)
            new_txt, n = pat.subn(_rewrite, txt)
            if n and new_txt != txt:
                try:
                    cfg.write_text(new_txt)
                    print(f"[build_capture] preflight: downgraded "
                          f"AM_INIT_AUTOMAKE in {cfg} to "
                          f"{installed_str} (installed)", flush=True)
                except Exception:
                    pass

    # Repair 2: run autoreconf when configure.ac is present but configure
    # is not (so the container's `./configure && make` recipe will work).
    # Global wall-time budget caps the total preflight regardless of how
    # many configure.ac subdirectories exist (e.g. pcre2 ships configure.ac
    # in the top, in pcre2_jit_test/, and in tests/, and naive per-call
    # timeouts compound to exceed the per-CVE wall budget). 90 s is enough
    # for the top-level autoreconf in every library we have observed; if a
    # nested subdir's autoreconf is still pending after that, we fall
    # through and let the build attempt run anyway. Library-agnostic.
    import time as _time
    _preflight_deadline = _time.monotonic() + 90.0
    for cfg in root_path.rglob("configure.ac"):
        if _time.monotonic() >= _preflight_deadline:
            print("[build_capture] preflight: 90s budget exhausted; "
                  "skipping remaining autoreconf passes", flush=True)
            break
        cfg_dir = cfg.parent
        if (cfg_dir / "configure").exists():
            continue
        # Skip nested vendor trees that have their own autotools.
        rel = cfg.relative_to(root_path)
        if any(part in {"third_party", "vendor", "external"}
               for part in rel.parts):
            continue
        print(f"[build_capture] preflight: running autoreconf -fvi in "
              f"{cfg_dir}", flush=True)
        _per_call_budget = max(30.0, _preflight_deadline - _time.monotonic())
        try:
            subprocess.run(
                ["autoreconf", "-fvi"],
                cwd=str(cfg_dir),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
                timeout=_per_call_budget,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            pass

def _build_once(root: str, build_script: str, log_path: str,
                instrumentation_flags: str, env_base: dict, label: str) -> tuple:
    """Run the build script once with the given instrumentation. Returns
    (returncode, captured_log_text). Captures stderr/stdout to a string buffer
    so we can detect specific link-failure signatures and decide whether to
    retry with a weaker sanitizer set."""
    env = dict(env_base)
    existing_cflags = env.get("CFLAGS", "")
    if "-fsanitize" not in existing_cflags:
        env["CFLAGS"] = f"{instrumentation_flags} {existing_cflags}".strip()
    else:
        # Strip any prior instrumentation we set so retries can swap it.
        env["CFLAGS"] = (existing_cflags
                         .replace("-fsanitize=address,undefined", "")
                         .replace("-fsanitize=undefined", "")
                         .replace("-fsanitize=address", "").strip())
        env["CFLAGS"] = f"{instrumentation_flags} {env['CFLAGS']}".strip()

    existing_cxxflags = env.get("CXXFLAGS", "")
    if "-fsanitize" not in existing_cxxflags:
        env["CXXFLAGS"] = f"{instrumentation_flags} {existing_cxxflags}".strip()
    else:
        env["CXXFLAGS"] = (existing_cxxflags
                           .replace("-fsanitize=address,undefined", "")
                           .replace("-fsanitize=undefined", "")
                           .replace("-fsanitize=address", "").strip())
        env["CXXFLAGS"] = f"{instrumentation_flags} {env['CXXFLAGS']}".strip()

    print(f"[build_capture] {label}: building with: {instrumentation_flags}")
    proc = subprocess.run(
        ["/bin/bash", "-lc", build_script],
        cwd=root, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, errors="replace",
    )
    sys.stdout.write(proc.stdout)
    sys.stdout.flush()
    return proc.returncode, proc.stdout


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

    # Preflight: repair source-tree mismatches with the container's
    # toolchain (Automake version pin, missing `configure` script).
    # Library-agnostic; idempotent.
    _preflight_source_repair(root)

    # First attempt: full ASan + UBSan + libFuzzer. This is what we want
    # whenever the toolchain supports it.
    primary = "-fsanitize=address,undefined -fsanitize=fuzzer-no-link -fno-omit-frame-pointer -gline-tables-only"
    rc, log = _build_once(root, build_script_cmd, log_path, primary, env,
                          "primary (ASan+UBSan)")
    if rc == 0:
        return 0

    # Detect "build.sh ran `make` but no Makefile/targets" — happens when a
    # pinned vulnerable revision predates committed Makefiles, or the build
    # recipe assumes `./configure` was already run. Re-run autoreconf and
    # retry the original build once. Library-agnostic.
    no_makefile = (
        "No targets specified and no makefile found" in log
        or "No rule to make target" in log and "configure" not in log
    )
    if no_makefile:
        print("[build_capture] no-Makefile failure detected; "
              "running autoreconf+configure and retrying primary build",
              flush=True)
        try:
            subprocess.run(
                ["bash", "-lc",
                 "autoreconf -fvi && ./configure --disable-shared || true"],
                cwd=root,
                stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                timeout=300,
            )
        except Exception:
            pass
        rc, log = _build_once(root, build_script_cmd, log_path, primary,
                              env, "retry after autoreconf (ASan+UBSan)")
        if rc == 0:
            return 0

    # Detect the canonical UBSan-typeinfo link failure that legacy clang
    # toolchains (e.g. clang 9 + libc++ in older OSS-Fuzz base images) emit.
    # When the link can't resolve C++ typeinfo symbols pulled in by
    # `libclang_rt.asan_cxx`, dropping UBSan eliminates the requirement.
    # ASan still catches every memory-safety bug we benchmark for. Generic;
    # no library-specific knowledge.
    ubsan_link_failure = (
        "undefined reference to" in log
        and ("typeinfo for" in log or "vtable for" in log)
        and "libclang_rt" in log
    )
    if not ubsan_link_failure:
        return rc

    print("[build_capture] UBSan link failure detected (legacy clang/libc++); "
          "retrying without -fsanitize=undefined", flush=True)
    # Persist the mode BEFORE the fallback build so rf-cc / rf-cxx wrappers
    # invoked during the build don't reinject `-fsanitize=undefined` from
    # their own defaults. Both the env var (for the in-process retry) and a
    # sentinel file (for sibling processes that inherit a stale env) are
    # written. Mirrored later by compile_harness for the harness compile so
    # the sanitizer modes match — mismatch produces the exact cascade of
    # typeinfo/vtable link errors we just hit.
    os.environ["RF_SANITIZER_MODE"] = "asan_only"
    env["RF_SANITIZER_MODE"] = "asan_only"
    try:
        sentinel = Path(log_path).resolve().parent / "rf_sanitizer_mode"
        sentinel.write_text("asan_only\n")
    except Exception:
        pass

    fallback = "-fsanitize=address -fsanitize=fuzzer-no-link -fno-omit-frame-pointer -gline-tables-only"
    rc2, _ = _build_once(root, build_script_cmd, log_path, fallback,
                         env, "fallback (ASan only)")
    return rc2

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