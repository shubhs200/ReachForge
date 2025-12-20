from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path
from typing import Optional, Tuple

# Support both package execution (python -m reachforge.cli) and script execution (python cli.py)
from reachforge.prompt_main2fuzz import build_main2fuzz_prompt, build_afg_prompt
from reachforge.llm_runner import run_llm_driver_spec, run_llm_seeds_spec
from reachforge.schema import validate_driver_spec, write_schema_file
from reachforge.generator import write_driver_from_spec
from reachforge.compiler import compile_driver
from reachforge.prompt_seeds import build_seeds_prompt
from reachforge.seeds_schema import validate_seeds_spec
from reachforge.afg_builder import build_afg


FALLBACK_DRIVER_EXTS = {".c", ".cc", ".cpp"}


def _choose_src_root(root: Path) -> Path:
    app_src = root / "app" / "src"
    return app_src if app_src.exists() else (root / "src" if (root / "src").exists() else root)


def _iter_source_files(root: Path) -> list[Path]:
    base = _choose_src_root(root)
    files: list[Path] = []
    for p in sorted(base.rglob("*")):
        if p.is_file() and p.suffix.lower() in {".c", ".cc", ".cpp"}:
            files.append(p)
    return files


def _parse_undefined_symbols(log_path: Path) -> list[str]:
    syms: list[str] = []
    try:
        text = log_path.read_text(encoding="utf-8")
    except Exception:
        return syms
    import re as _re
    for m in _re.finditer(r"undefined reference to `([^`]+)`", text):
        syms.append(m.group(1))
    out: list[str] = []
    seen: set[str] = set()
    for s in syms:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _file_defines_symbol(text: str, sym: str) -> bool:
    import re as _re
    if not _re.search(rf"\b{_re.escape(sym)}\s*\(", text):
        return False
    return bool(_re.search(rf"\b{_re.escape(sym)}\s*\([^;]*\)\s*\{{", text))


def _auto_fix_missing_sources(root: Path, out: Path, extras: set[str]) -> bool:
    """
    Parse compile.log.txt for undefined symbols, locate defining source files under app/src or src,
    and add them to extra_sources (relative to root). Returns True if any were added.
    """
    log_path = (out / "compile.log.txt").resolve()
    added = False
    symbols = _parse_undefined_symbols(log_path)
    if not symbols:
        return False
    files = _iter_source_files(root)
    for sym in symbols:
        for p in files:
            try:
                txt = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if _file_defines_symbol(txt, sym):
                try:
                    rel = p.resolve().relative_to(root.resolve())
                    rel_s = str(rel)
                except Exception:
                    rel_s = str(p)
                if rel_s not in extras:
                    extras.add(rel_s)
                    added = True
                break
    return added


def _func_defined_in_text(text: str, name: str) -> bool:
    import re as _re
    if not name:
        return False
    return _re.search(rf'^[^\n]*\b{_re.escape(name)}\s*\([^;{{]*\)\s*\{{', text, _re.M) is not None


def _auto_lift_from_entry(root: Path, out: Path, lift: set[str]) -> bool:
    """
    Parse compile.log.txt for undefined symbols; if any are defined as functions
    in the entry translation unit (file containing main), add them to lift_from_entry.
    Returns True if any were added.
    """
    # Lazy import to avoid cyclics
    from reachforge.source_index import find_entry_main_and_context

    log_path = (out / "compile.log.txt").resolve()
    symbols = _parse_undefined_symbols(log_path)
    if not symbols:
        return False

    ctx = find_entry_main_and_context(root)
    if not ctx:
        return False
    entry_text = ctx.main_file.content

    added = False
    for sym in symbols:
        if sym in lift:
            continue
        if _func_defined_in_text(entry_text, sym):
            lift.add(sym)
            added = True
    return added


def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _find_cli_harness(root: Path) -> Optional[Path]:
    """Best-effort detection of a CLI harness source file named cli.cpp.

    We check a few common locations under the project root and, if those
    fail, fall back to a unique cli.cpp anywhere under the tree.
    """
    root = root.resolve()
    # Preferred locations
    candidates = [
        root / "cli.cpp",
        root / "src" / "cli.cpp",
        root / "app" / "src" / "cli.cpp",
    ]
    for p in candidates:
        if p.exists() and p.is_file():
            return p

    # Fallback: unique cli.cpp somewhere under the root
    try:
        found = [p for p in root.rglob("cli.cpp") if p.is_file()]
    except Exception:
        found = []
    if len(found) == 1:
        return found[0]
    return None


def _collect_cli_seeds_from_poller(root: Path, out: Path) -> int:
    """Copy sample inputs from a poller directory into <out>/seeds_cli/.

    Default behavior: look for ``<root>/poller``.

    In CI pipelines where ``--root`` may point at a nested build/variant
    directory that does not contain the poller tree, callers can set the
    ``REACHFORGE_POLLER_ROOT`` environment variable to override the search
    root. We then look for a ``poller/`` directory under that root and a
    small number of its parents.

    We treat non-Python files under poller/ as seed candidates so that a
    manually maintained CLI harness (cli.cpp) can be fuzzed using the same
    inputs the poller already exercises.

    Returns the number of seed files copied.
    """
    # Allow CI to override where we look for poller inputs. This is useful
    # when --root points at a variant directory but the poller lives at the
    # repository root.
    poller_root_env = os.environ.get("REACHFORGE_POLLER_ROOT")
    base_root = Path(poller_root_env).resolve() if poller_root_env else root.resolve()

    # Build a small list of candidate poller/ locations: base_root/poller
    # and a couple of its parents (to handle nested build dirs).
    candidates: list[Path] = []
    cur = base_root
    for _ in range(3):  # e.g., base_root, parent, grandparent
        cand = cur / "poller"
        if cand not in candidates:
            candidates.append(cand)
        if cur.parent == cur:
            break
        cur = cur.parent

    poller_dir: Optional[Path] = None
    for cand in candidates:
        if cand.exists() and cand.is_dir():
            poller_dir = cand
            break

    if poller_dir is None:
        print(
            f"[rf2] CLI seeds: no poller/ dir found under candidates: "
            f"{[str(c) for c in candidates]}; skipping."
        )
        return 0

    seeds_dir = (out / "seeds_cli").resolve()
    seeds_dir.mkdir(parents=True, exist_ok=True)

    count = 0
    for p in sorted(poller_dir.rglob("*")):
        if not p.is_file():
            continue
        name_low = p.name.lower()
        # Skip the poller script and all Python artifacts
        if name_low == "poller.py" or name_low.endswith((".py", ".pyc", ".pyo")):
            continue
        # Skip Dockerfiles and obvious non-input artifacts (logs, temp files)
        if name_low.startswith("dockerfile") or name_low.endswith((".dockerfile", ".log", ".tmp")):
            continue
        dest = seeds_dir / p.name
        try:
            shutil.copy2(p, dest)
            count += 1
        except Exception:
            continue

    print(f"[rf2] CLI seeds: copied {count} files from poller dir {poller_dir} -> {seeds_dir}")
    return count


def _synthesize_cdf_seeds(seeds_dir: Path) -> int:
    """Synthesize a small set of generic CDF/OLE-style inputs.

    These are self-contained Compound Document File (CDF) like blobs that
    resemble the seeds we use to exercise libmagic's CDF parser. We do not
    read from any on-disk magic_seeds directory so that this logic is fully
    portable across targets.
    """
    seeds: dict[str, bytes] = {}

    # 1) Classic CDF header-only blob with some padding.
    #    Magic bytes: D0 CF 11 E0 A1 B1 1A E1
    seeds["cdf_header_only.bin"] = bytes.fromhex("D0CF11E0A1B11AE1") + b"\x00" * 64

    # 2) Minimal valid-ish CDF header + a small region of zeros to mimic
    #    a tiny FAT / directory area. This is intentionally rough but
    #    structurally closer to a real file than the pure header.
    hdr = bytearray(512)
    hdr[0:8] = bytes.fromhex("D0CF11E0A1B11AE1")
    # sector size = 512 (2^9)
    hdr[0x1E:0x20] = (0x0009).to_bytes(2, "little")
    # mini sector size = 64 (2^6)
    hdr[0x20:0x22] = (0x0006).to_bytes(2, "little")
    seeds["cdf_minimal_validish.bin"] = bytes(hdr) + b"\x00" * 1024

    # 3) Truncated header. Good for boundary and short-read behavior.
    seeds["cdf_truncated.bin"] = bytes.fromhex("D0CF11E0A1B11AE1")

    # 4) Header with inconsistent/"weird" sector sizes to nudge parsers
    #    down less-tested error paths.
    weird = bytearray(512)
    weird[0:8] = bytes.fromhex("D0CF11E0A1B11AE1")
    weird[0x1E:0x20] = (0x0002).to_bytes(2, "little")  # nonsensical sector size
    weird[0x20:0x22] = (0x0001).to_bytes(2, "little")
    seeds["cdf_weird_sector_sizes.bin"] = bytes(weird)

    # 5) Extra tiny seed: header + a few bytes of non-zero data.
    seeds["seed_cdf_minimal.bin"] = bytes.fromhex("D0CF11E0A1B11AE1") + b"\x01\x00\x00\x00"

    count = 0
    for name, data in seeds.items():
        try:
            (seeds_dir / name).write_bytes(data)
            count += 1
        except Exception:
            continue
    return count


def _prepare_cdf_seeds(out: Path) -> int:
    """Create <out>/seeds_cdf and populate it with synthesized CDF seeds.

    This is currently only invoked from the AFG + CLI harness path so that
    libmagic-style CDF parsing gets an additional corpus alongside seeds_cli.
    """
    seeds_dir = (out / "seeds_cdf").resolve()
    seeds_dir.mkdir(parents=True, exist_ok=True)
    return _synthesize_cdf_seeds(seeds_dir)


def _write_seeds_files(spec: dict, out_dir: Path, app_name: str) -> tuple[bool, str, Path]:
    """
    Decode and write seed files under <out_dir>/seeds/<app_name>/.
    Supports encodings: hex | base64 | utf8
    """
    import base64, binascii
    seeds = spec.get("seeds", [])
    target = (out_dir / "seeds" / app_name).resolve()
    target.mkdir(parents=True, exist_ok=True)
    for s in seeds:
        fn = s.get("filename") or "seed.bin"
        enc = (s.get("encoding") or "hex").lower()
        content = s.get("content") or ""
        data = b""
        try:
            if enc == "hex":
                data = binascii.unhexlify(content.strip().replace(" ", ""))
            elif enc == "base64":
                data = base64.b64decode(content)
            elif enc == "utf8":
                data = content.encode("utf-8", "ignore")
            else:
                return False, f"unsupported encoding: {enc}", target
        except Exception as e:
            return False, f"failed to decode {fn}: {e}", target
        (target / fn).write_bytes(data)
    return True, "ok", target


def _canonicalize_driver_filename(spec: dict) -> None:
    lang = (spec.get("language") or "").strip().lower()
    spec["driver_filename"] = "fuzz_driver.cc" if lang == "c++" else "fuzz_driver.c"


def _persist_driver_spec(spec: dict, path: Path) -> None:
    _canonicalize_driver_filename(spec)
    path.write_text(json.dumps(spec, indent=2), encoding="utf-8")


def _maybe_generate_seeds(root: Path, out: Path, *, llm_cmd: str | None, model: str | None = None, api_base: str | None = None, max_attempts: int = 3) -> int:
    """
    Build seeds prompt (using vulnerabilities.json + DriverSpec), ask LLM for SeedsSpec (10 seeds),
    validate, decode, and write to out/seeds/<app>.
    Poller-provided inputs are intentionally ignored for now; seeds always come from vulnerabilities.json guidance.
    """

    app_name = root.name
    seeds_target = (out / "seeds" / app_name).resolve()
    seeds_target.mkdir(parents=True, exist_ok=True)

    # NOTE: Poller input reuse is disabled so that the tool always generates fresh seeds from
    # vulnerabilities.json context. The previous logic that copied inputs from root/poller can be
    # restored later if we decide to re-enable that behavior.
    prompt = build_seeds_prompt(root, out)
    if not prompt:
        print("[rf2] Seeds: prerequisites missing (no driver/spec or no context). Skipping.")
        return 0

    out_spec = (out / "seeds" / "spec.json").resolve()
    out_spec.parent.mkdir(parents=True, exist_ok=True)

    last_err = "unknown error"
    spec: dict | None = None
    for attempt in range(1, max_attempts + 1):
        ok, msg = run_llm_seeds_spec(prompt, out_spec, llm_cmd=llm_cmd, model=model, api_base=api_base)
        if not ok:
            last_err = f"LLM failed: {msg}"
            print(f"[rf2] Seeds: LLM failed (attempt {attempt}/{max_attempts}): {msg}")
            continue

        # Parse SeedsSpec JSON
        try:
            spec_text = out_spec.read_text(encoding="utf-8")
            spec = json.loads(spec_text)
        except Exception as e:
            last_err = f"failed to parse JSON: {e}"
            print(f"[rf2] Seeds: failed to parse JSON (attempt {attempt}/{max_attempts}): {e}")
            # Leave the raw text around for debugging.
            continue

        ok_spec, err = validate_seeds_spec(spec)
        if not ok_spec:
            last_err = f"validation failed: {err}"
            print(f"[rf2] Seeds: validation failed (attempt {attempt}/{max_attempts}): {err}")
            # Keep the invalid candidate for inspection.
            try:
                (out / "seeds" / f"spec.invalid.attempt{attempt}.json").write_text(
                    json.dumps(spec, indent=2), encoding="utf-8"
                )
            except Exception:
                pass
            continue

        # If we reach here, we have a valid spec; break the retry loop.
        break
    else:
        # Exhausted attempts
        print(f"[rf2] Seeds: giving up after {max_attempts} attempts; last error: {last_err}")
        return 3

    # Write seed files
    ok, wmsg, target = _write_seeds_files(spec, out, app_name)
    if not ok:
        print(f"[rf2] Seeds: write failed: {wmsg}")
        return 3
    print(f"[rf2] Seeds written: {target}")
    return 0


def _build_driver_fix_prompt(
    root: Path,
    out: Path,
    app_name: str,
    *,
    spec_path: Path,
    src_path: Path,
    original_prompt: Path | None = None,
) -> Path:
    """Construct a compile-fix prompt.

    The prompt always includes:
      - The last DriverSpec JSON
      - The current driver source
      - The compile errors (compile.log.txt)

    If *original_prompt* is provided (the main2fuzz/AFG prompt used for the
    initial DriverSpec), it is included as read-only context so that the
    model preserves the same high-level subsystem/protocol/API focus instead
    of drifting to an unrelated driver design.
    """
    out = out.resolve()
    lines: list[str] = []
    lines.append("You are given a DriverSpec JSON, the resulting driver source, compile errors, and (optionally) the original driver-generation prompt.")
    lines.append("Task: Output ONLY a corrected DriverSpec JSON (no code fences, no prose) that fixes compilation while:")
    lines.append("- Preserving the single-shot, deterministic driver behavior; and")
    lines.append("- Preserving the same high-level target: the same application subsystem / protocol / library and the same vulnerable or high-risk APIs/functions that the previous DriverSpec was exercising.")
    lines.append("")
    lines.append("Constraints:")
    lines.append("- Do NOT redesign the driver around a different subsystem or input format just to make it compile.")
    lines.append("- Do NOT change the intended functionality or semantics of the driver, or which logical APIs it exercises, beyond what is strictly required to satisfy the compiler.")
    lines.append("- Keep the language field unchanged (c or c++).")
    lines.append("- Keep the single-shot design: read stdin once; no servers/event loops/threads/sockets/sleeps/RNG/time usage.")
    lines.append("- Use minimal, safe fixes: adjust includes, correct function signatures, minimal state init/cleanup, tweak extra_sources/flags only as needed.")
    lines.append("- Do NOT depend on build system changes. You may only change fields inside the DriverSpec (includes, driver_source, defines/flags, extra_sources, lift_from_entry as strictly necessary).")
    lines.append("- Output must be a single JSON object conforming to the DriverSpec schema. No extra text.")
    lines.append("")

    # Previous DriverSpec and driver source
    try:
        spec_text = spec_path.read_text(encoding="utf-8")
    except Exception:
        spec_text = "{}"
    try:
        src_text = src_path.read_text(encoding="utf-8")
    except Exception:
        src_text = ""
    comp_log = out / "compile.log.txt"
    try:
        comp_text = comp_log.read_text(encoding="utf-8")
    except Exception:
        comp_text = ""

    lines.append("Previous DriverSpec JSON (verbatim):")
    lines.append(spec_text)
    lines.append("")
    lines.append("Generated driver source (verbatim):")
    lines.append(src_text)
    lines.append("")
    lines.append("Compile errors (verbatim):")
    lines.append(comp_text)
    lines.append("")

    # Optional: original main2fuzz/AFG prompt for additional context
    orig_prompt_text = ""
    if original_prompt is not None:
        try:
            orig_prompt_text = original_prompt.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            orig_prompt_text = ""
    if orig_prompt_text:
        lines.append("Original driver-generation prompt (context only, do NOT re-emit):")
        lines.append("""\
Use the following original prompt only as background context. You MUST:
- Keep targeting the same application subsystem / protocol / library.
- Keep focusing on the same vulnerable or high-risk APIs/call paths it
  described (for example, the same functions, files, or AFG nodes).
- NOT switch to an unrelated parser or subsystem just to satisfy the
  compiler. Make minimal changes that keep the original intent.
""")
        lines.append(orig_prompt_text)
        lines.append("")

    lines.append("Now output ONLY the corrected DriverSpec JSON.")
    prompt_path = out / "context" / "prompt.driver_fix.inline.md"
    prompt_path.parent.mkdir(parents=True, exist_ok=True)
    prompt_path.write_text("\n".join(lines), encoding="utf-8")
    return prompt_path


# -------------------- AFL++ fuzzing and crash replay helpers --------------------

def _ensure_seed_dir(seeds_dir: Path) -> None:
    seeds_dir.mkdir(parents=True, exist_ok=True)
    # Ensure at least one non-empty seed exists (AFL prefers >=1 byte)
    if not any(seeds_dir.iterdir()):
        (seeds_dir / "seed.bin").write_bytes(b"A")


def _collect_crash_files(afl_out: Path) -> list[Path]:
    crashes: list[Path] = []
    if not afl_out.exists():
        return crashes
    # AFL++ typically writes into <afl_out>/default/crashes/
    for p in sorted(afl_out.rglob("*")):
        if p.is_file() and p.parent.name == "crashes" and p.name.startswith("id:"):
            crashes.append(p)
    return crashes


def _run_cmd(cmd: str, cwd: Path | None = None, timeout: int | None = None) -> tuple[int, str, str]:
    import subprocess
    p = subprocess.run(cmd, shell=True, cwd=str(cwd) if cwd else None, text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def _replay_crash(binary: Path, crash_file: Path, *, timeout_sec: int = 15) -> tuple[int, str, str]:
    """
    Feed crash file into the harness via stdin and capture output.
    """
    data = b""
    try:
        data = crash_file.read_bytes()
    except Exception:
        pass
    import subprocess
    try:
        p = subprocess.run([str(binary)], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout_sec)
        rc = p.returncode
        so = p.stdout.decode("utf-8", "ignore")
        se = p.stderr.decode("utf-8", "ignore")
        return rc, so, se
    except subprocess.TimeoutExpired as e:
        return 124, "", f"timeout after {timeout_sec}s"
    except Exception as e:
        return 1, "", f"exec failed: {e}"


def _seed_causes_crash_or_timeout(binary: Path, seed_file: Path, *, timeout_sec: int = 2) -> bool:
    """
    Return True if executing the harness with this seed via stdin immediately crashes or times out.
    """
    rc, _, _ = _replay_crash(binary, seed_file, timeout_sec=timeout_sec)
    # Consider any non-zero exit as crash; timeout (124) is non-zero and thus a bad seed too
    return rc != 0


def _filter_bad_seeds(binary: Path, seeds_dir: Path, *, timeout_sec: int = 2) -> tuple[int, int, Path]:
    """
    Scan seeds_dir and move any crashing/timeout seeds to a _rejected subfolder so AFL won't use them.
    Returns (kept, rejected, rejected_dir).

    This is intended for the main AFL harness, where we want to avoid
    any seeds that immediately crash or hang the driver.
    """
    rejected_dir = seeds_dir.parent / (seeds_dir.name + "_rejected")
    rejected_dir.mkdir(parents=True, exist_ok=True)
    kept = 0
    rejected = 0
    for p in sorted(seeds_dir.iterdir()):
        if not p.is_file():
            continue
        try:
            if _seed_causes_crash_or_timeout(binary, p, timeout_sec=timeout_sec):
                # Move to rejected
                dest = rejected_dir / p.name
                try:
                    dest.write_bytes(p.read_bytes())
                except Exception:
                    pass
                try:
                    p.unlink(missing_ok=True)  # type: ignore[arg-type]
                except Exception:
                    pass
                rejected += 1
            else:
                kept += 1
        except Exception:
            # On unexpected errors, err on the side of rejecting to avoid AFL startup failures
            dest = rejected_dir / p.name
            try:
                dest.write_bytes(p.read_bytes())
            except Exception:
                pass
            try:
                p.unlink(missing_ok=True)  # type: ignore[arg-type]
            except Exception:
                pass
            rejected += 1
    # Ensure at least one minimal non-crashing seed exists
    if kept == 0:
        # Create a tiny placeholder and test once
        placeholder = seeds_dir / "seed_min.bin"
        try:
            placeholder.write_bytes(b"RF")
        except Exception:
            pass
        if _seed_causes_crash_or_timeout(binary, placeholder, timeout_sec=timeout_sec):
            # If even placeholder crashes, replace with a single byte to avoid empty corpus
            try:
                placeholder.write_bytes(b"A")
            except Exception:
                pass
        else:
            kept = 1
    return kept, rejected, rejected_dir


def _filter_timeout_seeds_only(binary: Path, seeds_dir: Path, *, timeout_sec: int = 2) -> tuple[int, int, Path]:
    """
    CLI-specific variant: scan seeds_dir and move only timeout-inducing seeds
    to a _timeout subfolder.

    Important: the CLI harness is typically invoked by AFL as:
        ./fuzz_driver_cli @@ /dev/null
    so we must mimic that invocation style here (pass the seed path as argv[1]
    and "/dev/null" as argv[2]) instead of feeding the seed via stdin. This
    makes the timeout check consistent with the actual fuzzing campaign.

    Non-zero exit codes that return quickly are tolerated so that strict CLI
    exit-status semantics (e.g., usage errors) don't wipe out the seed corpus.

    Returns (kept, rejected, rejected_dir).
    """
    import subprocess

    rejected_dir = seeds_dir.parent / (seeds_dir.name + "_timeout")
    rejected_dir.mkdir(parents=True, exist_ok=True)
    kept = 0
    rejected = 0
    for p in sorted(seeds_dir.iterdir()):
        if not p.is_file():
            continue
        try:
            # Mimic AFL invocation: binary <seed_path> /dev/null
            args = [str(binary), str(p), "/dev/null"]
            try:
                subprocess.run(
                    args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=timeout_sec,
                )
                # Completed within timeout: keep, regardless of exit code
                kept += 1
            except subprocess.TimeoutExpired:
                # Hard timeout: move seed aside so AFL won't abort on it
                dest = rejected_dir / p.name
                try:
                    dest.write_bytes(p.read_bytes())
                except Exception:
                    pass
                try:
                    p.unlink(missing_ok=True)  # type: ignore[arg-type]
                except Exception:
                    pass
                rejected += 1
        except Exception:
            # On unexpected errors, keep the seed but log via caller if needed
            kept += 1
    return kept, rejected, rejected_dir


def _postprocess_crashes(binary: Path, afl_out: Path, report_path: Path) -> int:
    crashes = _collect_crash_files(afl_out)
    lines: list[str] = []
    lines.append(f"Crash replay report for: {binary}")
    lines.append(f"Total crashes found: {len(crashes)}")
    lines.append("")
    for i, cf in enumerate(crashes, 1):
        size = cf.stat().st_size if cf.exists() else -1
        rc, so, se = _replay_crash(binary, cf)
        lines.append(f"=== Crash {i} ===")
        lines.append(f"file: {cf}")
        lines.append(f"bytes: {size}")
        lines.append(f"exit_code: {rc}")
        if so.strip():
            lines.append("--- stdout ---")
            lines.append(so.strip()[:4000])
        if se.strip():
            lines.append("--- stderr ---")
            lines.append(se.strip()[:8000])
        lines.append("")
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return len(crashes)


def _run_afl_fuzz(binary: Path, seeds_dir: Path, afl_out: Path, *, hours: int = 5, afl_bin: str | None = None, workdir: Path | None = None) -> tuple[bool, str]:
    """
    Launch afl-fuzz with a wall-time limit (default 5h). AFL will pipe inputs to stdin.
    """
    _ensure_seed_dir(seeds_dir)
    afl_out.mkdir(parents=True, exist_ok=True)
    afl = afl_bin or "afl-fuzz"
    # Use external timeout to cap runtime; AFL pipes input to stdin when no @@ is present
    cmd = f'timeout {hours}h {afl} -i "{seeds_dir}" -o "{afl_out}" -- "{binary}"'
    try:
        rc, so, se = _run_cmd(cmd, cwd=workdir)
    except Exception as e:
        return False, f"failed to run afl-fuzz: {e}"
    log = afl_out / "afl_fuzz.log.txt"
    log.write_text(f"CMD:\n{cmd}\n\nEXIT: {rc}\n\nSTDOUT:\n{so}\n\nSTDERR:\n{se}\n", encoding="utf-8")
    # timeout returns 124 on timeout, but we still consider it okay; AFL returns 0 on normal stop
    ok = rc in (0, 124)
    return ok, f"afl-fuzz finished (rc={rc}); log: {log}"


def _find_bundled_driver() -> Optional[Path]:
    """Locate a bundled fallback driver under reachforge/drivers/.

    Preference order:
      - Any file named fuzz_driver.* with a known C/C++ extension.
      - Otherwise, any C/C++ file under the drivers directory.
      - If multiple candidates exist, return the lexicographically first path
        for determinism.
    """
    here = Path(__file__).parent
    drv_dir = here / "drivers"
    if not drv_dir.exists() or not drv_dir.is_dir():
        return None

    candidates: list[Path] = []
    for p in sorted(drv_dir.iterdir()):
        if p.is_file() and p.suffix.lower() in FALLBACK_DRIVER_EXTS:
            candidates.append(p)
    if not candidates:
        return None

    for p in candidates:
        if p.name.startswith("fuzz_driver"):
            return p
    return candidates[0]


def _run_fallback_driver_pipeline(
    root: Path,
    out: Path,
    workdir: Path,
    *,
    seeds_llm_cmd: str | None,
    seeds_model: str | None,
    seeds_api_base: str | None,
    generate_seeds: bool,
    seeds_max_attempts: int,
) -> int:
    """Fallback used when we cannot build a source-based prompt.

    Uses a bundled driver under reachforge/drivers/, compiles it for the target
    app, and optionally generates seeds using vulnerabilities.json guidance
    together with the driver source embedded in a synthetic DriverSpec.
    """
    app_name = root.name
    src_template = _find_bundled_driver()
    if src_template is None:
        print("[rf2] Error: no bundled fallback driver found under reachforge/drivers/.")
        return 2

    driver_dir = out / "drivers" / app_name
    driver_dir.mkdir(parents=True, exist_ok=True)
    driver_src = driver_dir / src_template.name
    try:
        shutil.copy2(src_template, driver_src)
        print(f"[rf2] Fallback driver copied to: {driver_src}")
    except Exception as e:
        print(f"[rf2] Error: failed to copy fallback driver: {e}")
        return 2

    # Compile fallback driver
    binary_path = driver_dir / driver_src.stem
    ok, cmsg = compile_driver(
        app_root=root,
        app_name=app_name,
        src_path=driver_src,
        binary_path=binary_path,
        out_dir=out,
        workdir=workdir,
        extra_sources=None,
    )
    print(f"[rf2] Fallback compile: {cmsg}")
    if not ok:
        return 4

    # Create a minimal DriverSpec so the seeds pipeline can run
    try:
        driver_source_text = driver_src.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        driver_source_text = ""

    spec = {
        "driver_filename": driver_src.name,
        "language": "c" if driver_src.suffix.lower() == ".c" else "c++",
        "includes": [],
        "driver_source": driver_source_text,
        "required_link_libs": [],
    }
    ok_spec, err = validate_driver_spec(spec)
    if not ok_spec:
        print(f"[rf2] Warning: synthetic DriverSpec for fallback driver failed validation: {err}")

    specs_dir = out / "specs"
    specs_dir.mkdir(parents=True, exist_ok=True)
    (specs_dir / "driver_spec.json").write_text(json.dumps(spec, indent=2), encoding="utf-8")

    if generate_seeds:
        rc = _maybe_generate_seeds(
            root,
            out,
            llm_cmd=seeds_llm_cmd,
            model=seeds_model,
            api_base=seeds_api_base,
            max_attempts=seeds_max_attempts,
        )
        if rc != 0:
            return rc

    # For fallback we stop after compile + seeds, as requested.
    print(f"[rf2] Fallback pipeline complete: binary={binary_path}")
    return 0


def cmd_main2fuzz(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    out = Path(args.out).resolve() if args.out else root / "reachforge2_out"
    workdir = Path(args.workdir).resolve() if args.workdir else root
    driver_llm_cmd = getattr(args, "driver_llm_cmd", None) or getattr(args, "llm_cmd", None)
    seeds_llm_cmd = getattr(args, "seeds_llm_cmd", None) or getattr(args, "llm_cmd", None)
    driver_model = getattr(args, "driver_model", None) or getattr(args, "model", None)
    driver_api_base = getattr(args, "driver_api_base", None) or getattr(args, "api_base", None)
    seeds_model = getattr(args, "seeds_model", None)
    seeds_api_base = getattr(args, "seeds_api_base", None)

    _ensure_dir(out)

    # 0) If using AFG, optionally compile existing cli.cpp harness and seeds_cli first
    if getattr(args, "use_afg", False):
        cli_src = _find_cli_harness(root)
        if cli_src is not None:
            driver_dir = out / "drivers" / root.name
            driver_dir.mkdir(parents=True, exist_ok=True)
            cli_dst = driver_dir / "cli.cpp"
            try:
                shutil.copy2(cli_src, cli_dst)
                print(f"[rf2] CLI harness copied to driver dir: {cli_dst}")
            except Exception as e:
                print(f"[rf2] Warning: failed to copy cli.cpp into driver dir: {e}; skipping CLI harness compile.")
            else:
                cli_binary = driver_dir / "fuzz_driver_cli"
                ok_cli, msg_cli = compile_driver(
                    app_root=root,
                    app_name=root.name,
                    src_path=cli_dst,
                    binary_path=cli_binary,
                    out_dir=out,
                    workdir=workdir,
                    extra_sources=None,
                )
                print(f"[rf2] CLI harness compile: {msg_cli}")
                if ok_cli:
                    n_cli_seeds = _collect_cli_seeds_from_poller(root, out)
                    seeds_cli_dir = (out / "seeds_cli").resolve()
                    print(f"[rf2] CLI seeds from poller: {n_cli_seeds} files -> {seeds_cli_dir}")
                    # Pre-screen CLI seeds to drop only timeout-inducing inputs before fuzzing.
                    # CLI tools often use non-zero exit codes for normal error reporting, so we
                    # only treat hard timeouts as bad here.
                    try:
                        if seeds_cli_dir.exists():
                            kept_cli, rejected_cli, rej_cli_dir = _filter_timeout_seeds_only(
                                cli_binary,
                                seeds_cli_dir,
                                timeout_sec=1,
                            )
                            print(
                                f"[rf2] CLI timeout prescreen: kept={kept_cli}, "
                                f"rejected={rejected_cli}, rejected_dir={rej_cli_dir}"
                            )
                    except Exception as e:
                        print(f"[rf2] Warning: CLI timeout prescreen failed: {e}")

                    # In AFG + CLI mode, also synthesize CDF-style seeds that
                    # help exercise libmagic-like CDF parsing behavior.
                    try:
                        n_cdf = _prepare_cdf_seeds(out)
                        seeds_cdf_dir = (out / "seeds_cdf").resolve()
                        print(f"[rf2] CDF seeds synthesized: {n_cdf} files -> {seeds_cdf_dir}")
                    except Exception as e:
                        print(f"[rf2] Warning: CDF seed synthesis failed: {e}")
                else:
                    print("[rf2] Warning: CLI harness compile failed; continuing with main driver only.")

    # 1) Build prompt (either classic main2fuzz or AFG-augmented, based on flag)
    if getattr(args, "use_afg", False):
        afg_path = build_afg(root, out)
        prompt_path = build_afg_prompt(root, out, afg_path)
    else:
        prompt_path = build_main2fuzz_prompt(root, out, include_vulns=getattr(args, "include_vulns", True))
    if not prompt_path:
        print("[rf2] Warning: failed to build main2fuzz prompt from sources; falling back to bundled driver.")
        seeds_max_attempts = int(getattr(args, "seeds_max_attempts", 3))
        return _run_fallback_driver_pipeline(
            root,
            out,
            workdir,
            seeds_llm_cmd=seeds_llm_cmd,
            seeds_model=seeds_model,
            seeds_api_base=seeds_api_base,
            generate_seeds=getattr(args, "generate_seeds", True),
            seeds_max_attempts=seeds_max_attempts,
        )
    # Schema file (informational)
    write_schema_file(out / "schemas" / "driver_spec.schema.json")
    print(f"[rf2] Prompt: {prompt_path}")

    # 2) Run LLM to produce DriverSpec JSON
    out_spec = out / "specs" / "driver_spec.json"
    ok, msg = run_llm_driver_spec(prompt_path, out_spec, llm_cmd=driver_llm_cmd, model=driver_model, api_base=driver_api_base)
    if not ok:
        print(f"[rf2] LLM failed: {msg}")
        return 3
    print(f"[rf2] DriverSpec: {out_spec}")

    # 3) Load and validate spec
    try:
        spec = json.loads(out_spec.read_text(encoding="utf-8"))
        _canonicalize_driver_filename(spec)
    except Exception as e:
        print(f"[rf2] Error: failed to parse DriverSpec JSON: {e}")
        return 3
    ok, err = validate_driver_spec(spec)
    if not ok:
        print(f"[rf2] DriverSpec validation failed: {err}")
        return 3
    _persist_driver_spec(spec, out_spec)

    # 4) Generate driver source file
    app_name = root.name
    ok, gmsg, src_path = write_driver_from_spec(spec, out, app_name=app_name, root=root)
    if not ok:
        print(f"[rf2] Driver generation failed: {gmsg}")
        return 3

    # Ensure binary name stays consistent even if the LLM attempted to change it
    spec["driver_filename"] = "fuzz_driver.cc" if src_path.suffix == ".cc" else "fuzz_driver.c"
    src_path = src_path.parent / spec["driver_filename"]
    src_path.write_text(src_path.read_text(encoding="utf-8"), encoding="utf-8")
    print(f"[rf2] Driver source: {src_path}")

    # 5) Compile using existing compile templates
    # Binary path is drivers/<app>/fuzz_driver (use driver_filename without extension)
    driver_filename = spec.get("driver_filename", "fuzz_driver.c")
    base = Path(driver_filename).stem
    binary_path = src_path.parent / base
    ok, cmsg = compile_driver(app_root=root, app_name=app_name, src_path=src_path, binary_path=binary_path, out_dir=out, workdir=workdir, extra_sources=spec.get("extra_sources"))
    print(f"[rf2] Compile: {cmsg}")
    if not ok:
        # Auto-fix missing symbols by adding extra_sources before LLM retry
        fixed = False
        extras_set = set(spec.get("extra_sources") or [])
        if _auto_fix_missing_sources(root, out, extras_set):
            spec["extra_sources"] = sorted(extras_set)
            (out / "specs" / "driver_spec.json").write_text(json.dumps(spec, indent=2), encoding="utf-8")
            ok, cmsg = compile_driver(app_root=root, app_name=app_name, src_path=src_path, binary_path=binary_path, out_dir=out, workdir=workdir, extra_sources=spec.get("extra_sources"))
            print(f"[rf2] Auto-fix compile: {cmsg}")
            if ok:
                fixed = True
        if not fixed:
            # Try lifting helper functions directly from the entry file
            lift_set = set(spec.get("lift_from_entry") or [])
            if _auto_lift_from_entry(root, out, lift_set):
                spec["lift_from_entry"] = sorted(lift_set)
                (out / "specs" / "driver_spec.json").write_text(json.dumps(spec, indent=2), encoding="utf-8")
                ok_g2, gmsg2, src_path2 = write_driver_from_spec(spec, out, app_name=app_name, root=root)
                if ok_g2:
                    ok2, cmsg_lift = compile_driver(app_root=root, app_name=app_name, src_path=src_path2, binary_path=binary_path, out_dir=out, workdir=workdir, extra_sources=spec.get("extra_sources"))
                    print(f"[rf2] Auto-lift compile: {cmsg_lift}")
                    if ok2:
                        fixed = True
                        src_path = src_path2

        if not fixed:
            # Integrated retry loop
            max_attempts = int(getattr(args, "max_attempts", 2))
            last_ok = False
            last_src = src_path
            for attempt in range(1, max_attempts + 1):
                print(f"[rf2] Retry attempt {attempt}/{max_attempts} ...")
                prompt_fix = _build_driver_fix_prompt(
                    root,
                    out,
                    app_name,
                    spec_path=out / "specs" / "driver_spec.json",
                    src_path=last_src,
                    original_prompt=prompt_path,
                )
                retry_spec_path = out / "specs" / f"driver_spec.retry{attempt}.json"
                ok_llm, msg_llm = run_llm_driver_spec(prompt_fix, retry_spec_path, llm_cmd=driver_llm_cmd, model=driver_model, api_base=driver_api_base)
                if not ok_llm:
                    print(f"[rf2] Retry LLM failed: {msg_llm}")
                    continue
                # Load and validate corrected spec
                try:
                    spec_retry = json.loads(retry_spec_path.read_text(encoding="utf-8"))
                except Exception as e:
                    print(f"[rf2] Retry failed to parse DriverSpec: {e}")
                    continue
                ok_v, err_v = validate_driver_spec(spec_retry)
                if not ok_v:
                    print(f"[rf2] Retry DriverSpec validation failed: {err_v}")
                    continue
                # Write driver and compile again
                ok_g, gmsg, new_src = write_driver_from_spec(spec_retry, out, app_name=app_name, root=root)
                if not ok_g:
                    print(f"[rf2] Retry driver generation failed: {gmsg}")
                    continue
                last_src = new_src
                # Recompute binary path based on new driver filename
                new_base = Path(spec_retry.get("driver_filename") or "fuzz_driver.c").stem
                new_bin = new_src.parent / new_base
                ok_c, cmsg2 = compile_driver(app_root=root, app_name=app_name, src_path=new_src, binary_path=new_bin, out_dir=out, workdir=workdir, extra_sources=spec_retry.get("extra_sources"))
                print(f"[rf2] Retry compile: {cmsg2}")
                if ok_c:
                    # Persist the successful spec as the current driver_spec.json for seed stage
                    (out / "specs" / "driver_spec.json").write_text(json.dumps(spec_retry, indent=2), encoding="utf-8")
                    src_path = new_src
                    binary_path = new_bin
                    last_ok = True
                    break
            if not last_ok:
                return 4

    # 6) Seeds generation (default: enabled; disable with --no-generate-seeds)
    if getattr(args, "generate_seeds", True):
        if not getattr(args, "use_afg", False):
            # Copy poller seeds into seeds/<app>/ instead of seeds_cli/
            seeds_dir = (out / "seeds" / root.name)
            seeds_dir.mkdir(parents=True, exist_ok=True)
            # Manually copy from poller into seeds/app
            n_cli_seeds = 0
            for p in sorted((root / "poller").rglob("*")):
                if p.is_file() and not p.name.lower().endswith((".py", ".pyc", ".pyo", ".log", ".tmp",".poller",".bmp",".jpg",".gif",".jp2",".png",".tiff")):
                    dest = seeds_dir / p.name
                    try:
                        shutil.copy2(p, dest)
                        n_cli_seeds += 1
                    except Exception:
                        pass
            print(f"[rf2] Non-AFG poller seeds copied into seeds/{root.name}: {n_cli_seeds}")
        else:
            # Restore original AFG behavior using LLM-generated seeds
            seeds_max_attempts = int(getattr(args, "seeds_max_attempts", 3))
            rc = _maybe_generate_seeds(
                root,
                out,
                llm_cmd=seeds_llm_cmd,
                model=seeds_model,
                api_base=seeds_api_base,
                max_attempts=seeds_max_attempts,
            )
            if rc != 0:
                return rc

    # 6.5) Create compatibility layout for downstream CI expecting fuzz-out structure
    try:
        app_name = root.name
        compat_bin = out / "fuzz_driver"
        if compat_bin.exists():
            try:
                compat_bin.unlink()
            except Exception:
                pass
        # Prefer symlink to the compiled binary; fallback to copy
        try:
            compat_bin.symlink_to(binary_path)
        except Exception:
            try:
                compat_bin.write_bytes(binary_path.read_bytes())
            except Exception:
                pass
        # Expose driver source at top-level for convenience (copy)
        try:
            driver_src_top = out / f"{binary_path.name}.c"
            if src_path.suffix:
                driver_src_top = out / f"{binary_path.name}{src_path.suffix}"
            driver_src_top.write_text(src_path.read_text(encoding="utf-8"), encoding="utf-8")
        except Exception:
            pass
        # Seeds -> afl_in
        afl_in = out / "afl_in"
        seeds_src = out / "seeds" / app_name
        if not seeds_src.exists():
            seeds_src = afl_in  # will be ensured below
        if afl_in.exists():
            try:
                import shutil as _sh
                if afl_in.is_symlink() or afl_in.is_file():
                    afl_in.unlink()
                elif afl_in.is_dir():
                    _sh.rmtree(afl_in)
            except Exception:
                pass
        try:
            afl_in.symlink_to(seeds_src)
        except Exception:
            # Fallback: copy tree
            try:
                import shutil as _sh
                _sh.copytree(seeds_src, afl_in)
            except Exception:
                pass
        _ensure_seed_dir(afl_in)
        # Ensure afl_out exists
        (out / "afl_out").mkdir(parents=True, exist_ok=True)
        # Note: Wrapper script for '@@' is no longer created; fuzz directly via stdin
        print(f"[rf2] CI compat: binary={compat_bin} seeds={afl_in} afl_out={out / 'afl_out'}")
    except Exception as e:
        print(f"[rf2] CI compat layout warning: {e}")

    # 7) Optional fuzzing stage with AFL++ (default: enabled unless --no-run-fuzz)
    if getattr(args, "run_fuzz", True):
        app_name = root.name
        seeds_dir = out / "afl_in"  # use compat path so downstream jobs align
        # Pre-screen seeds: remove any that crash or time out to allow AFL startup
        kept, rejected, rej_dir = _filter_bad_seeds(binary_path, seeds_dir, timeout_sec=2)
        print(f"[rf2] Seeds prescreen: kept={kept}, rejected={rejected}, rejected_dir={rej_dir}")
        afl_out_dir = Path(getattr(args, "afl_out", "")) if getattr(args, "afl_out", None) else (out / "afl_out")
        hours = int(getattr(args, "fuzz_hours", 5))
        afl_bin = getattr(args, "afl_bin", None)
        ok_fz, msg_fz = _run_afl_fuzz(binary_path, seeds_dir, afl_out_dir, hours=hours, afl_bin=afl_bin, workdir=workdir)
        print(f"[rf2] Fuzz: {msg_fz}")
        # After fuzzing, replay crashes and write a consolidated report
        report = out / "crash_report.txt"
        n = _postprocess_crashes(binary_path, afl_out_dir, report)
        print(f"[rf2] Crash replay complete: {n} crashes -> {report}")

    return 0

def make_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reachforge2",
        description="ReachForge 2.0 - Source-first main-to-fuzz driver generator (new driver only, no source edits)",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    pm = sub.add_parser("main2fuzz", help="Build prompt from entrypoint, ask LLM for DriverSpec JSON, generate driver, compile")
    pm.add_argument("--root", type=str, required=True, help="Project root containing app/src or src")
    pm.add_argument("--out", type=str, required=False, help="Output directory (default: <root>/reachforge2_out)")
    pm.add_argument("--workdir", type=str, required=False, help="Working directory for compile command (default: project root)")
    pm.add_argument("--llm-cmd", type=str, required=False, help="Optional external LLM command template with placeholders {prompt} and {out_spec} (legacy, used if per-stage not provided)")
    pm.add_argument("--driver-llm-cmd", type=str, required=False, help="External LLM command for DRIVER agent; overrides --llm-cmd for driver stage")
    pm.add_argument("--seeds-llm-cmd", type=str, required=False, help="External LLM command for SEEDS agent; overrides --llm-cmd for seeds stage")
    pm.add_argument("--model", type=str, required=False, help="Default model (legacy fallback for driver stage)")
    pm.add_argument("--api-base", type=str, required=False, help="Default API base URL (legacy fallback for driver stage)")
    pm.add_argument("--driver-model", type=str, required=False, help="Model for DRIVER agent (fallback: --model, env, config)")
    pm.add_argument("--driver-api-base", type=str, required=False, help="API base for DRIVER agent (fallback: --api-base, env, config)")
    pm.add_argument("--seeds-model", type=str, required=False, help="Model for SEEDS agent (fallback: env/config)")
    pm.add_argument("--seeds-api-base", type=str, required=False, help="API base for SEEDS agent (fallback: env/config)")
    pm.add_argument("--include-vulns", dest="include_vulns", action="store_true", help="Include vulnerabilities.json context in the driver prompt")
    pm.add_argument("--no-include-vulns", dest="include_vulns", action="store_false", help="Do not include vulnerabilities.json context in the driver prompt")
    pm.add_argument("--use-afg", action="store_true", help="Use AFG information derived from vulnerabilities.json to guide fuzz driver generation")
    # Seed generation flags: enabled by default, can be disabled explicitly
    pm.add_argument("--generate-seeds", dest="generate_seeds", action="store_true", default=True, help="Enable seed generation (default: enabled)")
    pm.add_argument("--no-generate-seeds", dest="generate_seeds", action="store_false", help="Disable seed generation")
    pm.add_argument("--seeds-max-attempts", type=int, required=False, default=3, help="Max retry attempts to regenerate SeedsSpec on validation failure (default: 3)")
    pm.add_argument("--max-attempts", type=int, required=False, default=10, help="Max retry attempts to auto-fix compile errors inline")
    # Fuzzing stage controls
    pm.add_argument("--run-fuzz", dest="run_fuzz", action="store_true", default=True, help="Run AFL++ fuzzing after seeds (default: enabled)")
    pm.add_argument("--no-run-fuzz", dest="run_fuzz", action="store_false", help="Disable fuzzing stage")
    pm.add_argument("--fuzz-hours", type=int, required=False, default=5, help="Fuzzing time budget in hours (default: 5)")
    pm.add_argument("--afl-out", type=str, required=False, help="Directory for AFL++ output (default: <out>/afl_out)")
    pm.add_argument("--afl-bin", type=str, required=False, help="Path to afl-fuzz binary (default: afl-fuzz on PATH)")
    pm.set_defaults(func=cmd_main2fuzz, include_vulns=True)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
