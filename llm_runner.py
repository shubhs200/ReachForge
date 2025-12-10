from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Tuple
import os
import re
import tempfile


def _run_shell(cmd: str, cwd: Path) -> Tuple[int, str, str]:
    import subprocess
    p = subprocess.run(cmd, shell=True, cwd=str(cwd), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode, p.stdout, p.stderr

# Iterative retrieval helpers (internal)
ALLOWED_EXTS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"}
MAX_FILE_LINES = 400
MAX_BUNDLE_BYTES = 400 * 1024
MAX_ROUNDS = int(os.getenv("REACHFORGE2_MAX_ROUNDS", "4"))
FETCH_RE = re.compile(r'^\s*FETCH:\s*(?P<path>.+?)\s*$', re.IGNORECASE)


def _read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _clip_text(text: str, max_lines: int = MAX_FILE_LINES) -> str:
    lines = text.splitlines()
    if len(lines) > max_lines:
        return "\n".join(lines[:max_lines]) + "\n/* ... clipped ... */\n"
    return text


def _infer_root_from_prompt_path(prompt_path: Path) -> Path:
    # prompt typically at <root>/reachforge2_out/context/prompt.main2fuzz.md
    try:
        return prompt_path.parents[2]
    except Exception:
        return prompt_path.parent


def _choose_source_root(root: Path) -> Path:
    app_src = root / "app" / "src"
    src = root / "src"
    return app_src if app_src.exists() else (src if src.exists() else root)


def _list_sources(base: Path) -> list[Path]:
    files: list[Path] = []
    for p in sorted(base.rglob("*")):
        if p.is_file() and p.suffix.lower() in ALLOWED_EXTS:
            files.append(p)
    return files


def _build_index(base: Path, files: list[Path]) -> list[str]:
    rels: list[str] = []
    for p in files:
        try:
            rels.append(str(p.relative_to(base)))
        except Exception:
            rels.append(p.name)
    return rels


def _sanitize_fetch_path(req: str) -> Optional[str]:
    req = req.strip().lstrip("./")
    if not req:
        return None
    p = Path(req)
    if any(part == ".." for part in p.parts):
        return None
    if p.suffix.lower() not in ALLOWED_EXTS:
        return None
    return str(p.as_posix())


def _extract_fetches(text: str) -> list[str]:
    reqs: list[str] = []
    for line in text.splitlines():
        m = FETCH_RE.match(line)
        if m:
            path = m.group("path")
            sp = _sanitize_fetch_path(path)
            if sp:
                reqs.append(sp)
    # de-dup preserving order
    out: list[str] = []
    seen: set[str] = set()
    for r in reqs:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def _build_index_section(base: Path, files: list[str]) -> str:
    preview = "\n".join(f"- {p}" for p in files[:200])
    more = "" if len(files) <= 200 else f"... ({len(files) - 200} more omitted)"
    return "\n".join([
        "Available source files under project source root:",
        preview,
        more,
        "",
    ])


def _bundle_files(base: Path, requests: list[str]) -> str:
    chunks: list[str] = []
    total = 0
    for rel in requests:
        fp = (base / rel).resolve()
        try:
            fp.relative_to(base.resolve())
        except Exception:
            continue
        if not fp.exists() or not fp.is_file():
            continue
        content = _clip_text(_read_text(fp), MAX_FILE_LINES)
        block = f"// file: {rel}\n{content}\n"
        bbytes = len(block.encode("utf-8", errors="ignore"))
        if total + bbytes > MAX_BUNDLE_BYTES:
            break
        chunks.append(block)
        total += bbytes
    if not chunks:
        return ""
    return "\n".join([
        "Additional files (verbatim or clipped):",
        *chunks,
        "",
        "Now either request more files with FETCH lines, or output ONLY the final DriverSpec JSON.",
        "",
    ])


def _write_tmp_prompt(content: str) -> Path:
    fd, tmp = tempfile.mkstemp(prefix="rf2_iter_", suffix=".md")
    p = Path(tmp)
    try:
        Path(tmp).write_text(content, encoding="utf-8")
    finally:
        try:
            os.close(fd)
        except Exception:
            pass
    return p


def _is_json_object(s: str) -> bool:
    s2 = s.strip()
    if not (s2.startswith("{") and s2.endswith("}")):
        return False
    try:
        json.loads(s2)
        return True
    except Exception:
        return False


def _strip_code_fences(text: str) -> str:
    """
    Remove common code fences like ```json ... ``` or ``` ... ``` around content.
    Returns the inner content if a fenced block is detected, else returns original text.
    """
    s = text.strip()
    if s.startswith("```"):
        # Find first fence end
        first_newline = s.find("\n")
        if first_newline != -1:
            body = s[first_newline + 1 :]
            fence_end = body.rfind("```")
            if fence_end != -1:
                return body[:fence_end].strip()
    return s


def _extract_json_object(reply: str) -> str | None:
    """
    Best-effort extraction of a single JSON object from an LLM reply that might include
    prose, code fences, or trailing text. Strategy:
      1) Strip code fences if present and test for pure JSON.
      2) Scan the whole reply for the first balanced {...} block and validate as JSON.
      3) Attempt to repair common JSON issues (unterminated strings, trailing commas).
    Returns the JSON string if found, else None.
    """
    import re

    # 1) Strip code fences, try direct parse
    stripped = _strip_code_fences(reply)
    if _is_json_object(stripped):
        return stripped

    # 2) Balanced-brace scan for first JSON object
    s = reply
    start = -1
    depth = 0
    in_str = False
    esc = False
    for i, ch in enumerate(s):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        else:
            if ch == '"':
                in_str = True
                continue
            if ch == "{":
                if depth == 0:
                    start = i
                depth += 1
            elif ch == "}":
                if depth > 0:
                    depth -= 1
                    if depth == 0 and start != -1:
                        candidate = s[start : i + 1]
                        # Try to parse as JSON
                        try:
                            json.loads(candidate)
                            return candidate
                        except Exception:
                            # Attempt to repair common JSON issues
                            repaired = candidate
                            # Remove trailing commas before } or ]
                            repaired = re.sub(r',(\s*[}\]])', r'\1', repaired)
                            # Attempt to close unterminated strings (add a quote if odd number of quotes)
                            if repaired.count('"') % 2 == 1:
                                repaired += '"'
                            try:
                                json.loads(repaired)
                                return repaired
                            except Exception:
                                # Log the raw candidate for debugging
                                try:
                                    with open("llm_seeds_json_error.log", "w", encoding="utf-8") as f:
                                        f.write("Malformed JSON candidate:\n")
                                        f.write(candidate)
                                except Exception:
                                    pass
                                # Continue searching in case there is another block later
                                start = -1
    return None


def _initial_header() -> str:
    return "\n".join([
        "You are generating a DriverSpec JSON for a single-shot, deterministic fuzz driver.",
        "",
        "Decision rubric:",
        "- Prefer APIs that accept a memory buffer and length, or a FILE* path, and run once deterministically.",
        "- Do not introduce servers, event loops, threads, sockets, sleeps, RNG, or time-based behavior.",
        "- If the provided entrypoint is long-running or server-based, do not reproduce it; instead, identify and invoke the underlying library/handler APIs directly in a single shot.",
        "",
        "Retrieval protocol:",
        "- If you need more source files, reply ONLY with one or more lines of the form:",
        "  FETCH: relative/path.ext",
        "  FETCH: another/relative.hpp",
        "- Request only what you need. Do not include any other text.",
        "- When you have enough information, output ONLY the final DriverSpec JSON object (no code fences, no prose).",
        "",
    ])


def _run_iterative_openai_json(prompt_path: Path, out_spec: Path, *, model: str, api_base: Optional[str]) -> Tuple[bool, str]:
    """
    Iterative retrieval loop using a JSON-only LLM helper under the hood.
    Prefers the bundled adapter (reachforge4.llm_adapters.openai.run_openai_json),
    falling back to reachforge.llm_openai.run_openai_json if available.
    Builds an augmented prompt with a file index; serves FETCH: requests with clipped file contents.
    """
    try:
        from llm_adapters.openai import run_openai_json  # bundled
    except Exception:
        try:
            from reachforge.llm_adapters.openai import run_openai_json  # legacy fallback
        except Exception as e:
            return False, f"missing LLM adapter: {e}"

    prompt_path = prompt_path.resolve()
    out_spec = out_spec.resolve()
    out_spec.parent.mkdir(parents=True, exist_ok=True)
    ctx_dir = out_spec.parent

    root = _infer_root_from_prompt_path(prompt_path)
    base = _choose_source_root(root)
    files = _list_sources(base)
    index_list = _build_index(base, files)
    rf2_prompt = _read_text(prompt_path)

    content = "\n".join([
        _initial_header(),
        _build_index_section(base, index_list),
        "Context from tool (original prompt follows):",
        rf2_prompt,
        "",
        "If you need more files, reply with one or more FETCH lines as described above. Otherwise, output ONLY the DriverSpec JSON.",
        "",
    ])

    for round_idx in range(1, MAX_ROUNDS + 1):
        tmp_prompt = _write_tmp_prompt(content)
        tmp_out = ctx_dir / f"driver_spec.iter{round_idx}.json"

        ok, msg = run_openai_json(tmp_prompt, tmp_out, model=model, api_base=api_base)
        reply = ""
        if tmp_out.exists():
            try:
                reply = tmp_out.read_text(encoding="utf-8")
            except Exception:
                reply = ""
        else:
            # Provider did not write a file; record the status message for diagnosis
            try:
                (ctx_dir / f"driver_spec.iter{round_idx}.provider_error.txt").write_text(f"ok={ok}\nmsg={msg}\n", encoding="utf-8")
            except Exception:
                pass

        if ok and reply:
            # Accept pure JSON object replies
            if _is_json_object(reply):
                out_spec.write_text(reply, encoding="utf-8")
                return True, "ok"

            # Try to extract a JSON object from fenced or mixed replies
            extracted = _extract_json_object(reply)
            if extracted:
                out_spec.write_text(extracted, encoding="utf-8")
                # Write a debug snapshot for transparency
                try:
                    (ctx_dir / f"driver_spec.iter{round_idx}.extracted.json").write_text(extracted, encoding="utf-8")
                except Exception:
                    pass
                return True, "ok"

        # Parse FETCH requests from reply (stdout-equivalent file content)
        reqs = _extract_fetches(reply)
        if not reqs:
            # Append the reply for transparency and ask again
            content += "\n".join([
                f"\n(Model reply in round {round_idx} was not JSON and had no FETCH lines; showing reply below for transparency.)\n",
                reply,
                "\nPlease either request files with FETCH lines, or output ONLY the final DriverSpec JSON.\n",
            ])
            continue

        bundle = _bundle_files(base, reqs)
        if not bundle:
            content += "\n(No requested files could be served; please output ONLY the final DriverSpec JSON if possible.)\n"
            continue

        content += "\n" + bundle

    # Exhausted rounds without valid JSON
    (ctx_dir / "llm_iterate.log.txt").write_text(
        f"Exhausted rounds without DriverSpec JSON. Last prompt stored in temporary files.\n", encoding="utf-8"
    )
    return False, "exhausted retrieval rounds without valid JSON"


def _load_llm_config() -> dict:
    cfg_path = Path(__file__).parent / "config" / "llm.json"
    try:
        return json.loads(cfg_path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _resolve_model_api(purpose: str, model: Optional[str], api_base: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """
    Resolve model/api_base with precedence:
      1) Function params (CLI)
      2) Env vars (purpose-specific, then legacy)
      3) Config file reachforge4/config/llm.json
         - Supports legacy flat keys {model, api_base}
         - Or nested {driver: {model, api_base}, seeds: {...}, default: {...}}
    """
    # Params first
    eff_model = model
    eff_base = api_base

    # Env vars (purpose specific)
    env_map = {
        "driver": ("REACHFORGE4_DRIVER_MODEL", "REACHFORGE4_DRIVER_API_BASE"),
        "seeds": ("REACHFORGE4_SEEDS_MODEL", "REACHFORGE4_SEEDS_API_BASE"),
    }
    if purpose in env_map:
        mkey, bkey = env_map[purpose]
        eff_model = eff_model or os.getenv(mkey)
        eff_base = eff_base or os.getenv(bkey)

    # Legacy env fallback (reachforge2-style)
    eff_model = eff_model or os.getenv("REACHFORGE2_MODEL")
    eff_base = eff_base or os.getenv("REACHFORGE2_API_BASE")

    # Config file
    cfg = _load_llm_config()
    if cfg:
        # Nested per-purpose section or default/legacy
        section = cfg.get(purpose) if isinstance(cfg.get(purpose), dict) else None
        default = cfg.get("default") if isinstance(cfg.get("default"), dict) else None
        eff_model = eff_model or (section or {}).get("model") or (default or {}).get("model") or cfg.get("model")
        eff_base = eff_base or (section or {}).get("api_base") or (default or {}).get("api_base") or cfg.get("api_base")

    return eff_model, eff_base


def run_llm_driver_spec(prompt_path: Path, out_spec: Path, *, llm_cmd: Optional[str] = None, model: Optional[str] = None, api_base: Optional[str] = None) -> Tuple[bool, str]:
    """
    Execute the DRIVER agent to write a DriverSpec JSON at out_spec.

    Priority:
      - If llm_cmd is provided: it must contain {prompt} and {out_spec} placeholders.
      - Else: resolve driver-specific model/api_base via CLI/env/config.
    """
    prompt_path = prompt_path.resolve()
    out_spec = out_spec.resolve()
    out_spec.parent.mkdir(parents=True, exist_ok=True)

    if llm_cmd:
        cmd = llm_cmd.replace("{prompt}", str(prompt_path)).replace("{out_spec}", str(out_spec))
        rc, so, se = _run_shell(cmd, cwd=out_spec.parent)
        if rc != 0 or not out_spec.exists():
            log = out_spec.parent / "llm_driver_spec.log.txt"
            log.write_text(f"CMD: {cmd}\nEXIT: {rc}\n\nSTDOUT:\n{so}\n\nSTDERR:\n{se}\n", encoding="utf-8")
            return False, f"external LLM failed; see {log}"
        return True, "ok"

    eff_model, eff_base = _resolve_model_api("driver", model, api_base)
    if not eff_model:
        return False, "No driver LLM model configured. Use --driver-model or set REACHFORGE4_DRIVER_MODEL (or legacy REACHFORGE2_MODEL), or configure reachforge4/config/llm.json."

    # Use iterative retrieval by default for driver stage so the model can FETCH needed files
    ok, msg = _run_iterative_openai_json(prompt_path, out_spec, model=eff_model, api_base=eff_base)
    if not ok:
        return False, msg
    return True, "ok"


def run_llm_seeds_spec(prompt_path: Path, out_spec: Path, *, llm_cmd: Optional[str] = None, model: Optional[str] = None, api_base: Optional[str] = None) -> Tuple[bool, str]:
    """
    Execute the SEEDS agent to write a SeedsSpec JSON at out_spec.

    Priority:
      - If llm_cmd is provided: it must contain {prompt} and {out_spec} placeholders.
      - Else: resolve seeds-specific model/api_base via CLI/env/config.
    """
    prompt_path = prompt_path.resolve()
    out_spec = out_spec.resolve()
    out_spec.parent.mkdir(parents=True, exist_ok=True)

    if llm_cmd:
        cmd = llm_cmd.replace("{prompt}", str(prompt_path)).replace("{out_spec}", str(out_spec))
        rc, so, se = _run_shell(cmd, cwd=out_spec.parent)
        if rc != 0 or not out_spec.exists():
            log = out_spec.parent / "llm_seeds_spec.log.txt"
            log.write_text(f"CMD: {cmd}\nEXIT: {rc}\n\nSTDOUT:\n{so}\n\nSTDERR:\n{se}\n", encoding="utf-8")
            return False, f"external LLM failed; see {log}"
        return True, "ok"

    eff_model, eff_base = _resolve_model_api("seeds", model, api_base)
    if not eff_model:
        return False, "No seeds LLM model configured. Use --seeds-model or set REACHFORGE4_SEEDS_MODEL (or legacy REACHFORGE2_MODEL), or configure reachforge4/config/llm.json."

    try:
        from llm_adapters.openai import run_openai_json  # bundled
    except Exception:
        try:
            from reachforge.llm_adapters.openai import run_openai_json  # legacy fallback
        except Exception as e:
            return False, f"missing LLM adapter: {e}"

    ok, msg = run_openai_json(prompt_path, out_spec, model=eff_model, api_base=eff_base)
    if not ok:
        return False, msg
    return True, "ok"
