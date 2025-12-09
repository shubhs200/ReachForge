from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Tuple, List, Optional

from reachforge.schema import validate_driver_spec
from reachforge.source_index import find_entry_main_and_context


def _compose_includes(includes: list[str]) -> str:
    # Ensure includes (quoted or angled) appear at the top. Avoid duplicates.
    inc_lines: list[str] = []
    seen = set()
    for inc in includes or []:
        token = inc.strip()
        if not token:
            continue
        if token.startswith("<") or token.startswith("\""):
            line = f"#include {token}"
        else:
            # Default to quoted project-relative header
            line = f"#include \"{token}\""
        if line not in seen:
            seen.add(line)
            inc_lines.append(line)
    return "\n".join(inc_lines)


def _find_function_block(text: str, func_name: str) -> Optional[str]:
    """
    Extract a C/C++ function definition block by name from the given text.
    Uses a simple brace-balancing scan starting from the function header.
    """
    # Match start of a function definition for func_name (not a prototype)
    # Allow static/extern qualifiers, pointers/refs, templates, etc. Keep it permissive.
    header_re = re.compile(
        rf'^[^\n]*\b{re.escape(func_name)}\s*\([^;{{]*\)\s*\{{',
        re.M,
    )
    m = header_re.search(text)
    if not m:
        return None
    start = m.start()
    # Balance braces from the first opening '{' after header
    open_brace_idx = text.find("{", m.start())
    if open_brace_idx == -1:
        return None
    i = open_brace_idx
    depth = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                return text[start:end]
        i += 1
    return None


def _lift_functions_from_entry(root: Optional[Path], func_names: List[str]) -> str:
    """
    Using the project's entry context, extract function definitions by name from the entry file.
    Returns concatenated code blocks or empty string if none found.
    """
    if not root or not func_names:
        return ""
    try:
        ctx = find_entry_main_and_context(root)
    except Exception:
        ctx = None
    if not ctx:
        return ""

    entry_text = ctx.main_file.content
    lifted_blocks: list[str] = []
    seen: set[str] = set()
    for name in func_names:
        if not name or name in seen:
            continue
        block = _find_function_block(entry_text, name)
        if block:
            lifted_blocks.append(block)
            seen.add(name)
    return "\n\n".join(lifted_blocks)


def write_driver_from_spec(
    spec: Dict,
    out_dir: Path,
    app_name: str,
    *,
    root: Optional[Path] = None,
) -> Tuple[bool, str, Path]:
    """
    Validate a DriverSpec and write the driver source to:
      <out_dir>/drivers/<app_name>/<driver_filename>

    Supports optional fields:
      - includes: list[str]
      - driver_source: str
      - extra_sources: list[str]  (handled in compiler step)
      - lift_from_entry: list[str]  (names of functions to lift verbatim from entry file)

    Returns (ok, message, src_path).
    """
    ok, err = validate_driver_spec(spec)
    if not ok:
        return False, f"invalid DriverSpec: {err}", Path()

    driver_filename = (spec.get("driver_filename") or "").strip()
    language = (spec.get("language") or "").strip().lower()
    includes = spec.get("includes", [])
    driver_source = spec.get("driver_source", "")
    lift_names = spec.get("lift_from_entry", []) or []

    if not driver_filename:
        return False, "driver_filename is empty", Path()
    if language not in ("c", "c++"):
        return False, f"unsupported language: {language}", Path()

    # Compose final source: includes + lifted helper functions + driver_source
    inc_blob = _compose_includes(includes)
    lifted_blob = _lift_functions_from_entry(root, list(lift_names))

    parts: list[str] = []
    if inc_blob:
        parts.append(inc_blob)
    if lifted_blob:
        parts.append(lifted_blob)
    if driver_source:
        parts.append(driver_source)

    code = "\n\n".join(p for p in parts if p)

    out_dir = out_dir.resolve()
    target_dir = out_dir / "drivers" / app_name
    target_dir.mkdir(parents=True, exist_ok=True)
    src_path = target_dir / driver_filename
    src_path.write_text(code, encoding="utf-8")

    return True, "ok", src_path
