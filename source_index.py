from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


SRC_EXTS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"}


@dataclass
class FileSnippet:
    path: str
    content: str


@dataclass
class EntryContext:
    root: str
    main_file: FileSnippet
    aux_snippets: List[FileSnippet]
    notes: Dict[str, str]


def _choose_source_root(root: Path) -> Optional[Path]:
    app_src = root / "app" / "src"
    if app_src.exists():
        return app_src
    src = root / "src"
    if src.exists():
        return src
    return None


def _list_source_files(src_root: Path, max_files: int = 800) -> List[Path]:
    files: List[Path] = []
    for p in sorted(src_root.rglob("*")):
        if p.is_file() and p.suffix.lower() in SRC_EXTS:
            files.append(p)
            if len(files) >= max_files:
                break
    return files


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _has_main(text: str) -> bool:
    # Capture typical main signatures
    return bool(re.search(r"\bint\s+main\s*\(", text))


def _extract_includes(text: str) -> List[str]:
    incs: List[str] = []
    inc_re = re.compile(r'^\s*#\s*include\s+([<"].*[>"])', re.M)
    for m in inc_re.finditer(text):
        incs.append(m.group(1))
    return incs


def _clip(text: str, cap_lines: int = 260) -> str:
    lines = text.splitlines()
    if len(lines) > cap_lines:
        return "\\n".join(lines[:cap_lines]) + "\\n/* ... clipped ... */"
    return text


def _file_has_buffer_handler_signature(text: str) -> bool:
    """
    Heuristic: detect functions that likely accept a (buffer,len[, ...]) signature:
    looks for 'const unsigned char *' and 'size_t' within the same parameter list.
    """
    try:
        has_buf = re.search(r'\([^)]*const\s+unsigned\s+char\s*\*', text) is not None
        has_len = re.search(r'\([^)]*size_t', text) is not None
        return bool(has_buf and has_len)
    except Exception:
        return False


def find_entry_main_and_context(root: Path, *, aux_files_cap: int = 8, aux_clip_lines: int = 160) -> Optional[EntryContext]:
    """
    Locate the translation unit that defines int main(), and collect a small set of
    auxiliary snippets referenced by main (headers/sources) for LLM context.

    Returns an EntryContext with full main file content and a handful of auxiliary snippets.
    """
    root = root.resolve()
    src_root = _choose_source_root(root)
    if not src_root:
        return None

    files = _list_source_files(src_root, max_files=800)
    main_file: Optional[Path] = None
    main_text: Optional[str] = None

    # Scan all source files for the first file that defines int main().
    # Explicitly skip cli.cpp so that pre-existing CLI harnesses are not
    # treated as the application entrypoint.
    for p in files:
        if p.name == "cli.cpp":
            continue
        txt = _read_text(p)
        # Debug: print which file is being checked and if main is found
        # print(f"Checking {p}: {'FOUND main' if _has_main(txt) else 'no main'}")
        if _has_main(txt):
            main_file, main_text = p, txt
            break

    if main_file is None or not main_text:
        return None

    # Extract function definitions from entry file (excluding main) for potential lifting
    try:
        _entry_func_def_re = re.compile(r'^\s*[A-Za-z_][\w\s\*\:&\<\>\[\]]+\s+([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{', re.M)
        entry_funcs = [m.group(1) for m in _entry_func_def_re.finditer(main_text) if m.group(1) != "main"]
    except Exception:
        entry_funcs = []

    # Gather auxiliary includes from main
    incs = _extract_includes(main_text)
    # Normalize include tokens to plain paths (strip quotes/angles)
    norm_incs: List[str] = []
    for inc in incs:
        token = inc.strip()
        if token.startswith("<") and token.endswith(">"):
            token = token[1:-1]
        if token.startswith('"') and token.endswith('"'):
            token = token[1:-1]
        if token:
            norm_incs.append(token)

    # Resolve a handful of auxiliary files by searching the repo for the basenames
    aux_map: Dict[str, Path] = {}
    seen_base: set[str] = set()
    for inc in norm_incs:
        base = inc.split("/")[-1] if "/" in inc else inc
        if not base or base in seen_base:
            continue
        # Try to find a header/source that ends with this basename
        for p in files:
            if p.name == base:
                aux_map[base] = p
                break
        seen_base.add(base)
        if len(aux_map) >= aux_files_cap:
            break

    # Heuristic: if aux slots remain, add files that define buffer handlers (const unsigned char*, size_t)
    if len(aux_map) < aux_files_cap:
        for p in files:
            if p.name in aux_map:
                continue
            try:
                txt = _read_text(p)
            except Exception:
                continue
            if _file_has_buffer_handler_signature(txt):
                aux_map[p.name] = p
                if len(aux_map) >= aux_files_cap:
                    break

    # Compose snippets list (clip for token budget)
    aux_snippets: List[FileSnippet] = []
    for base, path in aux_map.items():
        try:
            txt = _clip(_read_text(path), cap_lines=aux_clip_lines)
            # prefer project-relative path where possible
            try:
                rel = path.relative_to(root)
                aux_snippets.append(FileSnippet(path=str(rel), content=txt))
            except Exception:
                aux_snippets.append(FileSnippet(path=str(path), content=txt))
        except Exception:
            continue

    # Build EntryContext
    try:
        rel_main = main_file.relative_to(root)
        main_label = str(rel_main)
    except Exception:
        main_label = str(main_file)

    ctx = EntryContext(
        root=str(root),
        main_file=FileSnippet(path=main_label, content=_clip(main_text, cap_lines=800)),
        aux_snippets=aux_snippets,
        notes={
            "source_root": str(src_root.relative_to(root)) if src_root.is_relative_to(root) else str(src_root),
            "file_count": str(len(files)),
            "aux_files_count": str(len(aux_snippets)),
            "entry_defined_funcs": json.dumps(entry_funcs),
        },
    )
    return ctx


# -------- Generic source summarization (for prompt context) --------

_FUNC_DEF_RE = re.compile(r'^\s*[A-Za-z_][\w\s\*\:&\<\>\[\]]+\s+([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{', re.M)
_FUNC_PROTO_RE = re.compile(r'^\s*[A-Za-z_][\w\s\*\:&\<\>\[\]]+\s+([A-Za-z_]\w*)\s*\([^;{]*\)\s*;', re.M)


def _summarize_file(rel_path: str, text: str, *, max_funcs: int = 16) -> str:
    """
    Summarize a single C/C++ source/header:
      - includes list
      - up to N function names (definitions or prototypes)
      - byte size
    """
    includes = _extract_includes(text)
    size_b = len(text.encode("utf-8", "ignore"))
    funcs: list[str] = []

    try:
        for m in _FUNC_DEF_RE.finditer(text):
            funcs.append(m.group(1))
            if len(funcs) >= max_funcs:
                break
        if len(funcs) < max_funcs:
            for m in _FUNC_PROTO_RE.finditer(text):
                name = m.group(1)
                if name not in funcs:
                    funcs.append(name)
                    if len(funcs) >= max_funcs:
                        break
    except Exception:
        pass

    inc_preview = ", ".join(includes[:8])
    func_preview = ", ".join(funcs[:max_funcs])
    return f"- {rel_path} (bytes={size_b}; includes=[{inc_preview}]; funcs=[{func_preview}])"


def build_source_summaries(root: Path, *, max_files: int = 800, max_funcs_per_file: int = 16) -> str:
    """
    Produce a compact, generic summary of all source files under app/src or src.
    The summary is textual and model-agnostic, suitable for inclusion in prompts.
    """
    root = root.resolve()
    src_root = _choose_source_root(root)
    if not src_root:
        return "No source root found."

    files = _list_source_files(src_root, max_files=max_files)
    lines: list[str] = []
    lines.append(f"All sources overview: {len(files)} files under {str(src_root.relative_to(root)) if src_root.is_relative_to(root) else str(src_root)}")
    for p in files:
        text = _read_text(p)
        try:
            rel = p.relative_to(root)
            rel_label = str(rel)
        except Exception:
            rel_label = str(p)
        lines.append(_summarize_file(rel_label, text, max_funcs=max_funcs_per_file))
    return "\n".join(lines)
