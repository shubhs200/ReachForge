from __future__ import annotations

import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class AFGNode:
    id: str
    kind: str  # e.g. "source", "api", "sink"
    label: str
    file: Optional[str] = None
    vulnerable: bool = False
    cve: Optional[str] = None
    cwe_id: Optional[str] = None
    cwe_name: Optional[str] = None
    # Optional enrichment from dependency headers
    header: Optional[str] = None  # resolved header path if found (e.g. crow/query_string.h)
    signature: Optional[str] = None  # short function signature preview for api nodes


@dataclass
class AFGEdge:
    src: str
    dst: str
    label: str


@dataclass
class AFG:
    name: str
    nodes: List[AFGNode]
    edges: List[AFGEdge]
    dictionary_tokens: List[str]
    # Optional multi-hop entrypoint->...->vuln paths from simple callgraph analysis
    call_paths: List[List[str]]
    # Optional API-flow graph snippets (functions + type-based edges) near vulnerable APIs
    api_flow_edges: List[Dict[str, str]]
    notes: str = ""


def _load_vulnerabilities(root: Path) -> Dict[str, Any]:
    """Best-effort load of vulnerabilities.json from root or app/.

    Returns a dict with a top-level "vulnerabilities" list, or {} on failure.
    """
    for candidate in [root / "vulnerabilities.json", root / "app" / "vulnerabilities.json"]:
        if candidate.exists():
            try:
                return json.loads(candidate.read_text(encoding="utf-8"))
            except Exception:
                return {}
    return {}


def _extract_vuln_fields(v: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """Normalize common vulnerability fields used for AFG construction."""
    # Function / symbol name
    func = (
        v.get("affected-function")
        or v.get("function")
        or v.get("symbol")
        or v.get("name")
    )
    # File path
    file = (
        v.get("affected-file")
        or v.get("file")
        or v.get("source_file")
    )
    cve = v.get("cve-id") or v.get("cve")
    cwe_id = v.get("cwe-id")
    cwe_name = v.get("cwe-name") or v.get("cwe_name")
    pkg = v.get("package-name") or v.get("package")

    return {
        "func": func,
        "file": file,
        "cve": cve,
        "cwe_id": cwe_id,
        "cwe_name": cwe_name,
        "package": pkg,
    }


# -------------------- Dependency include + signature enrichment --------------------

def _iter_dep_include_roots(root: Path) -> List[Path]:
    """Return possible dependency include roots under build/vcpkg_installed.

    This is intentionally generic: if build/vcpkg_installed/<triplet>/include
    exists, we treat those include dirs as search roots for vulnerable headers.
    """
    roots: List[Path] = []
    vcpkg_root = root / "build" / "vcpkg_installed"
    if not vcpkg_root.exists():
        return roots
    try:
        for sub in vcpkg_root.iterdir():
            inc = sub / "include"
            if inc.is_dir():
                roots.append(inc)
    except Exception:
        pass
    return roots


def _find_header_for_file(root: Path, file_basename: str) -> Optional[Path]:
    """Locate a header by basename under known dependency include roots.

    Returns the first matching path, or None if not found.
    """
    if not file_basename:
        return None
    for inc_root in _iter_dep_include_roots(root):
        try:
            for p in inc_root.rglob(file_basename):
                if p.is_file():
                    return p
        except Exception:
            continue
    return None


def _extract_signature_preview(header_text: str, func: str, max_len: int = 160) -> Optional[str]:
    """Extract a one-line signature-like preview for a function name from header text.

    This is a best-effort regex that looks for a line containing `func(` and
    returns the header up to the closing parenthesis. It is intentionally
    conservative and truncated for prompt-friendliness.
    """
    if not header_text or not func:
        return None
    try:
        pat = rf"[^\n]*\b{re.escape(func)}\s*\([^;{{\n]*\)"
        m = re.search(pat, header_text)
        if not m:
            return None
        sig = m.group(0).strip()
        if len(sig) > max_len:
            sig = sig[: max_len - 3] + "..."
        return sig
    except Exception:
        return None


# -------------------- Very simple callgraph extraction --------------------

_FUNC_DEF_RE = re.compile(r"^[\t ]*[A-Za-z_][\w\s:\*&<>]*\b([A-Za-z_]\w*)\s*\([^;]*\)\s*\{", re.M)
_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")


def _choose_source_roots(root: Path) -> List[Path]:
    """Choose roots to scan for functions when building a callgraph.

    Includes project sources under app/src, src, and the repository root,
    plus any dependency include trees under build/vcpkg_installed/*/include
    so that inline definitions in headers (e.g., crow/query_string.h) are
    visible to the naive callgraph.
    """
    bases: List[Path] = []
    for cand in [root / "app" / "src", root / "src", root]:
        if cand.exists():
            bases.append(cand)
    # Also scan dependency include roots (e.g., build/vcpkg_installed/.../include)
    for inc_root in _iter_dep_include_roots(root):
        if inc_root not in bases:
            bases.append(inc_root)
    return bases


def _list_source_files(root: Path, exts: Tuple[str, ...] = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")) -> List[Path]:
    files: List[Path] = []
    for base in _choose_source_roots(root):
        for p in base.rglob("*"):
            if p.is_file() and p.suffix.lower() in exts:
                files.append(p)
    return files


def _iter_function_bodies(text: str) -> List[Tuple[str, str]]:
    """Extract (function_name, body_text) pairs using a naive brace balancer.

    This is intentionally simple and best-effort; it will miss some C++ edge
    cases but is good enough to approximate call paths.
    """
    out: List[Tuple[str, str]] = []
    for m in _FUNC_DEF_RE.finditer(text):
        name = m.group(1)
        start = text.find("{", m.end() - 1)
        if start == -1:
            continue
        depth = 0
        i = start
        n = len(text)
        while i < n:
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    body = text[start:end]
                    out.append((name, body))
                    break
            i += 1
    return out


def _build_callgraph(root: Path) -> Tuple[Dict[str, List[str]], Dict[str, str]]:
    """Build a very simple function-level callgraph.

    Returns (adjacency, func_to_file_rel):
      - adjacency[f] = list of functions directly called from f
      - func_to_file_rel[f] = project-relative path of the file where f is defined

    This is best-effort and ignores function overloading, namespaces, etc.; it
    treats any token `foo(` inside a function body as a call to `foo`.
    """
    adj: Dict[str, List[str]] = {}
    func_file: Dict[str, str] = {}

    for p in _list_source_files(root):
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        try:
            rel = p.relative_to(root)
            rel_s = rel.as_posix()
        except Exception:
            rel_s = p.as_posix()

        for fname, body in _iter_function_bodies(text):
            func_file.setdefault(fname, rel_s)
            calls: List[str] = []
            for cm in _CALL_RE.finditer(body):
                callee = cm.group(1)
                # Skip obvious self-calls and keywords
                if callee == fname:
                    continue
                if callee in {"if", "for", "while", "switch", "return", "sizeof"}:
                    continue
                calls.append(callee)
            if calls:
                # Deduplicate while preserving order
                seen: set[str] = set()
                uniq_calls = [c for c in calls if not (c in seen or seen.add(c))]
                adj.setdefault(fname, []).extend(uniq_calls)
            else:
                adj.setdefault(fname, [])

    return adj, func_file


def _find_entry_functions(adj: Dict[str, List[str]]) -> List[str]:
    """Heuristically pick entry functions (currently: any function named 'main')."""
    return [name for name in adj.keys() if name == "main"]


def _find_call_paths(
    adj: Dict[str, List[str]],
    entries: List[str],
    target: str,
    max_depth: int = 8,
    max_paths: int = 4,
) -> List[List[str]]:
    """Find simple call paths from any entry function to target using BFS.

    Returns a list of paths like ["main", "route_map", "crow_query_string", "qs_parse"].
    """
    paths: List[List[str]] = []
    if not entries or target not in adj and target not in entries:
        return paths

    from collections import deque

    for entry in entries:
        queue = deque([(entry, [entry])])
        visited: Dict[str, int] = {entry: 0}
        while queue and len(paths) < max_paths:
            cur, path = queue.popleft()
            depth = len(path) - 1
            if depth > max_depth:
                continue
            if cur == target and len(path) > 1:
                paths.append(path)
                continue
            for nxt in adj.get(cur, []):
                if nxt in visited and visited[nxt] <= depth + 1:
                    continue
                visited[nxt] = depth + 1
                queue.append((nxt, path + [nxt]))
    return paths


# -------------------- Optional libclang-based API-flow extraction --------------------


def _build_api_flow_edges_with_clang(root: Path, vulns: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Best-effort, optional API-flow graph using libclang, inspired by guestbookLLMNew.

    We try to import clang.cindex and, if available, parse headers/sources
    under the vcpkg include roots and project sources. We then:
      - Collect function declarations with their return types and parameter
        types.
      - Add edges A->B when the return type of A matches a parameter type of B
        (modulo const*/spacing), to approximate type-driven API flows.
      - Filter this to a small set of edges that mention vulnerable
        function names so the prompt stays compact.

    If libclang is not available or parsing fails, we return an empty list
    and the rest of the AFG still functions.
    """
    try:
        import clang.cindex  # type: ignore
    except Exception:
        return []

    # Try to set a default libclang path if env/config hasn't already
    try:
        # This path may need adjustment in different environments; we set it
        # only if not already configured.
        if not clang.cindex.Config.library_path:
            # Common default on Debian/Ubuntu with llvm-18; harmless no-op if missing.
            clang.cindex.Config.set_library_path("/usr/lib/llvm-18/lib")
    except Exception:
        pass

    # Collect all candidate files: project sources + vcpkg headers
    files = _list_source_files(root)

    # Build include args from dep include roots
    include_args: List[str] = []
    for inc_root in _iter_dep_include_roots(root):
        include_args.append(f"-I{inc_root.as_posix()}")

    idx = clang.cindex.Index.create()

    functions: List[Dict[str, Any]] = []
    clang_args = ["-x", "c++", "-std=c++17"] + include_args

    for path in files:
        try:
            tu = idx.parse(path.as_posix(), args=clang_args)
        except Exception:
            continue
        if not tu:
            continue
        # Skip files with hard errors
        hard_err = False
        for diag in tu.diagnostics:
            if diag.severity >= clang.cindex.Diagnostic.Error:
                hard_err = True
                break
        if hard_err:
            continue

        def _traverse(node):
            if node.kind == clang.cindex.CursorKind.FUNCTION_DECL:
                name = node.spelling or ""
                if not name:
                    return
                # Skip internal linkage / obvious compiler-builtins
                try:
                    if node.linkage == clang.cindex.LinkageKind.INTERNAL:
                        return
                except Exception:
                    pass
                ret_type = ""
                try:
                    ret_type = node.result_type.spelling or ""
                except Exception:
                    pass
                params: List[Tuple[str, str]] = []
                for p in node.get_arguments() or []:
                    try:
                        ptype = p.type.spelling or ""
                    except Exception:
                        ptype = ""
                    params.append((ptype, p.spelling or ""))
                functions.append({"name": name, "return": ret_type, "params": params})

            for child in node.get_children():
                _traverse(child)

        _traverse(tu.cursor)

    if not functions:
        return []

    # Build type-based edges A->B when ret(A) matches a param type of B
    def _norm(t: str) -> str:
        return t.replace("const", "").replace("volatile", "").strip().strip("* &")

    vuln_names: List[str] = []
    for v in vulns:
        f = _extract_vuln_fields(v)
        if f["func"]:
            vuln_names.append(str(f["func"]))

    api_edges: List[Dict[str, str]] = []
    for fa in functions:
        ra = _norm(fa.get("return", ""))
        if not ra:
            continue
        for fb in functions:
            if fa is fb:
                continue
            for ptype, _ in fb.get("params", []):
                rp = _norm(ptype)
                if not rp:
                    continue
                if ra == rp:
                    src = fa["name"]
                    dst = fb["name"]
                    # Keep only edges that mention at least one vulnerable function
                    if vuln_names and not any(name in (src, dst) for name in vuln_names):
                        continue
                    api_edges.append(
                        {
                            "src": src,
                            "dst": dst,
                            "reason": f"return {fa['return']} flows to param {ptype}",
                        }
                    )

    # Deduplicate edges
    seen_e: set[Tuple[str, str]] = set()
    uniq_edges: List[Dict[str, str]] = []
    for e in api_edges:
        key = (e["src"], e["dst"])
        if key in seen_e:
            continue
        seen_e.add(key)
        uniq_edges.append(e)

    # Keep it small
    return uniq_edges[:64]


# -------------------- Main AFG builder --------------------


def build_afg(root: Path, out: Path) -> Path:
    """Build an Abstract Fuzz Graph (AFG) from vulnerabilities.json.

    The AFG is vulnerability-focused:
      - A single source node representing fuzzer-controlled stdin bytes.
      - For each vulnerable function, an API node and a sink node.
      - Edges: stdin -> api_func, then api_func -> sink.

    When possible, API nodes are enriched with header and signature
    information discovered under build/vcpkg_installed/*/include.

    Additionally, we run a lightweight callgraph analysis to discover
    entrypoint→...→vulnerable-function paths and record them as
    `call_paths` so prompts can describe realistic chains from main() to
    the vulnerable API.

    Finally, if libclang is available, we optionally compute a small
    type-based API-flow edge set around the vulnerable APIs and attach it
    as `api_flow_edges` for richer prompt context.

    The resulting JSON is written under <out>/context/afg.json and the
    path is returned.
    """
    root = root.resolve()
    out = out.resolve()

    vuln_data = _load_vulnerabilities(root)
    vulns = vuln_data.get("vulnerabilities") or []

    ctx_dir = out / "context"
    ctx_dir.mkdir(parents=True, exist_ok=True)
    afg_path = ctx_dir / "afg.json"

    if not vulns:
        empty_afg = {
            "name": "project_afg",
            "nodes": [],
            "edges": [],
            "dictionary_tokens": [],
            "call_paths": [],
            "api_flow_edges": [],
            "notes": "No vulnerabilities.json found or it contained no vulnerabilities.",
        }
        afg_path.write_text(json.dumps(empty_afg, indent=2), encoding="utf-8")
        print(f"[rf2] No vulnerabilities found; wrote empty AFG at {afg_path}")
        return afg_path

    # Build a simple callgraph once per project
    adj, func_files = _build_callgraph(root)
    entry_funcs = _find_entry_functions(adj)

    nodes: List[AFGNode] = []
    edges: List[AFGEdge] = []
    dict_tokens: List[str] = []
    all_paths: List[List[str]] = []

    # Single shared source node representing stdin/fuzzer input
    src_id = "src_stdin"
    nodes.append(
        AFGNode(
            id=src_id,
            kind="source",
            label="stdin buffer (fuzzer input)",
        )
    )

    for v in vulns:
        f = _extract_vuln_fields(v)
        func = f["func"]
        if not func:
            continue

        file = f["file"]
        cve = f["cve"]
        cwe_id = f["cwe_id"]
        cwe_name = f["cwe_name"]
        pkg = f["package"]

        # Try to locate the header in dependency include paths
        header_path: Optional[Path] = None
        header_rel: Optional[str] = None
        signature_preview: Optional[str] = None
        if file:
            header_path = _find_header_for_file(root, Path(file).name)
            if header_path is not None:
                try:
                    header_text = header_path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    header_text = ""
                signature_preview = _extract_signature_preview(header_text, func)
                try:
                    header_rel = str(header_path.relative_to(root))
                except Exception:
                    header_rel = str(header_path)

        api_id = f"api_{func}"
        sink_id = f"sink_{func}"

        api_label = func
        if file:
            api_label += f" in {file}"

        sink_label_parts = []
        if cwe_id:
            sink_label_parts.append(f"CWE-{cwe_id}")
        if cwe_name:
            sink_label_parts.append(cwe_name)
        if cve:
            sink_label_parts.append(cve)
        sink_label = " | ".join(sink_label_parts) or "vulnerability"

        nodes.append(
            AFGNode(
                id=api_id,
                kind="api",
                label=api_label,
                file=file or header_rel,
                vulnerable=True,
                cve=cve,
                cwe_id=cwe_id,
                cwe_name=cwe_name,
                header=header_rel,
                signature=signature_preview,
            )
        )
        nodes.append(
            AFGNode(
                id=sink_id,
                kind="sink",
                label=sink_label,
                file=file or header_rel,
                vulnerable=True,
                cve=cve,
                cwe_id=cwe_id,
                cwe_name=cwe_name,
                header=header_rel,
            )
        )

        # Edges: stdin -> api, api -> sink (direct vuln abstraction)
        edges.append(
            AFGEdge(
                src=src_id,
                dst=api_id,
                label="buf,len (fuzzer input)",
            )
        )
        edges.append(
            AFGEdge(
                src=api_id,
                dst=sink_id,
                label="path to vuln (approx)",
            )
        )

        # Collect some lightweight dictionary tokens for the prompt
        if func:
            dict_tokens.append(func)
        if pkg:
            dict_tokens.append(str(pkg))
        if cwe_name:
            dict_tokens.extend(str(cwe_name).split())
        if header_rel:
            dict_tokens.extend(part for part in Path(header_rel).parts if part)

        # Callgraph-based entry->vuln paths (if any)
        if entry_funcs:
            paths = _find_call_paths(adj, entry_funcs, func)
            all_paths.extend(paths)

    # De-duplicate dictionary tokens and trim
    seen: set[str] = set()
    uniq_tokens: List[str] = []
    for t in dict_tokens:
        t = (t or "").strip()
        if not t:
            continue
        if t in seen:
            continue
        seen.add(t)
        uniq_tokens.append(t)

    # Optional: libclang-based API-flow edges near vulnerable functions
    api_flow_edges = _build_api_flow_edges_with_clang(root, vulns)

    afg = AFG(
        name="project_afg",
        nodes=nodes,
        edges=edges,
        dictionary_tokens=uniq_tokens[:64],
        call_paths=all_paths[:16],  # keep a reasonable number of paths
        api_flow_edges=api_flow_edges,
        notes=(
            "AFG derived from vulnerabilities.json; nodes focus on vulnerable APIs "
            "and are enriched with header/signature, simple entry->vuln call paths "
            "when available, and optional libclang-based API-flow edges around vulnerable functions."
        ),
    )

    afg_json = {
        "name": afg.name,
        "nodes": [asdict(n) for n in afg.nodes],
        "edges": [asdict(e) for e in afg.edges],
        "dictionary_tokens": afg.dictionary_tokens,
        "call_paths": afg.call_paths,
        "api_flow_edges": afg.api_flow_edges,
        "notes": afg.notes,
    }

    afg_path.write_text(json.dumps(afg_json, indent=2), encoding="utf-8")
    print(f"[rf2] AFG generated: {afg_path}")
    return afg_path
