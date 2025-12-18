from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

# Support both package and script execution
try:
    from .schema import DRIVER_SPEC_SCHEMA
    from .source_index import find_entry_main_and_context, build_source_summaries
    from .poller_index import build_poller_summary
except ImportError:  # Fallback when run as a script (no package parent)
    from schema import DRIVER_SPEC_SCHEMA
    from reachforge.source_index import find_entry_main_and_context, build_source_summaries
    from poller_index import build_poller_summary


def build_main2fuzz_prompt(root: Path, out_dir: Path, *, include_vulns: bool = False, include_poller: bool = True) -> Optional[Path]:
    """Build a source-first 'main-to-fuzz' prompt.

    - Full entrypoint (file with int main)
    - Bounded auxiliary snippets referenced by main (headers/sources)
    - Strict DriverSpec JSON schema and guardrails

    Returns the path to the prompt file (markdown), or None if context cannot be built.
    """
    root = root.resolve()
    out_dir = out_dir.resolve()
    ctx = find_entry_main_and_context(root)
    if not ctx:
        return None

    vulns_blob = ""
    if include_vulns:
        # Search for vulnerabilities.json starting at root and walking up parents,
        # supporting layouts where the app root is a subdir (e.g., variant-builds/0.1.0)
        candidates = []
        cur = root
        for cur in [cur, *cur.parents]:
            candidates.append(cur / "vulnerabilities.json")
            candidates.append(cur / "app" / "vulnerabilities.json")

        for vp in candidates:
            if vp.exists():
                try:
                    data = json.loads(vp.read_text(encoding="utf-8"))
                    vulns = data.get("vulnerabilities", [])
                    if vulns:
                        vulns_blob = json.dumps(
                            [
                                {
                                    "cve": v.get("cve-id"),
                                    "cwe": v.get("cwe-id"),
                                    "cwe_name": v.get("cwe-name"),
                                    "affected_function": v.get("affected-function"),
                                    "affected_file": v.get("affected-file"),
                                }
                                for v in vulns[:16]
                            ],
                            indent=2,
                        )
                except Exception:
                    pass
                break

    lines: list[str] = []
    # Optional poller insights to bias the model toward realistic I/O/use patterns
    if include_poller:
        try:
            poller_summary = build_poller_summary(root)
        except Exception:
            poller_summary = ""
        if poller_summary:
            lines.append("Poller insights (from poller/poller.py):")
            lines.append(poller_summary)
            lines.append("Use these insights to select a single-shot call path and realistic input shapes; do NOT implement servers/sockets or loops.")
            lines.append("")

    lines.append("You are given an application's entrypoint (file that contains int main) and a handful of supporting source snippets.")
    lines.append("Your task: output ONLY a DriverSpec JSON (no prose, no code fences) that defines a brand-new, single-shot fuzz driver (a separate program).")
    lines.append("")
    lines.append("The driver must:")
    lines.append("- Read stdin into a bounded buffer (cap to a safe limit). Use a minimum effective size (for example, ignore inputs smaller than ~16 bytes) and a soft maximum in the low hundreds of kilobytes (for example, 128–256 KiB).")
    lines.append("- Be compatible with AFL++-style persistent mode: structure the main fuzz logic so it can live inside a guarded loop (for example, while (__AFL_LOOP(N))) without relying on fork-per-input.")
    lines.append("- Within that loop, read a fresh input, process it once, and then reset all per-iteration state before the next iteration. When enforcing a minimum size, skip too-small inputs by continuing to the next iteration instead of exiting the program from inside the loop.")
    lines.append("- Build the minimal state/context required to call the same parsing/handling logic that main uses, in a deterministic, single-shot manner.")
    lines.append("- Recreate any decoder/codec/parser objects, histograms, and other mutable data structures on each iteration so that no state leaks across inputs; avoid using global/static caches that accumulate cross-input state.")
    lines.append("- Use simple, deterministic detection logic (for example, magic bytes, headers, or a type enum) so that each supported handler or decoder is actually reachable for some subset of inputs, rather than sending most inputs to a generic \"unknown\" path.")
    lines.append("- If the codebase exposes multiple decoders or format handlers, select at most one decoder or logical code path per input based on that detection logic instead of running many decoders on the same buffer or falling back through several codecs when the type is unknown; keep coverage stable and one-handler-per-input.")
    lines.append("- Where formats have very different typical sizes, allow format-sensitive soft limits (for example, larger caps for large, structured inputs and smaller caps for compact formats), while still enforcing an overall upper bound on the buffer.")
    lines.append("- Prohibit servers/event loops/threads/sockets/sleeps/RNG/time-based behaviors.")
    lines.append("- Ignore benign parse errors; then cleanup and return 0.")
    lines.append("- Do NOT modify any existing source files. Produce a new program only.")
    lines.append("- Do NOT introduce custom fast detection logic")
    lines.append("")
    lines.append("DriverSpec JSON (schema reminder; DO NOT add extra fields or text):")
    lines.append(json.dumps(DRIVER_SPEC_SCHEMA, indent=2))
    lines.append("")
    lines.append("Output format constraints:")
    lines.append("- Output strictly a single JSON object conforming to the DriverSpec schema.")
    lines.append("- No code fences, no commentary, no explanations outside of the allowed 'notes' field (1-2 short lines).")
    lines.append("- 'driver_source' must contain a complete, compilable single-shot program in the language specified.")
    lines.append("- 'includes' must use project-relative quoted headers and allowed externals visible in the provided sources.")
    lines.append("- If a function expects a file path or FILE*, write the buffer to a temp file in-driver and pass it.")
    lines.append("- If the functions you will call are declared in headers but implemented in project sources, populate 'extra_sources' with the required .c/.cc files (project-relative).")
    lines.append("- If the entry file defines helper functions you need (see list below), set 'lift_from_entry' to their names; the tool will insert their definitions verbatim from the entry file before your driver_source.")
    lines.append("")
    lines.append("General guidance (style-agnostic; infer from the provided sources):")
    lines.append("- If the app is protocol/server-like, avoid listen/poll loops; synthesize minimal manager/connection and call parse(buf,len[, ver], &obj) once. If multiple versions exist, try a small deterministic subset (e.g., v4 then v5).")
    lines.append("- If the app is library/format-like, detect type (if available) and switch to handlers; initialize minimal state structs required by those handlers.")
    lines.append("- Keep the driver minimal: one read, one call sequence, and cleanup.")
    lines.append("- If the provided sources implement HTTP handlers or servers (e.g., microhttpd), do NOT reproduce endpoints.")
    lines.append("- Instead, call the underlying processing/decoder functions that accept (buffer,len) or a FILE* path.")
    lines.append("- Prefer functions declared in project headers that take const unsigned char* and size_t len, e.g., image_handle_*(buf,len,hist).")
    lines.append("- Keep per-iteration overhead low in the fuzz driver: avoid building expensive debug-only JSON summaries (for example, histogram dumps), duplicating includes or heavy setup on every iteration, or running multi-pass fallback detection logic unless it is required to reach the target parsing/decoder code.")
    lines.append("- When using persistent mode, hoist immutable tables and configuration out of the main fuzz loop where possible, while keeping all input-dependent behavior inside the loop so that each iteration remains deterministic and isolated.")
    lines.append("- When the target exposes an embedded interpreter, virtual machine, or scripting-like runtime, initialize that runtime using its normal creation and library-initialization functions (as visible in the sources) and then drive it using the fuzz buffer.")
    lines.append("- In that case, reuse the same input buffer in multiple ways: (1) treat it as a high-level script/program that is compiled/loaded and, when possible, executed; (2) treat it as a raw blob passed to core data-creation APIs (for example, functions that create strings, tables, arrays, or similar containers); and (3) drive APIs that operate on containers with index/range/offset parameters.")
    lines.append("- Prefer driving core or global container/sequence APIs (for example, functions that conceptually operate on a list or table and take start/end or index parameters) over narrow methods on specific library tables when both are visible in the headers or entry file.")
    lines.append("- For container+index/range APIs, first build a container (array/list/table/etc.) from a prefix of the fuzz buffer and then derive indices, offsets, or bounds from later bytes (for example, interpret 4 or 8 tail bytes as signed/unsigned integers, clamp into valid ranges, and occasionally swap them so start <= end while still exploring start > end).")
    lines.append("- Avoid hardcoding indices or counts for such APIs; instead, map them from the fuzz data so that boundary and out-of-range behaviors are explored, while still keeping the harness deterministic and single-shot.")
    lines.append("")
    if vulns_blob:
        lines.append("Optional bias (if relevant): vulnerabilities summary")
        lines.append(vulns_blob)
        lines.append("Prefer calling functions/files that are listed as affected when possible, while staying deterministic and single-shot.")
        lines.append("")

    # Context: source summaries (overview)
    try:
        summaries = build_source_summaries(root)
    except Exception:
        summaries = ""
    if summaries:
        lines.append("Project source summaries (functions and includes):")
        lines.append(summaries)
        lines.append("")

    # Entry-defined helper functions available to lift verbatim
    try:
        entry_funcs_json = ctx.notes.get("entry_defined_funcs", "")
        if entry_funcs_json:
            lines.append("Entry-defined helper functions (available to lift verbatim via 'lift_from_entry'):")
            lines.append(entry_funcs_json)
            lines.append("If your driver needs any of the above (e.g., mg_mqtt_next_topic, mg_mqtt_next_sub, mg_mqtt_next_unsub, process_mqtt_message, fn), list them under 'lift_from_entry' and do NOT duplicate their bodies in driver_source.")
            lines.append("")
    except Exception:
        pass

    # Context: entrypoint (full)
    lines.append("Entry file (complete):")
    lines.append(f"// file: {ctx.main_file.path}")
    lines.append(ctx.main_file.content)

    # Context: auxiliary snippets (subset)
    if ctx.aux_snippets:
        lines.append("")
        lines.append("Auxiliary snippets (subset):")
        for sn in ctx.aux_snippets:
            lines.append(f"// file: {sn.path}")
            lines.append(sn.content)

    # Final instruction
    lines.append("")
    lines.append("Now output ONLY the DriverSpec JSON.")

    prompt_dir = out_dir / "context"
    prompt_dir.mkdir(parents=True, exist_ok=True)
    prompt_path = prompt_dir / "prompt.main2fuzz.md"
    prompt_path.write_text("\n".join(lines), encoding="utf-8")
    return prompt_path


def build_afg_prompt(root: Path, out_dir: Path, afg_path: Path) -> Optional[Path]:
    """Build an AFG-augmented DriverSpec prompt.

    This variant incorporates a vulnerability-focused Abstract Fuzz Graph (AFG)
    derived from vulnerabilities.json together with the single entry translation
    unit that defines int main(). Unlike build_main2fuzz_prompt, this mode does
    NOT include global source summaries; the model must reason mainly from the
    entry file and the AFG.
    """
    root = root.resolve()
    out_dir = out_dir.resolve()

    # Reuse the entry context for main
    ctx = find_entry_main_and_context(root)
    if not ctx:
        return None

    # Load AFG JSON (best-effort)
    try:
        afg = json.loads(Path(afg_path).read_text(encoding="utf-8"))
    except Exception:
        afg = {}

    # Optional vulnerabilities summary (for labeling AFG nodes)
    vulns_data: dict[str, object] | list[object] | None = None
    # Search for vulnerabilities.json starting at root and walking up parents.
    candidates = []
    cur = root
    for cur in [cur, *cur.parents]:
        candidates.append(cur / "vulnerabilities.json")
        candidates.append(cur / "app" / "vulnerabilities.json")

    for vp in candidates:
        if vp.exists():
            try:
                vulns_data = json.loads(vp.read_text(encoding="utf-8"))
            except Exception:
                vulns_data = None
            break

    lines: list[str] = []
    lines.append("You are generating a DriverSpec JSON for a single-shot, deterministic fuzz driver.")
    lines.append("")
    lines.append("You are given:")
    lines.append("- An Abstract Fuzz Graph (AFG) derived from vulnerabilities.json, focusing on vulnerable APIs and sinks.")
    lines.append("- The application's entry file that contains int main (shows how the program is normally configured and used).")
    lines.append("")
    lines.append("Your task: output ONLY a DriverSpec JSON (no prose, no code fences) that defines a brand-new, single-shot fuzz driver (a separate program).")
    lines.append("")
    lines.append("The driver must:")
    lines.append("- Read stdin into a bounded buffer (cap to a safe limit).")
    lines.append("- Build just enough state/context to exercise one or more vulnerable or high-risk APIs identified in the AFG, in a deterministic, single-shot manner.")
    lines.append("- Avoid reproducing servers, event loops, signal handlers, or threads from main; instead, construct the minimal objects needed and invoke the core logic once.")
    lines.append("- Ignore benign parse errors; then cleanup and return 0.")
    lines.append("- Do NOT modify any existing source files. Produce a new program only.")
    lines.append("- This repository uses AFL++-style stdin harnesses: your generated 'driver_source' MUST contain exactly one program entrypoint: 'int main(...)'.")
    lines.append("- DO NOT define or reference any libFuzzer/LLVM entrypoints (forbidden tokens: LLVMFuzzerTestOneInput, LLVMFuzzerInitialize, LLVMFuzzerCustomMutator, LLVMFuzzerCustomCrossOver).")
    lines.append("- DO NOT include or mention sanitizer/libFuzzer runtime APIs; all fuzz input must be read from stdin inside main().")
    lines.append("")
    lines.append("Decision guidance using main() + AFG:")
    lines.append("- Your driver MUST directly or indirectly invoke at least one function that is marked as vulnerable in vulnerabilities.json (affected-function) or appears as an 'api_' node in the AFG.")
    lines.append("- Do NOT design the driver around unrelated parsers or subsystems that are not mentioned in vulnerabilities.json / the AFG; focus your call sequence on the vulnerable APIs.")
    lines.append("- Use the entry file to understand how the application normally routes or processes input (e.g., request/response types, configuration, helper objects).")
    lines.append("- Use the AFG to choose which APIs and call paths to target. Prefer API nodes that lead directly to sinks in the AFG.")
    lines.append("- Map fuzzer bytes from stdin to the logical inputs used in those paths (for example, query parameters, request bodies, filenames, or template data), so that the vulnerable APIs see realistic but adversarial data.")
    lines.append("- If main configures a long-running server, do not start a server in the fuzz driver. Instead, instantiate the same request/handler objects in-process and call the vulnerable logic exactly once per fuzz iteration.")
    lines.append("")
    lines.append("Harness design patterns (generic, apply when they match the provided sources/AFG):")
    lines.append("- When a vulnerable API belongs to a stateful library or virtual machine (for example, a scripting engine or embedded runtime), create a real instance of that state using its normal initialization and teardown calls that are visible in the entry file or headers.")
    lines.append("- Prefer driving low-level primitives via the public helper or parsing functions that call them (as suggested by the AFG call paths) instead of calling them in isolation with null or dummy state pointers.")
    lines.append("- Reuse the fuzz input buffer in multiple logically distinct ways inside one execution. For example, treat an initial control byte or small header as a selector and use the remaining bytes as payload for one or more helper functions that eventually reach the vulnerable API.")
    lines.append("- When the AFG provides call paths such as main -> helper -> vulnerable_function, design the driver so it calls the same helper with fuzz-controlled arguments that mimic what main would normally produce, instead of bypassing it.")
    lines.append("- When functions take indices, offsets, or sizes, derive these from structured slices of the input (for example, interpret a few tail bytes as signed or unsigned integers, clamp or normalize them, and then use them as bounds or index parameters) so that edge cases around boundaries are exercised.")
    lines.append("- If a vulnerable API consumes string or buffer data, consider both indirect use (through a normal parser or loader that calls it internally) and direct use (calling it with raw fuzz bytes) when this is consistent with its signature and headers, while keeping the harness single-shot and deterministic.")
    lines.append("- When a vulnerable API is part of a language runtime or scripting engine and the entry file or headers expose load/compile helpers (for example, functions that compile or evaluate a buffer as source), first invoke those helpers with the entire fuzz buffer. Treat compilation or parse errors as benign: ignore them and continue.")
    lines.append("- After exercising such a high-level load/parse step, also call at least one lower-level or more focused API directly with fuzz-derived arguments (for example, slices of the same buffer) so that both the parser/compiler and the primitive are exercised in a single execution, but only when those lower-level APIs are declared in the allowed headers or visible sources (do not invent extern declarations for internal-only symbols).")
    lines.append("- Avoid introducing new 'extern' declarations or forward declarations for vulnerable/internal functions that are not declared in any of the allowed headers or entry file; instead, reach those implementations indirectly via their public wrappers, globals, or helper functions indicated by the AFG call_paths or api_flow_edges.")
    lines.append("- If an AFG api node appears to represent an internal/private function (for example, only defined in a .c file and not declared in the visible headers), treat it as an implementation detail and target it through the public APIs that call it, rather than naming or calling that internal symbol directly in your driver.")

    lines.append("- For APIs that operate on tables, arrays, or ranges, construct a container object from a prefix of the fuzz buffer, then derive one or two index parameters from later bytes. Interpret a few tail bytes as integers, clamp or normalize them into the valid range, and occasionally swap them so that start <= end most of the time but some executions still explore start > end behaviors.")
    lines.append("- When the AFG or vulnerabilities summary describe a specific function name in a particular file or module, and the entry file or headers expose a public symbol or global with that exact name, prefer calling that symbol (or the global it registers) over loosely related helpers.")
    lines.append("- Whenever it is safe and consistent with the headers, try to use the same fuzz buffer both as raw source or configuration (for example, passed to a load/parse/compile helper) and as binary or structured data (for example, elements of a container or payload passed to a lower-level API) by first invoking a load/parse function on the entire buffer and then slicing it into segments for secondary calls.")
    lines.append("")

    # DriverSpec schema reminder
    lines.append("DriverSpec JSON (schema reminder; DO NOT add extra fields or text):")
    lines.append(json.dumps(DRIVER_SPEC_SCHEMA, indent=2))
    lines.append("")
    lines.append("Output format constraints:")
    lines.append("- Output strictly a single JSON object conforming to the DriverSpec schema.")
    lines.append("- No code fences, no commentary, no explanations outside of the allowed 'notes' field (1-2 short lines).")
    lines.append("- 'driver_source' must contain a complete, compilable single-shot program in the language specified.")
    lines.append("- 'includes' must use project-relative quoted headers and allowed externals visible in the entry file and any headers it includes.")
    lines.append("- If a function expects a file path or FILE*, write the buffer to a temp file in-driver and pass it.")
    lines.append("- If the functions you will call are declared in headers but implemented in project sources, populate 'extra_sources' with the required .c/.cc files (project-relative).")
    lines.append("- If the entry file defines helper functions you need (see list below), set 'lift_from_entry' to their names; the tool will insert their definitions verbatim from the entry file before your driver_source.")
    lines.append("")

    # Vulnerabilities summary (for additional bias)
    vulns_list = []
    if isinstance(vulns_data, dict):
        vulns_list = vulns_data.get("vulnerabilities", []) or []
    if vulns_list:
        lines.append("Vulnerabilities summary (from vulnerabilities.json):")
        for v in vulns_list[:16]:
            lines.append(
                f"- {v.get('cve-id')} CWE-{v.get('cwe-id')} {v.get('cwe-name')}: "
                f"{v.get('affected-function')} in {v.get('affected-file')}"
            )
        lines.append("Use these as hints for which APIs and files to prioritize, while keeping the driver single-shot and deterministic.")
        lines.append("")

    # AFG summary section (compact) + explicit vulnerable API list + entry→vuln call paths
    if afg:
        nodes = afg.get("nodes", []) or []
        edges = afg.get("edges", []) or []
        dict_tokens = afg.get("dictionary_tokens", []) or []
        notes = afg.get("notes", "")
        call_paths = afg.get("call_paths", []) or []
        api_flow_edges = afg.get("api_flow_edges", []) or []

        # First, show the concrete vulnerable APIs that the driver should target
        api_nodes = []
        for n in nodes:
            kind = n.get("kind") or n.get("type")
            if kind == "api":
                api_nodes.append(n)
        if api_nodes:
            lines.append("Vulnerable APIs (from AFG; choose at least one of these to call directly in your driver):")
            for n in api_nodes[:16]:
                label = n.get("label") or n.get("id") or "(unnamed api)"
                header = n.get("header")
                sig = n.get("signature")
                desc_parts: list[str] = [label]
                if header:
                    desc_parts.append(f"header: {header}")
                if sig:
                    desc_parts.append(f"signature: {sig}")
                lines.append("- " + " | ".join(desc_parts))
            lines.append("")

        # Then, show any simple entry→...→vuln call paths discovered
        if call_paths:
            lines.append("Entry-to-vulnerability call paths (from entry functions such as main to vulnerable APIs):")
            for pth in call_paths[:12]:
                if not isinstance(pth, list) or len(pth) < 2:
                    continue
                lines.append("- " + " -> ".join(str(x) for x in pth))
            lines.append("Use one of these call chains as a template for your harness: construct the same sequence of logical calls, feeding fuzzer-controlled data at the appropriate step (e.g., query string, body, or buffer) so that the vulnerable API is invoked once per execution.")
            lines.append("")

        # Optionally, show API-level flows between vulnerable functions and nearby APIs
        if api_flow_edges:
            lines.append("API-level data flow between functions (from libclang-based analysis):")
            for e in api_flow_edges[:24]:
                src = e.get("src")
                dst = e.get("dst")
                reason = e.get("reason") or "type-based flow"
                if not src or not dst:
                    continue
                lines.append(f"- {src} -> {dst} ({reason})")
            lines.append(
                "Use these API-flow hints to decide which helper/library functions to call before or after the vulnerable API, "
                "preserving realistic type flows (e.g., constructing objects that feed into qs_parse or render_internal)."
            )
            lines.append("")

        # Finally, a lighter-weight structural summary of the graph
        lines.append("Abstract Fuzz Graph (AFG) overview:")
        lines.append(f"Name: {afg.get('name', 'project_afg')}")
        if notes:
            lines.append(f"Notes: {notes}")
        if nodes:
            preview_nodes = []
            for n in nodes[:20]:
                kind = n.get("kind") or n.get("type")
                label = n.get("label") or n.get("id")
                preview_nodes.append(f"{kind}:{label}")
            lines.append("Nodes (subset): " + ", ".join(preview_nodes))
        if edges:
            edge_strs = [
                f"{e.get('src')}->{e.get('dst')}:{e.get('label')}" for e in edges[:24]
            ]
            lines.append("Edges (subset): " + "; ".join(edge_strs))
        if dict_tokens:
            lines.append("Suggested dictionary tokens (from AFG/vulns): " + ", ".join(dict_tokens[:32]))
        lines.append("")

    # Entry-defined helper functions available to lift verbatim
    try:
        entry_funcs_json = ctx.notes.get("entry_defined_funcs", "")
        if entry_funcs_json:
            lines.append("Entry-defined helper functions (available to lift verbatim via 'lift_from_entry'):")
            lines.append(entry_funcs_json)
            lines.append("If your driver needs any of the above, list them under 'lift_from_entry' and do NOT duplicate their bodies in driver_source.")
            lines.append("")
    except Exception:
        pass

    # Context: entrypoint (full)
    lines.append("Entry file (complete):")
    lines.append(f"// file: {ctx.main_file.path}")
    lines.append(ctx.main_file.content)

    # Note: in AFG mode we intentionally do NOT include global source summaries
    # or additional snippets beyond the entry file, so the model focuses on
    # combining main() with the vulnerability graph.

    # Final instruction
    lines.append("")
    lines.append("Now output ONLY the DriverSpec JSON.")

    prompt_dir = out_dir / "context"
    prompt_dir.mkdir(parents=True, exist_ok=True)
    prompt_path = prompt_dir / "prompt.main2fuzz_afg.md"
    prompt_path.write_text("\n".join(lines), encoding="utf-8")
    return prompt_path
