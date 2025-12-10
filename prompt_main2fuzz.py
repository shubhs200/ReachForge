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
    """
    Build a source-first 'main-to-fuzz' prompt:
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
        for vp in [root / "vulnerabilities.json", root / "app" / "vulnerabilities.json"]:
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
    lines.append("- Read stdin into a bounded buffer (cap to a safe limit).")
    lines.append("- Build the minimal state/context required to call the same parsing/handling logic that main uses, in a deterministic, single-shot manner.")
    lines.append("- Prohibit servers/event loops/threads/sockets/sleeps/RNG/time-based behaviors.")
    lines.append("- Ignore benign parse errors; then cleanup and return 0.")
    lines.append("- Do NOT modify any existing source files. Produce a new program only.")
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
