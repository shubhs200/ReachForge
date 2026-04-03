#!/usr/bin/env python3
"""
Seed generator that uses static analysis artifacts to generate targeted inputs.
Uses: vulnerabilities.json, harness_plan.json, generated harness, and source code.
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def extract_function_source(source_file: str, function_name: str, context_lines: int = 50) -> str:
    """
    Extract the source code of a function from a file.
    Uses a simple heuristic: find function definition, extract until closing brace.
    """
    try:
        with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        return "// Could not read source file: " + str(e)
    
    # Find function definition
    start_idx = None
    brace_count = 0
    in_function = False
    
    for i, line in enumerate(lines):
        # Look for function definition pattern
        if function_name in line and '(' in line and not line.strip().startswith('//'):
            # Check if this looks like a function definition
            if not any(kw in line for kw in ['//', 'call', 'sizeof']):
                start_idx = i
                in_function = True
                brace_count = line.count('{') - line.count('}')
                continue
        
        if in_function:
            brace_count += line.count('{') - line.count('}')
            if brace_count == 0 and '{' in ''.join(lines[start_idx:i+1]):
                # Found closing brace
                end_idx = i + 1
                # Include some context before the function
                context_start = max(0, start_idx - 5)
                return ''.join(lines[context_start:end_idx])
    
    # Fallback: return context around any mention of the function
    for i, line in enumerate(lines):
        if function_name in line:
            start = max(0, i - 10)
            end = min(len(lines), i + 20)
            return ''.join(lines[start:end])
    
    return "// Function " + str(function_name) + " not found in " + str(source_file)


def get_vulnerable_function_source(harness_plan: Dict, root: Path) -> Tuple[str, str]:
    """
    Extract source code of the vulnerable function using usr_to_file mapping.
    Returns (source_code, file_path).
    """
    usr_to_file = harness_plan.get('usr_to_file', {})
    usr_to_name = harness_plan.get('usr_to_name', {})
    sink_usr = harness_plan.get('sink_usr', '')
    
    # Get the sink function name
    sink_name = usr_to_name.get(sink_usr, '')
    if '@' in sink_usr:
        # Extract from USR if not in usr_to_name
        sink_name = sink_usr.split('@')[-1].replace('F@', '')
    
    # Find the source file
    sink_loc = usr_to_file.get(sink_usr, '')
    if sink_loc:
        file_path = sink_loc.split(':')[0]
        if not os.path.isabs(file_path):
            file_path = root / file_path
        source = extract_function_source(str(file_path), sink_name)
        return source, str(file_path)
    
    return "// Could not locate source for " + str(sink_name), ""


def _cap_text(text, limit=2000):
    """Truncate *text* to *limit* characters with a marker."""
    if len(text) <= limit:
        return text
    return text[:limit] + "\n... [truncated]"


def build_seed_prompt(
    root,
    harness_plan_path,
    harness_source_path,
    vulns_path,
    out_dir
):
    """
    Build a prompt that asks the LLM to write a Python script which
    programmatically constructs seed files and writes seeds.json.

    The prompt is fully generic — no format-specific templates or branching.
    The LLM infers the expected input format from the harness code,
    vulnerable function source, and execution plan context.
    """
    # Load artifacts
    harness_plan = json.loads(harness_plan_path.read_text(encoding='utf-8'))

    try:
        harness_code = harness_source_path.read_text(encoding='utf-8')
    except Exception:
        harness_code = "// Harness not found"

    try:
        vulns_data = json.loads(vulns_path.read_text(encoding='utf-8'))
        vulns = vulns_data.get('vulnerabilities', vulns_data.get('vulns', []))
    except Exception:
        vulns = []

    # Extract vulnerable function source
    vuln_source, vuln_file = get_vulnerable_function_source(harness_plan, root)

    # Execution plan — rich context for parameter roles, call sequence, etc.
    execution_plan = harness_plan.get('execution_plan', {})

    # Load persisted trigger protocol if available
    trigger_protocol = {}
    tp_path = out_dir / 'context' / 'trigger_protocol.json'
    if tp_path.exists():
        try:
            trigger_protocol = json.loads(tp_path.read_text(encoding='utf-8'))
        except Exception:
            pass

    # ---- Build the prompt ----
    lines = []
    lines.append("# Seed Builder Script Generation")
    lines.append("")
    lines.append("Write a **self-contained Python 3 script** that programmatically")
    lines.append("constructs 5-10 targeted seed inputs and writes them to `seeds.json`")
    lines.append("in the current working directory.")
    lines.append("")
    lines.append("Study the fuzz harness and vulnerable function source below to determine")
    lines.append("the expected input format (binary file format, text protocol, raw buffer,")
    lines.append("etc.). Your script must produce inputs that are structurally valid enough")
    lines.append("to pass initial parsing and reach the vulnerable code path.")
    lines.append("")

    # -- Vulnerability info --
    if vulns:
        lines.append("## Vulnerability Information")
        lines.append("```json")
        vulns_compact = []
        for v in vulns:
            compact = {k: v[k] for k in v
                       if k not in ("patch_diffs", "enrichment_references", "fix_commits")}
            vulns_compact.append(compact)
        lines.append(json.dumps(vulns_compact, indent=2))
        lines.append("```")
        lines.append("")

    # -- Patch diff --
    vuln_entry = harness_plan.get('vuln_entry', {})
    patch_diffs = vuln_entry.get('patch_diffs', [])
    if patch_diffs:
        lines.append("## Fix Patch (shows exactly what code was vulnerable)")
        lines.append("```diff")
        diff_text = str(patch_diffs[0])
        if len(diff_text) > 8000:
            diff_text = diff_text[:8000] + "\n... [truncated]"
        lines.append(diff_text)
        lines.append("```")
        lines.append("")

    # -- Trigger condition --
    trigger_condition = vuln_entry.get('trigger_condition', {})
    if trigger_condition:
        trigger_summary = trigger_condition.get('trigger_summary', [])
        if trigger_summary:
            lines.append("## Trigger Condition")
            lines.append("")
            for item in trigger_summary:
                lines.append("- {}".format(item))
            lines.append("")

    # -- Trigger protocol --
    if trigger_protocol:
        key_insight = trigger_protocol.get('key_insight', '')
        input_requirements = trigger_protocol.get('input_requirements', '')
        protocol_steps = trigger_protocol.get('protocol_steps', [])
        if key_insight or input_requirements or protocol_steps:
            lines.append("## Vulnerability Trigger Protocol")
            lines.append("")
            if key_insight:
                lines.append("**Key insight:** {}".format(key_insight))
                lines.append("")
            if protocol_steps:
                lines.append("Steps to reach the vulnerable function:")
                lines.append("")
                for i, step in enumerate(protocol_steps, 1):
                    lines.append("{}. {}".format(i, step))
                lines.append("")
            if input_requirements:
                lines.append("**Input requirements:** {}".format(input_requirements))
                lines.append("")

    # -- Call path --
    lines.append("## Call Path to Vulnerable Function")
    wrapper_path = harness_plan.get('wrapper_path', [])
    usr_to_name = harness_plan.get('usr_to_name', {})
    path_names = [usr_to_name.get(u, u) for u in wrapper_path]
    lines.append("Input flows through: `" + ' -> '.join(path_names) + "`")
    lines.append("")

    # -- Public API --
    public_api = harness_plan.get('public_api_name', '')
    if public_api:
        lines.append("## Public API Entry Point: `{}()`".format(public_api))
        lines.append("")

    # -- Parameter roles (how each entry-function parameter is populated) --
    param_roles = execution_plan.get('parameter_roles', [])
    if param_roles:
        lines.append("## Entry Function Parameter Roles")
        lines.append("")
        lines.append("These describe how each parameter of the entry function is populated:")
        lines.append("```json")
        lines.append(_cap_text(json.dumps(param_roles, indent=2)))
        lines.append("```")
        lines.append("")

    # -- Call sequence (setup -> invoke -> cleanup ordering) --
    call_sequence = execution_plan.get('call_sequence', [])
    if call_sequence:
        lines.append("## API Call Sequence")
        lines.append("")
        lines.append("The harness follows this call order to set up state and invoke the target:")
        lines.append("```json")
        lines.append(_cap_text(json.dumps(call_sequence, indent=2)))
        lines.append("```")
        lines.append("")

    # -- Sensitive / trigger controls (most influential values to vary) --
    sensitive_controls = execution_plan.get('sensitive_controls', [])
    trigger_controls = execution_plan.get('trigger_controls', [])
    controls = sensitive_controls or trigger_controls
    if controls:
        lines.append("## Sensitive Controls (values that most influence the vulnerability)")
        lines.append("")
        lines.append("Vary these across seeds to explore different trigger conditions:")
        lines.append("```json")
        lines.append(_cap_text(json.dumps(controls, indent=2)))
        lines.append("```")
        lines.append("")

    # -- Path source excerpts (intermediate function source for data flow) --
    path_excerpts = harness_plan.get('path_source_excerpts', {})
    if path_excerpts:
        lines.append("## Intermediate Function Source (data flow from entry to sink)")
        lines.append("")
        excerpt_text = ""
        for fname, src in path_excerpts.items():
            excerpt_text += "### `{}`\n```c\n{}\n```\n\n".format(fname, src)
        lines.append(_cap_text(excerpt_text, 4000))
        lines.append("")

    # -- Vulnerable function source --
    lines.append("## Vulnerable Function Source Code")
    lines.append("File: `{}`".format(vuln_file))
    lines.append("```c")
    lines.append(vuln_source)
    lines.append("```")
    lines.append("")

    # -- Generated harness --
    lines.append("## Generated Fuzz Harness")
    lines.append("```c++")
    lines.append(harness_code)
    lines.append("```")
    lines.append("")

    # -- Script requirements --
    lines.append("## Script Requirements")
    lines.append("")
    lines.append("Write a Python 3 script that:")
    lines.append("1. Uses ONLY the standard library (`struct`, `zlib`, `base64`, `json`, `os`).")
    lines.append("2. Constructs 5-10 seed inputs as raw `bytes` objects.")
    lines.append("3. Each seed must be a structurally valid input that passes the target's")
    lines.append("   initial parsing (correct magic bytes, headers, checksums, framing, etc.).")
    lines.append("   Study the harness code above to determine the expected format.")
    lines.append("   For binary formats, use `struct.pack()` for fields and `zlib.crc32()`")
    lines.append("   for any checksums required by the format. Build the file byte-by-byte")
    lines.append("   so every field, length, and checksum is computed correctly.")
    lines.append("4. Vary field values across seeds to explore different trigger conditions")
    lines.append("   (overflow values, boundary cases, maximum values, zero values, etc.).")
    if controls:
        lines.append("   Focus especially on the **Sensitive Controls** listed above.")
    lines.append("5. After constructing each seed, add a basic validity check (e.g. verify")
    lines.append("   magic bytes are present, minimum length is met) before including it.")
    lines.append("6. Writes `seeds.json` to the current directory with this exact schema:")
    lines.append("")
    lines.append("```json")
    lines.append('{')
    lines.append('  "seeds": [')
    lines.append('    {')
    lines.append('      "name": "descriptive_name",')
    lines.append('      "content": "<base64-encoded bytes>",')
    lines.append('      "encoding": "base64",')
    lines.append('      "target": "what vulnerability condition this seed targets"')
    lines.append('    }')
    lines.append('  ]')
    lines.append('}')
    lines.append("```")
    lines.append("")
    lines.append("7. Use `base64.b64encode(raw_bytes).decode('ascii')` for the content field.")
    lines.append("8. The script must be self-contained and produce `seeds.json` when run with `python3 seed_builder.py`.")
    lines.append("")
    lines.append("Output ONLY the Python script. No markdown fences, no explanations, no prose.")

    # Write prompt
    ctx_dir = out_dir / "context"
    ctx_dir.mkdir(parents=True, exist_ok=True)
    prompt_path = ctx_dir / "prompt.seeds.md"
    prompt_path.write_text('\n'.join(lines), encoding='utf-8')

    return prompt_path


def _extract_python_code(text):
    """Strip markdown fences from LLM response to get plain Python code."""
    import re
    text = text.strip()
    # Remove ```python ... ``` or ``` ... ``` wrapper
    m = re.match(r'^```(?:python|py)?\s*\n(.*?)\n```\s*$', text, re.DOTALL)
    if m:
        return m.group(1)
    # Remove leading/trailing ``` if present
    if text.startswith('```'):
        text = re.sub(r'^```(?:python|py)?\s*\n', '', text)
        text = re.sub(r'\n```\s*$', '', text)
    return text


def generate_seeds(root, out_dir, model="gpt-4o"):
    """
    Generate seeds by asking the LLM to write a Python seed-builder script,
    then executing that script to produce seeds.json.
    """
    harness_plan_path = out_dir / "harness_plan.json"
    harness_source_path = out_dir / "fuzzer.cc"
    vulns_path = out_dir / "enriched_vulnerabilities.json"
    if not vulns_path.exists():
        vulns_path = root / "vulnerabilities.json"
    seeds_path = out_dir / "seeds.json"

    if not harness_plan_path.exists():
        print("Error: harness_plan.json not found at " + str(harness_plan_path))
        return None

    # Build the code-gen prompt
    prompt_path = build_seed_prompt(
        root, harness_plan_path, harness_source_path, vulns_path, out_dir
    )
    print("Seed prompt written to " + str(prompt_path))

    # Call LLM to generate a Python script
    from llm_adapters.openai import run_openai_code

    cfg_path = Path(__file__).parent / "config" / "llm.json"
    api_base = "https://api.openai.com/v1"
    try:
        cfg = json.loads(cfg_path.read_text(encoding='utf-8'))
        model = cfg.get("default", {}).get("model") or cfg.get("model") or model
        api_base = cfg.get("default", {}).get("api_base") or cfg.get("api_base") or api_base
    except Exception:
        pass

    script_path = out_dir / "seed_builder.py"
    ok, msg = run_openai_code(str(prompt_path), str(script_path), model=model, api_base=api_base)

    if not ok:
        print("LLM error generating seed script: " + str(msg))
        return None

    # Extract Python code (strip markdown fences if the LLM wrapped it)
    raw_script = script_path.read_text(encoding='utf-8')
    clean_script = _extract_python_code(raw_script)
    if clean_script != raw_script:
        script_path.write_text(clean_script, encoding='utf-8')

    print("Seed builder script written to " + str(script_path))

    # Execute the script to produce seeds.json
    try:
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(out_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60
        )
    except subprocess.TimeoutExpired:
        print("Error: seed builder script timed out after 60s")
        return None
    except Exception as e:
        print("Error running seed builder script: " + str(e))
        return None

    if result.returncode != 0:
        stderr_text = result.stderr.decode('utf-8', errors='replace') if result.stderr else ''
        print("Seed builder script failed (exit code " + str(result.returncode) + "):")
        print(stderr_text[:2000])
        return None

    if not seeds_path.exists():
        print("Error: seed builder script did not produce seeds.json")
        return None

    # Validate the output is parseable JSON with a seeds array
    try:
        data = json.loads(seeds_path.read_text(encoding='utf-8'))
        seed_count = len(data.get('seeds', []))
        print("Seeds generated at " + str(seeds_path) + " (" + str(seed_count) + " seeds)")
    except Exception as e:
        print("Warning: seeds.json parse error: " + str(e))

    return seeds_path


def main():
    parser = argparse.ArgumentParser(description="Generate seeds using static analysis")
    parser.add_argument("--root", required=True, help="Project root directory")
    parser.add_argument("--out", required=True, help="Output directory (contains harness_plan.json)")
    parser.add_argument("--model", default="gpt-4o", help="LLM model to use")
    args = parser.parse_args()
    
    root = Path(args.root).resolve()
    out_dir = Path(args.out).resolve()
    
    seeds_path = generate_seeds(root, out_dir, args.model)
    if seeds_path:
        print("Success! Seeds written to " + str(seeds_path))
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()