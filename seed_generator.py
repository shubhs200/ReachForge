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


def build_seed_prompt(
    root: Path,
    harness_plan_path: Path,
    harness_source_path: Path,
    vulns_path: Path,
    out_dir: Path
) -> Path:
    """
    Build a prompt for seed generation using all available artifacts.
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
    
    # Build the prompt
    lines = []
    lines.append("# Seed Generation Task")
    lines.append("")
    lines.append("Generate input seeds that will trigger the vulnerability when processed by the fuzz harness.")
    lines.append("Output ONLY a JSON object with a 'seeds' array containing 5-10 seed inputs.")
    lines.append("")
    
    # Vulnerability info
    if vulns:
        lines.append("## Vulnerability Information")
        lines.append("```json")
        lines.append(json.dumps(vulns, indent=2))
        lines.append("```")
        lines.append("")
    
    # Call path to vulnerability
    lines.append("## Call Path to Vulnerable Function")
    wrapper_path = harness_plan.get('wrapper_path', [])
    usr_to_name = harness_plan.get('usr_to_name', {})
    path_names = [usr_to_name.get(u, u) for u in wrapper_path]
    lines.append("Input flows through: `" + ' -> '.join(path_names) + "`")
    lines.append("")
    
    # Public API info
    public_api = harness_plan.get('public_api_name', '')
    if public_api:
        lines.append("## Public API Entry Point")
        lines.append("The input is processed by `" + str(public_api) + "()` before reaching the vulnerable function.")
        lines.append("")
    
    # Vulnerable function source
    lines.append("## Vulnerable Function Source Code")
    lines.append("File: `" + str(vuln_file) + "`")
    lines.append("```c")
    lines.append(vuln_source)
    lines.append("```")
    lines.append("")
    
    # Generated harness
    lines.append("## Generated Fuzz Harness")
    lines.append("```c++")
    lines.append(harness_code)
    lines.append("```")
    lines.append("")
    
    # Instructions
    lines.append("## Task")
    lines.append("Analyze the vulnerable function source code above and generate 5-10 seed inputs that:")
    lines.append("1. Will reach the vulnerable code path (through the call chain shown)")
    lines.append("2. Stress boundary conditions in buffer/loop operations")
    lines.append("3. Target specific variables and calculations in the function")
    lines.append("")
    lines.append("Output format (JSON only, no markdown):")
    lines.append("```json")
    lines.append('{')
    lines.append('  "seeds": [')
    lines.append('    {')
    lines.append('      "name": "descriptive_name",')
    lines.append('      "content": "base64 or hex encoded content",')
    lines.append('      "encoding": "base64|hex|utf8",')
    lines.append('      "target": "what condition this seed targets"')
    lines.append('    }')
    lines.append('  ]')
    lines.append('}')
    lines.append("```")
    lines.append("")
    lines.append("Focus on:")
    lines.append("- Buffer boundary conditions (off-by-one, truncation)")
    lines.append("- Loop termination conditions")
    lines.append("- Length field calculations")
    lines.append("- Character/value comparisons in the vulnerable function")
    lines.append("- Any condition that could cause out-of-bounds access")
    
    # Write prompt
    ctx_dir = out_dir / "context"
    ctx_dir.mkdir(parents=True, exist_ok=True)
    prompt_path = ctx_dir / "prompt.seeds.md"
    prompt_path.write_text('\n'.join(lines), encoding='utf-8')
    
    return prompt_path


def generate_seeds(root: Path, out_dir: Path, model: str = "gpt-4o") -> Optional[Path]:
    """
    Generate seeds using the LLM based on static analysis artifacts.
    """
    harness_plan_path = out_dir / "harness_plan.json"
    harness_source_path = out_dir / "fuzzer.cc"
    vulns_path = root / "vulnerabilities.json"
    seeds_path = out_dir / "seeds.json"
    
    if not harness_plan_path.exists():
        print("Error: harness_plan.json not found at " + str(harness_plan_path))
        return None
    
    # Build prompt
    prompt_path = build_seed_prompt(
        root, harness_plan_path, harness_source_path, vulns_path, out_dir
    )
    print("Seed prompt written to " + str(prompt_path))
    
    # Call LLM
    from llm_adapters.openai import run_openai_json
    
    # Load config
    cfg_path = Path(__file__).parent / "config" / "llm.json"
    api_base = "https://api.openai.com/v1"
    try:
        cfg = json.loads(cfg_path.read_text(encoding='utf-8'))
        model = cfg.get("default", {}).get("model") or cfg.get("model") or model
        api_base = cfg.get("default", {}).get("api_base") or cfg.get("api_base") or api_base
    except Exception:
        pass
    
    ok, msg = run_openai_json(str(prompt_path), str(seeds_path), model=model, api_base=api_base)
    
    if ok:
        print("Seeds generated at " + str(seeds_path))
        return seeds_path
    else:
        print("LLM error: " + str(msg))
        return None


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