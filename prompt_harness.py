#!/usr/bin/env python3
import argparse
import glob
import json
import os
import re
from pathlib import Path
from vuln_analyzer import analyze_vulnerable_function, extract_function_source
from cve_enrichment import _filter_security_patches, _sub_patch_touches_source, synthesize_trigger_protocol

# Generic planner-generated phrases that do not apply to most C/C++ libraries.
# These confuse the LLM into constructing imaginary "lookup-table" or
# "transform-config" objects that have nothing to do with the actual CVE.
_PLANNER_NOISE_PATTERNS = re.compile(
    r'lookup[-\s]?table|transform[-\s]?config|transform[-\s]?gating'
    r'|(?:setup|cleanup)\s+helper(?:s)?\s+(?:appear|nearby|MALLOC|FREE|REALLOC)'
    r'|resource\s+transitions\s+(?:near|to\s+exercise)'
    r'|setup\s+helper\s+MALLOC|cleanup\s+helper\s+FREE|setup\s+helper\s+REALLOC'
    r'|small\s+bounded\s+prefix'
    r'|stabilize\s+low-signal'
    r'|Suggested\s+workload\s+shaping'
    r'|Required\s+milestones\s+before\s+the\s+sink'
    r'|Enable\s+transform-related\s+state'
    r'|Initialize\s+library-owned\s+state\s+objects\s+through\s+public'
    r'|Create\s+or\s+initialize\s+valid\s+library-owned\s+state'
    r'|indexed\s+transforms'
    r'|selector[-\s]or[-\s]control'
    r'|table\s+.*valid'
    r'|real\s+support\s+object'
    r'|fuzzed\s+within\s+valid\s+bounds'
    r'|bounded[-\s]controls',
    re.IGNORECASE,
)


def _mentions_internal_var(text, internal_vars):
    """Return True if *text* mentions any sink-internal variable name.

    *internal_vars* is a frozenset of lowercased parameter names that the
    callgraph identified as unreachable from the public entry point.  When
    empty, no filtering is applied (conservative default).
    """
    if not internal_vars:
        return False
    regex = re.compile(
        r'\b(?:' + '|'.join(re.escape(v) for v in sorted(internal_vars)) + r')\b',
        re.IGNORECASE,
    )
    return bool(regex.search(str(text)))


def _is_planner_noise(text):
    """Return True if *text* is a generic planner-generated boilerplate string."""
    if isinstance(text, dict):
        # For support_objects / milestone_hints dicts, check the 'name' field
        text = text.get('name', '') + ' ' + text.get('reason', '') + ' ' + text.get('kind', '')
    return bool(_PLANNER_NOISE_PATTERNS.search(str(text)))


def _filter_noise(items):
    """Remove planner-noise entries from a list of strings or dicts."""
    return [item for item in items if not _is_planner_noise(item)]


def _extract_commit_messages(patch_texts):
    """Extract commit Subject + body from raw .patch file texts.

    Returns a list of strings, one per patch, containing the commit
    message (subject + body) stripped of email headers and diff hunks.
    """
    messages = []
    for patch in patch_texts:
        text = str(patch)
        # Find Subject line
        subject = ''
        body_lines = []
        in_body = False
        for line in text.splitlines():
            if not subject and line.startswith('Subject:'):
                # Strip "Subject: [PATCH ...] " prefix
                subj = re.sub(r'^Subject:\s*(?:\[PATCH[^\]]*\]\s*)?', '', line)
                subject = subj.strip()
                in_body = True
                continue
            if in_body:
                # The "---" line (with optional trailing whitespace) marks
                # the end of the commit message in git-format-patch output.
                if re.match(r'^---\s*$', line):
                    break
                body_lines.append(line)
        if subject:
            body = '\n'.join(body_lines).strip()
            msg = subject + ('\n\n' + body if body else '')
            messages.append(msg)
    return messages


def _resolve_ll_to_source(ll_path: str, root: Path) -> Path:
    """Resolve an LLVM IR .ll path to the corresponding .c/.cpp source file."""
    p = Path(ll_path.split(':')[0]) if ':' in ll_path else Path(ll_path)
    if p.suffix != '.ll':
        full = root / p if not p.is_absolute() else p
        return full if full.exists() else p
    base = p.stem  # e.g. xmlparse
    for ext in ('*.c', '*.cc', '*.cpp', '*.cxx'):
        for src in glob.glob(str(root / '**' / ext), recursive=True):
            if os.path.splitext(os.path.basename(src))[0] == base:
                return Path(src)
    return root / (base + '.c')


def resolve_vuln_context(root: Path, plan: dict, entry: dict) -> dict:
    """Use planner-provided context when available, otherwise analyze the sink source."""
    vuln_context = plan.get('vuln_context') or {}
    if vuln_context:
        return vuln_context

    affected_file = entry.get('affected-file', '')
    affected_function = entry.get('affected-function', '')
    if not affected_file or not affected_function:
        return {}

    source_file = root / affected_file
    if not source_file.exists():
        basename = Path(affected_file).name
        matches = list(root.glob('**/' + basename))
        if matches:
            source_file = matches[0]

    if not source_file.exists():
        return {}

    return analyze_vulnerable_function(source_file, affected_function, debug=False)


def append_section(lines, title):
    lines.append(title)
    lines.append('')


def append_bullets(lines, items, prefix='- '):
    for item in items:
        lines.append(prefix + str(item))
    lines.append('')


def _build_strategy_synthesis(lines, entry, execution_plan):
    """Synthesize a vulnerability-directed strategy section.

    Emits only the CVE advisory description and the call path from the
    public entry point to the sink.  All sink-centric analysis (state fields,
    field conditions, parameter conditions, trigger relations) is intentionally
    omitted — the harness calls the public entry point, not the sink, so
    analysis should focus on entry-point semantics.
    """
    vuln_description = entry.get('description', '')
    call_path = execution_plan.get('call_path', [])

    # Only emit if we have enough info to synthesize something useful
    if not vuln_description and not call_path:
        return

    lines.append("## Vulnerability-Directed Strategy")
    lines.append("")

    if vuln_description:
        lines.append("### Advisory")
        lines.append("")
        lines.append('> ' + vuln_description.replace('\n', '\n> '))
        lines.append("")

    # NOTE: Sink-centric subsections (state fields on vulnerable path,
    # conditions observed in the sink, parameter conditions, trigger
    # relations) are intentionally NOT emitted here.  They describe
    # internal state of the vulnerable function (the sink) which the
    # harness cannot directly control through the public API.

    if call_path:
        lines.append("Call path: " + " → ".join(call_path))
        lines.append("")


def build_harness_prompt(root: Path, plan_path: Path, out_dir: Path) -> Path:
    """
    Build a libFuzzer harness prompt based on a harness_plan.json.
    The prompt instructs the LLM to emit a fuzzer.cc with LLVMFuzzerTestOneInput.
    """
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    entry = plan["vuln_entry"]
    sink_usr = plan["sink_usr"]
    wrapper_path = plan["wrapper_path"]
    usr_to_file = plan["usr_to_file"]
    execution_plan = plan.get('execution_plan', {})
    trigger_plan = plan.get('trigger_plan', {})
    construction_plan = plan.get('construction_plan', {})

    # Dynamic set of sink-internal parameters (computed by callgraph parameter
    # flow tracing in harness_plan).  These names refer to sink function
    # parameters that have NO data-flow path from the public entry point and
    # therefore cannot be influenced by the harness.
    internal_vars = frozenset(
        v.lower() for v in execution_plan.get('sink_internal_params', []) if v
    )

    # Public API names for filtering sink-internal helpers / state fields.
    public_api_names = frozenset(plan.get('public_api_names', []))

    # Extract wrapper function name and file
    wrapper_usr = wrapper_path[0]
    wrapper_loc = usr_to_file.get(wrapper_usr, "")
    
    # Get the public API name from the plan
    public_api_name = plan.get("public_api_name", "")
    usr_to_name = plan.get("usr_to_name", {})
    
    # Get function name from USR if not already available
    if not public_api_name:
        public_api_name = usr_to_name.get(wrapper_usr, wrapper_usr.split('@')[-1].replace('F@', '') if '@' in wrapper_usr else wrapper_usr)
    
    # Resolve wrapper file from .ll to .c if needed
    wrapper_file = _resolve_ll_to_source(wrapper_loc, root) if wrapper_loc else None
    sig_snippet = ""
    entry_source = ""
    if wrapper_file and wrapper_file.exists():
        try:
            # Extract full entry point function body
            entry_source = extract_function_source(wrapper_file, public_api_name)
            if entry_source:
                entry_source = entry_source[:4000]  # Limit size
            # Fallback: extract a signature snippet
            if not entry_source:
                content = wrapper_file.read_text(encoding="utf-8", errors="ignore").splitlines()
                for line in content:
                    if public_api_name in line:
                        idx = content.index(line)
                        start = max(0, idx - 5)
                        end = min(len(content), idx + 15)
                        sig_snippet = "\n".join(content[start:end])
                        break
        except Exception:
            pass

    vuln_analysis = resolve_vuln_context(root, plan, entry)

    # Compute sink-derived noise names: parameter names from the sink's
    # vuln_analysis that are NOT present in the entry-point's parameter_roles.
    # When entry == sink these sets are identical and nothing extra is filtered.
    _sink_roles = vuln_analysis.get('parameter_roles', [])
    _entry_roles = execution_plan.get('parameter_roles', [])
    _sink_pnames = frozenset(r.get('name', '').lower() for r in _sink_roles if r.get('name'))
    _entry_pnames = frozenset(r.get('name', '').lower() for r in _entry_roles if r.get('name'))
    sink_only_names = _sink_pnames - _entry_pnames
    noise_names = internal_vars | sink_only_names

    affected_file = entry.get("affected-file", "")
    affected_function = entry.get("affected-function", "")
    print("[DEBUG] prompt_harness: affected file={} function={}".format(affected_file, affected_function))
    print("[DEBUG] prompt_harness: execution_plan keys={}".format(sorted(execution_plan.keys()) if execution_plan else []))
    
    lines = []
    lines.append("Generate a C++ libFuzzer harness (`fuzzer.cc`) for the vulnerability below.")
    lines.append("The harness must use the library's public API correctly — the vulnerability")
    lines.append("is in the library, not in the harness.")
    lines.append("")
    lines.append("## Vulnerability Information")
    lines.append("")
    # Only include essential fields — exclude noisy raw data (patch_diffs,
    # trigger_condition, enrichment_references, etc.) which are presented
    # in dedicated curated sections below.
    curated_entry = {}
    for k in ('cve-id', 'cwe-id', 'description', 'affected-file',
              'affected-function', 'package-name', 'severity'):
        if entry.get(k):
            curated_entry[k] = entry[k]
    lines.append(json.dumps(curated_entry, indent=2))
    lines.append("")

    # Add vulnerability description if available (from CVE advisory or user-provided)
    vuln_description = entry.get('description', '')
    if vuln_description:
        lines.append("## Vulnerability Description")
        lines.append("")
        lines.append(str(vuln_description))
        lines.append("")

    # Add fix patch context if available (from CVE enrichment)
    patch_diffs = entry.get('patch_diffs', [])

    # Pre-extract trigger function source for protocol synthesis.
    # These are also used later for the source-excerpts section.
    _trigger_function = plan.get('trigger_function', '')
    _path_source_excerpts = plan.get('path_source_excerpts', {})
    _trigger_func_source = _path_source_excerpts.get(_trigger_function, '') if _trigger_function else ''

    # Will be populated below when patches are available.
    commit_messages = []
    filtered_patches = []
    trigger_protocol = {}

    if patch_diffs:
        # Filter multi-commit diffs to only security-relevant patches FIRST,
        # then extract commit messages from the filtered result so that
        # irrelevant commit subjects don't appear in the trigger section.
        vuln_description_str = str(vuln_description) if vuln_description else ""
        afunc = entry.get('affected-function', '')
        for pd in patch_diffs[:2]:
            filtered = _filter_security_patches(pd, description=vuln_description_str,
                                                affected_function=afunc)
            if filtered:
                filtered_patches.append(filtered)
        # Only fall back to original patches if they touch source code;
        # otherwise the entire patch set is non-source (e.g. CONTRIBUTORS.md)
        # and would poison the prompt with garbage context.
        if not filtered_patches:
            source_patches = [pd for pd in patch_diffs[:2]
                              if _sub_patch_touches_source(pd)]
            filtered_patches = source_patches

        # Extract commit messages from security-filtered patches.
        commit_messages = _extract_commit_messages(filtered_patches) if filtered_patches else []
        if commit_messages:
            lines.append("## Trigger Mechanism (from patch commit)")
            lines.append("")
            lines.append("The developer who fixed this bug described the trigger as follows:")
            lines.append("")
            for i, msg in enumerate(commit_messages):
                if len(commit_messages) > 1:
                    lines.append("### Commit {}".format(i + 1))
                lines.append(msg)
                lines.append("")

        if filtered_patches:
            lines.append("## Fix Patch Context")
            lines.append("")
            for i, patch in enumerate(filtered_patches):
                if len(filtered_patches) > 1:
                    lines.append("### Patch {}".format(i + 1))
                lines.append("```diff")
                lines.append(str(patch))
                lines.append("```")
                lines.append("")

    # -- LLM-synthesized Vulnerability Trigger Protocol --
    # Ask the LLM to bridge the gap between the abstract commit message and
    # the concrete API-call / input-pattern sequence needed to trigger the
    # vulnerability through the public entry point.
    cve_id = entry.get('cve-id', '')
    cache_dir = out_dir / 'enrichment_cache' if out_dir else None
    trigger_protocol = synthesize_trigger_protocol(
        commit_messages=commit_messages,
        patch_diff=filtered_patches[0] if filtered_patches else '',
        trigger_function_source=_trigger_func_source,
        entry_function_name=public_api_name,
        entry_function_source=entry_source,
        description=str(vuln_description),
        cache_dir=cache_dir,
        cve_id=cve_id,
    )

    # Persist trigger protocol so the seed generator can use it.
    if trigger_protocol and out_dir:
        tp_path = out_dir / 'context' / 'trigger_protocol.json'
        tp_path.parent.mkdir(parents=True, exist_ok=True)
        tp_path.write_text(json.dumps(trigger_protocol, indent=2), encoding='utf-8')

    if trigger_protocol and trigger_protocol.get('protocol_steps'):
        lines.append("## Vulnerability Trigger Protocol")
        lines.append("")
        key_insight = trigger_protocol.get('key_insight', '')
        if key_insight:
            lines.append("**Key insight:** {}".format(key_insight))
            lines.append("")
        lines.append("To trigger this vulnerability through the public API, the harness MUST:")
        lines.append("")
        for i, step in enumerate(trigger_protocol['protocol_steps'], 1):
            lines.append("{}. {}".format(i, step))
        lines.append("")
        input_req = trigger_protocol.get('input_requirements', '')
        if input_req:
            lines.append("**Input requirements:** {}".format(input_req))
            lines.append("")

    # -- Trigger Condition Analysis (extracted from patch diff) --
    # When the LLM-synthesized trigger protocol is available, it supersedes
    # the regex-based trigger condition analysis (which produces generic
    # patterns like "Vulnerable operation: free" that can conflict with the
    # more specific protocol guidance above).
    trigger_condition = entry.get('trigger_condition', {})
    if trigger_condition and not trigger_protocol.get('protocol_steps'):
        lines.append("## Trigger Condition Analysis")
        lines.append("")

        trigger_summary = trigger_condition.get('trigger_summary', [])
        if trigger_summary:
            lines.append("### What triggers the bug")
            lines.append("")
            for item in trigger_summary:
                lines.append("- {}".format(item))
            lines.append("")

        vuln_lines = trigger_condition.get('vulnerable_lines', [])
        if vuln_lines:
            lines.append("### Vulnerable code (removed by fix)")
            lines.append("```c")
            for vl in vuln_lines[:10]:
                lines.append(vl)
            lines.append("```")
            lines.append("")

        fix_lines = trigger_condition.get('fix_lines', [])
        if fix_lines:
            lines.append("### Fix code (added)")
            lines.append("```c")
            for fl in fix_lines[:10]:
                lines.append(fl)
            lines.append("```")
            lines.append("")

        affected_funcs = trigger_condition.get('affected_functions', [])
        if affected_funcs:
            lines.append("### Functions modified by the fix: {}".format(", ".join(affected_funcs)))
            lines.append("")

    # -- Source Code Sections --
    # NOTE: The vulnerable function (sink) source code is intentionally NOT
    # included.  The harness calls the public entry point, not the sink.
    # Including 5000 chars of sink internals confused the LLM into
    # manipulating internal state instead of exercising the public API.

    if entry_source:
        lines.append("## Entry Point Function Source Code")
        lines.append("")
        lines.append("This is the source code of the public API entry point `{}` that your harness will call:".format(
            public_api_name))
        lines.append("")
        lines.append("```c")
        lines.append(entry_source)
        lines.append("```")
        lines.append("")
        lines.append("Use this to understand how the public API processes input and reaches the vulnerable function.")
        lines.append("")

    # -- Vulnerability-Directed Strategy Synthesis --
    # This section forces the LLM to reason about what SPECIFIC inputs trigger
    # the vulnerability, combining CVE description + static analysis state fields.
    _build_strategy_synthesis(lines, entry, execution_plan)

    # NOTE: The full machine-readable plan JSON is intentionally NOT dumped
    # here.  The human-readable sections below already present the relevant
    # fields in a curated form.  Dumping the raw JSON caused the LLM to
    # focus on generic planner metadata instead of the actual vulnerability.
    if not entry_source and sig_snippet:
        lines.append("## Public API Signature for " + str(public_api_name) + ":")
        lines.append("```c++")
        lines.append(sig_snippet)
        lines.append("```")
        lines.append("")

    # Add call-path semantic analysis section
    call_path_names = execution_plan.get('call_path', [])
    all_call_paths = plan.get('all_call_paths', [])
    trigger_function = plan.get('trigger_function', '')
    path_source_excerpts = plan.get('path_source_excerpts', {})

    if call_path_names and len(call_path_names) >= 2:
        sink_name = entry.get('affected-function', '')
        lines.append("## Call Path")
        lines.append("")
        lines.append("Sink `{}` is reached via: {}".format(sink_name, " -> ".join(call_path_names)))
        lines.append("")

        # Show all discovered paths if more than one
        if len(all_call_paths) > 1:
            lines.append("### All Discovered Call Paths (ranked by taint score)")
            lines.append("")
            for i, pinfo in enumerate(all_call_paths[:8]):
                path = pinfo.get('path', [])
                score = pinfo.get('score', 0)
                flag = " ★ trigger-adjacent" if pinfo.get('has_trigger') else ""
                marker = " ← selected" if i == 0 else ""
                lines.append("  {}. [score={}{}]{} {}".format(
                    i + 1, score, flag, marker, " -> ".join(path)))
            lines.append("")

        # Trigger function info
        if trigger_function:
            lines.append("### Vulnerability Trigger Function: `{}`".format(trigger_function))
            lines.append("")
            lines.append("The function `{}` was modified by the security patch that fixed this CVE.".format(trigger_function))
            if trigger_function not in call_path_names:
                lines.append("It is NOT on the primary call path but is critical for triggering the vulnerability.")
                lines.append("The harness may need to create conditions where `{}` is invoked during normal processing.".format(trigger_function))
            lines.append("")

    # -- Source excerpts for intermediate and trigger functions --
    if path_source_excerpts:
        # Exclude entry and sink (they get their own dedicated sections)
        intermediate_funcs = [f for f in call_path_names[1:-1] if f in path_source_excerpts]
        trigger_excerpt = path_source_excerpts.get(trigger_function, '') if trigger_function else ''

        if intermediate_funcs or trigger_excerpt:
            lines.append("## Intermediate / Trigger Function Source Excerpts")
            lines.append("")
            lines.append("These excerpts show how data flows from the entry point toward the sink,")
            lines.append("and how the vulnerability trigger function processes data.")
            lines.append("")

            for func_name in intermediate_funcs:
                excerpt = path_source_excerpts[func_name]
                lines.append("### `{}` (call-path intermediate)".format(func_name))
                lines.append("```c")
                lines.append(excerpt)
                lines.append("```")
                lines.append("")

            if trigger_excerpt:
                lines.append("### `{}` (patch-affected trigger function)".format(trigger_function))
                lines.append("```c")
                lines.append(trigger_excerpt)
                lines.append("```")
                lines.append("")

    # -- Entry → Sink Parameter Flow (computed from LLVM IR callgraph) --
    param_flow = execution_plan.get('parameter_flow', {})
    if param_flow:
        controlled = param_flow.get('entry_controlled_at_sink', {})
        internal = param_flow.get('sink_internal_params', [])
        entry_params = param_flow.get('entry_params', [])
        sink_params = param_flow.get('sink_params', [])
        if controlled or internal:
            lines.append("## Entry → Sink Parameter Data Flow")
            lines.append("")
            if controlled:
                lines.append("The callgraph shows how entry-function parameters reach the sink:")
                for sink_idx_str, (entry_idx, entry_name) in sorted(
                        controlled.items(), key=lambda kv: int(kv[0])):
                    sink_idx = int(sink_idx_str)
                    sink_pname = sink_params[sink_idx][1] if sink_idx < len(sink_params) else '?'
                    entry_ptype = entry_params[entry_idx][0] if entry_idx < len(entry_params) else '?'
                    lines.append("- Entry `{}` ({}) → sink `{}`".format(
                        entry_name, entry_ptype, sink_pname))
                lines.append("")
            if internal:
                # Skip listing when all names are positional IR placeholders
                # (e.g. param_0 … param_7) — they carry zero semantic signal.
                _has_real_names = any(not re.match(r'^param_\d+$', n) for n in internal)
                if _has_real_names:
                    lines.append("These sink parameters have **NO** data-flow path from the entry point — ")
                    lines.append("they are internal state. Do NOT attempt to control them from the harness:")
                    for name in internal:
                        lines.append("- `{}`".format(name))
                    lines.append("")

    input_model = execution_plan.get('input_model', vuln_analysis.get('input_model', {}))
    workload_model = execution_plan.get('workload_model', vuln_analysis.get('workload_model', {}))
    parameter_roles = execution_plan.get('parameter_roles', vuln_analysis.get('parameter_roles', []))

    sensitive_controls = execution_plan.get('sensitive_controls', [])
    # Collect all known parameter names from both entry and sink roles so we
    # can detect local-variable controls that leaked from the sink analysis.
    _all_known_params = (
        frozenset(r.get('name', '').lower() for r in execution_plan.get('parameter_roles', []) if r.get('name'))
        | frozenset(r.get('name', '').lower() for r in vuln_analysis.get('parameter_roles', []) if r.get('name'))
        | frozenset(f.get('owner', '').lower() for f in vuln_analysis.get('state_fields', []) if f.get('owner'))
    )
    # Filter out internal-only controls AND local-variable controls that
    # the harness cannot influence through public API calls.
    sensitive_controls = [
        c for c in sensitive_controls
        if c.get('target', '').lower() not in noise_names
        and (
            '->' in c.get('target', '') or '.' in c.get('target', '')
            or c.get('target', '').lower() in _all_known_params
        )
    ]
    # When entry != sink, suppress sensitive_controls if ALL surviving items
    # are struct-field accesses with no overlap with the entry's own params.
    _entry_is_sink = (execution_plan.get('entry_function', '') == execution_plan.get('sink_function', ''))
    if sensitive_controls and not _entry_is_sink:
        if not any(c.get('target', '').lower() in _entry_pnames for c in sensitive_controls):
            sensitive_controls = []
    setup_state_profiles = execution_plan.get('setup_state_profiles', [])
    trigger_relations = execution_plan.get('trigger_relations', [])
    # Filter out relations involving sink-internal or sink-only function variables
    trigger_relations = [
        r for r in trigger_relations
        if r.get('controller', '').lower() not in noise_names
        and r.get('dependent', '').split('->')[-1].strip().lower() not in noise_names
    ]
    # Suppress when entry != sink and no controller/dependent overlaps entry params
    if trigger_relations and not _entry_is_sink:
        if not any(
            r.get('controller', '').lower() in _entry_pnames
            or r.get('dependent', '').split('->')[-1].strip().lower() in _entry_pnames
            for r in trigger_relations
        ):
            trigger_relations = []
    trigger_controls = execution_plan.get('trigger_controls', [])
    trigger_controls = [
        t for t in trigger_controls
        if t.lower() not in noise_names
        and (
            '->' in t or '.' in t
            or t.lower() in _all_known_params
        )
    ]
    # Suppress when entry != sink and no control overlaps entry params
    if trigger_controls and not _entry_is_sink:
        if not any(t.lower() in _entry_pnames for t in trigger_controls):
            trigger_controls = []
    required_setup_calls = execution_plan.get('required_setup_calls', [])
    support_object_construction = execution_plan.get('support_object_construction', [])
    support_object_field_constraints = execution_plan.get('support_object_field_constraints', [])
    setup_requirements = execution_plan.get('setup_requirements', [])
    call_sequence = execution_plan.get('call_sequence', [])
    # NOTE: milestone_plan, sink_live_predicates, active_data_plan,
    # stage_contracts, deferred_stages, retrieved_stage_evidence,
    # and input_segments are intentionally NOT extracted or forwarded to
    # the prompt — they produced library-agnostic boilerplate
    # (lookup-table, transform-gating, generic predicates, etc.).
    constraints = execution_plan.get('constraints', [])
    coverage_goals = execution_plan.get('coverage_goals', [])
    sink_role = trigger_plan.get('sink_role', '')

    append_section(lines, "## Harness Construction Logic")
    if input_model:
        lines.append("Primary input model: {}".format(input_model.get('primary', 'raw-buffer')))
        if input_model.get('secondary'):
            lines.append("Secondary traits: {}".format(', '.join(input_model.get('secondary', []))))
        if input_model.get('evidence'):
            lines.append("Why this matters:")
            append_bullets(lines, input_model.get('evidence', []))

    if workload_model:
        # Only emit workload model if it has meaningful operators (not just
        # the generic 'control-biased' which causes byte-extraction patterns).
        operators = [o for o in workload_model.get('operators', []) if o != 'control-biased']
        if operators:
            lines.append("Workload shaping operators: {}".format(', '.join(operators)))
            # Only emit evidence when there are non-generic operators;
            # otherwise the evidence text pushes toward byte-extraction.
            if workload_model.get('evidence'):
                lines.append("Workload evidence:")
                append_bullets(lines, workload_model.get('evidence', []))

    if parameter_roles:
        lines.append("Parameter roles for the target API:")
        for role in parameter_roles:
            lines.append("- {name} ({type}): {role}. Harness strategy: {strategy}.".format(
                name=role.get('name', 'param'),
                type=role.get('type', 'unknown'),
                role=role.get('role', 'value'),
                strategy=role.get('strategy', 'provide a conservative valid value')
            ))
        lines.append("")

    # NOTE: input_segments intentionally omitted.  The planner's generic
    # segment prescription (selector / trigger-controls / bounded-lengths /
    # payload / control-bias) was causing the LLM to generate rigid
    # FuzzCursor-style byte-extraction harnesses regardless of the CVE.
    # The LLM should decide input structure from the CVE context.

    if sensitive_controls:
        lines.append("Most sensitive controls or state selectors:")
        for item in sensitive_controls[:6]:
            reason_text = '; '.join(item.get('reasons', [])[:2])
            lines.append("- {target} ({kind}, score={score}): {reasons}.".format(
                target=item.get('target', 'control'),
                kind=item.get('source_kind', 'parameter'),
                score=item.get('score', 0),
                reasons=reason_text or 'high inferred influence on sink reachability'
            ))
        lines.append("")

    if trigger_controls:
        lines.append("Trigger controls to vary deliberately:")
        append_bullets(lines, trigger_controls[:8])

    if trigger_relations:
        lines.append("Trigger relations to satisfy explicitly:")
        for relation in trigger_relations[:8]:
            lines.append("- {kind}: vary {dependent} relative to {controller}. Evidence: {evidence}. Expectation: {expectation}.".format(
                kind=relation.get('kind', 'relation'),
                dependent=relation.get('dependent', 'dependent'),
                controller=relation.get('controller', 'controller'),
                evidence=relation.get('evidence', 'planner inference'),
                expectation=relation.get('harness_expectation', 'exercise the inferred relation')
            ))
        lines.append("")

    if setup_state_profiles:
        lines.append("Setup-state ranking guidance:")
        for profile in setup_state_profiles[:4]:
            lines.append("- {name} [{priority}]: {rationale}".format(
                name=profile.get('name', 'setup-state-profile'),
                priority=profile.get('priority', 'high'),
                rationale=profile.get('ranking_rationale', 'prefer the most liveness-preserving setup controls first')
            ))
            for item in profile.get('preferred_properties', [])[:3]:
                lines.append("- {}".format(item))
        lines.append("")

    setup_requirements = _filter_noise(setup_requirements)
    if setup_requirements:
        lines.append("Setup requirements that should remain valid while fuzzing trigger controls:")
        append_bullets(lines, setup_requirements[:6])

    if required_setup_calls:
        lines.append("Mandatory setup or registration calls inferred from sink-gating state:")
        for item in required_setup_calls[:6]:
            lines.append("- {name} ({phase}): {reason}.".format(
                name=item.get('name', 'setup-call'),
                phase=item.get('phase', 'setup'),
                reason=item.get('reason', 'establish sink-gating state before the target API is exercised')
            ))
        lines.append("")

    # NOTE: activation_predicates, invariant_requirements, and
    # exploration_policy are intentionally omitted.  They are derived from
    # SINK analysis (the vulnerable function's internal state) and reference
    # parameters/fields the harness cannot control through the public API.
    # Including them pushes the LLM toward imaginary byte-extraction or
    # struct-manipulation patterns.

    # Collect setup/config API candidates only from non-transform phases.
    # configure-transform candidates are internal stage evidence (e.g.
    # callback registration APIs inferred from the source) — leaking them
    # as "setup APIs" confuses the LLM.
    _setup_api_candidates = []
    if call_sequence:
        lines.append("Required call sequence:")
        for step in call_sequence:
            phase = step.get('phase', 'step')
            goal = step.get('goal', 'perform the required API step')
            # Skip configure-transform phase — planner boilerplate that
            # pushes the LLM toward imaginary transform steps.
            if _is_planner_noise(goal) or 'configure-transform' in phase:
                continue
            # Only collect candidates from non-transform phases
            for c in step.get('candidates', []):
                if c and not _is_planner_noise(c):
                    _setup_api_candidates.append(c)
            lines.append("- {phase}: {goal}.".format(phase=phase, goal=goal))
        lines.append("")

    # Emit setup/config API candidates discovered from the callgraph
    if _setup_api_candidates:
        # Deduplicate while preserving order
        _seen_apis = set()
        _unique_apis = []
        for api in _setup_api_candidates:
            if api not in _seen_apis:
                _seen_apis.add(api)
                _unique_apis.append(api)
        if _unique_apis:
            lines.append("Suggested configuration/setup APIs (from callgraph):")
            for api in _unique_apis:
                lines.append("- {}".format(api))
            lines.append("")

    # NOTE: milestone_plan, sink_live_predicates, and active_data_plan are
    # intentionally omitted — the planner generates library-agnostic
    # boilerplate ("lookup-table", "transform-gating", generic predicates)
    # that confuses the LLM.  The vulnerability context (description, patch,
    # call path, source code) already tells the LLM what it needs.

    # NOTE: The trigger plan (sink_role, cleanup-specific lifecycle profiles,
    # failure modes from sink scanning, ownership transitions, trigger hints)
    # is intentionally NOT emitted.  These are all derived from the sink
    # function's internal analysis.  The harness exercises the public entry
    # point, so sink-centric trigger strategy is noise.

    if construction_plan:
        # Collect bullets; only emit the header when content survives filtering.
        cp_bullets = []
        if construction_plan.get('support_objects'):
            for item in _filter_noise(construction_plan.get('support_objects', []))[:5]:
                cp_bullets.append("- Support object {} ({}) is required: {}.".format(
                    item.get('name', 'support-object'),
                    item.get('kind', 'object'),
                    item.get('reason', 'provide a valid backing object')
                ))
        if construction_plan.get('required_setup_calls'):
            setup_lines = []
            for item in construction_plan.get('required_setup_calls', [])[:5]:
                setup_lines.append("- Call {} before the target API because {}.".format(
                    item.get('name', 'setup-call'),
                    item.get('reason', 'it establishes sink-gating state')
                ))
            if setup_lines:
                cp_bullets.append("- Required setup-call contract:")
                cp_bullets.extend(setup_lines)
        if construction_plan.get('support_object_construction'):
            soc_lines = []
            for item in construction_plan.get('support_object_construction', [])[:5]:
                soc_lines.append("- {} [{}]: {}.".format(
                    item.get('name', 'support-object'),
                    item.get('kind', 'support-object'),
                    item.get('expectation', item.get('reason', 'construct and initialize it before invoking the sink path'))
                ))
            if soc_lines:
                cp_bullets.append("- Support-object construction obligations:")
                cp_bullets.extend(soc_lines)
        if construction_plan.get('support_object_field_constraints'):
            sofc_lines = []
            for item in construction_plan.get('support_object_field_constraints', [])[:5]:
                sofc_lines.append("- {}".format(item.get('constraint', 'populate required support-object fields before the sink path is exercised')))
            if sofc_lines:
                cp_bullets.extend(sofc_lines)
        if construction_plan.get('helper_preconditions'):
            filtered_hp = _filter_noise(construction_plan.get('helper_preconditions', []))
            if filtered_hp:
                cp_bullets.append("- Helper/API preconditions:")
                for hp in filtered_hp[:6]:
                    cp_bullets.append("  - " + str(hp))
        # NOTE: sink_activation_conditions intentionally omitted — they
        # describe conditions for activating the SINK, not the entry point.

        if cp_bullets:
            lines.append("Construction requirements:")
            lines.extend(cp_bullets)
            lines.append("")
        # NOTE: stage_contracts, deferred-stage execution checklists,
        # construction_plan active_data_plan, valid_prefix_requirements,
        # control_prefix_policy, late_malformed_regions, and forbidden_shortcuts
        # are intentionally NOT included.  These planner-generated sections
        # were producing library-agnostic boilerplate (lookup-table, transform-
        # config, XML_ErrorString as placement candidates, etc.) that confused
        # the LLM into generating overly complex, formulaic harnesses instead
        # of vulnerability-specific ones.

    # NOTE: Sink-centric state fields, helper calls, and coverage goals are
    # intentionally NOT emitted.  They describe the vulnerable function's
    # internal state (the sink) which the harness cannot directly control.
    # The harness calls the public entry point, so only entry-centric
    # information (parameter roles, input model, call sequence) is useful.

    append_section(lines, "## Constraints")
    forbidden = [
        "Do not fabricate opaque library structs on the stack or zero-initialize internal state types manually — use the library's public constructors.",
        "Do not derive unbounded allocation sizes directly from attacker-controlled bytes.",
        "Do not ignore required setup or finalize phases if the execution plan indicates a stateful lifecycle."
    ]
    if construction_plan.get('support_objects'):
        forbidden.append("Do not pass nullptr/NULL placeholders to helper or transform APIs when the construction plan requires a real support object.")
    append_bullets(lines, forbidden)

    if constraints:
        constraints = [c for c in constraints
                       if not _is_planner_noise(c) and not _mentions_internal_var(c, noise_names)]
        if constraints:
            append_bullets(lines, constraints)

    # NOTE: Vulnerable Path Semantics (insights) and Concrete execution hints
    # are intentionally NOT emitted.  They are derived from the sink function's
    # internal analysis and reference parameters/state the harness cannot
    # control through the public API entry point.

    lines.append("## Output Format")
    lines.append("")
    lines.append("Generate a single C++ file `fuzzer.cc` containing:")
    lines.append("```c++")
    lines.append('extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {')
    lines.append("    // Your harness code here")
    lines.append("    return 0;")
    lines.append("}")
    lines.append("```")
    lines.append("")
    lines.append("Include the correct public API headers. Initialize state properly, call the")
    lines.append("target function, and clean up resources. The harness must be correct C++ code")
    lines.append("tailored to the specific vulnerability described above.")
    if public_api_name:
        lines.append("")
        lines.append("Target function: `" + str(public_api_name) + "()`")
    lines.append("")
    lines.append("Generate ONLY the C++ code. No explanation, no markdown, no placeholders, no TODO comments.")
    
    # Write prompt
    ctx = out_dir / "context"
    ctx.mkdir(parents=True, exist_ok=True)
    prompt_path = ctx / "prompt.harness.md"
    prompt_path.write_text("\n".join(lines), encoding="utf-8")
    return prompt_path

def main():
    parser = argparse.ArgumentParser(description="Build harness prompt for LLM")
    parser.add_argument("--root", required=True, help="Project root")
    parser.add_argument("--plan", required=True, help="Path to harness_plan.json")
    parser.add_argument("--out", required=True, help="Output directory for prompt")
    args = parser.parse_args()
    root = Path(args.root)
    plan = Path(args.plan)
    out = Path(args.out)
    prompt = build_harness_prompt(root, plan, out)
    print("Prompt written to " + str(prompt))

if __name__ == "__main__":
    from pathlib import Path
    main()