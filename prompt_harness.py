#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from vuln_analyzer import analyze_vulnerable_function

# Generic CWE-based test patterns - library-agnostic vulnerability guidance
# These guide how to exercise library code, NOT how to write buggy harness code
CWE_TEST_PATTERNS = {
    "CWE-476": {  # NULL Pointer Dereference
        "name": "NULL Pointer Dereference",
        "test_focus": "Exercise code paths that may not handle NULL properly",
        "harness_guidance": [
            "Initialize all required objects and handles properly (e.g., open database, allocate memory)",
            "Pass fuzzer input as data/parameters to the API, NOT as object pointers",
            "The library may have internal NULL checks that are missing - let it handle edge cases",
            "Test with empty input, minimal input, and truncated input",
        ],
        "input_transforms": [
            "Empty input (size == 0)",
            "Single byte input",
            "Input with embedded NULLs",
            "Input with special characters",
        ],
    },
    "CWE-125": {  # Out-of-bounds Read
        "name": "Out-of-bounds Read",
        "test_focus": "Input size variations to trigger buffer overreads",
        "harness_guidance": [
            "Properly initialize all required structures",
            "Pass fuzzer input directly to the vulnerable API",
            "Let the fuzzer explore various input sizes",
            "The library may read past buffer end - your harness should just provide varied inputs",
            "CRITICAL: Do NOT null-terminate or pad the buffer beyond the declared length. "
            "Allocate EXACTLY the declared size so that any overread lands in unallocated memory and is caught by AddressSanitizer. "
            "Adding a null byte or extra allocation past the declared length masks the very bug you are trying to trigger.",
        ],
        "input_transforms": [
            "Very small inputs (0-4 bytes)",
            "Medium inputs (128-512 bytes)",
            "Large inputs (4KB+)",
            "Inputs at boundary sizes (1023, 1024, 1025)",
        ],
    },
    "CWE-121": {  # Stack-based Buffer Overflow
        "name": "Stack-based Buffer Overflow",
        "test_focus": "Large inputs that may overflow stack buffers",
        "harness_guidance": [
            "Initialize the library properly before testing",
            "Pass large inputs from the fuzzer to API functions that copy to stack buffers",
            "No special handling needed - the fuzzer will generate large inputs naturally",
        ],
        "input_transforms": [
            "Inputs larger than common buffer sizes (256, 512, 1024, 4096)",
            "Repeated patterns",
            "All-zeros and all-0xff patterns",
        ],
    },
    "CWE-122": {  # Heap-based Buffer Overflow
        "name": "Heap-based Buffer Overflow",
        "test_focus": "Size mismatches in heap operations",
        "harness_guidance": [
            "Call library init/cleanup functions properly",
            "Pass size-related data from fuzzer input to the API",
            "The library may miscalculate allocation sizes based on input",
        ],
        "input_transforms": [
            "Input with embedded size fields",
            "Input with size mismatches",
            "Input with large size values",
        ],
    },
    "CWE-416": {  # Use After Free
        "name": "Use After Free",
        "test_focus": "Object lifetime and multiple operations",
        "harness_guidance": [
            "Call library init functions to create valid objects",
            "Perform multiple operations in sequence using the same objects",
            "The library may free objects internally and access them later",
            "Sequence operations based on fuzzer input",
        ],
        "input_transforms": [
            "First byte selects operation sequence",
            "Multiple operations on the same handle",
            "Open/create, use, and close operations in sequence",
        ],
    },
    "CWE-119": {  # Buffer Errors (generic)
        "name": "Buffer Error",
        "test_focus": "Input size variations",
        "harness_guidance": [
            "Initialize library state properly",
            "Pass varied inputs from fuzzer to the API",
        ],
        "input_transforms": [
            "Various input sizes",
            "Edge case sizes (0, 1, max-1, max, max+1)",
        ],
    },
    "CWE-190": {  # Integer Overflow
        "name": "Integer Overflow",
        "test_focus": "Numeric values or element counts that may cause overflow",
        "harness_guidance": [
            "Analyze the call path function names to determine WHAT is being counted or sized",
            "If the overflow is in a function that processes structured elements (attributes, fields, "
            "entries, rows, columns), generate inputs with a LARGE NUMBER of those elements",
            "If the path processes XML/HTML attributes, generate elements with many attributes "
            "(especially namespace-prefixed ones like xmlns:a, xmlns:b, a:x, b:y)",
            "If the path processes list/array entries, generate inputs with many entries",
            "The overflow is typically in a size/count calculation, not in a user-supplied integer - "
            "the fuzzer must force the LIBRARY to compute a large count from structured input",
            "Pass these values to API functions that perform arithmetic",
            "The library may overflow when calculating sizes or counts internally",
        ],
        "input_transforms": [
            "Structured input with many repeated elements (attributes, fields, entries)",
            "Input that forces large internal counters near power-of-2 boundaries",
            "Values near INT_MAX, UINT_MAX",
            "Large length fields or element counts",
        ],
    },
    "CWE-787": {  # Out-of-bounds Write
        "name": "Out-of-bounds Write",
        "test_focus": "Writes past buffer boundaries",
        "harness_guidance": [
            "Provide valid input buffers to the API",
            "The library may write past the end of buffers",
        ],
        "input_transforms": [
            "Short buffers with long expected sizes",
            "Input at boundary sizes",
        ],
    },
}

def get_cwe_guidance(cwe_id: str) -> dict:
    """Get CWE-specific guidance for harness generation."""
    if not cwe_id:
        return {}
    # Normalize CWE ID (handle both "CWE-476" and "476" formats)
    normalized = cwe_id.upper()
    if not normalized.startswith("CWE-"):
        normalized = "CWE-" + normalized
    return CWE_TEST_PATTERNS.get(normalized, {})


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

    # Extract wrapper function name and file
    wrapper_usr = wrapper_path[0]
    wrapper_loc = usr_to_file.get(wrapper_usr, "")
    
    # Get the public API name from the plan
    public_api_name = plan.get("public_api_name", "")
    usr_to_name = plan.get("usr_to_name", {})
    
    # Get function name from USR if not already available
    if not public_api_name:
        public_api_name = usr_to_name.get(wrapper_usr, wrapper_usr.split('@')[-1].replace('F@', '') if '@' in wrapper_usr else wrapper_usr)
    
    # Function signature snippet
    wrapper_file = root / wrapper_loc.split(":")[0] if wrapper_loc else None
    sig_snippet = ""
    if wrapper_file and wrapper_file.exists():
        try:
            content = wrapper_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            # include first 10 lines around function definition
            for line in content:
                if wrapper_usr in line or public_api_name in line:
                    idx = content.index(line)
                    start = max(0, idx - 5)
                    end = min(len(content), idx + 5)
                    sig_snippet = "\n".join(content[start:end])
                    break
        except Exception:
            pass

    # Get CWE-specific guidance
    cwe_id = entry.get("cwe-id", "")
    cwe_guidance = get_cwe_guidance(cwe_id)
    vuln_analysis = resolve_vuln_context(root, plan, entry)
    affected_file = entry.get("affected-file", "")
    affected_function = entry.get("affected-function", "")
    print("[DEBUG] prompt_harness: affected file={} function={}".format(affected_file, affected_function))
    print("[DEBUG] prompt_harness: execution_plan keys={}".format(sorted(execution_plan.keys()) if execution_plan else []))
    
    lines = []
    lines.append("You are to generate a C++ libFuzzer harness for a C/C++ library vulnerability.")
    lines.append("")
    lines.append("## IMPORTANT: Write CORRECT, BUG-FREE Harness Code")
    lines.append("")
    lines.append("Your harness must be valid, correct code that uses the library's public API properly.")
    lines.append("Do NOT intentionally introduce bugs (NULL pointers, use-after-free, etc.) in your harness.")
    lines.append("The VULNERABILITY is in the library - your harness should exercise the library correctly.")
    lines.append("The fuzzer's inputs will trigger library bugs through normal API usage.")
    lines.append("")
    lines.append("## Vulnerability Information")
    lines.append("")
    lines.append("The vulnerability is described as follows:")
    lines.append(json.dumps(entry, indent=2))
    lines.append("")

    # Add vulnerability description if available (from CVE advisory or user-provided)
    vuln_description = entry.get('description', '')
    if vuln_description:
        lines.append("## Vulnerability Description (from advisory)")
        lines.append("")
        lines.append("**CRITICAL — read this carefully and shape the harness accordingly:**")
        lines.append("")
        lines.append(str(vuln_description))
        lines.append("")
        lines.append("The harness MUST generate inputs that exercise the specific trigger condition")
        lines.append("described above, not just generic inputs to the public API.")
        lines.append("")

    # Add CWE-specific guidance if available
    if cwe_guidance:
        lines.append("## CWE-Specific Testing Strategy: " + str(cwe_guidance.get('name', cwe_id)))
        lines.append("**Test Focus**: " + str(cwe_guidance.get('test_focus', 'General testing')))
        lines.append("")
        lines.append("**How to exercise this vulnerability type in the library:**")
        for guidance in cwe_guidance.get("harness_guidance", []):
            lines.append("- " + str(guidance))
        lines.append("")
        if cwe_guidance.get("input_transforms"):
            lines.append("**Input transformations to consider:**")
            for transform in cwe_guidance["input_transforms"]:
                lines.append("- " + str(transform))
            lines.append("")

    append_section(lines, "## Harness Plan (machine-readable):")
    lines.append(json.dumps({
        "sink_usr": sink_usr,
        "public_wrapper_usr": wrapper_usr,
        "wrapper_location": wrapper_loc,
        "call_path": plan["wrapper_path"],
        "execution_plan": execution_plan,
        "trigger_plan": trigger_plan,
        "construction_plan": construction_plan,
    }, indent=2))
    lines.append("")
    if sig_snippet:
        lines.append("## Public API Signature for " + str(public_api_name) + ":")
        lines.append("```c++")
        lines.append(sig_snippet)
        lines.append("```")
        lines.append("")

    # Add call-path semantic analysis section
    call_path_names = execution_plan.get('call_path', [])
    if call_path_names and len(call_path_names) >= 2:
        sink_name = entry.get('affected-function', '')
        lines.append("## Call-Path Semantic Analysis")
        lines.append("")
        lines.append("The vulnerability sink `{}` is reached via the following call path:".format(sink_name))
        lines.append("  " + " -> ".join(call_path_names))
        lines.append("")
        lines.append("**IMPORTANT**: Analyze each function name in this path for domain semantics.")
        lines.append("Function names reveal what kind of input triggers the vulnerability:")
        lines.append("- Names containing 'Attr', 'Atts', 'attribute' suggest the sink processes element attributes")
        lines.append("- Names containing 'Content', 'Element', 'Node' suggest structured document elements")
        lines.append("- Names containing 'Parse', 'Read', 'Decode' suggest input processing stages")
        lines.append("- Names containing 'Store', 'Alloc', 'Realloc' suggest memory operations that may overflow")
        lines.append("- Names containing 'NS', 'Namespace', 'Prefix' suggest namespace handling")
        lines.append("")
        lines.append("Use these semantic cues to craft inputs that specifically exercise the path through all")
        lines.append("intermediate functions, not just generic inputs to the entry API.")
        lines.append("")
        cwe_id_raw = (entry.get('cwe-id') or '').upper().replace('CWE-', '')
        if cwe_id_raw == '190':
            lines.append("**Integer Overflow Path Guidance**: Since this is an integer overflow vulnerability,")
            lines.append("the sink function needs inputs that force *many iterations* or *large counts* through the")
            lines.append("processing path. If the path processes structured elements (attributes, fields, entries),")
            lines.append("generate inputs with a *large number* of those elements to trigger the overflow.")
            lines.append("")

    input_model = execution_plan.get('input_model', vuln_analysis.get('input_model', {}))
    workload_model = execution_plan.get('workload_model', vuln_analysis.get('workload_model', {}))
    parameter_roles = execution_plan.get('parameter_roles', vuln_analysis.get('parameter_roles', []))
    sensitive_controls = execution_plan.get('sensitive_controls', vuln_analysis.get('sensitive_controls', []))
    setup_state_profiles = execution_plan.get('setup_state_profiles', vuln_analysis.get('setup_state_profiles', []))
    trigger_relations = execution_plan.get('trigger_relations', vuln_analysis.get('trigger_relations', []))
    trigger_controls = execution_plan.get('trigger_controls', vuln_analysis.get('trigger_controls', []))
    required_setup_calls = execution_plan.get('required_setup_calls', vuln_analysis.get('required_setup_calls', []))
    activation_predicates = execution_plan.get('activation_predicates', vuln_analysis.get('activation_predicates', []))
    support_object_construction = execution_plan.get('support_object_construction', vuln_analysis.get('support_object_construction', []))
    support_object_field_constraints = execution_plan.get('support_object_field_constraints', vuln_analysis.get('support_object_field_constraints', []))
    setup_requirements = execution_plan.get('setup_requirements', vuln_analysis.get('setup_requirements', []))
    invariant_requirements = execution_plan.get('invariant_requirements', vuln_analysis.get('invariant_requirements', []))
    exploration_policy = execution_plan.get('exploration_policy', vuln_analysis.get('exploration_policy', []))
    call_sequence = execution_plan.get('call_sequence', [])
    input_segments = execution_plan.get('input_segments', [])
    milestone_plan = execution_plan.get('milestone_plan', [])
    sink_live_predicates = execution_plan.get('sink_live_predicates', vuln_analysis.get('sink_live_predicates', []))
    active_data_plan = execution_plan.get('active_data_plan', vuln_analysis.get('active_data_plan', {}))
    stage_contracts = execution_plan.get('stage_contracts', {})
    deferred_stages = execution_plan.get('deferred_stages', [])
    retrieved_stage_evidence = execution_plan.get('retrieved_stage_evidence', {})
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
        lines.append("Workload shaping operators: {}".format(', '.join(workload_model.get('operators', []))))
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

    if input_segments:
        lines.append("Use the fuzzer input in these semantic segments:")
        for segment in input_segments:
            lines.append("- {name}: {source}. Purpose: {purpose}.".format(
                name=segment.get('name', 'segment'),
                source=segment.get('source', 'fuzzer bytes'),
                purpose=segment.get('purpose', 'shape the API inputs')
            ))
        lines.append("")

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

    if activation_predicates:
        lines.append("Field-gated activation predicates to satisfy before sink-oriented fuzzing:")
        for item in activation_predicates[:6]:
            lines.append("- {target} {operator} {value} [{importance}].".format(
                target=item.get('target', 'field'),
                operator=item.get('operator', '!='),
                value=item.get('value', 'required-value'),
                importance=item.get('importance', 'medium')
            ))
        lines.append("")

    if invariant_requirements:
        lines.append("Invariants to preserve while exploring trigger relations:")
        append_bullets(lines, invariant_requirements[:6])

    if exploration_policy:
        lines.append("Exploration policy:")
        for policy in exploration_policy:
            lines.append("- {target} [{kind}] -> {policy}: {rationale}.".format(
                target=policy.get('target', 'workload'),
                kind=policy.get('kind', 'value'),
                policy=policy.get('policy', 'stabilize'),
                rationale=policy.get('rationale', 'focus fuzzing effort deliberately')
            ))
        lines.append("")

    if call_sequence:
        lines.append("Required call sequence:")
        for step in call_sequence:
            candidate_text = ''
            if step.get('candidates'):
                candidate_text = ' Candidate functions: {}.'.format(', '.join(step.get('candidates', [])[:6]))
            lines.append("- {phase}: {goal}.{candidates}".format(
                phase=step.get('phase', 'step'),
                goal=step.get('goal', 'perform the required API step'),
                candidates=candidate_text
            ))
        lines.append("")

    if milestone_plan:
        lines.append("Required milestones before the sink is plausibly live:")
        for milestone in milestone_plan:
            lines.append("- {name} [{kind}]: {goal}. Evidence: {evidence}. Harness expectation: {expectation}.".format(
                name=milestone.get('name', 'milestone'),
                kind=milestone.get('kind', 'lifecycle'),
                goal=milestone.get('goal', 'satisfy this milestone before sink-focused fuzzing'),
                evidence=', '.join(milestone.get('evidence', [])[:4]) or 'planner inference',
                expectation=milestone.get('harness_expectation', 'make this state true before expecting the sink')
            ))
        lines.append("")

    if sink_live_predicates:
        lines.append("Sink-live predicates:")
        append_bullets(lines, sink_live_predicates[:8])

    if active_data_plan:
        lines.append("Active data plan:")
        if active_data_plan.get('mutable_regions'):
            lines.append("- High-value mutable regions:")
            for item in active_data_plan.get('mutable_regions', [])[:8]:
                lines.append("- {name} [{kind}, priority={priority}]: {reason}.".format(
                    name=item.get('name', 'mutable-region'),
                    kind=item.get('kind', 'buffer'),
                    priority=item.get('priority', 'medium'),
                    reason=item.get('reason', 'this region influences sink-adjacent behavior')
                ))
        if active_data_plan.get('stabilized_regions'):
            lines.append("- Stabilized regions:")
            for item in active_data_plan.get('stabilized_regions', [])[:6]:
                lines.append("- {name} [{kind}]: {reason}.".format(
                    name=item.get('name', 'stabilized-region'),
                    kind=item.get('kind', 'structure'),
                    reason=item.get('reason', 'keep this valid so the sink remains reachable')
                ))
        if active_data_plan.get('derived_regions'):
            lines.append("- Derived regions:")
            for item in active_data_plan.get('derived_regions', [])[:6]:
                lines.append("- {name} [{kind}]: {reason}.".format(
                    name=item.get('name', 'derived-region'),
                    kind=item.get('kind', 'derived'),
                    reason=item.get('reason', 'derive this from surrounding data to preserve consistency')
                ))
        if active_data_plan.get('consistency_constraints'):
            lines.append("- Consistency constraints:")
            append_bullets(lines, active_data_plan.get('consistency_constraints', [])[:8])
        if active_data_plan.get('entropy_guidance'):
            lines.append("- Entropy guidance:")
            append_bullets(lines, active_data_plan.get('entropy_guidance', [])[:6])

    if trigger_plan:
        lines.append("Trigger strategy:")
        if trigger_plan.get('sink_role'):
            lines.append("- Sink role: {}.".format(trigger_plan.get('sink_role')))
        for profile in trigger_plan.get('lifecycle_profiles', [])[:3]:
            lines.append("- Lifecycle profile {}: {}.".format(
                profile.get('name', 'profile'),
                profile.get('goal', 'exercise the sink under this state shape')
            ))
        if trigger_plan.get('cleanup_preconditions'):
            lines.append("- Important preconditions before the sink: {}.".format(', '.join(trigger_plan.get('cleanup_preconditions', [])[:4])))
        if trigger_plan.get('failure_modes'):
            lines.append("- Failure/partial-init cues: {}.".format(' | '.join(trigger_plan.get('failure_modes', [])[:3])))
        if trigger_plan.get('ownership_transitions'):
            lines.append("- Resource transitions to exercise: {}.".format(', '.join(trigger_plan.get('ownership_transitions', [])[:4])))
        if trigger_plan.get('trigger_hints'):
            lines.append("- Trigger hints:")
            append_bullets(lines, trigger_plan.get('trigger_hints', [])[:6])
        else:
            lines.append("")

    if construction_plan:
        lines.append("Construction requirements:")
        if construction_plan.get('support_objects'):
            for item in construction_plan.get('support_objects', [])[:5]:
                lines.append("- Support object {} ({}) is required: {}.".format(
                    item.get('name', 'support-object'),
                    item.get('kind', 'object'),
                    item.get('reason', 'provide a valid backing object')
                ))
        if construction_plan.get('required_setup_calls'):
            lines.append("- Required setup-call contract:")
            for item in construction_plan.get('required_setup_calls', [])[:5]:
                lines.append("- Call {} before the target API because {}.".format(
                    item.get('name', 'setup-call'),
                    item.get('reason', 'it establishes sink-gating state')
                ))
            lines.append("")
        if construction_plan.get('support_object_construction'):
            lines.append("- Support-object construction obligations:")
            for item in construction_plan.get('support_object_construction', [])[:5]:
                lines.append("- {} [{}]: {}.".format(
                    item.get('name', 'support-object'),
                    item.get('kind', 'support-object'),
                    item.get('expectation', item.get('reason', 'construct and initialize it before invoking the sink path'))
                ))
            lines.append("")
        if construction_plan.get('support_object_field_constraints'):
            lines.append("- Support-object field constraints:")
            for item in construction_plan.get('support_object_field_constraints', [])[:5]:
                lines.append("- {}".format(item.get('constraint', 'populate required support-object fields before the sink path is exercised')))
            lines.append("")
        if construction_plan.get('helper_preconditions'):
            lines.append("- Helper/API preconditions:")
            append_bullets(lines, construction_plan.get('helper_preconditions', [])[:6])
        if construction_plan.get('sink_activation_conditions'):
            lines.append("- Sink activation conditions:")
            append_bullets(lines, construction_plan.get('sink_activation_conditions', [])[:6])
        if stage_contracts:
            for stage_name in deferred_stages:
                stage_contract = stage_contracts.get(stage_name, {})
                if not stage_contract:
                    continue
                has_items = any(stage_contract.get(field) for field in [
                    'required_setup_calls',
                    'support_object_construction',
                    'support_object_field_constraints',
                    'setup_requirements',
                    'sink_activation_conditions',
                    'milestone_hints',
                ])
                if not has_items:
                    continue
                lines.append("- Deferred {}-stage obligations:".format(stage_name))
                for item in stage_contract.get('required_setup_calls', [])[:4]:
                    lines.append("- {} stage setup call {}: {}.".format(
                        stage_name,
                        item.get('name', 'setup-call'),
                        item.get('reason', 'establish this stage only after earlier milestones are satisfied')
                    ))
                for item in stage_contract.get('support_object_construction', [])[:4]:
                    lines.append("- {} stage support object {}: {}.".format(
                        stage_name,
                        item.get('name', 'support-object'),
                        item.get('expectation', item.get('reason', 'construct it only when this later stage is being enabled'))
                    ))
                for item in stage_contract.get('support_object_field_constraints', [])[:4]:
                    lines.append("- {} stage field constraint: {}".format(
                        stage_name,
                        item.get('constraint', 'preserve the inferred support-object constraint')
                    ))
                if stage_contract.get('setup_requirements'):
                    lines.append("- {} stage requirements:".format(stage_name))
                    append_bullets(lines, stage_contract.get('setup_requirements', [])[:4])
                if stage_contract.get('sink_activation_conditions'):
                    lines.append("- {} stage activation conditions:".format(stage_name))
                    append_bullets(lines, stage_contract.get('sink_activation_conditions', [])[:4])
                if stage_name == 'transform':
                    lines.append("- {} stage placement: emit this configuration only after parser milestones are satisfied, preferably in the first info-ready, post-parse, or stage-transition callback rather than before parsing begins.".format(stage_name))
                    if stage_contract.get('execution_site_kind'):
                        lines.append("- {} stage execution-site kind: {}.".format(stage_name, stage_contract.get('execution_site_kind')))
                    if stage_contract.get('required_after_milestones'):
                        lines.append("- {} stage ordering: only execute this stage after milestones {} are satisfied.".format(
                            stage_name,
                            ', '.join(stage_contract.get('required_after_milestones', [])[:4])
                        ))
                    if stage_contract.get('must_consume_support_objects'):
                        lines.append("- {} stage support-object consumption: the later-stage site must consume {} in a real helper or transform call.".format(
                            stage_name,
                            ', '.join(stage_contract.get('must_consume_support_objects', [])[:4])
                        ))
                    if retrieved_stage_evidence.get('placement_candidates'):
                        lines.append("- {} stage execution site: choose one concrete later-stage execution site and make it real code, such as {}. Do not leave the selected callback or transition body empty.".format(
                            stage_name,
                            ', '.join(retrieved_stage_evidence.get('placement_candidates', [])[:3])
                        ))
                    for item in retrieved_stage_evidence.get('placement_hints', [])[:2]:
                        lines.append("- Retrieved placement hint: {}".format(item))
                    for item in retrieved_stage_evidence.get('evidence', [])[:2]:
                        lines.append("- Retrieved {} evidence in {}: {}.".format(
                            item.get('placement', 'stage-placement'),
                            item.get('function', 'source-context'),
                            item.get('api', 'config-api')
                        ))
                for item in stage_contract.get('milestone_hints', [])[:3]:
                    lines.append("- {} stage milestone {} [{}]: {}.".format(
                        stage_name,
                        item.get('name', 'milestone'),
                        item.get('kind', 'lifecycle'),
                        item.get('harness_expectation', item.get('reason', 'satisfy the milestone before expecting this stage to matter'))
                    ))
                lines.append("")
        if 'transform' in deferred_stages and stage_contracts.get('transform', {}):
            lines.append("- Deferred-stage execution checklist:")
            lines.append("- Name the exact code site that executes the deferred transform stage, such as a registered callback, info-ready hook, or post-parse transition block.")
            lines.append("- Keep deferred transform APIs out of the early setup section unless the execution plan marks them as direct-stage obligations.")
            lines.append("- If a callback or hook owns the deferred transform stage, its body must execute the transform APIs or support-object wiring; an empty callback is invalid.")
            lines.append("- Every support object planned for the deferred stage must be consumed by a real helper or transform call in that later-stage execution site.")
            lines.append("")
        if construction_plan.get('milestone_requirements'):
            lines.append("- Milestone requirements:")
            for item in construction_plan.get('milestone_requirements', [])[:6]:
                lines.append("- {name} [{kind}]: {expectation}.".format(
                    name=item.get('name', 'milestone'),
                    kind=item.get('kind', 'lifecycle'),
                    expectation=item.get('harness_expectation', item.get('goal', 'satisfy the milestone'))
                ))
            lines.append("")
        if construction_plan.get('active_data_plan'):
            lines.append("- Active data placement:")
            for item in construction_plan.get('active_data_plan', {}).get('mutable_regions', [])[:4]:
                lines.append("- Spend entropy on {name} [{kind}] because {reason}.".format(
                    name=item.get('name', 'mutable-region'),
                    kind=item.get('kind', 'buffer'),
                    reason=item.get('reason', 'it affects sink-adjacent behavior')
                ))
            for item in construction_plan.get('active_data_plan', {}).get('stabilized_regions', [])[:3]:
                lines.append("- Keep {name} stable enough to preserve parser and lifecycle reachability.".format(
                    name=item.get('name', 'stabilized-region')
                ))
            lines.append("")
        if construction_plan.get('valid_prefix_requirements'):
            lines.append("- Valid prefix requirements:")
            append_bullets(lines, construction_plan.get('valid_prefix_requirements', [])[:4])
        if construction_plan.get('control_prefix_policy'):
            lines.append("- Control prefix policy:")
            lines.append("- {}".format(construction_plan.get('control_prefix_policy')))
            lines.append("")
        if construction_plan.get('late_malformed_regions'):
            lines.append("- Safe late malformed regions:")
            append_bullets(lines, construction_plan.get('late_malformed_regions', [])[:4])
        if construction_plan.get('forbidden_shortcuts'):
            lines.append("- Forbidden shortcuts:")
            append_bullets(lines, construction_plan.get('forbidden_shortcuts', [])[:5])

    if vuln_analysis.get('state_fields'):
        lines.append("State fields touched by the vulnerable path:")
        for field in vuln_analysis.get('state_fields', [])[:8]:
            lines.append("- {owner}->{field} ({kind})".format(
                owner=field.get('owner', 'state'),
                field=field.get('field', 'field'),
                kind=field.get('kind', 'state')
            ))
        lines.append("")

    if vuln_analysis.get('helper_calls'):
        lines.append("Helper functions observed around the vulnerable path:")
        for helper in vuln_analysis.get('helper_calls', [])[:10]:
            lines.append("- {} ({})".format(helper.get('name', 'helper'), helper.get('phase', 'other')))
        lines.append("")

    if coverage_goals:
        lines.append("Coverage goals:")
        append_bullets(lines, coverage_goals[:10])

    append_section(lines, "## Forbidden Harness Patterns")
    forbidden = [
        "Do not pass arbitrary raw bytes directly when the target path expects a minimally valid container, header, or initialized object.",
        "Do not fabricate opaque library structs on the stack or zero-initialize internal state types manually.",
        "Do not call terminal or cleanup APIs multiple times on the same object unless the documented API requires it.",
        "Do not derive unbounded allocation sizes directly from attacker-controlled bytes.",
        "Do not ignore required setup or finalize phases if the execution plan indicates a stateful lifecycle.",
        "Do not write a generic parser harness that never reaches the reported sink semantics.",
        "Do not fuzz every valid parameter uniformly when the exploration policy marks some knobs as stabilize or bias-valid-space.",
        "Do not waste most entropy on trailing bytes that never survive parsing or never influence sink-adjacent state once milestones are satisfied."
    ]
    if sink_role == 'cleanup':
        forbidden.append("Do not exercise the cleanup sink only on the clean success path if the public API permits partially initialized or error-path cleanup states.")
    if construction_plan.get('support_objects'):
        forbidden.append("Do not pass nullptr/NULL placeholders to helper or transform APIs when the construction plan requires a real support object, table, palette, buffer, or metadata structure.")
    if construction_plan.get('requires_container_synthesis'):
        forbidden.append("Do not assume the post-prefix raw fuzzer bytes already form a valid structured file/container; synthesize the valid prefix/container yourself and then inject fuzz-controlled sections.")
    if 'transform' in deferred_stages and stage_contracts.get('transform', {}):
        forbidden.append("Do not execute deferred transform-stage APIs in the initial setup block before the parser reaches the milestone or callback that makes them live.")
        forbidden.append("Do not register a callback or transition hook for deferred transform work and then leave its body empty or unrelated to the required transform APIs.")
    append_bullets(lines, forbidden)

    if constraints:
        append_section(lines, "## Non-Negotiable Constraints")
        append_bullets(lines, constraints)

    if trigger_relations:
        append_section(lines, "## Trigger Sufficiency")
        lines.append("The harness is not sufficient unless it explicitly drives the inferred trigger relations above. Merely reaching the sink or calling the API with valid objects is not enough.")
        lines.append("")

    if 'transform' in deferred_stages and stage_contracts.get('transform', {}):
        append_section(lines, "## Deferred Stage Realization")
        lines.append("Before writing code, decide and follow one explicit realization plan for the deferred transform stage:")
        lines.append("")
        lines.append("- entry-stage calls and objects")
        lines.append("- parse-stage calls that establish the milestone")
        lines.append("- one concrete deferred execution site")
        lines.append("- transform-stage calls executed at that site")
        lines.append("- support objects consumed at that site")
        lines.append("- the later sink-oriented call path that becomes live afterward")
        lines.append("")

    if vuln_analysis and vuln_analysis.get('insights'):
        append_section(lines, "## Vulnerable Path Semantics")
        lines.append("These facts were extracted from the vulnerable implementation and must shape the harness:")
        lines.append("")
        append_bullets(lines, vuln_analysis.get('insights', []))

    if vuln_analysis.get('execution_hints'):
        lines.append("Concrete execution hints:")
        append_bullets(lines, vuln_analysis.get('execution_hints', []))

    lines.append("## Required Output Format")
    lines.append("")
    lines.append("Generate ONLY a single C++ file `fuzzer.cc` with this exact structure:")
    lines.append("```c++")
    lines.append('#include <cstdint>   // for uint8_t, size_t')
    lines.append('#include <cstdlib>   // for malloc, free')
    lines.append('#include <cstring>   // for memcpy, strlen, etc.')
    lines.append('#include "header.h"  // the PUBLIC API header for this library (use correct header name)')
    lines.append('')
    lines.append('extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {')
    lines.append("    // 1. PROPERLY INITIALIZE library state")
    lines.append("    //    - Call init/open functions if required")
    lines.append("    //    - Allocate valid objects with proper lifecycle")
    lines.append("    //    - Do NOT use NULL pointers for required parameters")
    lines.append("    //")
    lines.append("    // 2. TRANSFORM fuzzer input into API parameters")
    lines.append("    //    - Use semantic input segments (selector, lengths, payload, chunking) from the execution plan")
    lines.append("    //    - If a structured format is required, synthesize a minimally valid container/header first")
    lines.append("    //    - Satisfy required milestones before expecting sink-focused bytes to matter")
    lines.append("    //    - If transform work is deferred, choose one concrete callback or post-parse site and perform the transform/configuration there")
    lines.append("    //    - Place most remaining entropy into the active data plan's mutable regions, not unrelated trailing bytes")
    lines.append("    //    - Ensure valid parameters - bugs come from library, not harness")
    lines.append("    //")
    lines.append("    // 3. CALL the public API function")
    lines.append("    //    - Respect the required setup -> invoke -> update/finalize ordering from the execution plan")
    lines.append("    //    - Make milestone states true in order before relying on sink-adjacent mutation")
    lines.append("    //    - Do not leave registered callbacks empty when they own deferred transform work")
    lines.append("    //    - Pass valid objects plus fuzz-derived payload/control values")
    lines.append("    //")
    lines.append("    // 4. CLEANUP properly")
    lines.append("    //    - Free/close resources in correct order")
    lines.append("    //    - Avoid memory leaks but focus on exercising the vulnerability")
    lines.append("}")
    lines.append("```")
    lines.append("")
    lines.append("## Requirements")
    lines.append("")
    lines.append("1. **Use correct headers**: Include the actual public header file for this library")
    lines.append("2. **Initialize properly**: Call init/open/create functions before using the API")
    lines.append("3. **Valid parameters**: All pointers and handles must be valid (not NULL unless the API allows it)")
    lines.append("4. **Use the public API**: Call the library's documented public functions")
    lines.append("5. **No intentional bugs**: The harness itself must be correct code")
    lines.append("6. **Transform inputs semantically**: Convert fuzz bytes into selector, length, payload, and container fields as required")
    if public_api_name:
        lines.append("7. **Target function**: The function to test is `" + str(public_api_name) + "()`")
    if input_model.get('primary') == 'structured-format':
        lines.append("8. **Structured inputs required**: Build minimally valid containers or records before invoking the target API")
    if any(step.get('phase') == 'update' for step in call_sequence):
        lines.append("9. **Incremental lifecycle**: Preserve setup, update, finalize, and cleanup ordering")
    if sink_role == 'cleanup':
        lines.append("10. **Cleanup-state diversity**: Use selector bits to exercise the cleanup sink after at least two distinct pre-cleanup object states when the public API allows it, including a partial or failure-oriented path.")
    if construction_plan.get('support_objects'):
        lines.append("11. **Valid support objects**: Any helper or transform APIs must receive real backing objects/tables/buffers when the construction plan says they are required; do not use null placeholders.")
    if construction_plan.get('requires_container_synthesis'):
        lines.append("12. **Synthesize structured input**: If the target consumes a structured format, control bytes may select fields or chunk layout, but the harness must build a fresh minimally valid container instead of passing raw `data` or `data + offset` as if it were already a valid file.")
    if active_data_plan.get('mutable_regions'):
        lines.append("13. **Use sink-relevant mutations**: After milestone satisfaction, place most fuzz entropy into the active data plan's high-value mutable regions instead of appending unused trailing bytes.")
    if 'transform' in deferred_stages and stage_contracts.get('transform', {}):
        lines.append("14. **Realize deferred stages explicitly**: If transform obligations are deferred, pick one concrete callback or post-parse transition site, execute the transform APIs there, and keep them out of the early setup block.")
    lines.append("")
    lines.append("## Example Pattern")
    lines.append("")
    lines.append("For a database library with a function like `int db_query(db_handle* db, const char* sql)`:")
    lines.append("```c++")
    lines.append('#include "db.h"  // The library header')
    lines.append('')
    lines.append('extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {')
    lines.append('    // 1. Initialize properly')
    lines.append('    db_handle* db = db_open(":memory:");  // Valid handle')
    lines.append('    if (!db) return 0;  // Handle init failure gracefully')
    lines.append('')
    lines.append('    // 2. Transform input - use fuzzer data as SQL query')
    lines.append('    char* sql = (char*)malloc(size + 1);')
    lines.append('    if (!sql) { db_close(db); return 0; }')
    lines.append('    memcpy(sql, data, size);')
    lines.append('    sql[size] = "\\0";  // Null-terminate')
    lines.append('')
    lines.append('    // 3. Call the target API with valid parameters')
    lines.append('    db_query(db, sql);  // The bug is triggered by specific SQL patterns')
    lines.append('')
    lines.append('    // 4. Cleanup')
    lines.append('    free(sql);')
    lines.append('    db_close(db);')
    lines.append('    return 0;')
    lines.append('}')
    lines.append("```")
    lines.append("")
    lines.append("Generate ONLY the C++ code for fuzzer.cc. No explanation, no markdown, no placeholders, and no TODO comments.")
    lines.append("The harness must reflect the execution plan above, not a generic raw-buffer parser template.")
    
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