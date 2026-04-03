    #!/usr/bin/env python3
import argparse
import json
import os
import sys
import re
from pathlib import Path

# Parser/decoder entry function pattern — used to simplify parameter strategies
# when the entry function is a one-shot parser that naturally accepts data+size.
_PARSER_ENTRY_RE = re.compile(
    r'(?:parse|read|decode|load|deserialize|from_?(?:string|buffer|data|bytes|json|xml|yaml|cbor|msgpack))',
    re.IGNORECASE,
)

# Try to set libclang path before importing
try:
    # Try common libclang locations
    for lib_path in ['/usr/lib/llvm-18/lib', '/usr/lib/llvm-17/lib', '/usr/lib/llvm-16/lib', 
                     '/usr/lib/llvm-15/lib', '/usr/lib/llvm-14/lib', '/usr/lib/llvm-13/lib',
                     '/usr/lib/x86_64-linux-gnu', '/usr/local/lib']:
        if os.path.exists(lib_path):
            potential_so = os.path.join(lib_path, 'libclang.so')
            if os.path.exists(potential_so):
                import clang.cindex as clang_cindex
                clang_cindex.Config.set_library_file(potential_so)
                break
except Exception:
    pass

from public_api import (
    load_compile_commands as load_pubcmds, 
    find_public_include_dirs, 
    extract_public_usrs, 
    extract_function_signatures, 
    extract_exported_functions, 
    is_internal_function_name,
    get_exported_symbols,
    find_shared_libraries,
    extract_exported_symbols_from_library
)
from llvm_callgraph import build_callgraph_from_build_log, find_public_wrapper, find_ll_files, score_path_taint, trace_parameter_flow
from stage_retrieval import retrieve_stage_evidence
from vuln_analyzer import analyze_vulnerable_function


SEMANTIC_STOP_TOKENS = set([
    'api', 'arg', 'args', 'call', 'ctx', 'data', 'entry', 'fn', 'func', 'function',
    'get', 'handle', 'info', 'init', 'invoke', 'obj', 'object', 'out', 'param',
    'parser', 'ptr', 'read', 'set', 'state', 'stream', 'struct', 'target',
    'type', 'write'
])


def find_project_source(root, relative_path):
    """Resolve a source file path from vulnerability metadata."""
    if not relative_path:
        return None

    root_path = Path(root)
    direct = root_path / relative_path
    if direct.exists():
        return direct

    basename = os.path.basename(relative_path)
    if not basename:
        return None

    patterns = [
        '**/' + basename,
        relative_path,
    ]
    for pattern in patterns:
        matches = list(root_path.glob(pattern))
        if matches:
            return matches[0]
    return None


def normalize_lifecycle_base(name):
    """Strip common lifecycle suffixes so helper families can be matched generically."""
    if not name:
        return ''
    normalized = re.sub(r'[_0-9]+$', '', name)
    changed = True
    while changed and normalized:
        changed = False
        for suffix in ['Init', 'Open', 'Create', 'Setup', 'Begin', 'Start', 'Update', 'Write', 'Append', 'Push', 'Feed', 'Finish', 'Final', 'Flush', 'Close', 'Destroy', 'Free', 'Cleanup', 'End', 'Reset']:
            if normalized.endswith(suffix) and len(normalized) > len(suffix):
                normalized = normalized[:-len(suffix)]
                normalized = re.sub(r'[_0-9]+$', '', normalized)
                changed = True
                break
    return normalized.lower()


def build_parameter_roles_from_signature(signature_params):
    """Convert header signature tuples into generic harness parameter-role metadata."""
    roles = []
    for param_type, param_name in signature_params or []:
        name = param_name or ''
        type_name = param_type or 'unknown'
        lowered_name = name.lower()
        lowered_type = type_name.lower()

        role = 'value'
        strategy = 'supply a conservative default unless semantics suggest fuzz control matters'
        if lowered_name.startswith('num') or any(token in lowered_name for token in ['len', 'size', 'count', 'capacity', 'avail']):
            role = 'size'
            strategy = 'derive from payload length or a bounded integer extracted from fuzzer input'
        elif any(token in lowered_name for token in ['mode', 'type', 'flag', 'flags', 'option', 'options', 'kind', 'op', 'cmd', 'flush']):
            role = 'control'
            strategy = 'map a few fuzzer bits to valid enum or flag values to explore alternate branches'
        elif any(token in lowered_name for token in ['out', 'dst', 'dest', 'result', 'output', 'return']):
            role = 'output-buffer'
            strategy = 'allocate a bounded writable buffer owned by the harness before the call'
        elif '**' in lowered_type:
            role = 'output-buffer'
            strategy = 'allocate a bounded writable buffer owned by the harness before the call'
        elif any(token in lowered_name for token in ['state', 'ctx', 'context', 'stream', 'parser', 'handle', 'object', 'strm', 'info']) or (lowered_name.endswith('_ptr') and not any(token in lowered_name for token in ['buf', 'data', 'text', 'str'])) or '%struct' in lowered_type or (lowered_type.endswith('ptr') and '*' not in lowered_type):
            role = 'state'
            strategy = 'create or initialize a valid state object before invoking the target API'
        elif any(token in lowered_name for token in ['table', 'array', 'list', 'entry', 'entries', 'palette', 'hist', 'map']) or any(token in lowered_type for token in ['table', 'array', 'list', 'palette', 'hist']):
            role = 'support-buffer'
            strategy = 'allocate a bounded typed buffer or table and populate it from fuzz-controlled values while preserving count consistency'
        elif '*' in lowered_type or 'char' in lowered_type or 'void' in lowered_type or 'byte' in lowered_type:
            role = 'input-buffer'
            strategy = 'back with fuzz-controlled bytes, preserving required alignment or termination rules'
        elif any(token in lowered_type for token in ['int', 'long', 'short', 'size_t', 'ssize_t', 'uint', 'float', 'double']):
            role = 'numeric'
            strategy = 'extract a bounded scalar from fuzzer input and clamp it to valid ranges'

        roles.append({
            'name': name or 'param',
            'type': type_name,
            'role': role,
            'strategy': strategy,
        })
    return roles


def _normalize_parameter_name(name):
    return (name or '').strip().lstrip('*').lower()


def _score_parameter_roles(parameter_roles, evidence_names):
    score = 0
    evidence_names = set([_normalize_parameter_name(item) for item in evidence_names if item])
    for role in parameter_roles or []:
        role_name = role.get('role')
        name = _normalize_parameter_name(role.get('name'))
        if role_name == 'control':
            score += 4
        elif role_name == 'state':
            score += 2
        elif role_name in ['size', 'numeric'] and name in evidence_names:
            score += 2
        elif role_name in ['input-buffer', 'output-buffer'] and name in evidence_names:
            score += 1
        elif role_name == 'support-buffer':
            score -= 1
        if name in evidence_names:
            score += 3
    return score


def _resolve_parameter_roles(signature_roles, context_roles, vuln_context):
    signature_roles = list(signature_roles or [])
    context_roles = list(context_roles or [])
    if not signature_roles:
        return context_roles
    if not context_roles:
        return signature_roles

    signature_names = set([_normalize_parameter_name(item.get('name')) for item in signature_roles if item.get('name')])
    context_names = set([_normalize_parameter_name(item.get('name')) for item in context_roles if item.get('name')])
    overlap = len(signature_names.intersection(context_names))
    if overlap and overlap * 2 > max(len(signature_names), len(context_names)):
        return signature_roles

    evidence_names = []
    for cond in (vuln_context or {}).get('parameter_conditions', []):
        evidence_names.append(cond.get('parameter'))
    for branch in (vuln_context or {}).get('switch_branches', []):
        evidence_names.append(branch.get('variable'))

    signature_score = _score_parameter_roles(signature_roles, evidence_names)
    context_score = _score_parameter_roles(context_roles, evidence_names)
    if signature_score > context_score:
        return signature_roles
    return context_roles


def _implies_structured_wrapper_path(path_traits):
    return bool(
        path_traits.get('container_like') or
        (path_traits.get('parser_like') and path_traits.get('incremental_like') and path_traits.get('work_unit_like')) or
        (path_traits.get('parser_like') and path_traits.get('transform_like') and path_traits.get('work_unit_like'))
    )


def _tokenize_identifier(name):
    """Break identifiers into normalized semantic tokens."""
    cleaned = re.sub(r'[^A-Za-z0-9_]+', '_', name or '')
    parts = []
    for token in cleaned.replace('->', '_').replace('.', '_').split('_'):
        if not token:
            continue
        token = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', token)
        parts.extend([item.lower() for item in token.split() if item])
    return [item for item in parts if item not in ['ptr', 'const'] and item not in SEMANTIC_STOP_TOKENS]


def _is_public_control_candidate(name):
    value = (name or '').strip()
    if not value:
        return False
    if '->' in value or '.' in value:
        return False
    if re.match(r'^-?\d+(?:[uUlL]+)?$', value):
        return False
    if re.match(r'^[A-Z][A-Z0-9_]*$', value):
        return False
    return True


def _filter_weak_support_objects(support_objects, parameter_roles, input_model):
    support_objects = list(support_objects or [])
    if not support_objects:
        return []
    if input_model.get('primary') == 'structured-format':
        return support_objects[:6]
    if any(item.get('role') == 'support-buffer' for item in parameter_roles or []):
        return support_objects[:6]

    filtered = []
    for item in support_objects:
        if item.get('kind') in ['metadata', 'config']:
            continue
        filtered.append(item)
    return filtered[:6]


def _prune_support_text_items(items, dropped_names):
    if not dropped_names:
        return list(items or [])
    filtered = []
    for item in items or []:
        text = str(item)
        if any(name in text for name in dropped_names):
            continue
        filtered.append(item)
    return filtered


def _prune_support_named_items(items, dropped_names):
    if not dropped_names:
        return list(items or [])
    filtered = []
    for item in items or []:
        name = item.get('name', '')
        reason = item.get('reason', '')
        if any(dropped == name or dropped in reason for dropped in dropped_names):
            continue
        filtered.append(item)
    return filtered


def _prune_role_policy_items(items, dropped_names):
    if not dropped_names:
        return list(items or [])
    filtered = []
    for item in items or []:
        target = item.get('target', '')
        rationale = item.get('rationale', '')
        if any(dropped == target or dropped in rationale for dropped in dropped_names):
            continue
        filtered.append(item)
    return filtered


def _prune_role_relation_items(items, dropped_names):
    if not dropped_names:
        return list(items or [])
    filtered = []
    for item in items or []:
        controller = item.get('controller', '')
        dependent = item.get('dependent', '')
        evidence = item.get('evidence', '')
        expectation = item.get('harness_expectation', '')
        if any(name in [controller, dependent] or name in evidence or name in expectation for name in dropped_names):
            continue
        filtered.append(item)
    return filtered


def _sanitize_parameter_role_context(vuln_context, original_roles, resolved_roles):
    context = dict(vuln_context or {})
    original_names = set([item.get('name') for item in original_roles or [] if item.get('name')])
    resolved_names = set([item.get('name') for item in resolved_roles or [] if item.get('name')])
    dropped_names = sorted(list(original_names - resolved_names))
    if not dropped_names:
        context['parameter_roles'] = list(resolved_roles or [])
        return context

    context['parameter_roles'] = list(resolved_roles or [])
    context['execution_hints'] = _prune_support_text_items(context.get('execution_hints', []), dropped_names)
    context['insights'] = _prune_support_text_items(context.get('insights', []), dropped_names)
    context['setup_requirements'] = _prune_support_text_items(context.get('setup_requirements', []), dropped_names)
    context['invariant_requirements'] = _prune_support_text_items(context.get('invariant_requirements', []), dropped_names)
    context['trigger_controls'] = [item for item in context.get('trigger_controls', []) if item not in dropped_names]
    context['sensitive_controls'] = [item for item in context.get('sensitive_controls', []) if item.get('target') not in dropped_names]
    context['trigger_relations'] = _prune_role_relation_items(context.get('trigger_relations', []), dropped_names)
    context['exploration_policy'] = _prune_role_policy_items(context.get('exploration_policy', []), dropped_names)
    active_data_plan = dict(context.get('active_data_plan', {}))
    active_data_plan['mutable_regions'] = _prune_support_named_items(active_data_plan.get('mutable_regions', []), dropped_names)
    active_data_plan['stabilized_regions'] = _prune_support_named_items(active_data_plan.get('stabilized_regions', []), dropped_names)
    active_data_plan['derived_regions'] = _prune_support_named_items(active_data_plan.get('derived_regions', []), dropped_names)
    active_data_plan['consistency_constraints'] = _prune_support_text_items(active_data_plan.get('consistency_constraints', []), dropped_names)
    active_data_plan['entropy_guidance'] = _prune_support_text_items(active_data_plan.get('entropy_guidance', []), dropped_names)
    context['active_data_plan'] = active_data_plan
    return context


def _sanitize_support_object_context(vuln_context, parameter_roles, input_model):
    context = dict(vuln_context or {})
    support_objects = list(context.get('required_support_objects', []))
    filtered_support = _filter_weak_support_objects(support_objects, parameter_roles, input_model)
    if len(filtered_support) == len(support_objects):
        return context

    kept_names = set([item.get('name') for item in filtered_support])
    dropped_names = [item.get('name') for item in support_objects if item.get('name') not in kept_names]
    context['required_support_objects'] = filtered_support
    context['helper_preconditions'] = _prune_support_text_items(context.get('helper_preconditions', []), dropped_names)
    context['setup_requirements'] = _prune_support_text_items(context.get('setup_requirements', []), dropped_names)
    context['sink_activation_conditions'] = _prune_support_text_items(context.get('sink_activation_conditions', []), dropped_names)
    context['sink_live_predicates'] = _prune_support_text_items(context.get('sink_live_predicates', []), dropped_names)
    context['execution_hints'] = _prune_support_text_items(context.get('execution_hints', []), dropped_names)
    context['insights'] = _prune_support_text_items(context.get('insights', []), dropped_names)
    active_data_plan = dict(context.get('active_data_plan', {}))
    active_data_plan['mutable_regions'] = _prune_support_named_items(active_data_plan.get('mutable_regions', []), dropped_names)
    context['active_data_plan'] = active_data_plan
    return context


def _make_signature_sensitive_controls(parameter_roles):
    """Prefer explicit API knobs over inferred internal fields when available."""
    controls = []
    for role in parameter_roles:
        role_name = role.get('role')
        if role_name not in ['size', 'control', 'numeric']:
            continue
        score = 3 if role_name == 'control' else 2
        reason = 'explicit {} parameter in the public API signature'.format(role_name)
        controls.append({
            'target': role.get('name'),
            'source_kind': 'parameter',
            'score': score,
            'reasons': [reason],
        })
    return controls[:6]


def _make_signature_trigger_relations(parameter_roles):
    """Derive generic support-buffer/count relations from the public signature."""
    relations = []
    sizes = [item for item in parameter_roles if item.get('role') in ['size', 'numeric', 'control']]
    support_buffers = [item for item in parameter_roles if item.get('role') == 'support-buffer']

    for size_role in sizes[:4]:
        for support_role in support_buffers[:4]:
            relations.append({
                'kind': 'buffer-count-consistency',
                'controller': size_role.get('name'),
                'dependent': support_role.get('name'),
                'evidence': 'public signature pairs {} with {}'.format(size_role.get('name'), support_role.get('name')),
                'harness_expectation': 'Allocate {} with a bounded element count derived from {} and deliberately exercise boundary counts while preserving valid allocation size.'.format(
                    support_role.get('name'), size_role.get('name')),
                'priority': 'high' if size_role.get('role') in ['size', 'control'] else 'medium',
            })
    return relations[:6]


def _make_setup_state_bound_relations(public_api_name, parameter_roles, input_model):
    """Infer a generic cross-call hypothesis that setup-state may bound later sink arguments."""
    if (input_model or {}).get('primary') != 'semantic-arguments':
        return []

    state_roles = [item for item in parameter_roles if item.get('role') == 'state']
    size_roles = [item for item in parameter_roles if item.get('role') in ['size', 'numeric', 'control']]
    support_roles = [item for item in parameter_roles if item.get('role') == 'support-buffer']
    if not state_roles or not size_roles or not support_roles:
        return []

    state_names = [item.get('name') for item in state_roles[:4] if item.get('name')]
    support_names = [item.get('name') for item in support_roles[:4] if item.get('name')]
    relations = []
    for size_role in size_roles[:3]:
        dependent = size_role.get('name')
        if not dependent:
            continue
        relations.append({
            'kind': 'setup-state-bound-hypothesis',
            'controller': 'setup-state-control',
            'dependent': dependent,
            'state_targets': state_names[:4],
            'support_objects': support_names[:4],
            'evidence': 'stateful semantic-argument API {} uses state parameters {} alongside {} and support buffers {}'.format(
                public_api_name,
                ', '.join(state_names[:4]),
                dependent,
                ', '.join(support_names[:4])
            ),
            'harness_expectation': 'Before invoking {}, use at least one valid pre-sink state-configuration call on {} to establish or vary the legal range of {}; then exercise {} near that derived bound while keeping {} internally consistent.'.format(
                public_api_name,
                ', '.join(state_names[:4]),
                dependent,
                dependent,
                ', '.join(support_names[:4])
            ),
            'priority': 'high',
        })
    return relations[:4]


def _make_setup_state_profiles(public_api_name, parameter_roles, trigger_relations):
    """Rank setup-state choices generically by liveness preservation and bound sharpness."""
    state_names = [item.get('name') for item in parameter_roles if item.get('role') == 'state' and item.get('name')]
    if not state_names:
        return []

    profiles = []
    for relation in trigger_relations or []:
        if relation.get('kind') != 'setup-state-bound-hypothesis':
            continue
        dependent = relation.get('dependent') or 'dependent-argument'
        support_names = [item for item in relation.get('support_objects', []) if item]
        support_text = ', '.join(support_names[:4]) if support_names else 'required support objects'
        profiles.append({
            'name': 'liveness-ranked-setup-control',
            'priority': relation.get('priority', 'high'),
            'controller': relation.get('controller', 'setup-state-control'),
            'dependent': dependent,
            'state_targets': relation.get('state_targets', state_names[:4])[:4],
            'support_objects': support_names[:4],
            'ranking_rationale': 'Prefer pre-sink setup controls that keep {} semantically live while changing the legal range of {}.'.format(
                support_text,
                dependent,
            ),
            'preferred_properties': [
                'Vary the smallest number of valid pre-sink setup controls that still changes the legal range of {}.'.format(dependent),
                'Prefer setup choices that keep {} semantically active while {} is exercised near its derived bound.'.format(support_text, dependent),
                'Prefer setup controls that tighten or sharpen the bound for {} before broad mode changes that relax it to a generic maximum or default.'.format(dependent),
            ],
        })
    return profiles[:4]


def _make_signature_support_objects(parameter_roles):
    """Convert explicit support-buffer parameters into generic support objects."""
    support_objects = []
    for role in parameter_roles:
        if role.get('role') != 'support-buffer':
            continue
        support_objects.append({
            'name': role.get('name'),
            'kind': 'table',
            'reason': 'the public API explicitly requires this support buffer or table argument',
        })
    return support_objects[:6]


def _matches_semantic_anchor(text, anchor_tokens):
    """Return true when free-form text overlaps explicit API argument semantics."""
    text_tokens = set(_tokenize_identifier(text or ''))
    return bool(text_tokens.intersection(anchor_tokens))


def _filter_semantic_text_items(items, anchor_tokens):
    """Keep only free-form items relevant to explicit semantic-argument anchors."""
    filtered = []
    for item in items or []:
        if _matches_semantic_anchor(item, anchor_tokens):
            filtered.append(item)
    unique = []
    seen = set()
    for item in filtered:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique


def _filter_semantic_named_items(items, anchor_tokens, fields):
    """Keep only dict items whose named fields overlap explicit semantic anchors."""
    filtered = []
    for item in items or []:
        haystack = []
        for field in fields:
            value = item.get(field)
            if isinstance(value, list):
                haystack.extend([str(entry) for entry in value])
            elif value:
                haystack.append(str(value))
        if any(_matches_semantic_anchor(value, anchor_tokens) for value in haystack):
            filtered.append(item)
    return filtered


def _dedupe_text_items(items):
    """Deduplicate ordered text items."""
    unique = []
    seen = set()
    for item in items or []:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique


def _sanitize_semantic_argument_context(context, public_api_name, signature_roles, signature_support_objects,
                                        explicit_parameter_controls, signature_relations, setup_state_profiles):
    """Remove stale sink-body residue when explicit semantic arguments are the stronger signal."""
    context = dict(context or {})
    anchor_tokens = set()
    for role in signature_roles:
        anchor_tokens.update(_tokenize_identifier(role.get('name', '')))
    anchor_tokens.update(_tokenize_identifier(public_api_name or ''))
    for relation in signature_relations or []:
        anchor_tokens.update(_tokenize_identifier(relation.get('controller', '')))
        anchor_tokens.update(_tokenize_identifier(relation.get('dependent', '')))

    context['state_fields'] = _filter_semantic_named_items(context.get('state_fields', []), anchor_tokens, ['owner', 'field'])
    context['field_conditions'] = _filter_semantic_named_items(context.get('field_conditions', []), anchor_tokens, ['target', 'value'])
    context['parameter_conditions'] = _filter_semantic_named_items(context.get('parameter_conditions', []), anchor_tokens, ['parameter', 'value'])
    context['switch_branches'] = _filter_semantic_named_items(context.get('switch_branches', []), anchor_tokens, ['variable', 'cases'])
    context['helper_calls'] = _filter_semantic_named_items(context.get('helper_calls', []), anchor_tokens, ['name'])
    context['ownership_transitions'] = _filter_semantic_text_items(context.get('ownership_transitions', []), anchor_tokens)
    context['cleanup_preconditions'] = _filter_semantic_text_items(context.get('cleanup_preconditions', []), anchor_tokens)
    context['trigger_hints'] = _filter_semantic_text_items(context.get('trigger_hints', []), anchor_tokens)

    support_names = [item.get('name') for item in signature_support_objects[:4] if item.get('name')]
    control_names = [item for item in explicit_parameter_controls[:4] if item]
    relation_expectations = [item.get('harness_expectation') for item in signature_relations[:4] if item.get('harness_expectation')]
    setup_state_relations = [item for item in signature_relations if item.get('kind') == 'setup-state-bound-hypothesis']
    state_parameter_names = [item.get('name') for item in signature_roles if item.get('role') == 'state']
    context['setup_state_profiles'] = setup_state_profiles[:4]

    helper_preconditions = []
    if support_names:
        helper_preconditions.append('Provide valid support buffers or tables for explicit support-buffer parameters: {}.'.format(', '.join(support_names)))
    if setup_state_relations and state_parameter_names:
        helper_preconditions.append('Use at least one valid pre-sink state-configuration call on {} before invoking {} so setup-established bounds can vary with the sink arguments.'.format(
            ', '.join(state_parameter_names[:4]), public_api_name))
    setup_requirements = list(helper_preconditions)

    context['helper_preconditions'] = helper_preconditions[:6]
    context['setup_requirements'] = setup_requirements[:6]
    context['required_support_objects'] = signature_support_objects[:6]

    sink_activation_conditions = []
    if support_names:
        sink_activation_conditions.append('Supporting objects passed through explicit API arguments must be valid before invoking {}: {}.'.format(public_api_name, ', '.join(support_names)))
    sink_activation_conditions.extend(relation_expectations[:2])
    context['sink_activation_conditions'] = sink_activation_conditions[:6]

    sink_live_predicates = ['Create or initialize valid library-owned state before feeding fuzz-controlled bytes into the entry API.']
    if support_names:
        sink_live_predicates.append('Explicit support-buffer arguments must remain valid while {} executes: {}.'.format(public_api_name, ', '.join(support_names)))
    sink_live_predicates.extend(relation_expectations[:2])
    context['sink_live_predicates'] = sink_live_predicates[:6]

    milestone_hints = []
    if state_parameter_names:
        milestone_hints.append({
            'name': 'state-created',
            'kind': 'object-lifecycle',
            'required': True,
            'reason': 'the public API requires valid library-owned state parameters',
            'evidence': state_parameter_names[:4],
            'harness_expectation': 'Establish valid state with setup APIs before passing fuzz-controlled bytes into the entry API',
        })
    context['milestone_hints'] = milestone_hints[:4]

    active_data_plan = dict(context.get('active_data_plan', {}))
    mutable_regions = []
    for region in active_data_plan.get('mutable_regions', []):
        name = region.get('name', '')
        if name in ['bounded-controls', 'primary-payload'] or _matches_semantic_anchor(name, anchor_tokens):
            mutable_regions.append(region)
    if control_names and not any(region.get('name') == 'bounded-controls' for region in mutable_regions):
        mutable_regions.append({
            'name': 'bounded-controls',
            'kind': 'selector-or-control',
            'priority': 'medium',
            'reason': 'a small number of explicit API controls strongly influence sink reachability and should be fuzzed within valid ranges',
        })
    if setup_state_relations and not any(region.get('name') == 'setup-state-controls' for region in mutable_regions):
        mutable_regions.append({
            'name': 'setup-state-controls',
            'kind': 'selector-or-control',
            'priority': 'high',
            'reason': 'valid pre-sink state-configuration controls may determine the legal range of later sink arguments and should vary jointly with them',
        })
    for support_object in signature_support_objects[:4]:
        if any(region.get('name') == support_object.get('name') for region in mutable_regions):
            continue
        mutable_regions.append({
            'name': support_object.get('name'),
            'kind': support_object.get('kind', 'support-object'),
            'priority': 'high',
            'reason': support_object.get('reason', 'the public API requires this support object'),
        })
    active_data_plan['mutable_regions'] = mutable_regions[:8]
    active_data_plan['stabilized_regions'] = _filter_semantic_named_items(active_data_plan.get('stabilized_regions', []), anchor_tokens, ['name', 'reason'])
    active_data_plan['derived_regions'] = _filter_semantic_named_items(active_data_plan.get('derived_regions', []), anchor_tokens, ['name', 'reason'])
    if setup_state_profiles and not any(region.get('name') == 'non-essential-setup-state' for region in active_data_plan.get('stabilized_regions', [])):
        active_data_plan['stabilized_regions'].append({
            'name': 'non-essential-setup-state',
            'kind': 'selector-or-control',
            'reason': 'keep lower-leverage setup dimensions stable so the highest-value bound-setting controls can vary without collapsing sink liveness',
        })
    active_data_plan['consistency_constraints'] = relation_expectations[:4]
    entropy_guidance = []
    for item in active_data_plan.get('entropy_guidance', []):
        if _matches_semantic_anchor(item, anchor_tokens):
            entropy_guidance.append(item)
    for item in relation_expectations:
        if item not in entropy_guidance:
            entropy_guidance.append(item)
    active_data_plan['entropy_guidance'] = entropy_guidance[:6]
    context['active_data_plan'] = active_data_plan

    execution_hints = _filter_semantic_text_items(context.get('execution_hints', []), anchor_tokens)
    insights = _filter_semantic_text_items(context.get('insights', []), anchor_tokens)
    if support_names:
        execution_hints.append('Populate explicit support-buffer arguments such as {} with bounded fuzz-controlled contents rather than inventing unrelated internal metadata state.'.format(', '.join(support_names)))
        insights.append('Explicit support-buffer arguments inferred from the public signature: {}.'.format(', '.join(support_names)))
    if control_names:
        execution_hints.append('Bias exploration toward explicit API controls: {}.'.format(', '.join(control_names)))
        insights.append('Most sensitive controls inferred from the public signature: {}.'.format(', '.join(control_names)))
    if setup_state_relations and state_parameter_names:
        execution_hints.append('Do not keep all pre-sink state configuration constant; vary at least one valid configuration call on {} so it can tighten or relax the legal range of later sink arguments.'.format(', '.join(state_parameter_names[:4])))
        insights.append('A valid pre-sink state-configuration step may establish bounds for later sink arguments and should be varied jointly with them.')
    for profile in setup_state_profiles[:2]:
        rationale = profile.get('ranking_rationale')
        if rationale:
            execution_hints.append(rationale)
        for item in profile.get('preferred_properties', [])[:2]:
            execution_hints.append(item)
        insights.append('Rank pre-sink setup controls by sink liveness preservation before exploring broader mode changes.')
    for item in relation_expectations:
        if item not in execution_hints:
            execution_hints.append(item)
    context['execution_hints'] = _dedupe_text_items(execution_hints)[:8]
    context['insights'] = _dedupe_text_items(insights)[:12]

    return context


def normalize_vuln_context(vuln_context, public_api_name, public_signatures):
    """Repair weak sink-body inference with stronger public-signature semantics."""
    context = dict(vuln_context or {})
    signature_params = public_signatures.get(public_api_name, []) if public_signatures else []
    signature_roles = build_parameter_roles_from_signature(signature_params)
    resolved_roles = _resolve_parameter_roles(signature_roles, context.get('parameter_roles', []), context)
    context = _sanitize_parameter_role_context(context, context.get('parameter_roles', []), resolved_roles)
    context = _sanitize_support_object_context(context, context.get('parameter_roles', []), context.get('input_model', {}))
    if not resolved_roles:
        return context

    signature_controls = _make_signature_sensitive_controls(resolved_roles)
    signature_relations = _make_signature_trigger_relations(resolved_roles)
    signature_support_objects = _make_signature_support_objects(resolved_roles)

    input_model = dict(context.get('input_model', {}))
    if input_model.get('primary') == 'raw-buffer':
        has_input_buffer = any(item.get('role') == 'input-buffer' for item in resolved_roles)
        has_semantic_args = any(item.get('role') in ['size', 'numeric', 'control', 'support-buffer', 'state'] for item in resolved_roles)
        if not has_input_buffer and has_semantic_args:
            input_model['primary'] = 'semantic-arguments'
            secondary = list(input_model.get('secondary', []))
            if 'direct-api-arguments' not in secondary:
                secondary.append('direct-api-arguments')
            evidence = list(input_model.get('evidence', []))
            evidence.append('public signature exposes scalar controls or support buffers without a direct caller-provided raw data buffer')
            input_model['secondary'] = secondary[:8]
            input_model['evidence'] = evidence[:8]
    context['input_model'] = input_model
    setup_state_relations = _make_setup_state_bound_relations(public_api_name, resolved_roles, input_model)
    setup_state_profiles = _make_setup_state_profiles(public_api_name, resolved_roles, setup_state_relations)

    if signature_support_objects:
        existing_support = context.get('required_support_objects', [])
        if existing_support:
            signature_names = set([item.get('name') for item in signature_support_objects])
            filtered = []
            for item in existing_support:
                item_tokens = set(_tokenize_identifier(item.get('name', '')))
                if item.get('name') in signature_names or item_tokens.intersection(signature_names):
                    filtered.append(item)
            context['required_support_objects'] = filtered or signature_support_objects
        else:
            context['required_support_objects'] = signature_support_objects

    current_controls = context.get('trigger_controls', [])
    current_sensitive = context.get('sensitive_controls', [])
    current_relations = context.get('trigger_relations', [])

    explicit_parameter_controls = [item.get('target') for item in signature_controls]
    if explicit_parameter_controls and (not current_controls or not any(_is_public_control_candidate(item) for item in current_controls)):
        context['trigger_controls'] = explicit_parameter_controls[:8]

    if signature_controls:
        filtered_sensitive = [item for item in current_sensitive if _is_public_control_candidate(item.get('target'))]
        context['sensitive_controls'] = filtered_sensitive[:8] or signature_controls

    merged_relations = list(current_relations or [])
    for relation in signature_relations + setup_state_relations:
        key = (relation.get('kind'), relation.get('controller'), relation.get('dependent'))
        if any((item.get('kind'), item.get('controller'), item.get('dependent')) == key for item in merged_relations):
            continue
        merged_relations.append(relation)
    if merged_relations:
        context['trigger_relations'] = merged_relations[:8]

    if context.get('input_model', {}).get('primary') == 'semantic-arguments' and (signature_support_objects or explicit_parameter_controls):
        context = _sanitize_semantic_argument_context(
            context,
            public_api_name,
            resolved_roles,
            signature_support_objects,
            explicit_parameter_controls,
            context.get('trigger_relations', []),
            setup_state_profiles,
        )

    active_data_plan = dict(context.get('active_data_plan', {}))
    mutable_regions = list(active_data_plan.get('mutable_regions', []))
    mutable_names = set([item.get('name') for item in mutable_regions])
    for support_object in context.get('required_support_objects', [])[:4]:
        if support_object.get('name') in mutable_names:
            continue
        mutable_regions.append({
            'name': support_object.get('name'),
            'kind': support_object.get('kind', 'support-object'),
            'priority': 'high',
            'reason': support_object.get('reason', 'the public API requires this support object'),
        })
    active_data_plan['mutable_regions'] = mutable_regions[:8]
    active_data_plan.setdefault('derived_regions', [])
    active_data_plan.setdefault('stabilized_regions', [])
    active_data_plan.setdefault('consistency_constraints', [])
    active_data_plan.setdefault('entropy_guidance', [])
    for relation in context.get('trigger_relations', [])[:4]:
        text = relation.get('harness_expectation')
        if text and text not in active_data_plan['entropy_guidance']:
            active_data_plan['entropy_guidance'].append(text)
    context['active_data_plan'] = active_data_plan

    execution_hints = list(context.get('execution_hints', []))
    if signature_support_objects:
        execution_hints.append('Populate explicit support-buffer arguments such as {} with bounded fuzz-controlled contents rather than inventing unrelated metadata state.'.format(
            ', '.join([item.get('name') for item in signature_support_objects[:4]])))
    if explicit_parameter_controls:
        execution_hints.append('Bias exploration toward explicit API controls: {}.'.format(', '.join(explicit_parameter_controls[:4])))
    context['execution_hints'] = _dedupe_text_items(execution_hints)[:8]
    if setup_state_profiles:
        context['setup_state_profiles'] = setup_state_profiles[:4]

    return context


def _empty_stage_contract():
    return {
        'required_setup_calls': [],
        'activation_predicates': [],
        'support_object_construction': [],
        'support_object_field_constraints': [],
        'setup_requirements': [],
        'sink_activation_conditions': [],
        'milestone_hints': [],
        'execution_site_kind': '',
        'execution_site_candidates': [],
        'required_after_milestones': [],
        'must_consume_support_objects': [],
    }


def _with_stage(item, stage):
    if isinstance(item, dict):
        tagged = dict(item)
        tagged['stage'] = stage
        return tagged
    return item


def _stage_from_text(text, path_traits, default_stage):
    lowered = (text or '').lower()
    entry_tokens = ['init', 'open', 'create', 'setup', 'begin', 'start', 'alloc']
    parse_tokens = ['head', 'header', 'chunk', 'signature', 'magic', 'container', 'prefix', 'record', 'frame', 'packet', 'section', 'metadata', 'parse', 'parser']
    transform_tokens = ['transform', 'quant', 'quantize', 'convert', 'scale', 'expand', 'palette', 'lookup', 'hist']

    if any(token in lowered for token in parse_tokens):
        return 'parse'
    if any(token in lowered for token in transform_tokens):
        return 'transform'
    if any(token in lowered for token in entry_tokens):
        return 'entry'
    if path_traits.get('parser_like') and _implies_structured_wrapper_path(path_traits) and any(token in lowered for token in ['register', 'attach', 'assign', 'load', 'get']):
        return 'parse'
    return default_stage


def _classify_stage_item(item, item_kind, path_traits):
    if item_kind == 'milestone_hints':
        kind = item.get('kind', '')
        if kind == 'object-lifecycle':
            return 'entry'
        if kind in ['container-parse', 'incremental-feed', 'support-contract']:
            return 'parse'
        if kind == 'transform-gating':
            return 'transform'
        return 'sink'

    if item_kind == 'activation_predicates':
        return _stage_from_text(item.get('target', ''), path_traits, 'sink')

    if item_kind == 'required_setup_calls':
        basis = ' '.join([
            item.get('name', ''),
            item.get('reason', ''),
            item.get('phase', ''),
        ])
        return _stage_from_text(basis, path_traits, 'entry')

    if item_kind == 'support_object_construction':
        reason = (item.get('reason') or '').lower()
        kind = (item.get('kind') or '').lower()
        if 'public api signature exposes this support buffer explicitly' in reason and kind == 'support-buffer':
            # When the sink is behind a wrapper path, the sink's own
            # support-buffer parameters are NOT directly accessible from
            # the harness.  Keep them as informational context on the sink
            # stage rather than promoting them to a transform obligation.
            if path_traits.get('parser_like') and _implies_structured_wrapper_path(path_traits):
                return 'sink'
            return 'parse'
        basis = ' '.join([
            item.get('name', ''),
            item.get('kind', ''),
            item.get('reason', ''),
            item.get('expectation', ''),
            ' '.join(item.get('required_fields', [])[:4]),
        ])
        return _stage_from_text(basis, path_traits, 'sink')

    if item_kind == 'support_object_field_constraints':
        basis = ' '.join([
            item.get('object', ''),
            item.get('constraint', ''),
            ' '.join(item.get('fields', [])[:4]),
        ])
        return _stage_from_text(basis, path_traits, 'sink')

    if item_kind in ['setup_requirements', 'sink_activation_conditions']:
        return _stage_from_text(str(item), path_traits, 'sink')

    return 'sink'


def _build_stage_contracts(vuln_context, path_traits):
    stage_contracts = {
        'entry': _empty_stage_contract(),
        'parse': _empty_stage_contract(),
        'transform': _empty_stage_contract(),
        'sink': _empty_stage_contract(),
    }
    for field in ['required_setup_calls', 'activation_predicates', 'support_object_construction', 'support_object_field_constraints', 'milestone_hints']:
        for item in vuln_context.get(field, []) or []:
            stage = _classify_stage_item(item, field, path_traits)
            stage_contracts[stage][field].append(_with_stage(item, stage))
    for field in ['setup_requirements', 'sink_activation_conditions']:
        for item in vuln_context.get(field, []) or []:
            stage = _classify_stage_item(item, field, path_traits)
            stage_contracts[stage][field].append(item)
    return stage_contracts


def _dedupe_stage_items(items):
    out = []
    seen = set()
    for item in items:
        if isinstance(item, dict):
            key = json.dumps(item, sort_keys=True)
        else:
            key = str(item)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _merge_stage_contract_field(stage_contracts, stages, field, limit):
    merged = []
    for stage in stages:
        merged.extend(stage_contracts.get(stage, {}).get(field, []))
    merged = _dedupe_stage_items(merged)
    return merged[:limit]


def _project_text_items_for_stages(items, path_traits, stages, default_stage):
    projected = []
    for item in items or []:
        stage = _stage_from_text(item, path_traits, default_stage)
        if stage not in stages:
            continue
        projected.append(item)
    return _dedupe_text_items(projected)


def _project_named_items_for_stages(items, path_traits, stages, item_kind):
    projected = []
    for item in items or []:
        stage = _classify_stage_item(item, item_kind, path_traits)
        if stage not in stages:
            continue
        projected.append(item)
    return _dedupe_stage_items(projected)


def _build_stage_projected_context(vuln_context, stage_contracts, direct_stages, path_traits):
    projected = dict(vuln_context or {})
    projected['required_setup_calls'] = _merge_stage_contract_field(stage_contracts, direct_stages, 'required_setup_calls', 6)
    projected['activation_predicates'] = _merge_stage_contract_field(stage_contracts, direct_stages, 'activation_predicates', 6)
    projected['support_object_construction'] = _merge_stage_contract_field(stage_contracts, direct_stages, 'support_object_construction', 6)
    projected['support_object_field_constraints'] = _merge_stage_contract_field(stage_contracts, direct_stages, 'support_object_field_constraints', 6)
    projected['setup_requirements'] = _merge_stage_contract_field(stage_contracts, direct_stages, 'setup_requirements', 8)
    projected['sink_activation_conditions'] = _merge_stage_contract_field(stage_contracts, direct_stages, 'sink_activation_conditions', 6)
    projected['milestone_hints'] = _merge_stage_contract_field(stage_contracts, direct_stages, 'milestone_hints', 6)
    projected['required_support_objects'] = [
        {
            'name': item.get('name'),
            'kind': item.get('kind', 'support-object'),
            'reason': item.get('reason', 'this support object is required during the direct stages'),
        }
        for item in projected.get('support_object_construction', [])
        if item.get('name')
    ][:6]
    projected_support_names = {item.get('name') for item in projected['required_support_objects'] if item.get('name')}
    active_data_plan = dict(projected.get('active_data_plan', {}))
    if active_data_plan.get('mutable_regions'):
        active_data_plan['mutable_regions'] = [
            item for item in active_data_plan.get('mutable_regions', [])
            if item.get('name') in projected_support_names or 'public api explicitly requires this support buffer or table argument' not in (item.get('reason', '').lower())
        ]
    projected['active_data_plan'] = active_data_plan
    projected['sink_live_predicates'] = _project_text_items_for_stages(
        vuln_context.get('sink_live_predicates', []), path_traits, direct_stages, 'sink')[:8]
    projected['execution_hints'] = _project_text_items_for_stages(
        vuln_context.get('execution_hints', []), path_traits, direct_stages, 'sink')[:8]
    projected['insights'] = _project_text_items_for_stages(
        vuln_context.get('insights', []), path_traits, direct_stages, 'sink')[:12]
    projected['trigger_controls'] = [
        item for item in vuln_context.get('trigger_controls', [])
        if _stage_from_text(item, path_traits, 'entry') in direct_stages
    ][:8]
    projected['sensitive_controls'] = [
        item for item in vuln_context.get('sensitive_controls', [])
        if _stage_from_text(item.get('target', ''), path_traits, 'entry') in direct_stages
    ][:8]
    projected['trigger_relations'] = _project_named_items_for_stages(
        vuln_context.get('trigger_relations', []), path_traits, direct_stages, 'sink_activation_conditions')[:8]
    return projected


def _enrich_stage_execution_contracts(stage_contracts, retrieved_stage_evidence, milestone_plan, path_traits):
    stage_contracts = dict(stage_contracts or {})
    transform_contract = dict(stage_contracts.get('transform', {}) or {})
    has_transform_obligation = any(transform_contract.get(field) for field in [
        'required_setup_calls',
        'support_object_construction',
        'support_object_field_constraints',
        'setup_requirements',
        'sink_activation_conditions',
        'milestone_hints',
    ])
    if not has_transform_obligation:
        stage_contracts['transform'] = transform_contract
        return stage_contracts

    evidence = retrieved_stage_evidence.get('evidence', []) if retrieved_stage_evidence else []
    candidates = list(retrieved_stage_evidence.get('placement_candidates', [])) if retrieved_stage_evidence else []
    placements = [item.get('placement') for item in evidence if item.get('placement')]
    execution_site_kind = ''
    if any(item == 'post-parse-callback' for item in placements):
        execution_site_kind = 'callback'
    elif any(item == 'post-parse-transition' for item in placements):
        execution_site_kind = 'post-parse-transition'
    elif path_traits.get('parser_like') and _implies_structured_wrapper_path(path_traits):
        execution_site_kind = 'callback-or-post-parse-transition'

    required_after = []
    for item in milestone_plan or []:
        if not item.get('required'):
            continue
        if item.get('kind') in ['container-parse', 'incremental-feed', 'work-unit']:
            required_after.append(item.get('name'))

    transform_contract['execution_site_kind'] = execution_site_kind
    transform_contract['execution_site_candidates'] = candidates[:4]
    transform_contract['required_after_milestones'] = required_after[:4]
    transform_contract['must_consume_support_objects'] = [
        item.get('name') for item in transform_contract.get('support_object_construction', [])
        if item.get('name')
    ][:4]
    stage_contracts['transform'] = transform_contract
    return stage_contracts


def _select_direct_stages(path_traits):
    if path_traits.get('parser_like') and _implies_structured_wrapper_path(path_traits):
        return ['entry', 'parse'], ['transform', 'sink']
    if path_traits.get('transform_like'):
        return ['entry', 'transform'], ['parse', 'sink']
    return ['entry', 'parse', 'transform', 'sink'], []


def infer_public_lifecycle_candidates(public_api_name, public_api_names, phase_name):
    """Infer same-family public lifecycle helpers from exported/header-declared APIs."""
    if not public_api_name or not public_api_names:
        return []

    suffixes_by_phase = {
        'setup': ['Init2_', 'Init_', 'Init2', 'Init', 'Open', 'Create', 'Setup', 'Begin', 'Start'],
        'update': ['Update', 'Write', 'Append', 'Push', 'Feed'],
        'cleanup': ['End', 'Close', 'Destroy', 'Cleanup', 'Free', 'Reset'],
    }

    base = normalize_lifecycle_base(public_api_name)
    exact_prefix = public_api_name
    phase_suffixes = suffixes_by_phase.get(phase_name, [])
    matches = []
    for candidate in sorted(public_api_names):
        if candidate == public_api_name:
            continue
        if normalize_lifecycle_base(candidate) != base:
            continue
        if not any(candidate.endswith(suffix) for suffix in phase_suffixes):
            continue
        if candidate.startswith(exact_prefix) or normalize_lifecycle_base(candidate) == base:
            matches.append(candidate)

    # Substring fallback: when base-matching finds nothing, check if the
    # public_api_name is a case-insensitive substring of the candidate AND
    # the candidate ends with a lifecycle suffix for the phase.
    # E.g. XML_Parse is a substring of XML_ParserCreate → match on 'setup'.
    if not matches and phase_suffixes:
        lowered_api = public_api_name.lower()
        for candidate in sorted(public_api_names):
            if candidate == public_api_name:
                continue
            if lowered_api not in candidate.lower():
                continue
            if not any(candidate.endswith(suffix) for suffix in phase_suffixes):
                continue
            matches.append(candidate)

    return matches[:8]


def trim_plan_symbol_maps(usr_to_file, usr_to_name, sink_usr, wrapper_path):
    """Keep only symbol metadata needed by downstream prompt and seed generation."""
    keep = set(wrapper_path or [])
    if sink_usr:
        keep.add(sink_usr)

    trimmed_usr_to_file = {}
    trimmed_usr_to_name = {}
    for usr in keep:
        if usr in usr_to_file:
            trimmed_usr_to_file[usr] = usr_to_file[usr]
        if usr in usr_to_name:
            trimmed_usr_to_name[usr] = usr_to_name[usr]
    return trimmed_usr_to_file, trimmed_usr_to_name


def collect_phase_candidates(vuln_context, phase_name, public_api_name=None, public_api_names=None):
    """Collect helper names associated with a setup/update/cleanup phase."""
    names = []
    seen = set()
    preferred = []
    fallback = []
    target_base = normalize_lifecycle_base(public_api_name)

    def append_name(helper_name):
        if not helper_name or helper_name in seen:
            return
        seen.add(helper_name)
        helper_base = normalize_lifecycle_base(helper_name)
        if target_base and helper_base == target_base:
            preferred.append(helper_name)
        else:
            fallback.append(helper_name)

    for helper in vuln_context.get('helper_calls', []):
        if helper.get('phase') != phase_name:
            continue
        helper_name = helper.get('name')
        append_name(helper_name)

    if phase_name == 'setup':
        for helper in vuln_context.get('related_init_functions', []):
            helper_name = helper.get('name')
            append_name(helper_name)

    public_set = set(public_api_names or [])
    names = preferred if target_base else fallback
    if public_set:
        names = [name for name in names if name in public_set]

    if not names:
        names = infer_public_lifecycle_candidates(public_api_name, public_set, phase_name)
    return names[:8]


def build_input_segments(vuln_context):
    """Describe how the harness should carve fuzz input into semantic pieces."""
    segments = []
    parameter_roles = vuln_context.get('parameter_roles', [])
    input_model = vuln_context.get('input_model', {})
    switch_branches = vuln_context.get('switch_branches', [])
    workload_model = vuln_context.get('workload_model', {})

    control_names = [item.get('name') for item in parameter_roles if item.get('role') == 'control']
    size_names = [item.get('name') for item in parameter_roles if item.get('role') == 'size']
    support_names = [item.get('name') for item in parameter_roles if item.get('role') == 'support-buffer']
    trigger_relations = vuln_context.get('trigger_relations', [])
    trigger_controls = vuln_context.get('trigger_controls', [])

    if control_names or switch_branches:
        segments.append({
            'name': 'selector',
            'source': 'first 1-2 bytes',
            'purpose': 'choose a valid mode, flag set, or branch family before deeper parsing'
        })

    if trigger_controls:
        segments.append({
            'name': 'trigger-controls',
            'source': 'small bounded prefix integers',
            'purpose': 'drive the high-signal controls or derived-bound variables {}'.format(', '.join(trigger_controls[:5]))
        })

    setup_state_relations = [item for item in trigger_relations if item.get('kind') == 'setup-state-bound-hypothesis']
    if setup_state_relations:
        dependent_names = [item.get('dependent') for item in setup_state_relations[:4] if item.get('dependent')]
        segments.append({
            'name': 'setup-state-controls',
            'source': 'small bounded prefix integers',
            'purpose': 'drive valid pre-sink state-configuration calls that may establish or tighten the legal range of {}'.format(', '.join(dependent_names[:4]))
        })

    if 'repeated-records' in workload_model.get('operators', []):
        segments.append({
            'name': 'record-count',
            'source': 'small bounded prefix integer',
            'purpose': 'expand the workload into multiple logical entries while keeping counts valid and bounded'
        })

    if input_model.get('primary') == 'structured-format':
        segments.append({
            'name': 'container-shape',
            'source': 'derived constants plus a few control bytes',
            'purpose': 'build a minimally valid header or container so the API accepts the payload'
        })

    if size_names:
        segments.append({
            'name': 'bounded-lengths',
            'source': 'small integers derived from early bytes',
            'purpose': 'keep {} consistent with the buffers supplied by the harness'.format(', '.join(size_names[:5]))
        })

    if support_names:
        segments.append({
            'name': 'support-objects',
            'source': 'remaining bytes after controls',
            'purpose': 'populate typed tables or support buffers such as {} while preserving valid bounds'.format(', '.join(support_names[:5]))
        })

    if input_model.get('primary') != 'semantic-arguments' or not support_names:
        segments.append({
            'name': 'payload',
            'source': 'remaining bytes',
            'purpose': 'fill the main buffer, chunk content, or structured-body fields consumed by the target API'
        })

    if trigger_relations:
        segments.append({
            'name': 'relation-bias',
            'source': 'one or two control bytes',
            'purpose': 'bias values near inferred trigger relations instead of fuzzing every argument uniformly'
        })

    if 'streaming-or-incremental' in input_model.get('secondary', []):
        segments.append({
            'name': 'chunking',
            'source': 'small integer derived from selector or length bytes',
            'purpose': 'split payload across repeated update-style calls without violating lifecycle order'
        })

    if 'control-biased' in workload_model.get('operators', []):
        segments.append({
            'name': 'control-bias',
            'source': 'a narrow selector byte',
            'purpose': 'steer high-impact control values while stabilizing lower-signal parameters'
        })

    return segments


def build_trigger_plan(entry, public_api_name, execution_plan, vuln_context):
    """Build a compact trigger-oriented plan.

    Since the harness calls the public entry point (not the sink), this
    returns a simple 'primary-invoke' lifecycle profile.  Sink-centric
    cleanup roles, failure-path indicators, and ownership transitions are
    intentionally omitted — they describe the sink function's internals.
    """
    lifecycle_profiles = [
        {
            'name': 'primary-invoke',
            'goal': 'exercise the selected public API with valid setup and controlled workload shaping'
        }
    ]

    input_shaping = list(execution_plan.get('input_segments', []))[:4]

    return {
        'sink_role': 'invoke',
        'sink_role_evidence': [],
        'lifecycle_profiles': lifecycle_profiles,
        'cleanup_preconditions': [],
        'ownership_transitions': [],
        'failure_modes': [],
        'input_shaping': input_shaping,
        'trigger_hints': [],
    }


def build_construction_plan(entry, public_api_name, execution_plan, trigger_plan, vuln_context):
    """Build an explicit state-construction plan for the LLM and validator."""
    input_model = execution_plan.get('input_model', {})
    workload_model = execution_plan.get('workload_model', {})
    support_objects = list(execution_plan.get('support_object_construction', []))
    if not support_objects and not execution_plan.get('stage_contracts'):
        support_objects = _filter_weak_support_objects(vuln_context.get('required_support_objects', []), execution_plan.get('parameter_roles', []), input_model)
    required_setup_calls = execution_plan.get('required_setup_calls', [])
    activation_predicates = execution_plan.get('activation_predicates', [])
    support_object_construction = execution_plan.get('support_object_construction', [])
    support_object_field_constraints = execution_plan.get('support_object_field_constraints', [])
    helper_preconditions = execution_plan.get('setup_requirements', [])
    sink_activation_conditions = execution_plan.get('sink_activation_conditions', [])
    if not execution_plan.get('stage_contracts'):
        if not helper_preconditions:
            helper_preconditions = vuln_context.get('helper_preconditions', [])
        if not sink_activation_conditions:
            sink_activation_conditions = vuln_context.get('sink_activation_conditions', [])
    milestone_plan = execution_plan.get('milestone_plan', [])
    active_data_plan = execution_plan.get('active_data_plan', {})
    stage_contracts = execution_plan.get('stage_contracts', {})
    deferred_stages = execution_plan.get('deferred_stages', [])

    valid_prefix_requirements = []
    if input_model.get('primary') == 'structured-format':
        valid_prefix_requirements.append('Build a minimally valid container/header prefix before fuzzing later body sections.')
    if 'mode-selection' in input_model.get('secondary', []):
        valid_prefix_requirements.append('Reserve a small selector space for valid mode or branch selection.')

    late_malformed_regions = []
    if input_model.get('primary') == 'structured-format':
        late_malformed_regions.append('Prefer mutating trailing data, optional chunks, or later sections after the valid prefix is established.')
    if trigger_plan.get('sink_role') == 'cleanup':
        late_malformed_regions.append('For cleanup sinks, allow bounded malformed or partially initialized late-state variants before cleanup.')

    forbidden_shortcuts = [
        'Do not pass null placeholders to helper or transform APIs when a real support object or table is required.',
        'Do not attempt to activate the sink before setup APIs have populated the relevant library state.',
    ]
    if workload_model.get('operators'):
        forbidden_shortcuts.append('Do not collapse the workload into one opaque byte blob when the execution plan calls for structured shaping or staged processing.')

    requires_container_synthesis = input_model.get('primary') == 'structured-format'
    control_prefix_policy = ''
    if requires_container_synthesis:
        control_prefix_policy = 'If selector or control bytes are consumed from the fuzzer input, build a fresh minimally valid container from those controls and the remaining payload instead of assuming the raw input already begins with a valid file signature.'

    return {
        'support_objects': support_objects[:6],
        'required_setup_calls': required_setup_calls[:6],
        'activation_predicates': activation_predicates[:6],
        'support_object_construction': support_object_construction[:6],
        'support_object_field_constraints': support_object_field_constraints[:6],
        'helper_preconditions': helper_preconditions[:8],
        'hard_preconditions': helper_preconditions[:6],
        'sink_activation_conditions': sink_activation_conditions[:6],
        'milestone_requirements': milestone_plan[:6],
        'active_data_plan': active_data_plan,
        'valid_prefix_requirements': valid_prefix_requirements[:4],
        'late_malformed_regions': late_malformed_regions[:4],
        'lifecycle_variants': trigger_plan.get('lifecycle_profiles', [])[:3],
        'forbidden_shortcuts': forbidden_shortcuts[:6],
        'requires_container_synthesis': requires_container_synthesis,
        'control_prefix_policy': control_prefix_policy,
        'stage_contracts': stage_contracts,
        'deferred_stages': deferred_stages,
    }


def infer_path_semantic_traits(path_names, public_api_name):
    """Infer generic parser, streaming, work-unit, and transform traits from the public wrapper path."""
    names = [item for item in (path_names or []) if item]
    lowered = ' '.join([item.lower() for item in names + ([public_api_name] if public_api_name else [])])

    parser_tokens = ['read', 'parse', 'decode', 'process', 'handle']
    container_tokens = ['chunk', 'header', 'signature', 'magic', 'metadata', 'record', 'frame', 'section', 'packet', 'table']
    incremental_tokens = ['push', 'feed', 'update', 'stream', 'progressive', 'some_data']
    work_unit_tokens = ['row', 'rows', 'frame', 'block', 'record']
    transform_tokens = ['transform', 'quantize', 'convert', 'scale', 'expand']

    return {
        'parser_like': any(token in lowered for token in parser_tokens),
        'container_like': any(token in lowered for token in container_tokens),
        'incremental_like': any(token in lowered for token in incremental_tokens),
        'work_unit_like': any(token in lowered for token in work_unit_tokens),
        'transform_like': any(token in lowered for token in transform_tokens),
    }


def refine_input_model_from_path(input_model, path_traits):
    """Upgrade sink-local input modeling using public-wrapper path semantics."""
    refined = dict(input_model or {})
    secondary = list(refined.get('secondary', []))
    evidence = list(refined.get('evidence', []))

    if path_traits.get('parser_like') and _implies_structured_wrapper_path(path_traits):
        refined['primary'] = 'structured-format'
        if 'magic-or-container-header' not in secondary:
            secondary.append('magic-or-container-header')
        if 'parser-lifecycle' not in secondary:
            secondary.append('parser-lifecycle')
        evidence.append('public wrapper path shows parser-driven state plus incremental or work-unit production, so the entry API expects a minimally valid structured container')

    if path_traits.get('incremental_like') and 'streaming-or-incremental' not in secondary:
        secondary.append('streaming-or-incremental')
        evidence.append('public wrapper path contains push, feed, update, or progressive markers, indicating incremental processing')

    if path_traits.get('work_unit_like') and 'post-parse-work-units' not in secondary:
        secondary.append('post-parse-work-units')
        evidence.append('public wrapper path contains row, frame, block, or image markers, indicating produced work units before the sink')

    refined['secondary'] = secondary
    refined['evidence'] = evidence[:8]
    return refined


def _has_header_registration_contract(vuln_context, public_api_name):
    required_setup_calls = vuln_context.get('required_setup_calls', [])
    activation_predicates = vuln_context.get('activation_predicates', [])
    support_object_construction = vuln_context.get('support_object_construction', [])

    setup_names = {(item.get('name') or '').lower() for item in required_setup_calls}
    support_names = {(item.get('name') or '').lower() for item in support_object_construction}
    predicate_targets = ' '.join([(item.get('target') or '').lower() for item in activation_predicates])

    # Generic: any setup call whose name mentions "header" implies a header contract.
    if any('header' in name for name in setup_names):
        return True
    # Generic: a support object named head/header with predicate targets mentioning
    # header-related fields implies a header registration lifecycle.
    if 'head' in support_names or 'header' in support_names:
        if any(token in predicate_targets for token in ['head', 'header']):
            return True
    return False


def refine_input_model_from_contract(input_model, vuln_context, public_api_name):
    """Upgrade sink-local input modeling when semantic contracts imply a structured header/container lifecycle."""
    refined = dict(input_model or {})
    secondary = list(refined.get('secondary', []))
    evidence = list(refined.get('evidence', []))

    if _has_header_registration_contract(vuln_context, public_api_name):
        refined['primary'] = 'structured-format'
        for tag in ['magic-or-container-header', 'header-registration', 'stateful-object']:
            if tag not in secondary:
                secondary.append(tag)
        evidence.append('semantic contract requires registering a header-bearing support object before the target API becomes live, implying a structured container or header prefix')

    refined['secondary'] = secondary
    refined['evidence'] = evidence[:8]
    return refined


def refine_workload_model_from_path(workload_model, path_traits):
    """Upgrade workload shaping when the wrapper path shows parser or incremental behavior."""
    refined = dict(workload_model or {})
    operators = list(refined.get('operators', []))
    evidence = list(refined.get('evidence', []))

    if path_traits.get('incremental_like') and 'chunked-stream' not in operators:
        operators.append('chunked-stream')
        evidence.append('public wrapper path contains progressive or update-style steps, so bounded chunking is required')

    if path_traits.get('parser_like') and _implies_structured_wrapper_path(path_traits) and 'structured-container' not in operators:
        operators.append('structured-container')
        evidence.append('public wrapper path shows parser-driven progressive or work-unit stages, so the workload should preserve a minimally valid structured skeleton')

    if not operators:
        operators.append('direct-buffer')
    refined['operators'] = operators
    refined['evidence'] = evidence[:8]
    return refined


def refine_workload_model_from_contract(workload_model, vuln_context, public_api_name):
    """Upgrade workload shaping when semantic contracts imply a structured container/header path."""
    refined = dict(workload_model or {})
    operators = list(refined.get('operators', []))
    evidence = list(refined.get('evidence', []))

    if _has_header_registration_contract(vuln_context, public_api_name):
        if 'structured-container' not in operators:
            operators.append('structured-container')
        evidence.append('semantic contract requires a registered header-bearing support object, so fuzzing should preserve a minimally valid structured wrapper while mutating sink-relevant regions')

    if not operators:
        operators.append('direct-buffer')
    refined['operators'] = operators
    refined['evidence'] = evidence[:8]
    return refined


def refine_active_data_plan_from_path(active_data_plan, path_traits, milestone_plan):
    """Ensure active data planning reflects produced work units and structured-container stability."""
    plan = dict(active_data_plan or {})
    mutable_regions = list(plan.get('mutable_regions', []))
    stabilized_regions = list(plan.get('stabilized_regions', []))
    derived_regions = list(plan.get('derived_regions', []))
    consistency_constraints = list(plan.get('consistency_constraints', []))
    entropy_guidance = list(plan.get('entropy_guidance', []))

    mutable_names = set([item.get('name') for item in mutable_regions])
    stable_names = set([item.get('name') for item in stabilized_regions])
    derived_names = set([item.get('name') for item in derived_regions])
    milestone_names = set([item.get('name') for item in (milestone_plan or [])])

    if (path_traits.get('work_unit_like') or 'work-unit-produced' in milestone_names) and 'decoded-work-unit' not in mutable_names:
        mutable_regions.insert(0, {
            'name': 'decoded-work-unit',
            'kind': 'row-or-block-data',
            'priority': 'high',
            'reason': 'the wrapper path shows produced rows, blocks, frames, or image data before the sink, so fuzz entropy should reach that post-parse work unit',
        })

    if path_traits.get('parser_like') and _implies_structured_wrapper_path(path_traits) and 'container-skeleton' not in stable_names:
        stabilized_regions.insert(0, {
            'name': 'container-skeleton',
            'kind': 'container',
            'priority': 'high',
            'reason': 'keep the structural prefix and container framing valid so parsing reaches sink-adjacent logic',
        })

    if path_traits.get('parser_like') and _implies_structured_wrapper_path(path_traits) and 'container-lengths' not in derived_names:
        derived_regions.append({
            'name': 'container-lengths',
            'kind': 'derived-lengths',
            'priority': 'high',
            'reason': 'container sizes, chunk lengths, or related framing fields should be recomputed from emitted payload data',
        })

    if path_traits.get('incremental_like') and 'chunk-boundaries' not in derived_names:
        derived_regions.append({
            'name': 'chunk-boundaries',
            'kind': 'derived-chunking',
            'priority': 'medium',
            'reason': 'incremental feeds should split the payload into bounded valid chunks instead of arbitrary opaque fragments',
        })

    if path_traits.get('parser_like') and _implies_structured_wrapper_path(path_traits):
        consistency_constraints.append('Parser-facing paths require a minimally valid container skeleton, with lengths or checksums recomputed from the emitted body instead of fuzzed independently.')
    if path_traits.get('work_unit_like'):
        consistency_constraints.append('Decoded work-unit size and layout should remain consistent with the image, frame, or record metadata that produces them.')
    if path_traits.get('incremental_like'):
        consistency_constraints.append('Chunk sizes and update ordering must remain bounded and internally consistent with the supplied payload buffer.')

    if path_traits.get('work_unit_like'):
        entropy_guidance.append('After milestone satisfaction, prefer mutating decoded row, block, frame, or image contents over appending unrelated trailing bytes.')

    def dedupe(items):
        out = []
        seen = set()
        for item in items:
            key = item.get('name') if isinstance(item, dict) else item
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
        return out

    def dedupe_text(items):
        out = []
        seen = set()
        for item in items:
            if item in seen:
                continue
            seen.add(item)
            out.append(item)
        return out

    plan['mutable_regions'] = dedupe(mutable_regions)[:8]
    plan['stabilized_regions'] = dedupe(stabilized_regions)[:6]
    plan['derived_regions'] = dedupe(derived_regions)[:6]
    plan['consistency_constraints'] = dedupe_text(consistency_constraints)[:8]
    plan['entropy_guidance'] = dedupe_text(entropy_guidance)[:6]
    return plan


def build_milestone_plan(public_api_name, path_names, input_model, workload_model,
                         parameter_roles, state_fields, setup_candidates,
                         update_candidates, vuln_context):
    """Infer generic milestones that the harness must satisfy before the sink is plausibly reachable."""
    milestones = []
    seen = set()
    sink_function = vuln_context.get('function_name') or ''
    sink_live_predicates = vuln_context.get('sink_live_predicates', [])
    state_targets = ['{}.{}'.format(item.get('owner', 'state'), item.get('field', 'field')) for item in state_fields[:4]]
    token_haystack = ' '.join([item.lower() for item in path_names if item])
    token_haystack += ' ' + ' '.join([item.lower() for item in state_targets])
    token_haystack += ' ' + sink_function.lower()

    def add(name, kind, goal, evidence, expectation):
        key = (name, kind)
        if key in seen:
            return
        seen.add(key)
        milestones.append({
            'name': name,
            'kind': kind,
            'required': True,
            'goal': goal,
            'evidence': [item for item in evidence if item][:5],
            'harness_expectation': expectation,
        })

    if setup_candidates or any(role.get('role') == 'state' for role in parameter_roles) or state_fields:
        add(
            'state-created',
            'object-lifecycle',
            'Create valid library-owned state before fuzz-controlled processing begins.',
            setup_candidates + state_targets,
            'Establish valid state with setup APIs before passing fuzz-controlled bytes into the entry API.',
        )

    path_traits = infer_path_semantic_traits(path_names, public_api_name)

    if input_model.get('primary') == 'structured-format' or (path_traits.get('parser_like') and _implies_structured_wrapper_path(path_traits)):
        add(
            'structured-input-accepted',
            'container-parse',
            'Build a minimally valid structured container or prefix that the public API can accept.',
            path_names[:3] + sink_live_predicates,
            'Construct a minimally valid container and only fuzz sink-relevant later regions aggressively.',
        )

    if update_candidates or 'chunked-stream' in workload_model.get('operators', []) or 'streaming-or-incremental' in input_model.get('secondary', []) or path_traits.get('incremental_like'):
        add(
            'incremental-feed-established',
            'incremental-feed',
            'Drive the API through repeated feed or update steps with bounded chunking.',
            update_candidates + path_names[:4],
            'Use bounded repeated feed or update calls instead of a single opaque bulk invocation.',
        )

    if path_traits.get('work_unit_like') or any(token in token_haystack for token in ['row', 'rows', 'scanline', 'frame', 'block', 'record', 'chunk', 'pixel', 'image']):
        add(
            'work-unit-produced',
            'work-unit',
            'Reach a state where the library has produced a row, block, record, or equivalent work unit before expecting the sink.',
            path_names + state_targets,
            'Shape inputs so upstream parsing or decoding produces at least one concrete work unit before cleanup or return.',
        )

    if path_traits.get('transform_like') or any(token in token_haystack for token in ['transform', 'quant', 'quantize', 'convert', 'scale', 'expand', 'palette', 'lookup', 'hist']):
        add(
            'transform-ready',
            'transform-gating',
            'Enable transform or sink-adjacent configuration only after prerequisites are valid.',
            path_names + vuln_context.get('sink_activation_conditions', []),
            'Enable sink-adjacent transform or configuration state using valid support objects after parser and state milestones are satisfied.',
        )

    if vuln_context.get('sink_role', {}).get('role') == 'cleanup':
        add(
            'cleanup-state-reached',
            'cleanup-lifecycle',
            'Exercise cleanup or finalization after a valid or partially initialized state transition.',
            path_names + vuln_context.get('cleanup_preconditions', []),
            'Reach cleanup only after at least one valid or partially initialized object state has been established.',
        )

    for item in vuln_context.get('milestone_hints', [])[:4]:
        add(
            item.get('name', 'milestone'),
            item.get('kind', 'lifecycle'),
            item.get('reason', item.get('harness_expectation', 'Satisfy this state milestone before sink-focused fuzzing.')),
            item.get('evidence', []),
            item.get('harness_expectation', 'Satisfy this state milestone before sink-focused fuzzing.'),
        )

    return milestones[:8]


def build_execution_sink_live_predicates(milestone_plan, vuln_context):
    """Merge milestone expectations with sink activation conditions into concise live predicates."""
    predicates = []
    for item in milestone_plan[:4]:
        expectation = item.get('harness_expectation')
        if expectation:
            predicates.append(expectation)
    for item in vuln_context.get('sink_live_predicates', [])[:4]:
        predicates.append(item)
    for item in vuln_context.get('sink_activation_conditions', [])[:2]:
        predicates.append(item)

    unique = []
    seen = set()
    for item in predicates:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique[:8]


# ─────────── LLM-based execution strategy (replaces heuristic planning) ───────────

def _load_llm_config():
    """Load model and API base from config/llm.json."""
    cfg_path = Path(__file__).resolve().parent / "config" / "llm.json"
    model = "gpt-4o"
    api_base = "https://api.openai.com/v1"
    try:
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        model = cfg.get("default", {}).get("model") or model
        api_base = cfg.get("default", {}).get("api_base") or api_base
    except Exception:
        pass
    return model, api_base


# ─────────── LLM-based entry-path selection ───────────

def llm_select_entry_path(all_paths, sink_name, entry, public_signatures,
                          cache_dir=None):
    """Use the LLM to select the best entry-point path from BFS candidates.

    The LLM receives all candidate paths together with vulnerability context
    (CVE description, CWE, affected function) and function signatures for
    each entry point.  It picks the path that gives the harness maximum
    control over the state needed to trigger the specific vulnerability.

    Returns the selected path (list of function names) or None on failure,
    in which case the caller should fall back to heuristic scoring.
    """
    import hashlib
    import tempfile

    try:
        from llm_adapters.openai import run_openai_json
    except ImportError:
        return None

    if not (os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_API_TOKEN")):
        return None

    model, api_base = _load_llm_config()

    # ── Build the prompt ──

    cve_id = entry.get('cve-id', 'unknown')
    description = entry.get('description', '')
    cwe_id = entry.get('cwe-id', '')
    affected_func = entry.get('affected-function', sink_name)

    # Format each candidate path with its entry-function signature
    path_lines = []
    for idx, path in enumerate(all_paths, 1):
        entry_func = path[0]
        sig = ''
        params = public_signatures.get(entry_func, [])
        if params:
            sig = ', '.join(
                '{} {}'.format(t, n) if n else t
                for t, n in params
            )
        chain = ' -> '.join(path)
        if len(path) == 1:
            chain += '  (direct call - sink IS the public API)'
        path_lines.append(
            '  {idx}. {func}({sig})  :  {chain}'.format(
                idx=idx, func=entry_func, sig=sig, chain=chain)
        )

    prompt = (
        'You are a vulnerability researcher selecting the best public-API '
        'entry point for a libFuzzer harness that must trigger a specific '
        'vulnerability.\n\n'
        'VULNERABILITY:\n'
        '  CVE:              {cve}\n'
        '  CWE:              {cwe}\n'
        '  Affected function (sink): {sink}\n'
        '  Description:      {desc}\n\n'
        'CANDIDATE PATHS (entry_function(signature) : call chain):\n'
        '{paths}\n\n'
        'SELECTION CRITERIA (in priority order):\n'
        '1. The entry point must give the harness DIRECT control over the '
        'internal state that the vulnerability depends on.  Wrapper functions '
        'that hide or pre-configure internal objects (e.g. allocating and '
        'managing a stream struct internally) remove that control and are '
        'WORSE even if they accept more pointer parameters.\n'
        '2. Shorter paths are preferred - fewer hops means fewer chances for '
        'the library to sanitise or discard fuzz input before it reaches the '
        'sink.\n'
        '3. If the sink function itself is a public API (direct / length-1 path), '
        'strongly prefer it unless the vulnerability specifically requires '
        'multi-step state setup that only a wrapper provides.\n\n'
        'Return a JSON object:\n'
        '{{\n'
        '  "selected_path": <1-based index of the best path>,\n'
        '  "reasoning": "<1-3 sentences explaining why this path is best>"\n'
        '}}'
    ).format(
        cve=cve_id,
        cwe=cwe_id or 'unknown',
        sink=affected_func,
        desc=description[:800] if description else 'No description available.',
        paths='\n'.join(path_lines),
    )

    # ── Cache check ──
    cache_file = None
    if cache_dir:
        cache_dir_p = Path(cache_dir)
        path_key = '|'.join(
            '->'.join(p) for p in sorted(all_paths, key=lambda x: '->'.join(x))
        )
        key = hashlib.sha256(
            (sink_name + path_key + cve_id).encode()
        ).hexdigest()[:16]
        cache_file = cache_dir_p / 'llm_entry_path_{}.json'.format(key)
        if cache_file.exists():
            try:
                cached = json.loads(cache_file.read_text(encoding='utf-8'))
                sel = cached.get('selected_path')
                if isinstance(sel, int) and 1 <= sel <= len(all_paths):
                    print('[llm_select_entry_path] Using cached selection: path {}'.format(sel))
                    return all_paths[sel - 1]
            except Exception:
                pass

    # ── LLM call ──
    try:
        tmp_dir = Path(tempfile.mkdtemp(prefix='rf_entry_path_'))
        prompt_file = tmp_dir / 'prompt_entry_path.md'
        out_file = tmp_dir / 'response.json'
        prompt_file.write_text(prompt, encoding='utf-8')

        ok, msg = run_openai_json(
            prompt_path=prompt_file,
            out_path=out_file,
            model=model,
            api_base=api_base,
            max_retries=2,
        )
        if not ok:
            print('[llm_select_entry_path] LLM call failed: {}'.format(msg),
                  file=sys.stderr)
            return None

        result = json.loads(out_file.read_text(encoding='utf-8'))
    except Exception as exc:
        print('[llm_select_entry_path] Error: {}'.format(exc), file=sys.stderr)
        return None

    # ── Parse & validate ──
    sel = result.get('selected_path')
    reasoning = result.get('reasoning', '')
    if not isinstance(sel, int) or sel < 1 or sel > len(all_paths):
        print('[llm_select_entry_path] Invalid selection {} (need 1-{}), '
              'falling back to heuristics'.format(sel, len(all_paths)),
              file=sys.stderr)
        return None

    selected = all_paths[sel - 1]
    # Sanitize reasoning to ASCII for Python 3.5 Docker containers
    safe_reasoning = reasoning.encode('ascii', 'replace').decode('ascii') if reasoning else ''
    print('[llm_select_entry_path] LLM selected path {}: {} - {}'.format(
        sel, ' -> '.join(selected), safe_reasoning))

    # ── Cache result ──
    if cache_file:
        try:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps(
                {'selected_path': sel, 'reasoning': reasoning}, indent=2
            ), encoding='utf-8')
        except Exception:
            pass

    return selected


def llm_plan_harness_strategy(entry_function, entry_signature_params, sink_function,
                               call_path_names, setup_apis, update_apis, cleanup_apis,
                               sink_source_snippet, cache_dir=None):
    """Use the LLM to plan the harness execution strategy.

    Replaces the heuristic planning chain (infer_path_semantic_traits,
    _select_direct_stages, build_milestone_plan, refine_active_data_plan_from_path)
    with a single LLM call that reads the full context and produces a clean plan.

    Returns a dict with any subset of:
      - input_model       (overrides heuristic + path-refined input_model)
      - parameter_roles   (entry-function-level parameter strategies)
      - call_sequence     (ordered API call plan)
      - milestone_plan    (required state milestones)
      - support_objects   (objects to construct)
      - constraints       (specific constraints)
    Returns {} on failure.
    """
    import hashlib
    import tempfile

    try:
        from llm_adapters.openai import run_openai_json
    except ImportError:
        return {}

    if not (os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_API_TOKEN")):
        return {}

    model, api_base = _load_llm_config()

    def _fmt_param(p):
        if isinstance(p, (list, tuple)) and len(p) >= 2:
            return '{} {}'.format(p[0], p[1])
        if isinstance(p, dict):
            return '{} {}'.format(p.get('type', '?'), p.get('name', '?'))
        return str(p)

    sig = ', '.join(_fmt_param(p) for p in (entry_signature_params or [])[:10])
    path = ' -> '.join(call_path_names) if call_path_names else 'direct'
    setup = ', '.join(setup_apis[:10]) if setup_apis else 'none found'
    update = ', '.join(update_apis[:10]) if update_apis else 'none found'
    cleanup = ', '.join(cleanup_apis[:10]) if cleanup_apis else 'none found'

    prompt = """You are a vulnerability researcher designing a libFuzzer harness to trigger a specific vulnerability.

ENTRY FUNCTION (public API the harness calls):
  {entry}({sig})

VULNERABLE FUNCTION (internal sink we need to reach):
  {sink}

CALL PATH from entry to sink:
  {path}

AVAILABLE PUBLIC APIs discovered in the library:
- Setup/init: {setup}
- Update/feed: {update}
- Cleanup/free: {cleanup}

SINK FUNCTION SOURCE (excerpt):
```c
{source}
```

Design an execution plan for a libFuzzer harness that calls the entry function to reach the sink.

Return a JSON object:
{{
  "input_model": {{
    "primary": "structured-format" or "raw-buffer" or "semantic-arguments",
    "format_type": "XML" or "JSON" or "PNG" or "TIFF" or "ZIP" or "gzip" or "unknown",
    "secondary": ["from: magic-or-container-header, mode-selection, stateful-object, streaming-or-incremental, numeric-controls, parser-lifecycle, post-parse-work-units"],
    "evidence": ["clear reasons for classification"]
  }},
  "parameter_roles": [
    {{"name": "param_name", "type": "param_type", "role": "input-buffer or output-buffer or size or control or state or support-buffer or numeric or value", "strategy": "specific strategy for this parameter"}}
  ],
  "call_sequence": [
    {{"phase": "setup", "function": "actual_function_name", "reason": "why"}},
    {{"phase": "invoke", "function": "entry_function_name", "reason": "main call"}},
    {{"phase": "cleanup", "function": "cleanup_function_name", "reason": "why"}}
  ],
  "milestone_plan": [
    {{"name": "milestone", "kind": "category", "goal": "what to achieve", "harness_expectation": "what the harness does"}}
  ],
  "support_objects": [
    {{"name": "object_name", "kind": "type", "reason": "why the harness must create this"}}
  ],
  "constraints": ["specific constraints - not generic boilerplate"]
}}

RULES:
- call_sequence MUST use real function names from the available APIs above. Do NOT invent function names.
- parameter_roles should describe the ENTRY function's parameters, not the sink's internal parameters.
- milestone_plan should only include milestones specific to THIS vulnerability path. Skip generic lifecycle milestones if they don't matter.
- constraints should be specific and actionable. Skip "do not pass null" type generic advice.
- If the entry function is a parser (XML, JSON, image decoder), input_model.primary should be "structured-format" with the correct format_type.""".format(
        entry=entry_function or '?',
        sig=sig,
        sink=sink_function or '?',
        path=path,
        setup=setup,
        update=update,
        cleanup=cleanup,
        source=(sink_source_snippet or '')[:3000],
    )

    # Cache check
    cache_file = None
    if cache_dir:
        cache_dir = Path(cache_dir)
        key = hashlib.sha256(
            ((entry_function or '') + (sink_function or '') + path).encode()
        ).hexdigest()[:16]
        cache_file = cache_dir / 'llm_harness_strategy_{}.json'.format(key)
        if cache_file.exists():
            try:
                cached = json.loads(cache_file.read_text(encoding="utf-8"))
                if cached.get('input_model') or cached.get('call_sequence'):
                    print("[llm_harness_strategy] Using cached strategy for {} -> {}".format(
                        entry_function, sink_function))
                    return cached
            except Exception:
                pass

    try:
        tmp_dir = Path(tempfile.mkdtemp(prefix="rf_harness_strategy_"))
        prompt_file = tmp_dir / "prompt_harness_strategy.md"
        out_file = tmp_dir / "response.json"
        prompt_file.write_text(prompt, encoding="utf-8")

        ok, msg = run_openai_json(
            prompt_path=prompt_file,
            out_path=out_file,
            model=model,
            api_base=api_base,
            max_retries=2,
        )
        if not ok:
            print("[llm_harness_strategy] LLM call failed: {}".format(msg),
                  file=sys.stderr)
            return {}

        result = json.loads(out_file.read_text(encoding="utf-8"))
    except Exception as exc:
        print("[llm_harness_strategy] Error: {}".format(exc), file=sys.stderr)
        return {}

    # Validate and extract
    strategy = {}
    if 'input_model' in result and isinstance(result['input_model'], dict):
        im = result['input_model']
        if im.get('primary') in ('structured-format', 'raw-buffer', 'semantic-arguments'):
            strategy['input_model'] = im
    if 'parameter_roles' in result and isinstance(result['parameter_roles'], list):
        strategy['parameter_roles'] = result['parameter_roles'][:15]
    if 'call_sequence' in result and isinstance(result['call_sequence'], list):
        strategy['call_sequence'] = result['call_sequence'][:12]
    if 'milestone_plan' in result and isinstance(result['milestone_plan'], list):
        strategy['milestone_plan'] = result['milestone_plan'][:8]
    if 'support_objects' in result and isinstance(result['support_objects'], list):
        strategy['support_objects'] = result['support_objects'][:6]
    if 'constraints' in result and isinstance(result['constraints'], list):
        strategy['constraints'] = result['constraints'][:8]

    # Cache
    if cache_file and strategy:
        try:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps(strategy, indent=2), encoding="utf-8")
        except Exception:
            pass

    print("[llm_harness_strategy] LLM planned {} -> {} - input: {}, {} steps".format(
        entry_function, sink_function,
        strategy.get('input_model', {}).get('primary', '?'),
        len(strategy.get('call_sequence', []))))
    return strategy


def build_execution_plan(entry, public_api_name, wrapper_path, usr_to_name, vuln_context, public_signatures, public_api_names):
    """Build a generic, machine-readable harness construction plan."""
    path_names = [usr_to_name.get(item, item) for item in wrapper_path]

    # Trace which entry parameters flow through the call path to the sink.
    param_flow = trace_parameter_flow(path_names)

    signature_params = public_signatures.get(public_api_name, []) if public_signatures else []
    signature_roles = build_parameter_roles_from_signature(signature_params)
    sink_function = vuln_context.get('function_name') or ''
    original_context = dict(vuln_context or {})
    if signature_roles and public_api_name and sink_function and public_api_name != sink_function:
        parameter_roles = signature_roles
    else:
        parameter_roles = _resolve_parameter_roles(signature_roles, vuln_context.get('parameter_roles', []), vuln_context)
    if not parameter_roles:
        parameter_roles = vuln_context.get('parameter_roles', [])
    vuln_context = _sanitize_parameter_role_context(vuln_context, original_context.get('parameter_roles', []), parameter_roles)
    input_model = vuln_context.get('input_model', {})
    vuln_context = _sanitize_support_object_context(vuln_context, parameter_roles, input_model)

    # For parser/decoder entry functions that accept data+size, simplify the
    # input-buffer strategy — the LLM should pass raw fuzz data directly
    # instead of malloc+copy+null-terminate which can mask OOB reads.
    if public_api_name and _PARSER_ENTRY_RE.search(public_api_name):
        has_size = any(r.get('role') == 'size' for r in parameter_roles)
        if has_size:
            for role in parameter_roles:
                if role.get('role') == 'input-buffer':
                    role['strategy'] = 'pass raw fuzz data directly - the function accepts an explicit length parameter'
    setup_candidates = collect_phase_candidates(vuln_context, 'setup', public_api_name, public_api_names)
    update_candidates = collect_phase_candidates(vuln_context, 'update', public_api_name, public_api_names)
    cleanup_candidates = collect_phase_candidates(vuln_context, 'cleanup', public_api_name, public_api_names)
    state_fields = vuln_context.get('state_fields', [])
    sensitive_controls = vuln_context.get('sensitive_controls', [])
    setup_state_profiles = vuln_context.get('setup_state_profiles', [])
    trigger_relations = vuln_context.get('trigger_relations', [])
    trigger_controls = vuln_context.get('trigger_controls', [])
    required_setup_calls = vuln_context.get('required_setup_calls', [])
    activation_predicates = vuln_context.get('activation_predicates', [])
    support_object_construction = vuln_context.get('support_object_construction', [])
    support_object_field_constraints = vuln_context.get('support_object_field_constraints', [])
    setup_requirements = vuln_context.get('setup_requirements', [])
    invariant_requirements = vuln_context.get('invariant_requirements', [])
    exploration_policy = vuln_context.get('exploration_policy', [])
    allowed_policy_targets = set([item.get('name') for item in parameter_roles if item.get('name')])
    allowed_policy_targets.update(['workload.chunks'])
    exploration_policy = [
        item for item in exploration_policy
        if not item.get('target') or item.get('target') in allowed_policy_targets or item.get('kind') == 'workload'
    ]
    workload_model = vuln_context.get('workload_model', {})
    workload_constraints = vuln_context.get('workload_constraints', [])
    path_traits = infer_path_semantic_traits(path_names, public_api_name)
    stage_contracts = _build_stage_contracts(original_context, path_traits)
    direct_stages, deferred_stages = _select_direct_stages(path_traits)
    retrieved_stage_evidence = retrieve_stage_evidence(
        vuln_context.get('project_root'),
        original_context,
        public_api_name,
        path_names,
        stage_contracts,
    )
    direct_context = _build_stage_projected_context(vuln_context, stage_contracts, direct_stages, path_traits)
    input_model = refine_input_model_from_contract(input_model, vuln_context, public_api_name)
    input_model = refine_input_model_from_path(input_model, path_traits)
    workload_model = refine_workload_model_from_contract(workload_model, vuln_context, public_api_name)
    workload_model = refine_workload_model_from_path(workload_model, path_traits)
    required_setup_calls = direct_context.get('required_setup_calls', [])
    activation_predicates = direct_context.get('activation_predicates', [])
    support_object_construction = direct_context.get('support_object_construction', [])
    support_object_field_constraints = direct_context.get('support_object_field_constraints', [])
    setup_requirements = direct_context.get('setup_requirements', [])
    sink_activation_conditions = direct_context.get('sink_activation_conditions', [])
    milestone_plan = build_milestone_plan(public_api_name, path_names, input_model, workload_model,
                                          parameter_roles, state_fields, setup_candidates,
                                          update_candidates, direct_context)
    stage_contracts = _enrich_stage_execution_contracts(stage_contracts, retrieved_stage_evidence, milestone_plan, path_traits)
    sink_live_predicates = build_execution_sink_live_predicates(milestone_plan, direct_context)
    active_data_plan = direct_context.get('active_data_plan', {})
    active_data_plan = refine_active_data_plan_from_path(active_data_plan, path_traits, milestone_plan)

    constraints = [
        'Use only documented public APIs and valid library-owned objects.',
        'Do not pass fabricated opaque structs or invalid pointers.',
        'Keep buffer sizes and length fields internally consistent.',
        'Cleanup in normal API order and avoid double-finalization in the harness.'
    ]
    if input_model.get('primary') == 'structured-format':
        constraints.append('Do not feed arbitrary raw bytes directly if the target path expects a minimally valid container or header.')
    if update_candidates:
        constraints.append('If using update-style calls, preserve setup -> update -> finalize ordering.')
    constraints.extend(workload_constraints[:4])
    constraints.extend(active_data_plan.get('consistency_constraints', [])[:3])
    constraints.extend(invariant_requirements[:3])

    if trigger_relations:
        for relation in trigger_relations[:3]:
            constraints.append(relation.get('harness_expectation', 'Honor the inferred trigger relation.'))
    constraints = _dedupe_text_items(constraints)

    call_sequence = [
        {
            'phase': 'setup',
            'goal': 'create valid objects, handles, or decoder/reader state before varying trigger controls',
            'candidates': setup_candidates,
        },
        {
            'phase': 'shape-input',
            'goal': 'map bytes into {}'.format(input_model.get('primary', 'raw-buffer')),
            'candidates': [],
        }
    ]

    if stage_contracts.get('parse', {}).get('required_setup_calls') or stage_contracts.get('parse', {}).get('support_object_construction') or stage_contracts.get('parse', {}).get('milestone_hints'):
        call_sequence.append({
            'phase': 'parse',
            'goal': 'satisfy parser or container milestones before sink-local transforms or sink conditions are expected to matter',
            'candidates': [public_api_name] if public_api_name else [],
        })

    if stage_contracts.get('transform', {}).get('required_setup_calls') or stage_contracts.get('transform', {}).get('support_object_construction') or stage_contracts.get('transform', {}).get('milestone_hints'):
        transform_candidates = [item.get('name') for item in stage_contracts.get('transform', {}).get('required_setup_calls', [])[:6]]
        transform_candidates.extend(stage_contracts.get('transform', {}).get('execution_site_candidates', []))
        transform_candidates.extend(retrieved_stage_evidence.get('placement_candidates', []))
        deduped_transform_candidates = []
        seen_transform_candidates = set()
        for item in transform_candidates:
            if not item or item in seen_transform_candidates:
                continue
            seen_transform_candidates.add(item)
            deduped_transform_candidates.append(item)
        call_sequence.append({
            'phase': 'configure-transform',
            'goal': 'apply transform or sink-adjacent configuration only after entry and parser prerequisites are valid, preferably at the first parser-established info or post-parse stage rather than before parsing begins',
            'candidates': deduped_transform_candidates[:6],
            'execution_site_kind': stage_contracts.get('transform', {}).get('execution_site_kind', ''),
            'required_after_milestones': stage_contracts.get('transform', {}).get('required_after_milestones', []),
            'must_consume_support_objects': stage_contracts.get('transform', {}).get('must_consume_support_objects', []),
        })

    call_sequence.append({
        'phase': 'invoke',
        'goal': 'call {} with valid state objects and fuzz-controlled data'.format(public_api_name),
        'candidates': [public_api_name] if public_api_name else [],
    })

    if update_candidates:
        call_sequence.append({
            'phase': 'update',
            'goal': 'repeat incremental operations on bounded chunks of the payload',
            'candidates': update_candidates,
        })

    call_sequence.append({
        'phase': 'cleanup',
        'goal': 'release objects, end sessions, or close handles in a consistent order',
        'candidates': cleanup_candidates,
    })

    # NOTE: coverage_goals are intentionally NOT built from
    # direct_context['execution_hints'] or direct_context['insights'] —
    # those are sink-centric analysis.  Only non-sink sources (e.g.
    # retrieved stage evidence placement hints) contribute.
    coverage_goals = []
    if deferred_stages:
        for item in retrieved_stage_evidence.get('placement_hints', [])[:2]:
            if item not in coverage_goals:
                coverage_goals.append(item)
    coverage_goals = _dedupe_text_items(coverage_goals)

    # ── LLM-based execution strategy override ──
    # The heuristic pipeline above uses keyword-matching (path trait tokens,
    # parameter name substrings) that produces frequent misclassifications.
    # Ask the LLM to plan the strategy with full context and override.
    llm_strategy = llm_plan_harness_strategy(
        entry_function=public_api_name,
        entry_signature_params=signature_params,
        sink_function=entry.get('affected-function'),
        call_path_names=path_names,
        setup_apis=setup_candidates,
        update_apis=update_candidates,
        cleanup_apis=cleanup_candidates,
        sink_source_snippet=vuln_context.get('source_snippet', ''),
        cache_dir=vuln_context.get('project_root'),
    )

    if llm_strategy:
        # Override input_model — this is the #1 misclassification issue
        if 'input_model' in llm_strategy:
            input_model = llm_strategy['input_model']

        # Override parameter_roles with LLM-classified entry-level roles
        if 'parameter_roles' in llm_strategy:
            llm_roles = llm_strategy['parameter_roles']
            # Merge: LLM roles take precedence, keep heuristic roles for
            # parameters the LLM didn't mention
            llm_role_map = {}
            for r in llm_roles:
                name = r.get('name')
                if name:
                    llm_role_map[name] = r
            merged_roles = []
            for existing in parameter_roles:
                name = existing.get('name')
                if name and name in llm_role_map:
                    llm_r = llm_role_map.pop(name)
                    merged_roles.append({
                        'name': name,
                        'type': existing.get('type', llm_r.get('type', '')),
                        'role': llm_r.get('role', existing.get('role', 'value')),
                        'strategy': llm_r.get('strategy', existing.get('strategy', '')),
                    })
                else:
                    merged_roles.append(existing)
            # Add any LLM-only params not in existing roles
            for name, llm_r in llm_role_map.items():
                merged_roles.append({
                    'name': name,
                    'type': llm_r.get('type', ''),
                    'role': llm_r.get('role', 'value'),
                    'strategy': llm_r.get('strategy', ''),
                })
            parameter_roles = merged_roles

        # Override call_sequence with LLM-planned sequence
        if 'call_sequence' in llm_strategy:
            llm_seq = llm_strategy['call_sequence']
            # Convert LLM format to internal format
            new_call_sequence = []
            for step in llm_seq:
                phase = step.get('phase', 'invoke')
                func = step.get('function', '')
                reason = step.get('reason', '')
                new_call_sequence.append({
                    'phase': phase,
                    'goal': reason,
                    'candidates': [func] if func else [],
                })
            if new_call_sequence:
                call_sequence = new_call_sequence

        # Override milestone_plan
        if 'milestone_plan' in llm_strategy:
            llm_milestones = llm_strategy['milestone_plan']
            new_milestones = []
            for m in llm_milestones:
                new_milestones.append({
                    'name': m.get('name', 'milestone'),
                    'kind': m.get('kind', 'lifecycle'),
                    'required': True,
                    'goal': m.get('goal', ''),
                    'evidence': [],
                    'harness_expectation': m.get('harness_expectation', ''),
                })
            if new_milestones:
                milestone_plan = new_milestones

        # Override support object construction
        if 'support_objects' in llm_strategy:
            llm_support = llm_strategy['support_objects']
            if llm_support:
                support_object_construction = [
                    {
                        'name': s.get('name', ''),
                        'kind': s.get('kind', 'object'),
                        'reason': s.get('reason', ''),
                    }
                    for s in llm_support
                ]

        # Override constraints
        if 'constraints' in llm_strategy:
            llm_constraints = llm_strategy['constraints']
            if llm_constraints:
                constraints = llm_constraints

    return {
        'entry_function': public_api_name,
        'sink_function': entry.get('affected-function'),
        'call_path': path_names,
        'input_model': input_model,
        'workload_model': workload_model,
        'parameter_roles': parameter_roles,
        'sensitive_controls': sensitive_controls,
        'setup_state_profiles': setup_state_profiles,
        'trigger_relations': direct_context.get('trigger_relations', trigger_relations),
        'trigger_controls': direct_context.get('trigger_controls', trigger_controls),
        'required_setup_calls': required_setup_calls,
        'activation_predicates': activation_predicates,
        'support_object_construction': support_object_construction,
        'support_object_field_constraints': support_object_field_constraints,
        'setup_requirements': setup_requirements,
        'sink_activation_conditions': sink_activation_conditions,
        'invariant_requirements': invariant_requirements,
        'exploration_policy': exploration_policy,
        'setup_candidates': setup_candidates,
        'update_candidates': update_candidates,
        'cleanup_candidates': cleanup_candidates,
        'input_segments': build_input_segments(direct_context),
        'call_sequence': call_sequence,
        'milestone_plan': milestone_plan,
        'sink_live_predicates': sink_live_predicates,
        'active_data_plan': active_data_plan,
        'coverage_goals': coverage_goals,
        'constraints': constraints,
        'stage_contracts': stage_contracts,
        'direct_stages': direct_stages,
        'deferred_stages': deferred_stages,
        'retrieved_stage_evidence': retrieved_stage_evidence,
        'parameter_flow': param_flow,
        'sink_internal_params': param_flow.get('sink_internal_params', []),
    }


def build_vulnerability_context(root, entry):
    """Analyze the sink source file and return distilled harness semantics."""
    affected_file = entry.get('affected-file', '')
    affected_function = entry.get('affected-function', '')
    if not affected_file or not affected_function:
        return {}

    source_path = find_project_source(root, affected_file)
    if not source_path:
        print('DEBUG: Could not resolve vulnerable source file ' + str(affected_file))
        return {}

    analysis = analyze_vulnerable_function(source_path, affected_function, debug=False)
    if analysis.get('error'):
        # The patch may touch a different file than the one containing the
        # function definition (e.g. png.c patch, but function in pngread.c).
        # Search other project source files for the function definition.
        print('DEBUG: vuln_analyzer failed on {}, searching other source files...'.format(affected_file))
        root_path = Path(root)
        found = False
        for pattern in ['**/*.c', '**/*.cc', '**/*.cpp', '**/*.cxx']:
            for candidate in root_path.glob(pattern):
                if candidate == source_path:
                    continue
                alt_analysis = analyze_vulnerable_function(candidate, affected_function, debug=False)
                if not alt_analysis.get('error'):
                    print('DEBUG: Found {} in {}'.format(affected_function, candidate))
                    analysis = alt_analysis
                    found = True
                    break
            if found:
                break
        if not found:
            print('DEBUG: vuln_analyzer failed: ' + str(analysis.get('error')))
            return {}

    return {
        'project_root': root,
        'function_name': analysis.get('function_name'),
        'source_file': analysis.get('source_file'),
        'insights': analysis.get('insights', []),
        'parameter_conditions': analysis.get('parameter_conditions', []),
        'switch_branches': analysis.get('switch_branches', []),
        'format_checks': analysis.get('format_checks', []),
        'state_machine': analysis.get('state_machine', {}),
        'related_init_functions': analysis.get('related_init_functions', []),
        'parameter_roles': analysis.get('parameter_roles', []),
        'helper_calls': analysis.get('helper_calls', []),
        'state_fields': analysis.get('state_fields', []),
        'field_conditions': analysis.get('field_conditions', []),
        'loop_features': analysis.get('loop_features', {}),
        'input_model': analysis.get('input_model', {}),
        'workload_model': analysis.get('workload_model', {}),
        'sensitive_controls': analysis.get('sensitive_controls', []),
        'exploration_policy': analysis.get('exploration_policy', []),
        'execution_hints': analysis.get('execution_hints', []),
        'api_roles': analysis.get('api_roles', []),
        'workload_constraints': analysis.get('workload_constraints', []),
        'sink_role': analysis.get('sink_role', {}),
        'failure_path_indicators': analysis.get('failure_path_indicators', {}),
        'cleanup_preconditions': analysis.get('cleanup_preconditions', []),
        'ownership_transitions': analysis.get('ownership_transitions', []),
        'trigger_hints': analysis.get('trigger_hints', []),
        'trigger_relations': analysis.get('trigger_relations', []),
        'trigger_controls': analysis.get('trigger_controls', []),
        'required_support_objects': analysis.get('required_support_objects', []),
        'semantic_contract': analysis.get('semantic_contract', {}),
        'required_setup_calls': analysis.get('required_setup_calls', []),
        'activation_predicates': analysis.get('activation_predicates', []),
        'support_object_construction': analysis.get('support_object_construction', []),
        'support_object_field_constraints': analysis.get('support_object_field_constraints', []),
        'helper_preconditions': analysis.get('helper_preconditions', []),
        'setup_requirements': analysis.get('setup_requirements', []),
        'invariant_requirements': analysis.get('invariant_requirements', []),
        'sink_activation_conditions': analysis.get('sink_activation_conditions', []),
        'milestone_hints': analysis.get('milestone_hints', []),
        'sink_live_predicates': analysis.get('sink_live_predicates', []),
        'active_data_plan': analysis.get('active_data_plan', {}),
    }

def find_sink_usr(root, entry, sink_file, sink_func):
    """Find the USR of the sink function by parsing its source file."""
    # Try using clang if available
    try:
        from clang import cindex
        src = os.path.join(entry['cwd'], entry['src'])
        args = entry.get('args', [])
        index = cindex.Index.create()
        tu = index.parse(src, args=args)
        for node in tu.cursor.get_children():
            if node.spelling == sink_func and node.is_definition():
                return node.get_usr()
    except Exception as e:
        print("Warning: libclang parsing failed: " + str(e))
        print("Using fallback regex-based USR generation")
    
    # Fallback: generate a pseudo-USR from function name and file
    # Format: c:@F@funcname (similar to libclang USR format)
    return "c:@F@" + sink_func

def find_public_api_by_name(log_path, sink_func, sink_file):
    """Find a public API that could reach the sink function by analyzing source files."""
    # Load compile commands to get include paths
    cmds = load_clangcmds(log_path)
    
    # Collect header files
    headers = set()
    for cmd in cmds:
        src = cmd.get('src', '')
        if src.endswith('.h') or src.endswith('.hpp'):
            headers.add(os.path.join(cmd.get('cwd', '.'), src))
    
    # Search for public API functions in headers
    public_apis = []
    for header in headers:
        try:
            content = open(header, 'r', encoding='utf-8', errors='ignore').read()
            # Find function declarations
            for match in re.finditer(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*;', content):
                func_name = match.group(1)
                if func_name not in ['if', 'while', 'for', 'switch', 'return', 'sizeof']:
                    public_apis.append(func_name)
        except Exception:
            continue
    
    return public_apis


def _extract_path_source_excerpts(root, wrapper_path, usr_to_name, usr_to_file, entry):
    """Extract smart source excerpts for functions on the best call path + trigger function.

    Returns a dict mapping function_name → excerpt string.
    """
    from llvm_callgraph import _resolve_ll_to_source_path
    try:
        from vuln_analyzer import extract_smart_excerpt
    except ImportError:
        return {}

    excerpts = {}
    # Collect function names to extract
    path_names = [usr_to_name.get(u, u) for u in wrapper_path]
    trigger_funcs = entry.get('trigger_condition', {}).get('affected_functions', [])
    func_names = list(path_names) + [tf for tf in trigger_funcs if tf not in path_names]

    for func_name in func_names:
        if func_name in excerpts:
            continue
        # Find source file location
        loc = usr_to_file.get(func_name, '')
        if not loc:
            # Try the USR form
            for usr, name in usr_to_name.items():
                if name == func_name:
                    loc = usr_to_file.get(usr, '')
                    if loc:
                        break
        if not loc:
            continue

        src_path = _resolve_ll_to_source_path(loc, root)
        if not src_path or not os.path.exists(src_path):
            continue

        # Use compact excerpt for intermediate functions (2000 chars),
        # larger for entry/sink (3000 chars)
        is_endpoint = (func_name == path_names[0] or func_name == path_names[-1])
        max_chars = 3000 if is_endpoint else 2000
        excerpt = extract_smart_excerpt(src_path, func_name, max_chars=max_chars)
        if excerpt:
            excerpts[func_name] = excerpt
            print("DEBUG: Extracted source excerpt for {} ({} chars)".format(func_name, len(excerpt)))

    return excerpts


def main():
    p = argparse.ArgumentParser(description="Generate harness plan from vuln and build log")
    p.add_argument("--root", required=True, help="Project root directory")
    p.add_argument("--vulns", required=True, help="Path to vulnerabilities.json")
    p.add_argument("--cve-id", required=True, help="CVE ID to target")
    p.add_argument("--log", required=False, default="rf_build_commands.jsonl", help="Build-capture JSONL log")
    p.add_argument("--out", required=False, default="harness_plan.json", help="Output plan JSON")
    args = p.parse_args()

    # Load vulnerability entry
    data = json.loads(open(args.vulns, encoding="utf-8").read())
    vulns = data.get("vulnerabilities") or data.get("vulns") or []
    entry = next((v for v in vulns if v.get("cve-id") == args.cve_id), None)
    if not entry:
        sys.exit("CVE " + str(args.cve_id) + " not found in " + str(args.vulns))

    sink_file = entry.get("affected-file")
    sink_func = entry.get("affected-function")
    if not sink_func:
        print("WARNING: affected-function not found for {}. "
              "Enrichment could not auto-derive it from description, patches, "
              "references, or LLM. Skipping this vulnerability.".format(
                  entry.get('cve-id', '?')), file=sys.stderr)
        sys.exit(1)
    # affected-file is optional — if missing, search the callgraph and source tree
    if not sink_file:
        print("DEBUG: affected-file not provided, will locate via callgraph or source tree")

    # Load compile commands for public API discovery
    pub_cmds = load_pubcmds(args.log)
    
    # Build project callgraph from LLVM IR files
    log_path = os.path.join(args.root, args.log) if not os.path.isabs(args.log) else args.log
    adj, usr_to_file, usr_to_name = build_callgraph_from_build_log(log_path, args.root)
    
    # For sink USR, use function name directly (LLVM IR uses function names, not USRs)
    sink_usr = sink_func  # In LLVM IR, we use function names as identifiers

    # Auto-locate affected-file from callgraph if not provided
    if not sink_file:
        # Try usr_to_file first (sink_func is the "USR" in LLVM IR mode)
        loc = usr_to_file.get(sink_func, "")
        if loc:
            sink_file = loc.split(":")[0] if ":" in loc else loc
            # LLVM IR paths (.ll) need resolution to their .c/.cpp source
            if sink_file.endswith('.ll'):
                # e.g. /src/expat/expat/lib/.libs/xmlparse.ll → xmlparse.c
                # LLVM IR filenames may embed the original source extension:
                #   cjson_add.c.ll → ll_base = 'cjson_add.c'
                # Strip both the .ll and any embedded source extension to
                # get the true stem for matching.
                ll_base = os.path.splitext(os.path.basename(sink_file))[0]
                _src_exts = ('.c', '.cc', '.cpp', '.cxx')
                stem = ll_base
                # Strip libtool prefix: libfoo_la-bar → bar
                stem = re.sub(r'^lib\w+_la-', '', stem)
                for _ext in _src_exts:
                    if ll_base.endswith(_ext):
                        stem = ll_base[:-len(_ext)]
                        break
                import glob
                for ext in ('*.c', '*.cc', '*.cpp', '*.cxx'):
                    for src in glob.glob(os.path.join(args.root, '**', ext), recursive=True):
                        if os.path.splitext(os.path.basename(src))[0] == stem:
                            sink_file = os.path.relpath(src, args.root)
                            break
                    if not sink_file.endswith('.ll'):
                        break
                else:
                    # Could not resolve .ll to source — use ll_base if it
                    # already has a source extension, otherwise append .c
                    if any(ll_base.endswith(e) for e in _src_exts):
                        sink_file = ll_base
                    else:
                        sink_file = ll_base + '.c'
            # Make relative to root
            if os.path.isabs(sink_file) and sink_file.startswith(args.root):
                sink_file = os.path.relpath(sink_file, args.root)
            entry["affected-file"] = sink_file
            print("DEBUG: Auto-located affected-file from callgraph: {}".format(sink_file))
        else:
            # Fallback: grep for function definition in source files
            import glob
            for src in glob.glob(os.path.join(args.root, '**', '*.c'), recursive=True):
                try:
                    with open(src, 'r', errors='ignore') as f:
                        for line in f:
                            if re.search(r'\b' + re.escape(sink_func) + r'\s*\(', line):
                                sink_file = os.path.relpath(src, args.root)
                                entry["affected-file"] = sink_file
                                print("DEBUG: Auto-located affected-file from source grep: {}".format(sink_file))
                                break
                    if sink_file:
                        break
                except Exception:
                    continue
        if not sink_file:
            sys.exit("Could not locate source file for function '{}'. Provide affected-file manually.".format(sink_func))

    # Discover public APIs from header files (GENERIC - no hardcoded prefixes)
    public_dirs = find_public_include_dirs(pub_cmds, args.root)
    
    # Use extract_function_signatures to get function names directly from headers
    # This is more reliable than USR parsing and works for any library
    public_signatures = extract_function_signatures(public_dirs)
    public_api_names = set(public_signatures.keys())
    
    # Filter out C standard library functions (these are NOT the library's public APIs)
    # This is a blocklist of common stdlib functions that appear in project headers
    STDLIB_FUNCTIONS = {
        # stdio.h
        'printf', 'fprintf', 'sprintf', 'snprintf', 'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf',
        'scanf', 'fscanf', 'sscanf', 'fopen', 'fclose', 'fread', 'fwrite', 'fseek', 'ftell', 'rewind',
        'fgetc', 'fgets', 'fputc', 'fputs', 'getchar', 'putchar', 'puts', 'gets', 'ungetc',
        'fflush', 'clearerr', 'feof', 'ferror', 'perror', 'remove', 'rename', 'tmpfile', 'tmpnam',
        'setbuf', 'setvbuf', 'fileno', 'fdopen', 'popen', 'pclose',
        # stdlib.h
        'malloc', 'calloc', 'realloc', 'free', 'abort', 'exit', 'atexit', 'quick_exit', 'at_quick_exit',
        'getenv', 'system', 'atoi', 'atol', 'atoll', 'atof', 'strtol', 'strtoll', 'strtoul', 'strtoull',
        'strtof', 'strtod', 'strtold', 'rand', 'srand', 'random', 'srandom', 'rand_r', 'drand48', 'srand48',
        'abs', 'labs', 'llabs', 'div', 'ldiv', 'lldiv', 'bsearch', 'qsort', 'mblen', 'mbtowc', 'wctomb',
        'mbstowcs', 'wcstombs', 'mkstemp', 'mkdtemp', 'mktemp', 'mkostemp', 'mkstemps',
        # string.h
        'memcpy', 'memmove', 'memset', 'memcmp', 'memchr', 'strcpy', 'strncpy', 'strcat', 'strncat',
        'strcmp', 'strncmp', 'strchr', 'strrchr', 'strstr', 'strtok', 'strlen', 'strerror', 'strcoll',
        'strxfrm', 'strdup', 'strndup', 'strcasestr', 'strcasecmp', 'strncasecmp',
        # ctype.h
        'isalnum', 'isalpha', 'isblank', 'iscntrl', 'isdigit', 'isgraph', 'islower', 'isprint',
        'ispunct', 'isspace', 'isupper', 'isxdigit', 'tolower', 'toupper',
        # math.h
        'sin', 'cos', 'tan', 'asin', 'acos', 'atan', 'atan2', 'sinh', 'cosh', 'tanh',
        'exp', 'log', 'log10', 'log2', 'pow', 'sqrt', 'ceil', 'floor', 'fabs', 'fmod', 'round',
        'trunc', 'fmod', 'remainder', 'hypot', 'cbrt', 'erf', 'erfc', 'lgamma', 'tgamma',
        'isnan', 'isinf', 'isfinite', 'isnanf', 'isinff', 'finite', 'fpclassify', 'signbit',
        'sqrtf', 'sqrtl', 'sinf', 'sinl', 'cosf', 'cosl', 'tanf', 'tanl', 'expf', 'expl',
        'logf', 'logl', 'powf', 'powl', 'ceilf', 'ceill', 'floorf', 'floorl', 'fabsf', 'fabsl',
        'ldexp', 'ldexpf', 'ldexpl', 'frexp', 'frexpf', 'frexpl', 'modf', 'modff', 'modfl',
        # time.h
        'time', 'clock', 'difftime', 'mktime', 'strftime', 'asctime', 'ctime', 'gmtime', 'localtime',
        'gettimeofday', 'clock_gettime', 'clock_settime', 'nanosleep', 'sleep', 'usleep',
        # unistd.h / fcntl.h
        'open', 'close', 'read', 'write', 'pread', 'pwrite', 'lseek', 'dup', 'dup2', 'pipe',
        'fork', 'exec', 'execve', 'execl', 'execlp', 'execle', 'execv', 'execvp', 'execvpe',
        'wait', 'waitpid', 'waitid', '_exit', 'chdir', 'fchdir', 'getcwd', 'chown', 'fchown', 'lchown',
        'link', 'unlink', 'symlink', 'readlink', 'rename', 'truncate', 'ftruncate', 'access', 'faccessat',
        'getpid', 'getppid', 'getuid', 'geteuid', 'getgid', 'getegid', 'getlogin', 'getlogin_r',
        'setuid', 'seteuid', 'setgid', 'setegid', 'getgroups', 'setgroups', 'chroot',
        # assert.h
        '__assert_fail', 'assert',
        # pthread.h
        'pthread_create', 'pthread_exit', 'pthread_join', 'pthread_detach', 'pthread_self',
        'pthread_equal', 'pthread_mutex_init', 'pthread_mutex_destroy', 'pthread_mutex_lock',
        'pthread_mutex_unlock', 'pthread_mutex_trylock', 'pthread_cond_init', 'pthread_cond_destroy',
        'pthread_cond_wait', 'pthread_cond_signal', 'pthread_cond_broadcast', 'pthread_cond_timedwait',
        'pthread_rwlock_init', 'pthread_rwlock_destroy', 'pthread_rwlock_rdlock', 'pthread_rwlock_wrlock',
        'pthread_rwlock_unlock', 'pthread_key_create', 'pthread_key_delete', 'pthread_getspecific',
        'pthread_setspecific', 'pthread_once', 'pthread_atfork',
        # signal.h
        'signal', 'sigaction', 'sigprocmask', 'sigpending', 'sigsuspend', 'sigwait', 'kill', 'raise',
        'alarm', 'pause', 'sigemptyset', 'sigfillset', 'sigaddset', 'sigdelset', 'sigismember',
        # dirent.h
        'opendir', 'closedir', 'readdir', 'readdir_r', 'rewinddir', 'seekdir', 'telldir', 'scandir',
        # errno.h
        'strerror', 'perror',
        # misc common
        'index', 'rindex', 'ecvt', 'fcvt', 'gcvt', 'putenv', 'setenv', 'unsetenv', 'clearenv',
        'bzero', 'bcopy', 'bcmp', 'explicit_bzero', 'strdupa', 'strndupa',
        # internal/test functions
        '_fail_unless', '_INTERNAL_trim_to_complete_utf8_characters',
    }
    
    # Remove stdlib functions from public APIs
    public_api_names = public_api_names - STDLIB_FUNCTIONS
    
    # Method 1: Get exported symbols from compiled libraries (MOST RELIABLE)
    # This uses nm/readelf to read actual symbol tables from .so/.a/.lib files
    # This is the ONLY method we use when libraries are found - no heuristics needed
    exported_symbols, found_libraries = get_exported_symbols(args.root)
    
    print("DEBUG: Found " + str(len(found_libraries)) + " libraries: " + str(found_libraries[:5]))
    print("DEBUG: Exported symbols from libraries (" + str(len(exported_symbols)) + " total): " + str(list(exported_symbols)[:20]))
    
    # PRIORITY ORDER (strictly in order, no mixing):
    # 1. Exported symbols from compiled libraries (most reliable - actual exports)
    # 2. Functions with export macros in headers (good fallback)
    # 3. All header functions (last resort - may include internal functions)
    
    if exported_symbols:
        # Cross-reference exported symbols with header declarations
        # A TRUE public API must be:
        # 1. Exported from the shared library (GLOBAL binding + DEFAULT visibility)
        # 2. Declared in a public header file
        # This filters out internal functions that are accidentally exported
        
        # Get functions declared in headers (from earlier extraction)
        header_functions = set(extract_function_signatures(public_dirs).keys())
        
        # Debug: check if sink function is in exported symbols or headers
        print("DEBUG: Is sink '" + str(sink_func) + "' in exported_symbols? " + str(sink_func in exported_symbols))
        print("DEBUG: Is sink '" + str(sink_func) + "' in header_functions? " + str(sink_func in header_functions))
        
        # True public APIs = exported AND in headers
        true_public_apis = exported_symbols.intersection(header_functions)
        
        print("DEBUG: Cross-referencing exported symbols with header declarations")
        print("DEBUG: Exported symbols: " + str(len(exported_symbols)))
        print("DEBUG: Header functions: " + str(len(header_functions)))
        print("DEBUG: True public APIs (exported AND in headers): " + str(len(true_public_apis)))
        
        # Debug: check if sink is in true_public_apis
        print("DEBUG: Is sink '" + str(sink_func) + "' in true_public_apis? " + str(sink_func in true_public_apis))
        
        if true_public_apis:
            public_api_names = true_public_apis
            print("DEBUG: Using cross-referenced public APIs (exported AND declared in headers)")
        else:
            # Fallback: use exported symbols if cross-reference fails
            public_api_names = exported_symbols
            print("DEBUG: Cross-reference empty, using all exported symbols")
    else:
        # Method 2: Use export macro detection from headers (good fallback)
        exported_signatures = extract_exported_functions(public_dirs)
        exported_api_names = set(exported_signatures.keys())
        
        print("DEBUG: No exported symbols found - trying export macro detection")
        print("DEBUG: Exported APIs (with export macros from headers): " + str(list(exported_api_names)[:20]))
        
        if exported_api_names:
            # Use export macro detection - these are explicitly marked for export
            public_api_names = exported_api_names
            print("DEBUG: Using export macro detection from headers")
        else:
            # Method 3: All header functions (last resort)
            # Note: This may include internal functions declared in headers
            # But without exports or macros, we have no way to distinguish
            print("DEBUG: Using all header functions as public APIs (last resort)")
    
    print("DEBUG: Final public_api_names count: " + str(len(public_api_names)))
    print("DEBUG: Public APIs sample: " + str(list(public_api_names)[:20]))
    
    # Build entry for find_sink_usr (still needed for USR fallback)
    build_entry = {'cwd': args.root, 'src': sink_file, 'args': []}

    # Build name-to-USR mapping from callgraph
    name_to_usr = {}
    for usr, name in usr_to_name.items():
        name_to_usr[name] = usr
    
    # NOTE: USR-based extraction is intentionally NOT used here because:
    # 1. extract_public_usrs() doesn't filter private headers (pngpriv.h, etc.)
    # 2. The symbol-based cross-reference is more reliable
    # 3. Adding USRs would pollute public_api_names with internal functions
    # public_usrs is still used for the wrapper path search below
    public_usrs = extract_public_usrs(public_dirs)
    # DO NOT add USR-based names to public_api_names - it bypasses our filtering

    # Find wrapper path using USRs
    wrapper_path = find_public_wrapper(adj, usr_to_file, sink_usr, list(public_usrs))
    public_api_name = None  # Initialize
    all_scored_paths = []  # All candidate paths with scores (for prompt)
    
    # If not found by USR, try name-based matching
    if not wrapper_path:
        # Get sink function name
        sink_name = sink_func
        # Find callers by name - build reverse adjacency (callee -> callers)
        name_adjacency = {}  # callee_name -> [caller_names]
        for caller_usr, callee_usrs in adj.items():
            caller_name = usr_to_name.get(caller_usr, '')
            for callee_usr in callee_usrs:
                callee_name = usr_to_name.get(callee_usr, '')
                if callee_name and caller_name:
                    if caller_name not in name_adjacency.setdefault(callee_name, []):
                        name_adjacency[callee_name].append(caller_name)
        
        # Debug: show the callers of parse_string and parse_value
        print("DEBUG: Callers of '" + str(sink_name) + "': " + str(name_adjacency.get(sink_name, [])))
        
        # SPECIAL CASE: If sink has NO callers, it IS a public API (root function)
        # No BFS needed - the sink itself is the entry point
        if sink_name not in name_adjacency or len(name_adjacency.get(sink_name, [])) == 0:
            print("DEBUG: Sink '" + str(sink_name) + "' has no callers - treating as public API")
            wrapper_path = [sink_usr]
            public_api_name = sink_name
            print("INFO: Sink function '" + str(sink_func) + "' is a root function (no callers) - treating as public API")
        else:
            # Identify ROOT functions (have NO callers within the library)
            # These are the true entry points / public APIs
            all_callees = set()
            for caller, callees in name_adjacency.items():
                all_callees.update(callees)
            
            root_functions = set()
            for func_name in usr_to_name.values():
                if func_name not in all_callees and func_name not in ['main', '__libc_start_main']:
                    # This function has no callers - it's a root/entry point
                    root_functions.add(func_name)
            
            # Entry points = root functions that are also public APIs (from headers)
            # This is GENERIC - no hardcoded naming conventions
            entry_point_candidates = root_functions.intersection(public_api_names)
            if not entry_point_candidates:
                # Fall back to all public APIs that can reach the sink
                # (any function declared in headers is a valid entry point)
                entry_point_candidates = public_api_names
            
            print("DEBUG: Root functions (no callers): " + str(list(root_functions)[:20]))
            print("DEBUG: Entry point candidates: " + str(list(entry_point_candidates)[:20]))
            
            # BFS from sink_name to find a public API - continue up the call chain
            # Use deterministic ordering (sorted) for reproducibility
            from collections import deque
            queue = deque([[sink_name]])
            visited = set([sink_name])
            found_path = None
            all_paths = []  # Collect all paths to public APIs
            
            # DEBUG: Check if sink is in public_api_names right before BFS
            print("DEBUG: Right before BFS - Is sink '" + str(sink_name) + "' in public_api_names? " + str(sink_name in public_api_names))
            
            while queue:
                path = queue.popleft()
                cur = path[0]
                
                # Check if this is a public API (by name)
                if cur in public_api_names:
                    # Always include the path — even when the sink itself
                    # is a public API (length-1 self-path).  The taint
                    # scorer will rank it against wrapper paths on merit
                    # (direct data control, no hop penalty, etc.).
                    all_paths.append(path)
                    # For the self-path keep exploring callers so wrapper
                    # paths are still discovered; for wrapper paths stop.
                    if not (len(path) == 1 and cur == sink_name):
                        continue
                
                # Find callers of current function - SORT for determinism
                callers = sorted(name_adjacency.get(cur, []))
                for caller in callers:
                    if caller not in visited:
                        visited.add(caller)
                        new_path = [caller] + path
                        queue.append(new_path)
            
            # Prefer entry-point candidates, but still score them instead of taking the first BFS hit.
            if all_paths:
                candidate_paths = [path for path in all_paths if path[0] in entry_point_candidates]
                if candidate_paths:
                    all_paths = candidate_paths

            # ── LLM-based path selection (before heuristic scoring) ──
            # When multiple candidate paths exist, ask the LLM to pick the
            # best entry point using vulnerability context that heuristics lack.
            llm_selected = False
            if all_paths and len(all_paths) > 1:
                llm_path = llm_select_entry_path(
                    all_paths, sink_name, entry, public_signatures,
                    cache_dir=args.root,
                )
                if llm_path is not None:
                    found_path = llm_path
                    llm_selected = True
                else:
                    print("WARNING: LLM entry-path selection unavailable or "
                          "failed, falling back to heuristic scoring",
                          file=sys.stderr)

            # Score candidate paths using path-flow and taint heuristics.
            # Also boost paths that go through trigger-relevant (patch-affected) functions.
            trigger_funcs = set(
                entry.get('trigger_condition', {}).get('affected_functions', [])
            )
            if all_paths:
                # Score each path using taint analysis
                scored_paths = []
                for p in all_paths:
                    score = score_path_taint(p)
                    # Bonus for paths passing through patch-affected functions
                    if trigger_funcs:
                        overlap = trigger_funcs.intersection(p)
                        if overlap:
                            score += 30 * len(overlap)
                    scored_paths.append((score, p))
                
                # Sort by score (highest first)
                scored_paths.sort(key=lambda x: -x[0])
                
                # Print all paths with scores
                print("DEBUG: Found " + str(len(all_paths)) + " paths to public APIs (sorted by taint score):")
                for i, (score, p) in enumerate(scored_paths[:20]):  # Show top 20
                    flag = ""
                    if trigger_funcs and trigger_funcs.intersection(p):
                        flag = " [* trigger]"
                    sel_flag = " [<- LLM selected]" if llm_selected and p == found_path else ""
                    print("  Path " + str(i+1) + " (score=" + str(score) + ")" + flag + sel_flag + ": " + " -> ".join(p))
                
                # Use LLM selection if available, otherwise highest-scoring path
                if not llm_selected:
                    found_path = scored_paths[0][1]
                # Store all scored paths for prompt (limit to top 10)
                for score, p in scored_paths[:10]:
                    has_trigger = bool(trigger_funcs and trigger_funcs.intersection(p))
                    all_scored_paths.append({
                        'path': p,
                        'score': score,
                        'has_trigger': has_trigger,
                    })
                if llm_selected:
                    print("DEBUG: Selected path via LLM: " + " -> ".join(found_path))
                else:
                    print("DEBUG: Selected path with highest taint score: " + " -> ".join(found_path))
            
            if found_path:
                # Convert names back to USRs
                wrapper_path = [name_to_usr.get(n, n) for n in found_path]
                public_api_name = found_path[0]  # First element is the public API
    
    if not wrapper_path:
        # Check if the sink function itself is a public API
        # This happens when the vulnerable function is directly exposed (no wrapper needed)
        
        # First check project's header files directly
        project_public_apis = set()
        
        # Method 1: Use public_dirs from compile commands
        for header_dir in public_dirs:
            header_path = os.path.join(args.root, header_dir)
            if os.path.exists(header_path):
                try:
                    content = open(header_path, 'r', encoding='utf-8', errors='ignore').read()
                    for match in re.finditer(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*;', content):
                        func_name = match.group(1)
                        if func_name not in ['if', 'while', 'for', 'switch', 'return', 'sizeof']:
                            project_public_apis.add(func_name)
                except Exception:
                    pass
        
        # Method 2: Scan all .h files in project root (fallback)
        if not project_public_apis:
            print("DEBUG: Scanning project root for header files...")
            for root_dir, dirs, files in os.walk(args.root):
                # Skip build directories and hidden dirs
                dirs[:] = [d for d in dirs if d not in ['build', '.git', 'CMakeFiles']]
                for f in files:
                    if f.endswith('.h') or f.endswith('.hpp'):
                        try:
                            header_path = os.path.join(root_dir, f)
                            content = open(header_path, 'r', encoding='utf-8', errors='ignore').read()
                            # Pattern 1: Standard C function declaration: func_name(args);
                            for match in re.finditer(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*;', content):
                                func_name = match.group(1)
                                if func_name not in ['if', 'while', 'for', 'switch', 'return', 'sizeof']:
                                    project_public_apis.add(func_name)
                            # Pattern 2: Macro-wrapped function: MACRO_NAME func_name(args)
                            for match in re.finditer(r'\b[A-Z_][A-Z0-9_]*\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', content):
                                func_name = match.group(1)
                                project_public_apis.add(func_name)
                            # Pattern 3: ANY_MACRO(return_type) followed by func_name on next line(s)
                            # Handles: MACRO(type)\nfunc_name(args)
                            for match in re.finditer(r'[A-Z_][A-Z0-9_]*\s*\([^)]*\)\s*\n\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', content):
                                func_name = match.group(1)
                                project_public_apis.add(func_name)
                            # Pattern 4: Function name at line start followed by paren (declaration)
                            for match in re.finditer(r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*;', content, re.MULTILINE):
                                func_name = match.group(1)
                                if func_name not in ['if', 'while', 'for', 'switch', 'return', 'sizeof', 'typedef', 'struct', 'enum', 'union']:
                                    project_public_apis.add(func_name)
                            # Pattern 5: Uppercase prefix functions like XML_Parse, JSON_Parse etc.
                            for match in re.finditer(r'\b([A-Z][a-zA-Z]+_[a-zA-Z_][a-zA-Z0-9_]*)\s*\(', content):
                                func_name = match.group(1)
                                project_public_apis.add(func_name)
                        except Exception:
                            pass
        
        print("DEBUG: Project public APIs from headers: " + str(list(project_public_apis)[:20]))
        
        if sink_func in public_api_names or sink_func in project_public_apis:
            print("INFO: Sink function '" + str(sink_func) + "' is already a public API - no wrapper needed")
            wrapper_path = [sink_usr]
            public_api_name = sink_func
        else:
            # Debug: show what we searched
            print("DEBUG: BFS visited " + str(len(visited)) + " functions")
            print("DEBUG: visited functions: " + str(list(visited)[:20]))
            print("DEBUG: public_api_names sample: " + str(list(public_api_names)[:20]))
            print("DEBUG: project_public_apis: " + str(list(project_public_apis)[:20]))
            sys.exit("Could not find a public API wrapper for sink '" + str(sink_func) + "'. Public APIs found: " + str(list(public_api_names)[:20]))

    # Get the public API name from the wrapper path
    # Path format is [sink, ..., public_api] - so public API is at the END
    if wrapper_path and not public_api_name:
        public_api_usr = wrapper_path[-1]  # Last element is the public API
        public_api_name = usr_to_name.get(public_api_usr, public_api_usr.split('@')[-1].replace('F@', '') if '@' in public_api_usr else public_api_usr)
    
    print("DEBUG: Final public_api_name: " + str(public_api_name))

    vuln_context = build_vulnerability_context(args.root, entry)
    vuln_context = normalize_vuln_context(vuln_context, public_api_name, public_signatures)
    execution_plan = build_execution_plan(entry, public_api_name, wrapper_path, usr_to_name, vuln_context, public_signatures, public_api_names)
    trigger_plan = build_trigger_plan(entry, public_api_name, execution_plan, vuln_context)
    construction_plan = build_construction_plan(entry, public_api_name, execution_plan, trigger_plan, vuln_context)
    
    plan_usr_to_file, plan_usr_to_name = trim_plan_symbol_maps(
        usr_to_file,
        usr_to_name,
        sink_usr,
        wrapper_path,
    )

    # ── Extract source excerpts for call-path + trigger functions ──
    path_source_excerpts = _extract_path_source_excerpts(
        args.root, wrapper_path, usr_to_name, usr_to_file, entry
    )

    # Identify trigger function (patch-affected function NOT on best path)
    trigger_funcs = set(entry.get('trigger_condition', {}).get('affected_functions', []))
    best_path_names = [usr_to_name.get(u, u) for u in wrapper_path]
    trigger_function = ''
    for tf in trigger_funcs:
        if tf not in best_path_names and tf != sink_func:
            trigger_function = tf
            break

    # Emit harness plan
    plan = {
        "vuln_entry": entry,
        "sink_usr": sink_usr,
        "wrapper_path": wrapper_path,
        "usr_to_file": plan_usr_to_file,
        "usr_to_name": plan_usr_to_name,
        "public_api_name": public_api_name,
        "public_api_names": sorted(public_api_names),
        "vuln_context": vuln_context,
        "execution_plan": execution_plan,
        "trigger_plan": trigger_plan,
        "construction_plan": construction_plan,
        "all_call_paths": all_scored_paths,
        "trigger_function": trigger_function,
        "path_source_excerpts": path_source_excerpts,
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(plan, f, indent=2)
    print("Harness plan written to " + str(args.out))

if __name__ == "__main__":
    main()