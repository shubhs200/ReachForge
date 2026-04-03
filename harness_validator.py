#!/usr/bin/env python3
import json
import os
import re
import shutil
import subprocess
from pathlib import Path


def _load_plan(plan_path):
    try:
        return json.loads(Path(plan_path).read_text(encoding="utf-8"))
    except Exception:
        return {}


def _read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


# Regex matching common one-shot parser/reader/decoder function name patterns.
# When the entry function matches, raw data+size is the *expected* calling
# convention, so _direct_raw_buffer_call violations should be suppressed.
_PARSER_ENTRY_RE = re.compile(
    r'(?:parse|read|decode|load|deserialize|from_?(?:string|buffer|data|bytes|json|xml|yaml|cbor|msgpack))',
    re.IGNORECASE,
)


def _is_parser_entry(func_name):
    """Return True if func_name looks like a one-shot parser/reader/decoder."""
    return bool(func_name and _PARSER_ENTRY_RE.search(func_name))


def _count_calls(code, func_name):
    if not code or not func_name:
        return 0
    pattern = re.compile(r'\b' + re.escape(func_name) + r'\s*\(')
    return len(pattern.findall(code))


def _has_loop(code):
    return bool(re.search(r'\b(for|while|do)\b', code))


def _has_selector_logic(code):
    if '%' in code or 'switch' in code:
        return True
    if re.search(r'static\s+const\s+.*\[\]', code):
        return True
    if re.search(r'case\s+[-_A-Za-z0-9]+\s*:', code):
        return True
    return False


def _has_generic_state_setup(code):
    pattern = re.compile(r'\b(?:[A-Za-z_][A-Za-z0-9_:]*(?:init|create|open|setup|begin|alloc)[A-Za-z0-9_:]*)\s*\(', re.IGNORECASE)
    return bool(pattern.search(code or ''))


def _has_transform_configuration(code, plan_keywords=None):
    generic_tokens = ['transform', 'option', 'config', 'convert', 'scale']
    tokens = list(plan_keywords or []) + generic_tokens
    pattern = re.compile(r'\b([A-Za-z_][A-Za-z0-9_:]*)\s*\(', re.IGNORECASE)
    for match in pattern.finditer(code or ''):
        name = match.group(1).lower()
        if name in ['setjmp', 'memset', 'memcpy', 'if', 'for', 'while', 'return', 'sizeof']:
            continue
        if any(token in name for token in tokens):
            return True
    return False


def _call_uses_synthesized_buffer(code, entry_function):
    if not code or not entry_function:
        return False
    call_pattern = re.compile(r'\b' + re.escape(entry_function) + r'\s*\(([^;]+)\)', re.DOTALL)
    for match in call_pattern.finditer(code):
        args = match.group(1).lower()
        if '.data(' not in args:
            continue
        if re.search(r'\bdata\s*\.data\s*\(', args):
            continue
        return True
    return False


def _looks_like_synthesized_container(code, entry_function=None):
    lowered = (code or '').lower()
    shaping_score = 0

    if entry_function and _call_uses_synthesized_buffer(code, entry_function):
        shaping_score += 2

    if re.search(r'\b(?:header|magic|signature|container|record|frame|section|packet|block|table|prefix|payload)\b', lowered):
        shaping_score += 1

    if re.search(r'\b(?:append|push_back|insert|resize|reserve|assign|emplace_back|clear)\s*\(', code or '', re.IGNORECASE):
        shaping_score += 1

    if re.search(r'\b(?:memcpy|memmove|copy|fill_n)\s*\(', code or '', re.IGNORECASE):
        shaping_score += 1

    if re.search(r'\b(?:crc|checksum|adler|hash|htonl|htons|writebe|writele|bswap)\w*\s*\(', code or '', re.IGNORECASE):
        shaping_score += 1

    if re.search(r'\b(?:std::)?(?:vector|string|array)\s*<', code or '', re.IGNORECASE):
        shaping_score += 1

    if re.search(r'\b(?:uint(?:8|16|32|64)_t|unsigned\s+char|char)\s+[A-Za-z_][A-Za-z0-9_]*\s*\[[^\]]+\]', code or '', re.IGNORECASE):
        shaping_score += 1

    return shaping_score >= 2


def _has_structured_container_shaping(code, entry_function=None):
    return _looks_like_synthesized_container(code, entry_function)


def _looks_like_trailing_append_only(code):
    patterns = [
        r'memcpy\s*\([^\)]*\+\s*[A-Za-z_][A-Za-z0-9_]*\s*,\s*data\s*,\s*[A-Za-z_][A-Za-z0-9_]*\)',
        r'\b(?:append|insert|assign)\s*\([^\)]*\bdata\b',
        r'if\s*\([^\)]*extra[^\)]*\)\s*std::memcpy\s*\([^\)]*data[^\)]*\)',
        r'ConsumeRemainingBytes\s*\(',
    ]
    return any(re.search(pattern, code or '', re.IGNORECASE | re.DOTALL) for pattern in patterns)


def _looks_like_direct_progressive_passthrough(code, entry_function):
    if not code or not entry_function:
        return False
    call_pattern = re.compile(r'\b' + re.escape(entry_function) + r'\s*\(([^;]+)\)', re.DOTALL)
    for match in call_pattern.finditer(code):
        args = match.group(1).lower()
        synthesized_buffer = _call_uses_synthesized_buffer(match.group(0), entry_function)
        if synthesized_buffer:
            continue
        if 'data +' in args or 'data,' in args or 'data )' in args or re.search(r'reinterpret_cast<[^>]+>\s*\(\s*data\b', args):
            return True
    return False


def _counts_data_usages(code):
    return len(re.findall(r'\bdata\s*(?:\[|\+|,|\))', code or ''))


def _has_data_driven_support_object(code, support_keywords=None):
    keywords = list(support_keywords or [])
    if not keywords:
        return False
    for kw in keywords:
        pattern = re.compile(r'\b' + re.escape(kw) + r'\s*\[[^\]]+\][^;\n]*=\s*.*data', re.IGNORECASE)
        if pattern.search(code or ''):
            return True
        pattern2 = re.compile(r'\b' + re.escape(kw) + r'[^\n;=]*=\s*.*data', re.IGNORECASE)
        if pattern2.search(code or ''):
            return True
    return False


def _extract_stack_symbols(output):
    """Extract function names from the primary ASAN crash stack only.

    ASAN output contains multiple sections: the crash stack, then metadata
    sections like "allocated by:", "freed by:", "previously allocated by:",
    and "Thread T" blocks.  We must only parse the *first* crash stack to
    avoid false sink-hit classification when the sink appears only in
    allocation metadata.
    """
    symbols = []
    frame_re = re.compile(r'#\d+\s+[^\n]*?in\s+([A-Za-z_][A-Za-z0-9_:]*)')
    # Stop markers: ASAN metadata sections that follow the primary crash stack.
    stop_re = re.compile(
        r'^\s*(?:allocated by|freed by|previously allocated by|'
        r'Thread T\d|SUMMARY:|==\d+==ABORTING)',
        re.MULTILINE,
    )
    text = output or ''
    # Find where the metadata begins and only parse up to that point.
    stop_match = stop_re.search(text)
    crash_section = text[:stop_match.start()] if stop_match else text
    for match in frame_re.finditer(crash_section):
        symbols.append(match.group(1))
    return symbols


def classify_runtime_evidence(plan_path, output, returncode):
    plan = _load_plan(plan_path)
    execution_plan = plan.get('execution_plan', {})
    sink_function = execution_plan.get('sink_function') or plan.get('vuln_entry', {}).get('affected-function')
    entry_function = execution_plan.get('entry_function') or plan.get('public_api_name')
    call_path = execution_plan.get('call_path') or plan.get('wrapper_path') or []
    stack_symbols = _extract_stack_symbols(output)
    classification = 'smoke-only'
    score = 15
    rationale = []

    if returncode != 0:
        classification = 'harness-or-setup-fault'
        score = 5
        rationale.append('the runtime probe crashed')

    # Check for harness-only crashes FIRST — if the crash stack points
    # exclusively into generated harness code, don't let downstream
    # sink-hit / sink-adjacent classification override that signal.
    harness_fault = '/fuzzer.cc:' in (output or '') and not stack_symbols

    if not harness_fault and sink_function and sink_function in stack_symbols:
        classification = 'sink-hit'
        score = 100
        rationale.append('the crash stack reached the selected sink function {}'.format(sink_function))
    elif not harness_fault:
        sink_adjacent = [name for name in call_path[-3:] if name in stack_symbols]
        path_hit = [name for name in call_path if name in stack_symbols]
        if sink_adjacent:
            classification = 'sink-adjacent'
            score = max(score, 80)
            rationale.append('the stack reached sink-adjacent path functions {}'.format(', '.join(sink_adjacent)))
        elif entry_function and entry_function in stack_symbols:
            classification = 'entry-reached'
            score = max(score, 50)
            rationale.append('the stack reached the selected public entry function {}'.format(entry_function))
        elif path_hit:
            classification = 'path-reached'
            score = max(score, 40)
            rationale.append('the stack reached part of the wrapper path {}'.format(', '.join(path_hit[:4])))

    if '/fuzzer.cc:' in (output or '') and classification not in ['sink-hit', 'sink-adjacent']:
        classification = 'harness-or-setup-fault'
        score = min(score, 10)
        rationale.append('the stack points primarily into generated harness code rather than the target path')

    return {
        'classification': classification,
        'score': score,
        'stack_symbols': stack_symbols[:16],
        'rationale': rationale[:6],
    }


def _direct_raw_buffer_call(code, entry_function):
    if not code or not entry_function:
        return False
    call_pattern = re.compile(r'\b' + re.escape(entry_function) + r'\s*\(([^;]+)\)')
    staged_tokens = [
        'payload_buffer', 'container', 'record', 'frame', 'section', 'packet',
        'row_storage.data(', 'scratch.data(', 'staged.data(', 'assembled.data('
    ]
    for match in call_pattern.finditer(code):
        args = match.group(1)
        lowered = args.lower()
        # Distinguish real raw-input passthrough from structured-buffer usage via
        # intermediate buffers, container builders, or staged payload variables.
        has_raw_data = re.search(r'\bdata\b|\bdata\s*\+', lowered) is not None
        has_size_var = re.search(r'\bsize\b|\bpayload_size\b|\blen\b', lowered) is not None
        uses_nonraw_data_method = '.data(' in lowered and re.search(r'\bdata\s*\.data\s*\(', lowered) is None
        uses_staged_token = any(token in lowered for token in staged_tokens)
        synthesized_buffer = uses_nonraw_data_method or uses_staged_token

        if has_raw_data and has_size_var and not synthesized_buffer and 'memcpy' not in lowered:
            return True
    return False


def _mentions_any(code, names):
    for name in names:
        if name and _count_calls(code, name):
            return True
    return False


def _mentions_field_token(code, token):
    if not code or not token:
        return False
    pattern = re.compile(r'\b' + re.escape(token) + r'\b')
    return bool(pattern.search(code))


def _has_support_object_construction_evidence(code, construction_items):
    lowered = (code or '').lower()
    for item in construction_items or []:
        name = (item.get('name') or '').lower()
        if name and name not in lowered:
            continue
        required_fields = item.get('required_fields', [])
        if required_fields and not all(_mentions_field_token(code, field) for field in required_fields):
            return False
    return True


def _extract_support_keywords(construction_plan, stage_contracts=None):
    keywords = set()
    items = list(construction_plan.get('support_objects', []))
    items += list(construction_plan.get('support_object_construction', []))
    for stage in (stage_contracts or {}).values():
        if isinstance(stage, dict):
            items += list(stage.get('support_object_construction', []))
    for item in items:
        if not isinstance(item, dict):
            continue
        for value in [item.get('name', ''), item.get('kind', ''), item.get('reason', '')]:
            for token in re.split(r'[^a-z0-9]+', value.lower()):
                if len(token) >= 4:
                    keywords.add(token)
    return keywords


def _relation_token(name):
    lowered = (name or '').lower().replace('->', '.').replace('[', '.').replace(']', '')
    return lowered.split('.')[-1]


def _has_variable_setup_argument(args, state_targets):
    lowered = (args or '').lower()
    if re.search(r'\bdata\s*(?:\[|\+|,|\))', lowered):
        return True
    if re.search(r'\b(?:control|selector|choice|mode|kind|flag|depth|width|height|count|size|num|range|getbyte|getu32|getrange)\w*\b', lowered):
        return True

    ignored = set([
        'const', 'false', 'nullptr', 'null', 'ptr', 'size', 'static', 'true',
    ])
    for target in state_targets or []:
        ignored.update(re.split(r'[^a-z0-9_]+', (target or '').lower()))

    for token in re.findall(r'[A-Za-z_][A-Za-z0-9_]*', args or ''):
        lowered_token = token.lower()
        if lowered_token in ignored:
            continue
        if token.isupper():
            continue
        if re.match(r'^[A-Z0-9_]+$', token):
            continue
        return True
    return False


def _iter_pre_sink_call_statements(code, entry_function):
    entry_match = re.search(r'\b' + re.escape(entry_function) + r'\s*\(', code) if entry_function else None
    pre_sink_code = code[:entry_match.start()] if entry_match else code
    starts = list(re.finditer(r'^[ \t]*([A-Za-z_][A-Za-z0-9_:]*)\s*\(', pre_sink_code, re.MULTILINE))
    skip_names = set(['if', 'for', 'while', 'switch', 'return'])

    for match in starts:
        func_name = match.group(1)
        if func_name in skip_names:
            continue
        start = match.start()
        end = pre_sink_code.find(';', start)
        if end == -1:
            continue
        statement = pre_sink_code[start:end + 1]
        if '{' in statement or '}' in statement:
            continue
        open_paren = statement.find('(')
        close_paren = statement.rfind(')')
        if open_paren == -1 or close_paren == -1 or close_paren < open_paren:
            continue
        args = statement[open_paren + 1:close_paren]
        yield func_name, args


def _extract_setup_bound_identifiers(code, entry_function, dependent):
    if not code:
        return set(), []

    dependent_token = _relation_token(dependent)
    entry_match = re.search(r'\b' + re.escape(entry_function) + r'\s*\(', code) if entry_function else None
    pre_sink_code = code[:entry_match.start()] if entry_match else code
    identifiers = set()
    bound_lines = []
    assignments = {}

    assign_pattern = re.compile(r'\b(?:int|unsigned|long|short|size_t|[A-Za-z_][A-Za-z0-9_]*_t)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);')
    for match in assign_pattern.finditer(pre_sink_code):
        lhs = match.group(1)
        rhs = match.group(2)
        assignments[lhs.lower()] = rhs
        lowered = rhs.lower()
        if dependent_token and dependent_token not in lowered and lhs.lower() != dependent_token:
            if not any(token in lowered for token in ['max', 'min', 'bound', 'limit', '<<', '>>']):
                continue
        if lhs.lower() == dependent_token or dependent_token in lowered:
            bound_lines.append(match.group(0))
            identifiers.update([token.lower() for token in re.findall(r'[A-Za-z_][A-Za-z0-9_]*', rhs)])

    for match in re.finditer(r'\b' + re.escape(dependent_token) + r'\s*=\s*([^;]+);', pre_sink_code):
        rhs = match.group(1)
        bound_lines.append(match.group(0))
        identifiers.update([token.lower() for token in re.findall(r'[A-Za-z_][A-Za-z0-9_]*', rhs)])

    expanded = set(identifiers)
    for token in list(identifiers):
        rhs = assignments.get(token)
        if not rhs:
            continue
        if any(marker in rhs for marker in ['<<', '>>', 'max', 'min', 'bound', 'limit']) or dependent_token in rhs.lower():
            expanded.update([item.lower() for item in re.findall(r'[A-Za-z_][A-Za-z0-9_]*', rhs)])

    ignored = set(['int', 'long', 'short', 'unsigned', 'size_t', dependent_token, 'max', 'min'])
    return set([item for item in expanded if item not in ignored]), bound_lines[-4:]


def _setup_call_variables(code, entry_function, state_targets):
    skip_tokens = ['create', 'destroy', 'free', 'cleanup', 'close', 'setjmp', 'longjmp', 'memcpy', 'memmove', 'memset']
    variables = set()
    setup_calls = []

    for func_name, args in _iter_pre_sink_call_statements(code, entry_function):
        lowered_func = func_name.lower()
        if func_name == entry_function or any(token in lowered_func for token in skip_tokens):
            continue
        lowered_args = args.lower()
        if not any(target.lower() in lowered_args for target in state_targets):
            continue
        tokens = [token.lower() for token in re.findall(r'[A-Za-z_][A-Za-z0-9_]*', args)]
        variables.update(tokens)
        setup_calls.append((func_name, args))
    return variables, setup_calls


def _has_effective_setup_bound_coupling(code, entry_function, relation, parameter_roles):
    state_targets = relation.get('state_targets') or [
        item.get('name') for item in parameter_roles if item.get('role') == 'state'
    ]
    state_targets = [item for item in state_targets if item]
    if not state_targets:
        return False, 'no state targets available for setup-bound analysis'

    setup_variables, setup_calls = _setup_call_variables(code, entry_function, state_targets)
    if not setup_calls:
        return False, 'no qualifying pre-sink setup call was found'

    bound_identifiers, bound_lines = _extract_setup_bound_identifiers(code, entry_function, relation.get('dependent', ''))
    if not bound_lines:
        return False, 'no derived bound expression for {} was detected before the sink'.format(relation.get('dependent', 'the dependent argument'))

    ignored = set([_relation_token(relation.get('dependent', '')), _relation_token(relation.get('controller', ''))])
    support_objects = relation.get('support_objects', []) or []
    for name in state_targets + support_objects:
        ignored.update(re.split(r'[^a-z0-9_]+', (name or '').lower()))

    effective_overlap = set()
    for token in bound_identifiers:
        if token in ignored:
            continue
        if token in setup_variables:
            effective_overlap.add(token)

    if effective_overlap:
        return True, 'setup-controlled identifiers participate in the derived bound: {}'.format(', '.join(sorted(effective_overlap)[:4]))

    return False, 'setup varies before the sink, but the derived bound for {} does not appear to depend on any setup-controlled identifier'.format(
        relation.get('dependent', 'the dependent argument')
    )


def _has_setup_state_bound_evidence(code, entry_function, relation, parameter_roles):
    if not code or not entry_function:
        return False

    state_targets = relation.get('state_targets') or [
        item.get('name') for item in parameter_roles if item.get('role') == 'state'
    ]
    state_targets = [item for item in state_targets if item]
    if not state_targets:
        return False

    skip_tokens = ['create', 'destroy', 'free', 'cleanup', 'close', 'setjmp', 'longjmp', 'memcpy', 'memmove', 'memset']

    for func_name, args in _iter_pre_sink_call_statements(code, entry_function):
        lowered_func = func_name.lower()
        if func_name == entry_function or any(token in lowered_func for token in skip_tokens):
            continue
        lowered_args = args.lower()
        if not any(target.lower() in lowered_args for target in state_targets):
            continue
        if _has_variable_setup_argument(args, state_targets):
            return True
    return False


def _has_broad_setup_mode_switch(code, entry_function):
    if not code:
        return False

    entry_match = re.search(r'\b' + re.escape(entry_function) + r'\s*\(', code) if entry_function else None
    pre_sink_code = code[:entry_match.start()] if entry_match else code
    setup_tokens = re.findall(r'\b(?:setup|state|control|selector|mode|kind|type)\w*\b', pre_sink_code, re.IGNORECASE)
    if not setup_tokens:
        return False

    enum_assignments = set()
    for match in re.finditer(r'=\s*([A-Z][A-Z0-9_]{2,})\s*;', pre_sink_code):
        token = match.group(1)
        if any(marker in token for marker in ['TYPE', 'MODE', 'FORMAT', 'KIND', 'CLASS', 'PROFILE', 'COLOR']):
            enum_assignments.add(token)

    return len(enum_assignments) >= 3


def _has_trigger_relation_evidence(code, relation, entry_function=None, parameter_roles=None):
    lowered = (code or '').lower()
    controller = _relation_token(relation.get('controller', ''))
    dependent = _relation_token(relation.get('dependent', ''))
    evidence = (relation.get('evidence') or '').lower()
    kind = relation.get('kind', '')

    if kind == 'setup-state-bound-hypothesis':
        return _has_setup_state_bound_evidence(code, entry_function, relation, parameter_roles or [])

    if kind == 'boundary-value':
        return controller in lowered and ((relation.get('dependent') or '').lower() in lowered or '%' in lowered or 'switch' in lowered or 'if (' in lowered)

    lines = lowered.splitlines()
    for line in lines:
        if controller and dependent and controller in line and dependent in line:
            return True
        if dependent and dependent in line and any(token in line for token in ['max', 'min', 'bound', 'limit', '<<', '>>']):
            return True
        if controller and controller in line and any(token in line for token in ['<<', '>>', '%', 'max', 'min']):
            return True
    if evidence and evidence in lowered:
        return True
    return False


def _relation_diagnostics(code, relation, entry_function=None, parameter_roles=None):
    kind = relation.get('kind', '')
    if kind == 'setup-state-bound-hypothesis':
        return _has_effective_setup_bound_coupling(code, entry_function, relation, parameter_roles or [])
    if _has_trigger_relation_evidence(code, relation, entry_function, parameter_roles or []):
        return True, 'relation evidence detected'
    return False, 'relation evidence not detected'


def _has_setup_requirement_evidence(code, requirement):
    lowered = (code or '').lower()
    req = (requirement or '').lower()
    interesting = [token for token in re.split(r'[^a-z0-9_]+', req) if len(token) >= 5]
    return any(token in lowered for token in interesting[:4])


def _find_suspicious_null_helper_calls(code, construction_plan):
    issues = []
    keywords = _extract_support_keywords(construction_plan)
    # Do NOT use re.DOTALL — prevents the regex from spanning across
    # function-definition boundaries into the body.
    helper_pattern = re.compile(r'\b([A-Za-z_][A-Za-z0-9_:]*)\s*\(([^)\n]*)\)\s*;')
    for match in helper_pattern.finditer(code or ''):
        func_name = match.group(1)
        args = match.group(2)
        lowered_func = func_name.lower()
        lowered_args = args.lower()
        if 'nullptr' not in lowered_args and 'null' not in lowered_args:
            continue

        # Count NULL vs total arguments — if only 1 out of many is null,
        # it is likely a default/unused parameter, not a missing support object.
        arg_parts = [part.strip() for part in args.split(',') if part.strip()]
        null_count = sum(1 for part in arg_parts if re.search(r'\b(?:nullptr|null|z_null)\b', part, re.IGNORECASE))
        if len(arg_parts) >= 3 and null_count <= 1:
            continue

        helper_like = any(token in lowered_func for token in [
            'set', 'init', 'create', 'config',
            'transform', 'update', 'combine', 'progressive', 'record', 'header', 'frame'
        ])
        # Cleanup/destructor functions are typically safe to call with NULL
        # (e.g. cJSON_Delete(NULL), free(NULL), xmlFreeDoc(NULL)).
        cleanup_like = any(token in lowered_func for token in [
            'delete', 'free', 'destroy', 'close', 'release', 'cleanup', 'teardown', 'finalize'
        ])
        if cleanup_like:
            continue
        support_related = any(token in lowered_func or token in lowered_args for token in keywords)
        has_positive_size = re.search(r'(^|[^A-Za-z_])(\d{1,6})([^A-Za-z_]|$)', args) is not None

        if helper_like and (support_related or has_positive_size):
            issues.append('Suspicious helper call {}(...) uses NULL/nullptr placeholders where the construction plan suggests a real support object is required.'.format(func_name))
    return issues[:6]


def _find_null_callback_setup_calls(code):
    issues = []
    helper_pattern = re.compile(r'\b([A-Za-z_][A-Za-z0-9_:]*)\s*\((.*?)\)', re.DOTALL)
    for match in helper_pattern.finditer(code or ''):
        func_name = match.group(1)
        lowered_func = func_name.lower()
        if not any(token in lowered_func for token in ['create', 'init', 'open', 'setup', 'begin', 'alloc']):
            continue
        args = match.group(2)
        null_count = len(re.findall(r'\b(?:nullptr|null|z_null)\b', args, re.IGNORECASE))
        if null_count < 2:
            continue
        issues.append(func_name)
    return issues[:4]


def _extract_function_body(code, func_name):
    if not code or not func_name:
        return ''

    pattern = re.compile(r'\b' + re.escape(func_name) + r'\s*\([^;{}]*\)\s*\{', re.DOTALL)
    match = pattern.search(code)
    if not match:
        return ''

    start = match.end()
    depth = 1
    index = start
    while index < len(code):
        ch = code[index]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return code[start:index]
        index += 1
    return ''


def _extract_function_call_names(code):
    if not code:
        return []
    skip = set(['if', 'for', 'while', 'switch', 'return', 'sizeof'])
    calls = []
    for match in re.finditer(r'\b([A-Za-z_][A-Za-z0-9_:]*)\s*\(', code):
        name = match.group(1)
        if name in skip:
            continue
        calls.append(name)
    return calls


def _find_registered_callback_names(code, placement_candidates):
    """Find harness-defined callback functions relevant to deferred stages.

    Placement candidates may be library functions (registration sites) or
    harness-defined callbacks.  For registration-site names that are CALLED
    but not DEFINED in the harness, extract the function-pointer arguments
    passed to them — those are the actual callbacks.
    """
    if not code:
        return []

    candidate_names = [item for item in placement_candidates or [] if item]
    harness_defined = []
    registration_sites = []

    for name in candidate_names:
        if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', name or ''):
            continue
        if not re.search(r'\b' + re.escape(name) + r'\b', code):
            continue
        # Check if the candidate is DEFINED in the harness (has a body)
        has_definition = bool(re.search(
            r'\b' + re.escape(name) + r'\s*\([^;{}]*\)\s*\{', code, re.DOTALL
        ))
        if has_definition:
            harness_defined.append(name)
        else:
            registration_sites.append(name)

    # For registration-site calls, extract function-pointer arguments that
    # could be harness-defined callbacks.
    for site in registration_sites:
        call_pattern = re.compile(
            r'\b' + re.escape(site) + r'\s*\(([^)]+)\)', re.DOTALL
        )
        for match in call_pattern.finditer(code):
            for arg_token in re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\b', match.group(1)):
                if arg_token in ('nullptr', 'NULL', 'void', 'static', 'const'):
                    continue
                if re.search(
                    r'\b' + re.escape(arg_token) + r'\s*\([^;{}]*\)\s*\{',
                    code, re.DOTALL
                ):
                    if arg_token not in harness_defined:
                        harness_defined.append(arg_token)

    return harness_defined[:8]


def _find_empty_transform_callbacks(code, callback_names, required_api_names):
    issues = []
    required_api_names = [item for item in required_api_names or [] if item]
    for name in callback_names or []:
        body = _extract_function_body(code, name)
        if not body:
            # Not defined in the harness — skip (library function, not a callback).
            continue
        call_names = _extract_function_call_names(body)
        if not call_names:
            # Only flag truly empty bodies when we know what transform work
            # should be there.  Data-handling callbacks that only do casts or
            # trivial forwarding are not transform callbacks.
            if required_api_names:
                issues.append(name)
            continue
        if required_api_names and not any(item in call_names for item in required_api_names):
            issues.append(name)
    return issues[:4]


def _find_early_transform_calls(code, entry_function, transform_api_names, callback_names):
    if not code:
        return []

    entry_index = -1
    if entry_function:
        entry_match = re.search(r'\b' + re.escape(entry_function) + r'\s*\(', code)
        if entry_match:
            entry_index = entry_match.start()

    callback_ranges = []
    for name in callback_names or []:
        pattern = re.compile(r'\b' + re.escape(name) + r'\s*\([^;{}]*\)\s*\{', re.DOTALL)
        match = pattern.search(code)
        if not match:
            continue
        body = _extract_function_body(code, name)
        if not body:
            continue
        body_start = match.end()
        callback_ranges.append((body_start, body_start + len(body)))

    early = []
    for api_name in transform_api_names or []:
        if not api_name:
            continue
        for match in re.finditer(r'\b' + re.escape(api_name) + r'\s*\(', code):
            call_index = match.start()
            in_callback = any(start <= call_index < end for start, end in callback_ranges)
            if in_callback:
                continue
            if entry_index != -1 and call_index < entry_index:
                early.append(api_name)
                break
    deduped = []
    seen = set()
    for item in early:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped[:4]


def _find_dead_support_state_names(code, support_keywords=None):
    if not code:
        return []

    tokens = list(support_keywords or [])
    if not tokens:
        return []
    candidates = []
    patterns = [
        re.compile(r'([A-Za-z_][A-Za-z0-9_]*(?:->|\.)[A-Za-z_][A-Za-z0-9_]*)\s*\[[^\]]+\]\s*='),
        re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\[[^\]]+\]\s*='),
    ]
    for pattern in patterns:
        for match in pattern.finditer(code):
            name = match.group(1)
            lowered = name.lower()
            if not any(token in lowered for token in tokens):
                continue
            candidates.append(name)

    issues = []
    seen = set()
    for name in candidates:
        if name in seen:
            continue
        seen.add(name)
        total_refs = len(re.findall(re.escape(name), code))
        assignment_refs = len(re.findall(re.escape(name) + r'\s*\[[^\]]+\]\s*=', code))
        call_refs = len(re.findall(r'\([^\)]*' + re.escape(name) + r'[^\)]*\)', code))
        if total_refs > 0 and total_refs == assignment_refs and call_refs == 0:
            issues.append(name)
    return issues[:4]


def validate_harness_source(plan_path, source_path):
    plan = _load_plan(plan_path)
    code = _read_text(source_path)
    execution_plan = plan.get('execution_plan', {})
    vuln_context = plan.get('vuln_context', {})
    construction_plan = plan.get('construction_plan', {})
    active_data_plan = execution_plan.get('active_data_plan', {})
    entry_function = execution_plan.get('entry_function') or plan.get('public_api_name')
    setup_candidates = execution_plan.get('setup_candidates', [])
    update_candidates = execution_plan.get('update_candidates', [])
    workload_model = execution_plan.get('workload_model', {})
    milestone_plan = execution_plan.get('milestone_plan', [])
    input_model = execution_plan.get('input_model', {})
    sensitive_controls = execution_plan.get('sensitive_controls', [])
    setup_state_profiles = execution_plan.get('setup_state_profiles', vuln_context.get('setup_state_profiles', []))
    exploration_policy = execution_plan.get('exploration_policy', [])
    parameter_roles = execution_plan.get('parameter_roles', [])
    state_fields = execution_plan.get('state_fields', [])
    trigger_relations = execution_plan.get('trigger_relations', [])
    trigger_controls = execution_plan.get('trigger_controls', [])
    required_setup_calls = execution_plan.get('required_setup_calls', [])
    stage_contracts = execution_plan.get('stage_contracts', {})
    deferred_stages = execution_plan.get('deferred_stages', [])
    retrieved_stage_evidence = execution_plan.get('retrieved_stage_evidence', {})
    setup_requirements = execution_plan.get('setup_requirements', [])
    invariant_requirements = execution_plan.get('invariant_requirements', [])
    failure_path_indicators = vuln_context.get('failure_path_indicators', {})
    relation_diagnostics = []

    # Derive support-object keywords from the plan so checks are generic.
    support_keywords = _extract_support_keywords(construction_plan, stage_contracts)

    violations = []
    warnings = []
    critical = False
    score = 100

    # Parser/decoder entry functions (parse, read, decode, load, etc.) are
    # designed to accept raw buffer + size -- don't penalise that pattern.
    parser_entry = _is_parser_entry(entry_function)

    # Resource-leak vulnerabilities (CWE-401, CWE-772, CWE-775) need simple
    # harnesses that allocate without cleanup so ASan's leak detector fires.
    # Complex support-object / trigger-relation infrastructure is counter-
    # productive -- soften those checks like we do for parser entries.
    vuln_entry = plan.get('vuln_entry', {})
    cwe_id = vuln_entry.get('cwe-id', '')
    _LEAK_CWES = {'CWE-401', 'CWE-772', 'CWE-775'}
    leak_vuln = cwe_id in _LEAK_CWES

    if entry_function and _count_calls(code, entry_function) == 0:
        violations.append('Harness never calls the selected public entry function {}.'.format(entry_function))
        score -= 40
        critical = True

    needs_state_setup = bool(setup_candidates) and (
        any(role.get('role') == 'state' for role in parameter_roles) or bool(state_fields)
    )
    if needs_state_setup and not _mentions_any(code, setup_candidates):
        violations.append('Execution plan requires setup/state initialization, but no setup candidate appears in the harness: {}.'.format(', '.join(setup_candidates[:5])))
        score -= 25

    missing_setup_calls = [item.get('name') for item in required_setup_calls[:4] if item.get('name') and _count_calls(code, item.get('name')) == 0]
    if missing_setup_calls:
        if parser_entry or leak_vuln:
            warnings.append('Harness may be missing setup or registration calls inferred from sink-gating state ({} - may not be needed): {}.'.format(
                'leak vulnerability' if leak_vuln else 'parser entry', ', '.join(missing_setup_calls)))
            score -= 8
        else:
            violations.append('Harness is missing required setup or registration calls inferred from sink-gating state: {}.'.format(', '.join(missing_setup_calls)))
            score -= 20

    if 'repeated-records' in workload_model.get('operators', []) and not _has_loop(code) and not parser_entry:
        violations.append('Workload model expects repeated logical records, but the harness does not appear to build them in a loop.')
        score -= 20

    if 'chunked-stream' in workload_model.get('operators', []) and not _has_loop(code) and not parser_entry:
        violations.append('Workload model expects incremental or chunked processing, but the harness does not implement a repeated update-style flow.')
        score -= 20

    if not parser_entry and input_model.get('primary') == 'structured-format' and entry_function and _direct_raw_buffer_call(code, entry_function):
        violations.append('Execution plan expects structured input shaping, but the harness appears to pass raw data/size directly into the target API.')
        score -= 20

    if not parser_entry and construction_plan.get('requires_container_synthesis') and _direct_raw_buffer_call(code, entry_function) and not _looks_like_synthesized_container(code, entry_function):
        violations.append('Construction plan requires synthesizing a minimally valid structured container, but the harness appears to forward raw input bytes after a control prefix instead of building a fresh container.')
        score -= 25

    path_requires_staged_input = (
        construction_plan.get('requires_container_synthesis') or
        'container-parse' in set([item.get('kind') for item in milestone_plan if item.get('required')]) or
        'incremental-feed' in set([item.get('kind') for item in milestone_plan if item.get('required')]) or
        'chunked-stream' in workload_model.get('operators', [])
    )
    if not parser_entry and path_requires_staged_input and _looks_like_direct_progressive_passthrough(code, entry_function) and not _has_structured_container_shaping(code, entry_function):
        violations.append('The selected wrapper path is parser or progressive-read oriented, but the harness appears to feed raw fuzz bytes directly into the public API without constructing a minimally valid structured input first.')
        score -= 25

    if sensitive_controls and not _has_selector_logic(code):
        warnings.append('Sensitive controls were inferred, but the harness has no obvious selector logic to bias them deliberately.')
        score -= 8

    if any(item.get('policy') == 'stabilize' for item in exploration_policy) and code.count('data[') > 8:
        warnings.append('The harness may be spending entropy on too many direct byte-to-parameter mappings instead of stabilizing low-signal knobs.')
        score -= 5

    if not parser_entry and input_model.get('primary') == 'semantic-arguments' and _direct_raw_buffer_call(code, entry_function):
        violations.append('Execution plan models this sink as semantic arguments or support objects, but the harness still appears to forward raw fuzzer bytes directly into the target API.')
        score -= 20

    if trigger_controls and not _has_selector_logic(code):
        warnings.append('Trigger controls were inferred, but the harness does not show deliberate bounded control selection for them: {}.'.format(', '.join(trigger_controls[:4])))
        score -= 8

    for relation in trigger_relations[:6]:
        relation_ok, relation_reason = _relation_diagnostics(code, relation, entry_function, parameter_roles)
        relation_diagnostics.append({
            'kind': relation.get('kind', 'relation'),
            'controller': relation.get('controller'),
            'dependent': relation.get('dependent'),
            'ok': relation_ok,
            'reason': relation_reason,
        })
        if not relation_ok:
            message = 'Harness does not appear to exercise inferred trigger relation between {} and {}: {}.'.format(
                relation.get('controller', 'controller'),
                relation.get('dependent', 'dependent'),
                relation.get('harness_expectation', 'exercise the relation explicitly')
            )
            if relation_reason:
                message += ' Diagnostic: {}.'.format(relation_reason)
            if relation.get('priority') == 'high' and not leak_vuln:
                violations.append(message)
                score -= 18
            else:
                warnings.append(message)
                score -= 6

    if setup_state_profiles and _has_broad_setup_mode_switch(code, entry_function):
        warnings.append('Harness varies broad setup-mode families before the sink; prefer the smallest liveness-preserving setup controls that still change the legal range of later arguments.')
        score -= 8

    for requirement in setup_requirements[:3]:
        if not _has_setup_requirement_evidence(code, requirement):
            warnings.append('Harness may be missing a setup requirement that should stay valid while trigger controls are varied: {}.'.format(requirement))
            score -= 2 if leak_vuln else 4

    if 'setjmp(' in code and 'abort()' in code:
        violations.append('Harness uses setjmp-style error recovery but still aborts in an error callback, which can cause false positive crashes.')
        score -= 20
        critical = True

    null_helper_issues = _find_suspicious_null_helper_calls(code, construction_plan)
    for issue in null_helper_issues:
        violations.append(issue)
        score -= 20

    if construction_plan.get('support_object_construction') and not _has_support_object_construction_evidence(code, construction_plan.get('support_object_construction', [])):
        if parser_entry or leak_vuln:
            warnings.append('Harness shows weak evidence of constructing the required support object fields before the sink path is exercised ({} - may not be needed).'.format(
                'leak vulnerability' if leak_vuln else 'parser entry'))
            score -= 6
        else:
            violations.append('Harness shows weak evidence of constructing the required support object fields before the sink path is exercised.')
            score -= 18

    null_callback_setups = _find_null_callback_setup_calls(code)
    if null_callback_setups and any(role.get('role') == 'state' for role in parameter_roles) and failure_path_indicators.get('error_calls') and 'setjmp(' not in code:
        if parser_entry:
            warnings.append('Harness creates state through setup-style calls with NULL/nullptr placeholders and no local error recovery (parser entry - NULL args may be valid defaults): {}.'.format(', '.join(null_callback_setups)))
            score -= 8
        else:
            violations.append('Harness appears to create state through setup-style calls with repeated NULL/nullptr callback placeholders and no local error recovery: {}. Install non-fatal callback handling or equivalent error containment in the harness.'.format(', '.join(null_callback_setups)))
            score -= 25

    milestone_kinds = set([item.get('kind') for item in milestone_plan if item.get('required')])
    if 'object-lifecycle' in milestone_kinds and not (_mentions_any(code, setup_candidates) or _has_generic_state_setup(code)):
        violations.append('Milestone plan requires valid state creation before sink-oriented fuzzing, but the harness shows no plausible setup or object-lifecycle construction.')
        score -= 20

    if not parser_entry and 'container-parse' in milestone_kinds and input_model.get('primary') == 'structured-format' and not _has_structured_container_shaping(code, entry_function):
        violations.append('Milestone plan requires the library to accept a minimally valid structured container before the sink can be live, but the harness shows no plausible container shaping.')
        score -= 20

    if 'incremental-feed' in milestone_kinds and not _has_loop(code) and not parser_entry:
        violations.append('Milestone plan requires repeated feed or update progress before the sink is likely to execute, but the harness has no obvious bounded incremental flow.')
        score -= 18

    if 'transform-gating' in milestone_kinds and not _has_transform_configuration(code, support_keywords):
        warnings.append('Milestone plan suggests sink-adjacent transform or configuration state is required, but the harness shows no obvious transform-configuration step.')
        score -= 6

    deferred_transform = 'transform' in deferred_stages and stage_contracts.get('transform', {})
    if deferred_transform:
        transform_contract = stage_contracts.get('transform', {})
        transform_api_names = [item.get('name') for item in transform_contract.get('required_setup_calls', []) if item.get('name')]
        placement_candidates = list(transform_contract.get('execution_site_candidates', []))
        for extra in retrieved_stage_evidence.get('placement_candidates', []):
            if extra not in placement_candidates:
                placement_candidates.append(extra)
        callback_names = _find_registered_callback_names(code, placement_candidates)
        has_transform_obligation = any(transform_contract.get(field) for field in [
            'required_setup_calls',
            'support_object_construction',
            'support_object_field_constraints',
            'setup_requirements',
            'sink_activation_conditions',
            'milestone_hints',
        ])
        if has_transform_obligation and not _has_transform_configuration(code, support_keywords):
            warnings.append('Deferred transform-stage obligations were inferred, but the harness shows no obvious later-stage transform or configuration step after parser or setup milestones.')
            score -= 6
        empty_callbacks = _find_empty_transform_callbacks(code, callback_names, transform_api_names)
        if empty_callbacks:
            violations.append('Deferred transform-stage callbacks are registered but do not execute the required transform work: {}. Place the deferred transform APIs inside the callback or stage-transition body that owns this stage.'.format(', '.join(empty_callbacks)))
            score -= 20
            critical = True
        early_transform_calls = _find_early_transform_calls(code, entry_function, transform_api_names, callback_names)
        if early_transform_calls:
            violations.append('Deferred transform-stage APIs appear before the first public entry invocation instead of executing at a later callback or post-parse transition site: {}.'.format(', '.join(early_transform_calls)))
            score -= 20
            critical = True
        dead_support_state = _find_dead_support_state_names(code, support_keywords)
        if dead_support_state:
            warnings.append('Harness populates support-like staged state that is never consumed by any helper or transform call: {}.'.format(', '.join(dead_support_state)))
            score -= 6

    if 'work-unit' in milestone_kinds and not (_has_loop(code) or _has_structured_container_shaping(code, entry_function)):
        warnings.append('Milestone plan suggests the sink depends on produced rows, blocks, records, or similar work units, but the harness has weak evidence of driving the API that far.')
        score -= 6

    mutable_regions = active_data_plan.get('mutable_regions', [])
    high_priority_names = [item.get('name') for item in mutable_regions if item.get('priority') == 'high']
    if high_priority_names and _looks_like_trailing_append_only(code) and not _has_data_driven_support_object(code, support_keywords):
        violations.append('Active data plan expects sink-relevant mutation placement, but the harness appears to spend entropy on trailing appended bytes without driving high-value mutable regions such as {}.'.format(', '.join(high_priority_names[:4])))
        score -= 20

    if any(item.get('name') == 'decoded-work-unit' for item in mutable_regions) and _looks_like_trailing_append_only(code):
        violations.append('Active data plan says decoded work units should carry fuzz entropy, but the harness appears to append raw bytes after a finished body instead of mutating post-parse work-unit contents.')
        score -= 18

    if any(item.get('kind') in ['table', 'config'] for item in mutable_regions) and not _has_data_driven_support_object(code, support_keywords):
        warnings.append('Active data plan suggests support tables or configuration should be fuzz-driven within valid bounds, but the harness appears to keep them constant.')
        score -= 6

    if active_data_plan.get('stabilized_regions') and _counts_data_usages(code) > 14 and input_model.get('primary') == 'structured-format':
        warnings.append('The harness may still be injecting fuzz entropy too broadly into structured input instead of stabilizing the container skeleton and concentrating on sink-relevant regions.')
        score -= 5

    for requirement in invariant_requirements[:3]:
        if not _has_setup_requirement_evidence(code, requirement):
            warnings.append('Harness shows weak evidence that it preserves an inferred trigger invariant: {}.'.format(requirement))
            score -= 4

    # A harness passes if no critical violation was found AND the score
    # stays above the acceptance threshold.  This avoids false rejections
    # caused by minor plan-mismatch violations while still catching
    # genuinely broken harnesses (missing entry call, setjmp+abort, etc.).
    _SCORE_THRESHOLD = 60
    passed = (not critical) and (max(0, score) >= _SCORE_THRESHOLD)

    return {
        'ok': passed,
        'score': max(0, score),
        'violations': violations,
        'warnings': warnings,
        'relation_diagnostics': relation_diagnostics,
    }


def run_runtime_smoke(harness_binary, out_dir, plan_path=None):
    out_dir = Path(out_dir)
    probe_dir = out_dir / 'context' / 'runtime_probe'
    if probe_dir.exists():
        shutil.rmtree(str(probe_dir))
    probe_dir.mkdir(parents=True, exist_ok=True)

    (probe_dir / 'empty').write_bytes(b'')
    (probe_dir / 'tiny').write_bytes(b'A')
    (probe_dir / 'pattern').write_bytes((b'ABCD' * 16))

    env = os.environ.copy()
    env['ASAN_OPTIONS'] = 'abort_on_error=1:detect_leaks=0'
    env['UBSAN_OPTIONS'] = 'abort_on_error=1'

    try:
        result = subprocess.run(
            [str(harness_binary), '-runs=3', str(probe_dir)],
            cwd=str(out_dir),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=20,
        )
    except subprocess.TimeoutExpired:
        return {
            'ok': False,
            'issue': 'Runtime smoke test timed out before completing three runs.',
            'output': '',
        }
    except Exception as exc:
        return {
            'ok': False,
            'issue': 'Runtime smoke test failed to execute: {}'.format(exc),
            'output': '',
        }

    combined = (result.stdout or '') + '\n' + (result.stderr or '')
    evidence = classify_runtime_evidence(plan_path, combined, result.returncode) if plan_path else {}
    if result.returncode != 0:
        # A crash that reaches the sink or sink-adjacent path means the
        # harness is working — even trivial inputs can trigger certain bugs.
        # Treat this as success rather than requesting a repair.
        ev_score = evidence.get('score', 0) if evidence else 0
        if ev_score >= 80:
            return {
                'ok': True,
                'issue': '',
                'output': combined[:4000],
                'evidence': evidence,
                'vulnerability_triggered': True,
            }
        return {
            'ok': False,
            'issue': 'Harness crashed or exited abnormally on trivial runtime probe inputs.',
            'output': combined[:4000],
            'evidence': evidence,
        }

    return {
        'ok': True,
        'issue': '',
        'output': combined[:2000],
        'evidence': evidence,
    }