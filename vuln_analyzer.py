#!/usr/bin/env python3
"""
Vulnerability Path Analyzer

Automatically extracts vulnerability-relevant context from source code:
- Parameter constraints and modes (e.g., windowBits values)
- State machine transitions
- Format checks (magic bytes)
- Switch/case branches that indicate different code paths

This is completely generic - no library-specific knowledge required.
"""
import re
import json
import hashlib
import tempfile
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

from contract_inference import infer_semantic_contract


CONTROL_KEYWORDS = [
    'mode', 'type', 'flag', 'flags', 'option', 'options', 'kind', 'op', 'cmd',
    'count', 'len', 'length', 'size', 'width', 'height', 'offset', 'version',
    'flush'
]

HELPER_SKIP_NAMES = {
    'if', 'for', 'while', 'switch', 'return', 'sizeof', 'memcpy', 'memmove',
    'memset', 'memcmp', 'malloc', 'calloc', 'realloc', 'free', 'strlen',
    'strcpy', 'strncpy', 'strcat', 'strcmp', 'fprintf', 'printf', 'abort',
    'assert',
    # Bare allocator / deallocator names used through function-pointer hooks
    # (e.g. cJSON internal_hooks.allocate).  These are NOT public setup APIs.
    'allocate', 'deallocate', 'reallocate',
}

PLURAL_TOKENS = ['list', 'array', 'items', 'entries', 'texts', 'records', 'chunks', 'rows', 'cols', 'names']

LIFECYCLE_SUFFIXES = [
    'init', 'open', 'create', 'setup', 'begin', 'start',
    'update', 'write', 'append', 'push', 'feed',
    'finish', 'final', 'flush', 'close', 'destroy', 'free', 'cleanup', 'end',
    'reset'
]

SUPPORT_OBJECT_HINTS = [
    (['lookup', 'lut'], 'lookup-table', 'table', 'indexed transforms usually require a valid lookup table'),
    (['row', 'rows'], 'row-buffer', 'buffer', 'row-oriented decoding and transforms require writable row storage'),
    (['info', 'header', 'metadata', 'profile'], 'metadata-structure', 'metadata', 'metadata-oriented paths require valid metadata or descriptor structures'),
    (['transform', 'convert'], 'transform-config', 'config', 'transform helpers usually require valid configuration state'),
]

WEAK_SUPPORT_OBJECTS = set(['metadata-structure', 'transform-config'])

_CAMEL_BOUNDARY_RE = re.compile(r'([a-z])([A-Z])')

def _split_name_tokens(name: str):
    """Split a C identifier into lowercase tokens on ``_``, digits, and camelCase boundaries."""
    # Insert a separator at camelCase boundaries: contentType → content_Type
    expanded = _CAMEL_BOUNDARY_RE.sub(r'\1_\2', name)
    return [t.lower() for t in re.split(r'[_\d]+', expanded) if t]


def _name_has_token(name: str, token: str) -> bool:
    """Return True if *token* appears as an independent word in *name*."""
    return token.lower() in _split_name_tokens(name)


def _is_size_like_parameter_name(name: str) -> bool:
    lowered = (name or '').lower()
    return lowered.startswith('num') or any(_name_has_token(name, t) for t in ['len', 'length', 'size', 'count', 'capacity', 'avail'])


def _split_arguments(arg_text: str) -> List[str]:
    """Split a C/C++ argument list while respecting nested delimiters."""
    parts = []
    current = []
    depth = 0
    for char in arg_text:
        if char in '(<[{':
            depth += 1
        elif char in ')>]}':
            depth = max(0, depth - 1)
        if char == ',' and depth == 0:
            part = ''.join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue
        current.append(char)
    tail = ''.join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _strip_comments_and_literals(source_code: str) -> str:
    """Remove comments and string literals before regex-based source analysis."""
    if not source_code:
        return ''
    pattern = re.compile(
        r'//.*?$|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
        re.DOTALL | re.MULTILINE
    )

    def _preserve_layout(match):
        text = match.group(0)
        return ''.join('\n' if char == '\n' else ' ' for char in text)

    return pattern.sub(_preserve_layout, source_code)


def _find_matching_brace(text: str, open_index: int) -> int:
    """Return the index of the matching closing brace or -1."""
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == '{':
            depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0:
                return index
    return -1


def _find_matching_paren(text: str, open_index: int) -> int:
    """Return the index of the matching closing parenthesis or -1."""
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
            if depth == 0:
                return index
    return -1


def _normalize_condition_value(value: str) -> str:
    """Trim trailing syntax noise from a captured comparison value."""
    cleaned = (value or '').strip()
    if not cleaned:
        return ''

    cleaned = re.split(r'\s*(?:&&|\|\|)\s*', cleaned, 1)[0].strip()
    cleaned = cleaned.rstrip(';,')

    while cleaned:
        if cleaned.endswith(')') and cleaned.count(')') > cleaned.count('('):
            cleaned = cleaned[:-1].rstrip()
            continue
        if cleaned.endswith(']') and cleaned.count(']') > cleaned.count('['):
            cleaned = cleaned[:-1].rstrip()
            continue
        if cleaned.endswith('}') and cleaned.count('}') > cleaned.count('{'):
            cleaned = cleaned[:-1].rstrip()
            continue
        break

    return cleaned.strip()


def _select_guidance_parameter_conditions(parameter_conditions: List[Dict[str, Any]], role_map: Dict[str, str]) -> List[Dict[str, Any]]:
    """Prefer high-signal parameter conditions when building guidance text."""
    grouped = {}
    for condition in parameter_conditions or []:
        parameter = condition.get('parameter')
        if not parameter:
            continue
        grouped.setdefault(parameter, []).append(condition)

    selected = []
    for parameter, conditions in grouped.items():
        role = role_map.get(parameter)
        if role != 'control':
            selected.extend(conditions)
            continue

        equality_conditions = [
            item for item in conditions
            if item.get('type') == 'comparison' and item.get('operator') in ['==', '&'] and not re.match(r'^-?\d+$', str(item.get('value', '')))
        ]
        if equality_conditions:
            selected.extend(equality_conditions)
            continue

        filtered = []
        for item in conditions:
            if item.get('type') != 'comparison':
                filtered.append(item)
                continue
            operator = item.get('operator')
            value = str(item.get('value', ''))
            if operator in ['<', '>', '<=', '>=']:
                continue
            if re.match(r'^-?\d+$', value):
                continue
            filtered.append(item)
        selected.extend(filtered)

    return selected


def _extract_keyword_paren_contents(text: str, keyword: str) -> List[str]:
    """Extract balanced parenthesized expressions after a keyword like if/switch."""
    contents = []
    pattern = re.compile(r'\b' + re.escape(keyword) + r'\s*\(')
    for match in pattern.finditer(text or ''):
        open_index = text.find('(', match.start())
        if open_index == -1:
            continue
        close_index = _find_matching_paren(text, open_index)
        if close_index == -1:
            continue
        contents.append(text[open_index + 1:close_index].strip())
    return contents


def _skip_post_signature_tokens(text: str, index: int) -> int:
    """Skip qualifiers that can appear between a signature and the function body."""
    qualifiers = set(['const', 'noexcept', 'override', 'final', 'volatile'])

    while index < len(text):
        if text[index].isspace():
            index += 1
            continue

        if text.startswith('__attribute__', index):
            attr_open = text.find('(', index + len('__attribute__'))
            if attr_open == -1:
                return index
            attr_close = _find_matching_paren(text, attr_open)
            if attr_close == -1:
                return index
            index = attr_close + 1
            continue

        if text.startswith('throw', index):
            token_end = index + len('throw')
            probe = token_end
            while probe < len(text) and text[probe].isspace():
                probe += 1
            if probe < len(text) and text[probe] == '(':
                close_index = _find_matching_paren(text, probe)
                if close_index == -1:
                    return index
                index = close_index + 1
                continue

        token_match = re.match(r'[A-Za-z_][A-Za-z0-9_]*', text[index:])
        if token_match and token_match.group(0) in qualifiers:
            index += len(token_match.group(0))
            continue

        if text.startswith('->', index):
            index += 2
            while index < len(text) and text[index].isspace():
                index += 1
            return_match = re.match(r'[A-Za-z_][A-Za-z0-9_:<>]*', text[index:])
            if return_match:
                index += len(return_match.group(0))
                continue

        break

    return index


def _skip_old_style_param_declarations(text: str, index: int) -> int:
    """Skip K&R-style parameter declaration lines that appear between ')' and '{'."""
    probe = index
    declaration_pattern = re.compile(
        r'^[ \t]*(?:const\s+|volatile\s+|unsigned\s+|signed\s+|struct\s+|enum\s+|union\s+|long\s+|short\s+|int\s+|char\s+|float\s+|double\s+|[A-Za-z_][A-Za-z0-9_]*\s+)[^\{;]*;\s*$',
        re.MULTILINE
    )

    while probe < len(text):
        while probe < len(text) and text[probe].isspace():
            probe += 1
        if probe >= len(text) or text[probe] == '{':
            break

        line_end = text.find('\n', probe)
        if line_end == -1:
            line_end = len(text)
        line = text[probe:line_end + 1]
        if not declaration_pattern.match(line):
            break
        probe = line_end + 1

    return probe


def _find_function_definition_span(text: str, function_name: str) -> Optional[Tuple[int, int]]:
    """Find the exact definition span for a function, ignoring declarations and call sites."""
    if not text or not function_name:
        return None

    sanitized = _strip_comments_and_literals(text)
    pattern = re.compile(r'(^|[^A-Za-z0-9_])' + re.escape(function_name) + r'\s*\(', re.MULTILINE)

    for match in pattern.finditer(sanitized):
        name_start = match.start() + len(match.group(1))
        line_start = text.rfind('\n', 0, name_start) + 1
        prefix = text[line_start:name_start]
        if ';' in prefix:
            continue

        open_index = sanitized.find('(', name_start)
        if open_index == -1:
            continue
        close_index = _find_matching_paren(sanitized, open_index)
        if close_index == -1:
            continue

        body_open = _skip_post_signature_tokens(sanitized, close_index + 1)
        if body_open < len(sanitized) and sanitized[body_open] != '{':
            body_open = _skip_old_style_param_declarations(sanitized, body_open)
        if body_open >= len(sanitized) or sanitized[body_open] != '{':
            continue

        body_close = _find_matching_brace(sanitized, body_open)
        if body_close == -1:
            continue

        return (line_start, body_close + 1)

    return None


def extract_function_parameters(source_code: str, function_name: str) -> List[Dict[str, str]]:
    """Extract parameter names and types from the target function signature."""
    span = _find_function_definition_span(source_code, function_name)
    if not span:
        return []

    signature_source = source_code[span[0]:span[1]]
    name_index = signature_source.find(function_name)
    if name_index == -1:
        return []

    open_index = signature_source.find('(', name_index)
    if open_index == -1:
        return []
    close_index = _find_matching_paren(signature_source, open_index)
    if close_index == -1:
        return []

    params = []
    signature_params = []
    for raw_param in _split_arguments(signature_source[open_index + 1:close_index]):
        param = raw_param.strip()
        if not param or param == 'void' or param == '...':
            continue
        param = re.sub(r'\s*=\s*[^,]+$', '', param).strip()
        name_match = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[.*\])?\s*$', param)
        if not name_match:
            continue
        param_name = name_match.group(1)
        param_type = param[:name_match.start(1)].strip()
        signature_params.append((param_name, param_type or 'unknown'))

    old_style_only = signature_params and all(item[1] == 'unknown' for item in signature_params)
    if old_style_only:
        body_open = _skip_post_signature_tokens(signature_source, close_index + 1)
        body_open = _skip_old_style_param_declarations(signature_source, body_open)
        declaration_block = signature_source[close_index + 1:body_open]
        declaration_map = {}
        for line in declaration_block.splitlines():
            line = line.strip()
            if not line or not line.endswith(';'):
                continue
            line = line[:-1].strip()
            names = _split_arguments(line)
            if not names:
                continue
            first = names[0].strip()
            first_match = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*$', first)
            if not first_match:
                continue
            first_name = first_match.group(1)
            base_type = first[:first_match.start(1)].strip()
            if not base_type:
                continue
            declaration_map[first_name] = base_type
            for extra in names[1:]:
                extra = extra.strip()
                if not extra:
                    continue
                declaration_map[extra.lstrip('*').strip()] = base_type + (' *' if extra.startswith('*') else '')

        for param_name, _ in signature_params:
            params.append({
                'name': param_name,
                'type': declaration_map.get(param_name, 'unknown')
            })
        return params

    for param_name, param_type in signature_params:
        params.append({
            'name': param_name,
            'type': param_type
        })
    return params


# Tokens that require word-boundary matching in parameter names to avoid
# false positives (e.g. 'type' inside 'content_type', 'out' inside 'layout').
_CONTROL_NAME_TOKENS = ['mode', 'type', 'flag', 'flags', 'option', 'options', 'kind', 'op', 'cmd', 'flush']
_OUTPUT_NAME_TOKENS = ['out', 'dst', 'dest', 'result', 'output']
_STATE_NAME_TOKENS = ['state', 'ctx', 'context', 'stream', 'parser', 'handle', 'object', 'info', 'strm']
_SUPPORT_NAME_TOKENS = ['table', 'array', 'list', 'entry', 'entries', 'palette', 'hist', 'map']
_SUPPORT_TYPE_TOKENS = ['table', 'array', 'list', 'palette', 'hist']

VALID_PARAMETER_ROLES = frozenset([
    'state', 'input-buffer', 'size', 'control',
    'output-buffer', 'support-buffer', 'numeric', 'value',
])


def classify_parameter_role(param_name: str, param_type: str) -> Dict[str, str]:
    """Classify how a parameter should be treated by the harness."""
    orig_name = param_name or ''
    name = orig_name.lower()
    type_name = (param_type or '').lower()

    if _is_size_like_parameter_name(orig_name):
        return {
            'role': 'size',
            'strategy': 'derive from payload length or a bounded integer extracted from fuzzer input'
        }
    if any(_name_has_token(orig_name, t) for t in _CONTROL_NAME_TOKENS):
        return {
            'role': 'control',
            'strategy': 'map a few fuzzer bits to valid enum or flag values to explore alternate branches'
        }
    # 'return' is a keyword — only match the exact name, not as a substring.
    if any(_name_has_token(orig_name, t) for t in _OUTPUT_NAME_TOKENS) or name == 'return':
        return {
            'role': 'output-buffer',
            'strategy': 'allocate a bounded writable buffer owned by the harness before the call'
        }
    if '**' in type_name:
        return {
            'role': 'output-buffer',
            'strategy': 'allocate a bounded writable buffer owned by the harness before the call'
        }
    if any(_name_has_token(orig_name, t) for t in _STATE_NAME_TOKENS) or (name.endswith('_ptr') and not any(t in name for t in ['buf', 'data', 'text', 'str'])) or '%struct' in type_name or (type_name.endswith('ptr') and '*' not in type_name):
        return {
            'role': 'state',
            'strategy': 'create or initialize a valid state object before invoking the target API'
        }
    if any(_name_has_token(orig_name, t) for t in _SUPPORT_NAME_TOKENS) or any(t in type_name for t in _SUPPORT_TYPE_TOKENS):
        return {
            'role': 'support-buffer',
            'strategy': 'allocate a bounded typed buffer or table and populate it from fuzz-controlled values while preserving count consistency'
        }
    if '*' in type_name or 'char' in type_name or 'uint8' in type_name or 'int8' in type_name or 'void' in type_name or 'byte' in type_name:
        return {
            'role': 'input-buffer',
            'strategy': 'back with fuzz-controlled bytes, preserving required alignment or termination rules'
        }
    if any(re.search(r'\b' + t + r'\b', type_name) for t in ['int', 'long', 'short', 'size_t', 'ssize_t', 'uint', 'float', 'double']):
        return {
            'role': 'numeric',
            'strategy': 'extract a bounded scalar from fuzzer input and clamp it to valid ranges'
        }
    return {
        'role': 'value',
        'strategy': 'supply a conservative default unless semantics suggest fuzz control matters'
    }


def extract_parameter_roles(source_code: str, function_name: str) -> List[Dict[str, str]]:
    """Return parameter role metadata for harness construction."""
    roles = []
    for param in extract_function_parameters(source_code, function_name):
        role_info = classify_parameter_role(param.get('name', ''), param.get('type', ''))
        roles.append({
            'name': param.get('name', ''),
            'type': param.get('type', ''),
            'role': role_info['role'],
            'strategy': role_info['strategy']
        })
    return roles


def extract_helper_calls(source_code: str, function_name: str) -> List[Dict[str, str]]:
    """Extract nearby helper calls that imply lifecycle or sequencing requirements."""
    helper_calls = []
    seen = set()
    scan_code = _strip_comments_and_literals(source_code)
    call_pattern = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')
    for match in call_pattern.finditer(scan_code):
        callee = match.group(1)
        if callee == function_name or callee in HELPER_SKIP_NAMES:
            continue
        if len(callee) <= 2:
            continue
        if callee in seen:
            continue
        seen.add(callee)
        lowered = callee.lower()
        phase = 'other'
        # Check cleanup BEFORE setup so that 'deallocate' (contains 'alloc')
        # or 'free_context' (contains 'free') are not mis-classified.
        if any(token in lowered for token in ['finish', 'final', 'flush', 'close', 'destroy', 'free', 'cleanup', 'end', 'dealloc', 'release', 'teardown']):
            phase = 'cleanup'
        elif any(token in lowered for token in ['init', 'open', 'create', 'alloc', 'new', 'setup', 'begin', 'start']):
            phase = 'setup'
        elif any(token in lowered for token in ['parse', 'read', 'decode', 'load', 'consume', 'process']):
            phase = 'consume'
        elif any(token in lowered for token in ['update', 'write', 'append', 'push', 'feed']):
            phase = 'update'
        helper_calls.append({
            'name': callee,
            'phase': phase
        })
    return helper_calls[:20]


def extract_state_fields(source_code: str) -> List[Dict[str, Any]]:
    """Extract struct-field access patterns that indicate object state requirements."""
    field_counts = {}
    access_pattern = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*(?:->|\.)\s*([A-Za-z_][A-Za-z0-9_]*)')
    scan_code = _strip_comments_and_literals(source_code)
    ignored_owners = set([
        'file', 'files', 'function', 'functions', 'line', 'lines',
        # Common local-variable / return-value names that are never
        # harness-controllable state.
        'ret', 'result', 'rv', 'rc', 'res', 'err', 'error', 'status',
        'tmp', 'temp', 'val', 'ok',
    ])
    ignored_fields = set(['returns', 'better'])
    for match in access_pattern.finditer(scan_code):
        owner = match.group(1)
        field = match.group(2)
        if owner.lower() in ['this'] or owner.lower() in ignored_owners or field.lower() in ignored_fields:
            continue
        key = owner + '.' + field
        info = field_counts.setdefault(key, {
            'owner': owner,
            'field': field,
            'reads': 0,
            'kind': 'state'
        })
        info['reads'] += 1
        field_lower = field.lower()
        if any(token in field_lower for token in ['mode', 'type', 'flag', 'state', 'phase', 'status']):
            info['kind'] = 'control-state'
        elif any(token in field_lower for token in ['len', 'size', 'count', 'avail', 'capacity']):
            info['kind'] = 'size-state'
        elif any(token in field_lower for token in ['buf', 'data', 'next', 'ptr', 'input', 'output']):
            info['kind'] = 'buffer-state'
    fields = list(field_counts.values())
    fields.sort(key=lambda item: (-item['reads'], item['owner'], item['field']))
    return fields[:12]


def extract_field_conditions(source_code: str) -> List[Dict[str, str]]:
    """Extract comparisons and switches involving struct fields or state members."""
    conditions = []
    comparison_pattern = re.compile(
        r'([A-Za-z_][A-Za-z0-9_]*(?:->|\.)[A-Za-z_][A-Za-z0-9_]*)\s*(==|!=|<=|>=|<|>|&)\s*([^&|]+(?:\([^\)]*\)[^&|]*)?)'
    )
    for condition_text in _extract_keyword_paren_contents(source_code, 'if') + _extract_keyword_paren_contents(source_code, 'while'):
        for match in comparison_pattern.finditer(condition_text):
            value = _normalize_condition_value(match.group(3))
            if not value:
                continue
            conditions.append({
                'target': match.group(1).strip(),
                'operator': match.group(2),
                'value': value,
                'type': 'comparison'
            })

    switch_pattern = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*(?:->|\.)[A-Za-z_][A-Za-z0-9_]*)$')
    for expression in _extract_keyword_paren_contents(source_code, 'switch'):
        target = expression.strip()
        if not switch_pattern.match(target):
            continue
        conditions.append({
            'target': target,
            'type': 'switch',
            'values': []
        })
    return conditions


def extract_loop_features(source_code: str, parameter_roles: List[Dict[str, str]]) -> Dict[str, Any]:
    """Infer repeated-record or chunked processing structure from loops and role names."""
    features = {
        'loop_count': 0,
        'count_controlled_loops': [],
        'buffer_loops': [],
        'record_like_params': [],
    }

    loop_pattern = re.compile(r'(for|while)\s*\(([^\)]*)\)', re.MULTILINE)
    for match in loop_pattern.finditer(source_code):
        header = match.group(2)
        features['loop_count'] += 1
        lowered = header.lower()
        if any(token in lowered for token in ['len', 'size', 'count', 'num', 'avail']):
            features['count_controlled_loops'].append(header.strip())
        if any(token in lowered for token in ['next', 'buf', 'data', 'input', 'output', 'offset', 'chunk']):
            features['buffer_loops'].append(header.strip())

    for role in parameter_roles:
        name = role.get('name', '').lower()
        if any(token in name for token in PLURAL_TOKENS):
            features['record_like_params'].append(role.get('name'))
    return features


def infer_workload_model(parameter_roles: List[Dict[str, str]], helper_calls: List[Dict[str, str]],
                        state_fields: List[Dict[str, Any]], field_conditions: List[Dict[str, Any]],
                        loop_features: Dict[str, Any]) -> Dict[str, Any]:
    """Infer how the harness should expand fuzz input into a workload, not just a buffer."""
    operators = []
    evidence = []

    size_roles = [role for role in parameter_roles if role.get('role') == 'size']
    buffer_roles = [role for role in parameter_roles if role.get('role') == 'input-buffer']
    control_roles = [role for role in parameter_roles if role.get('role') == 'control']
    stream_state_fields = [
        field for field in state_fields
        if (field.get('field') or '').lower() in ['avail_in', 'avail_out', 'next_in', 'next_out', 'pending_out']
    ]

    if loop_features.get('record_like_params') or (size_roles and loop_features.get('count_controlled_loops')):
        operators.append('repeated-records')
        evidence.append('loops are driven by counts or plural-like parameters, suggesting arrays or repeated entries')

    has_update_helpers = any(call.get('phase') == 'update' for call in helper_calls)
    # Only promote buffer_loops to chunked-stream when the call path shows
    # external incremental processing (update helpers or dedicated stream
    # state).  Sink-internal buffer loops alone indicate the sink iterates
    # internally, not that the harness needs to feed chunks.
    if has_update_helpers or stream_state_fields or (loop_features.get('buffer_loops') and has_update_helpers):
        operators.append('chunked-stream')
        if stream_state_fields:
            evidence.append('stream-state fields such as avail_in, avail_out, next_in, or next_out indicate incremental processing over bounded chunks')
        else:
            evidence.append('loop structure or helper calls suggest incremental processing over the payload')

    control_state_fields = [field for field in state_fields if field.get('kind') == 'control-state']
    if control_roles or control_state_fields or any(item.get('type') == 'switch' for item in field_conditions):
        operators.append('control-biased')
        evidence.append('control parameters or state fields steer branches and should be selected deliberately')

    if buffer_roles and size_roles and not operators:
        operators.append('bounded-buffer')
        evidence.append('the API mainly consumes buffers plus sizes without stronger structural evidence')

    if not operators:
        operators.append('direct-buffer')
        evidence.append('no repeated-record or streaming markers were found, so direct buffer feeding is the baseline')

    return {
        'operators': operators,
        'evidence': evidence,
    }


def infer_sensitive_controls(parameter_roles: List[Dict[str, str]], parameter_conditions: List[Dict[str, Any]],
                             switch_branches: List[Dict[str, Any]], field_conditions: List[Dict[str, Any]],
                             state_fields: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Rank controls and state variables by likely influence on vulnerability reachability."""
    sensitivity = {}

    def ensure(name, source_kind):
        item = sensitivity.setdefault(name, {
            'target': name,
            'source_kind': source_kind,
            'score': 0,
            'reasons': [],
        })
        return item

    for role in parameter_roles:
        if role.get('role') == 'control':
            item = ensure(role.get('name'), 'parameter')
            item['score'] += 2
            item['reasons'].append('exposed as a control-like parameter in the public or sink signature')

    role_map = dict((item.get('name'), item.get('role')) for item in parameter_roles if item.get('name'))

    for cond in parameter_conditions:
        target = cond.get('parameter')
        source_kind = 'field' if _is_internal_state_reference(target) else 'parameter'
        if source_kind == 'parameter' and cond.get('type') == 'comparison':
            parameter_role = role_map.get(target)
            if parameter_role in ['input-buffer', 'output-buffer', 'size', 'support-buffer'] and _is_null_like_value(cond.get('value', '')):
                continue
        item = ensure(target, source_kind)
        item['score'] += 3 if cond.get('type') == 'comparison' else 5
        item['reasons'].append('appears in {} logic inside the vulnerable function'.format(cond.get('type')))

    for branch in switch_branches:
        target = branch.get('variable')
        kind = 'field' if '->' in target or '.' in target else 'parameter'
        item = ensure(target, kind)
        item['score'] += min(6, branch.get('num_paths', 0))
        item['reasons'].append('controls {} distinct branch paths'.format(branch.get('num_paths', 0)))

    for cond in field_conditions:
        target = cond.get('target')
        item = ensure(target, 'field')
        item['score'] += 4 if cond.get('type') == 'switch' else 2
        item['reasons'].append('state field participates in {}'.format(cond.get('type')))

    for field in state_fields:
        if field.get('kind') == 'control-state':
            target = '{}.{}'.format(field.get('owner'), field.get('field'))
            item = ensure(target, 'field')
            item['score'] += min(4, field.get('reads', 0))
            item['reasons'].append('control-state field is read repeatedly in the sink path')

    ranked = list(sensitivity.values())
    ranked.sort(key=lambda item: (-item['score'], item['target']))
    return ranked[:10]


def build_exploration_policy(parameter_roles: List[Dict[str, str]], sensitive_controls: List[Dict[str, Any]],
                             workload_model: Dict[str, Any]) -> List[Dict[str, str]]:
    """Decide which knobs should be stabilized, biased, or driven directly by fuzz bytes."""
    policies = []
    top_sensitive = set([item.get('target') for item in sensitive_controls[:2]])

    for role in parameter_roles:
        name = role.get('name', '')
        role_name = role.get('role', 'value')
        policy = 'stabilize'
        rationale = 'keep non-essential parameters in a valid regime so fuzzing pressure goes to likely trigger controls'

        if role_name == 'input-buffer':
            policy = 'shape-from-payload'
            rationale = 'use the remaining fuzz bytes to construct the main workload consumed by the target API'
        elif role_name == 'size':
            policy = 'derive-bounded'
            rationale = 'derive from payload size or a bounded prefix so sizes stay consistent with supplied buffers'
        elif role_name == 'output-buffer':
            policy = 'allocate-valid'
            rationale = 'allocate writable buffers in the harness rather than fuzzing invalid storage'
        elif name in top_sensitive or role_name == 'control':
            policy = 'bias-valid-space'
            rationale = 'focus entropy on a small valid control space because this knob appears to steer sink reachability'
        elif role_name == 'state':
            policy = 'initialize-via-api'
            rationale = 'create or initialize the object through library setup functions, not raw fuzz bytes'

        policies.append({
            'target': name,
            'kind': role_name,
            'policy': policy,
            'rationale': rationale,
        })

    if 'repeated-records' in workload_model.get('operators', []):
        policies.append({
            'target': 'workload.records',
            'kind': 'workload',
            'policy': 'expand-small-to-many',
            'rationale': 'transform a compact prefix into a bounded number of repeated logical records or entries'
        })
    if 'chunked-stream' in workload_model.get('operators', []):
        policies.append({
            'target': 'workload.chunks',
            'kind': 'workload',
            'policy': 'split-into-bounded-chunks',
            'rationale': 'divide the payload into chunks and drive repeated update-style processing with valid ordering'
        })
    return policies


def build_input_model(parameter_roles: List[Dict[str, str]], format_checks: List[Dict],
                      switch_branches: List[Dict], state_fields: List[Dict],
                      helper_calls: List[Dict[str, str]]) -> Dict[str, Any]:
    """Infer how the harness should shape inputs before calling the target API."""
    primary = 'raw-buffer'
    secondary = []
    evidence = []

    if format_checks:
        primary = 'structured-format'
        secondary.append('magic-or-container-header')
        evidence.append('source code checks magic bytes or memcmp signatures before deeper parsing')

    control_branches = [b for b in switch_branches if b.get('num_paths', 0) > 1]
    if control_branches:
        secondary.append('mode-selection')
        evidence.append('switch branches indicate alternate semantic modes selected by a parameter or state field')

    if any(role.get('role') == 'state' for role in parameter_roles) or state_fields:
        secondary.append('stateful-object')
        evidence.append('the function accesses state/context fields and expects initialized objects')

    support_roles = [role for role in parameter_roles if role.get('role') == 'support-buffer']
    input_buffer_roles = [role for role in parameter_roles if role.get('role') == 'input-buffer']
    scalar_roles = [role for role in parameter_roles if role.get('role') in ['size', 'numeric', 'control']]
    stream_state_fields = [
        field for field in state_fields
        if (field.get('field') or '').lower() in ['avail_in', 'avail_out', 'next_in', 'next_out', 'pending_out']
    ]
    if not input_buffer_roles and (support_roles or scalar_roles):
        primary = 'semantic-arguments'
        secondary.append('direct-api-arguments')
        evidence.append('the sink is driven more by scalar controls and support-object contents than by a direct raw byte buffer parameter')

    if any(call.get('phase') == 'update' for call in helper_calls) or stream_state_fields:
        secondary.append('streaming-or-incremental')
        if stream_state_fields:
            evidence.append('stream-state fields indicate bounded repeated feed or flush style operation')
        else:
            evidence.append('helper calls suggest incremental feeding or update-style operation')

    if any(role.get('role') in ['size', 'numeric', 'control'] for role in parameter_roles):
        secondary.append('numeric-controls')
        evidence.append('numeric or control parameters influence path selection or sizes')

    if not evidence:
        evidence.append('no explicit container or lifecycle markers found, so treat input as a direct buffer')

    return {
        'primary': primary,
        'secondary': secondary,
        'evidence': evidence
    }


def build_execution_hints(function_name: str, parameter_roles: List[Dict[str, str]],
                          helper_calls: List[Dict[str, str]], format_checks: List[Dict],
                          switch_branches: List[Dict], state_fields: List[Dict],
                          workload_model: Dict[str, Any], sensitive_controls: List[Dict[str, Any]],
                          exploration_policy: List[Dict[str, str]]) -> List[str]:
    """Generate concrete, harness-oriented guidance from extracted semantics."""
    hints = []
    if format_checks:
        hints.append('Construct minimally valid structured inputs before mutating payload bytes so the parser reaches deeper logic.')
    if any(role.get('role') == 'state' for role in parameter_roles) or state_fields:
        hints.append('Initialize context or state objects through the library API instead of fabricating opaque structs in the harness.')
    if any(call.get('phase') == 'setup' for call in helper_calls):
        hints.append('Use discovered setup helpers or init variants to create valid objects before invoking {}.'.format(function_name))
    if any(call.get('phase') == 'update' for call in helper_calls):
        hints.append('Model the API as incremental: derive chunk sizes from fuzz input and call update-style operations in-order.')
    if any(branch.get('num_paths', 0) > 2 for branch in switch_branches):
        hints.append('Reserve a few input bits for mode or case selection so the harness explores alternate branches deterministically.')
    size_params = [role.get('name') for role in parameter_roles if role.get('role') == 'size']
    if size_params:
        hints.append('Keep size parameters bounded and consistent with the supplied buffers: {}.'.format(', '.join(size_params[:6])))
    output_params = [role.get('name') for role in parameter_roles if role.get('role') == 'output-buffer']
    if output_params:
        hints.append('Allocate writable output buffers in the harness for {} and clean them up after the call.'.format(', '.join(output_params[:6])))
    support_params = [role.get('name') for role in parameter_roles if role.get('role') == 'support-buffer']
    if support_params:
        hints.append('Populate support buffers or tables such as {} from fuzz-controlled values while keeping their lengths and counts internally consistent.'.format(', '.join(support_params[:6])))
    if 'repeated-records' in workload_model.get('operators', []):
        hints.append('Expand a small fuzz-controlled prefix into multiple bounded logical records instead of treating the whole input as one blob.')
    if 'chunked-stream' in workload_model.get('operators', []):
        hints.append('Use chunk sizes derived from a small prefix and call the API repeatedly to exercise incremental state transitions.')
    public_controls = _public_sensitive_control_targets(sensitive_controls)
    if public_controls:
        hints.append('Bias exploration toward the most sensitive controls: {}.'.format(', '.join(public_controls[:4])))
    elif sensitive_controls:
        hints.append('Bias exploration toward the most sensitive controls: {}.'.format(', '.join([item.get('target') for item in sensitive_controls[:4]])))
    if any(policy.get('policy') == 'stabilize' for policy in exploration_policy):
        hints.append('Do not spend entropy on every valid knob equally; stabilize low-signal parameters and focus on the sensitive ones.')
    if not hints:
        hints.append('Treat the API as a direct buffer consumer and map fuzz input into valid parameters without violating preconditions.')
    return hints


def infer_sink_role(function_name: str, helper_calls: List[Dict[str, str]]) -> Dict[str, Any]:
    """Classify the vulnerable function's lifecycle role."""
    lowered = (function_name or '').lower()
    role = 'invoke'
    evidence = []

    if any(token in lowered for token in ['free', 'cleanup', 'destroy', 'release', 'close', 'end', 'final', 'deinit']):
        role = 'cleanup'
        evidence.append('function name suggests finalization, release, or cleanup semantics')
    elif any(token in lowered for token in ['init', 'open', 'create', 'setup', 'begin', 'start']):
        role = 'setup'
        evidence.append('function name suggests initialization or object creation semantics')
    elif any(token in lowered for token in ['update', 'write', 'append', 'push', 'feed']):
        role = 'update'
        evidence.append('function name suggests incremental mutation or feed semantics')
    elif any(token in lowered for token in ['read', 'parse', 'decode', 'load', 'process', 'finish']):
        role = 'consume'
        evidence.append('function name suggests parsing, reading, or terminal consume semantics')

    cleanup_helpers = [item.get('name') for item in helper_calls if item.get('phase') == 'cleanup']
    if cleanup_helpers and role == 'invoke':
        evidence.append('nearby cleanup helpers indicate the sink participates in lifecycle finalization')

    return {
        'role': role,
        'evidence': evidence[:4],
    }


def _normalize_relation_token(name: str) -> str:
    lowered = (name or '').lower().replace('->', '.').replace('[', '.').replace(']', '')
    return lowered.split('.')[-1]


def _is_count_like(name: str) -> bool:
    token = _normalize_relation_token(name)
    return any(part in token for part in ['count', 'num', 'len', 'size', 'capacity', 'entry', 'entries', 'item', 'items', 'element', 'elements', 'palette', 'slot'])


def _is_bound_like(name: str) -> bool:
    token = _normalize_relation_token(name)
    return any(part in token for part in ['bit', 'bits', 'depth', 'width', 'height', 'shift', 'bpp', 'level'])


def _is_constant_like_token(name: str) -> bool:
    value = (name or '').strip()
    if not value:
        return True
    if re.match(r'^-?\d+(?:[uUlL]+)?$', value):
        return True
    if re.match(r'^[A-Z][A-Z0-9_]*$', value):
        return True
    return False


def _is_null_like_value(value: str) -> bool:
    lowered = (value or '').strip().lower()
    return lowered in ['null', 'nullptr', 'z_null']


def _is_internal_state_reference(name: str) -> bool:
    value = (name or '').strip()
    if not value:
        return False
    return '->' in value or '.' in value


def _is_public_trigger_name(name: str) -> bool:
    value = (name or '').strip()
    if not value:
        return False
    if _is_constant_like_token(value):
        return False
    if _is_internal_state_reference(value):
        return False
    return True


def _is_public_mutable_region_name(name: str) -> bool:
    return _is_public_trigger_name(name)


def _public_sensitive_control_targets(sensitive_controls: List[Dict[str, Any]]) -> List[str]:
    targets = []
    seen = set()
    for item in sensitive_controls or []:
        target = item.get('target')
        if not _is_public_trigger_name(target):
            continue
        if target in seen:
            continue
        seen.add(target)
        targets.append(target)
    return targets[:6]


def infer_trigger_relations(function_name: str, parameter_roles: List[Dict[str, str]], parameter_conditions: List[Dict[str, Any]],
                            field_conditions: List[Dict[str, Any]], state_fields: List[Dict[str, Any]], source_code: str) -> List[Dict[str, Any]]:
    """Infer generic trigger relations such as derived bounds or edge-value controls."""
    relations = []
    seen = set()
    numeric_like = [
        item.get('name') for item in parameter_roles
        if item.get('name') and item.get('role') in ['numeric', 'size', 'control']
    ]
    role_map = dict((item.get('name'), item.get('role')) for item in parameter_roles if item.get('name'))
    guidance_conditions = _select_guidance_parameter_conditions(parameter_conditions, role_map)
    state_targets = ['{}.{}'.format(item.get('owner', 'state'), item.get('field', 'field')) for item in state_fields[:8]]
    condition_texts = _extract_keyword_paren_contents(source_code or '', 'if')

    def add(kind: str, controller: str, dependent: str, evidence: str, expectation: str, priority: str = 'medium'):
        key = (kind, controller, dependent, evidence)
        if key in seen:
            return
        seen.add(key)
        relations.append({
            'kind': kind,
            'controller': controller,
            'dependent': dependent,
            'evidence': evidence,
            'harness_expectation': expectation,
            'priority': priority,
        })

    for cond in condition_texts:
        lowered = cond.lower()
        identifier_tokens = set(re.findall(r'[A-Za-z_][A-Za-z0-9_]*', lowered))
        for dependent in numeric_like:
            if dependent.lower() not in lowered or not _is_count_like(dependent):
                continue
            for controller in numeric_like + state_targets:
                controller_token = _normalize_relation_token(controller)
                if controller == dependent or controller_token not in identifier_tokens:
                    continue
                if _is_bound_like(controller) or '<<' in lowered or '>>' in lowered:
                    add(
                        'derived-bound',
                        controller,
                        dependent,
                        cond.strip(),
                        'Derive or bias {} from {} and deliberately exercise values at or just beyond the inferred legal bound.'.format(dependent, controller),
                        'high'
                    )

    for cond in guidance_conditions:
        parameter = cond.get('parameter')
        if not parameter:
            continue
        if cond.get('type') == 'comparison' and cond.get('value'):
            value = cond.get('value')
            role = role_map.get(parameter)
            if role in ['input-buffer', 'output-buffer', 'size', 'support-buffer'] and _is_null_like_value(value):
                continue
            if role == 'control' and cond.get('operator') in ['<', '>', '<=', '>=']:
                continue
            if role == 'control' and re.match(r'^-?\d+$', str(value)):
                continue
            operator = cond.get('operator', '==')
            add(
                'boundary-value',
                parameter,
                str(value),
                '{} {} {}'.format(parameter, operator, value),
                'Bias {} toward edge values around {} because the sink compares them directly.'.format(parameter, value),
                'medium'
            )

    if not relations:
        count_like = [name for name in numeric_like if _is_count_like(name)]
        bound_like = [name for name in numeric_like + state_targets if _is_bound_like(name)]
        for dependent in count_like[:3]:
            for controller in bound_like[:3]:
                if controller == dependent:
                    continue
                if _is_internal_state_reference(controller) and role_map.get(dependent) in ['size', 'input-buffer', 'output-buffer']:
                    continue
                add(
                    'count-vs-bound-hypothesis',
                    controller,
                    dependent,
                    '{} / {}'.format(controller, dependent),
                    'Test whether {} shrinks the safe range of {} and exercise values near that derived limit.'.format(controller, dependent),
                    'medium'
                )

    deduped = []
    seen_pairs = set()
    for relation in sorted(relations, key=lambda item: (0 if '==' in item.get('evidence', '') else 1, item.get('evidence', ''))):
        pair = (relation.get('controller'), relation.get('dependent'))
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        deduped.append(relation)

    return deduped[:8]


def summarize_trigger_controls(sensitive_controls: List[Dict[str, Any]], trigger_relations: List[Dict[str, Any]]) -> List[str]:
    """Separate the few controls that should vary from setup state that should remain valid."""
    controls = []
    seen = set()

    def add_control(target: str):
        if not target or target in seen:
            return
        seen.add(target)
        controls.append(target)

    public_sensitive = [
        item for item in sensitive_controls[:8]
        if item.get('source_kind') == 'parameter' and _is_public_trigger_name(item.get('target'))
    ]
    fallback_sensitive = [item for item in sensitive_controls[:8] if _is_public_trigger_name(item.get('target'))]

    chosen_sensitive = public_sensitive or fallback_sensitive
    for item in chosen_sensitive:
        add_control(item.get('target'))

    for relation in trigger_relations[:8]:
        controller = relation.get('controller')
        dependent = relation.get('dependent')
        if _is_public_trigger_name(controller):
            add_control(controller)
        if relation.get('kind') == 'count-vs-bound-hypothesis' and not _is_public_trigger_name(controller):
            continue
        if _is_public_trigger_name(dependent) and _is_count_like(dependent):
            add_control(dependent)

    return controls[:8]


def build_setup_and_invariant_requirements(parameter_roles: List[Dict[str, str]], helper_preconditions: List[str],
                                          trigger_relations: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    setup_requirements = []
    invariant_requirements = []
    if any(role.get('role') == 'state' for role in parameter_roles):
        setup_requirements.append('Initialize valid library-owned state through documented setup APIs before varying trigger controls.')
    setup_requirements.extend(helper_preconditions[:4])
    for relation in trigger_relations[:6]:
        if relation.get('kind') in ['derived-bound', 'count-vs-bound-hypothesis']:
            invariant_requirements.append('Keep valid setup and support-object invariants intact while varying {} relative to {}.'.format(
                relation.get('dependent', 'dependent'), relation.get('controller', 'controller')
            ))
    return {
        'setup_requirements': setup_requirements[:6],
        'invariant_requirements': invariant_requirements[:6],
    }


def extract_failure_path_indicators(source_code: str) -> Dict[str, Any]:
    """Extract generic error, fail, and cleanup markers around the sink body."""
    indicators = {
        'error_labels': [],
        'goto_targets': [],
        'return_checks': [],
        'error_calls': [],
        'partial_init_markers': [],
    }

    for match in re.finditer(r'goto\s+([A-Za-z_][A-Za-z0-9_]*)\s*;', source_code):
        target = match.group(1)
        lowered = target.lower()
        indicators['goto_targets'].append(target)
        if any(token in lowered for token in ['fail', 'error', 'cleanup', 'end']):
            indicators['error_labels'].append(target)

    for match in re.finditer(r'if\s*\(([^\)]{1,120})\)\s*return\s+([^;]+);', source_code):
        indicators['return_checks'].append(match.group(1).strip())

    for match in re.finditer(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', source_code):
        callee = match.group(1)
        lowered = callee.lower()
        if any(token in lowered for token in ['error', 'warn', 'fail', 'invalid']):
            if callee not in indicators['error_calls']:
                indicators['error_calls'].append(callee)

    partial_patterns = [
        r'\bif\s*\([^\)]*==\s*(?:NULL|Z_NULL|0)\)',
        r'\bif\s*\([^\)]*!=\s*(?:NULL|Z_NULL|0)\)',
        r'\bsetjmp\s*\(',
        r'\blongjmp\s*\(',
        r'\bwarning\b',
        r'\berror\b',
    ]
    for pattern in partial_patterns:
        if re.search(pattern, source_code):
            indicators['partial_init_markers'].append(pattern)

    for key in indicators:
        indicators[key] = indicators[key][:8]
    return indicators


def summarize_cleanup_preconditions(field_conditions: List[Dict[str, Any]], state_fields: List[Dict[str, Any]]) -> List[str]:
    """Summarize the object-state checks that gate cleanup or release behavior."""
    preconditions = []
    seen = set()

    for condition in field_conditions:
        target = condition.get('target')
        value = condition.get('value')
        operator = condition.get('operator')
        if not target or target in seen:
            continue
        if value in ['NULL', 'Z_NULL', '0', 'nullptr'] or operator in ['==', '!=']:
            seen.add(target)
            preconditions.append('{} {} {}'.format(target, operator, value))

    for field in state_fields:
        target = '{}->{}'.format(field.get('owner', 'state'), field.get('field', 'field'))
        if target in seen:
            continue
        if field.get('kind') in ['buffer-state', 'size-state', 'control-state']:
            seen.add(target)
            preconditions.append('cleanup depends on {}'.format(target))

    return preconditions[:6]


def summarize_ownership_transitions(helper_calls: List[Dict[str, str]], field_conditions: List[Dict[str, Any]]) -> List[str]:
    """Distill resource and ownership transitions relevant to a cleanup sink."""
    transitions = []
    for helper in helper_calls:
        phase = helper.get('phase')
        name = helper.get('name')
        if phase in ['setup', 'update', 'cleanup']:
            transitions.append('{} helper {}'.format(phase, name))
    for condition in field_conditions:
        target = condition.get('target', '')
        if target and any(token in target.lower() for token in ['buffer', 'data', 'row', 'image', 'info', 'ptr', 'next']):
            transitions.append('resource field {}'.format(target))
    unique = []
    seen = set()
    for item in transitions:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique[:8]


def build_trigger_hints(function_name: str, sink_role: Dict[str, Any], failure_indicators: Dict[str, Any],
                        cleanup_preconditions: List[str], ownership_transitions: List[str]) -> List[str]:
    """Generate concise trigger-oriented hints, especially for cleanup/failure sinks."""
    hints = []
    role = sink_role.get('role', 'invoke')
    if role == 'cleanup':
        hints.append('The vulnerable sink is a cleanup/finalize API; exercise it after multiple pre-cleanup object states, not only the happy path.')
        if failure_indicators.get('error_labels') or failure_indicators.get('return_checks'):
            hints.append('Drive cleanup after partial initialization or error handling when the public API allows it.')
        if cleanup_preconditions:
            hints.append('Important pre-cleanup state checks: {}.'.format(', '.join(cleanup_preconditions[:4])))
    elif role == 'setup':
        hints.append('The vulnerable sink appears to initialize state; vary preconditions and selector bits before the setup call.')
    if ownership_transitions:
        hints.append('Relevant resource transitions near the sink: {}.'.format(', '.join(ownership_transitions[:4])))
    if not hints:
        hints.append('Translate public inputs into the internal state transitions most likely to reach the vulnerable sink path.')
    return hints


def infer_required_support_objects(function_name: str, helper_calls: List[Dict[str, str]],
                                   state_fields: List[Dict[str, Any]], field_conditions: List[Dict[str, Any]],
                                   input_model: Dict[str, Any], parameter_roles: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Infer auxiliary objects, tables, or buffers that helper APIs likely require."""
    candidates = []
    seen = set()

    support_parameter_names = [
        item.get('name', '').lower() for item in parameter_roles or [] if item.get('role') == 'support-buffer'
    ]
    strong_haystack = ' '.join([
        (function_name or '').lower(),
        ' '.join([(item.get('name') or '').lower() for item in helper_calls]),
        ' '.join([(item.get('target') or '').lower() for item in field_conditions]),
        ' '.join(support_parameter_names),
    ])
    weak_haystack = ' '.join([
        '{} {}'.format((item.get('owner') or '').lower(), (item.get('field') or '').lower()) for item in state_fields
    ])

    for tokens, name, kind, reason in SUPPORT_OBJECT_HINTS:
        strong_match = any(token in strong_haystack for token in tokens)
        weak_match = any(token in weak_haystack for token in tokens)
        if not strong_match and not weak_match:
            continue
        if name in seen:
            continue
        if name in WEAK_SUPPORT_OBJECTS and not strong_match and input_model.get('primary') != 'structured-format':
            continue
        seen.add(name)
        candidates.append({
            'name': name,
            'kind': kind,
            'reason': reason,
        })

    if input_model.get('primary') == 'structured-format' and 'metadata-structure' not in seen:
        candidates.append({
            'name': 'container-metadata',
            'kind': 'metadata',
            'reason': 'structured-format sinks usually need a valid prefix, chunk layout, or metadata structure before deeper processing'
        })

    return candidates[:6]


def build_helper_preconditions(parameter_roles: List[Dict[str, str]], helper_calls: List[Dict[str, str]],
                               required_support_objects: List[Dict[str, str]], input_model: Dict[str, Any],
                               sink_role: Dict[str, Any]) -> List[str]:
    """Generate hard preconditions for setup or transform helpers."""
    preconditions = []

    if any(role.get('role') == 'state' for role in parameter_roles):
        preconditions.append('Initialize library-owned state objects through public setup APIs before calling helper or transform functions.')
    if input_model.get('primary') == 'structured-format':
        preconditions.append('Construct a minimally valid container prefix before mutating later sections or optional chunks.')
    for support in required_support_objects[:4]:
        preconditions.append('Provide a valid {} for {} instead of null placeholders.'.format(
            support.get('kind', 'support object'), support.get('name', 'helper state')))
    if any(call.get('phase') == 'update' for call in helper_calls):
        preconditions.append('Do not call update or transform helpers until the public API has populated the relevant decode or parser state.')
    if sink_role.get('role') == 'cleanup':
        preconditions.append('Ensure cleanup runs after at least one valid or partially initialized object state has been created by public APIs.')

    unique = []
    seen = set()
    for item in preconditions:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique[:8]


def build_sink_activation_conditions(input_model: Dict[str, Any], workload_model: Dict[str, Any],
                                     required_support_objects: List[Dict[str, str]], helper_preconditions: List[str],
                                     trigger_hints: List[str]) -> List[str]:
    """Summarize the minimal conditions under which the sink is meaningfully live."""
    conditions = []
    if input_model.get('primary') == 'structured-format':
        conditions.append('The sink becomes meaningful only after a minimally valid structured prefix is accepted by the library.')
    if 'chunked-stream' in workload_model.get('operators', []):
        conditions.append('The sink is more likely to activate after repeated feed/read/update operations rather than a single bulk call.')
    if required_support_objects:
        conditions.append('Supporting objects must be valid before enabling transform or metadata helpers: {}.'.format(', '.join([item.get('name') for item in required_support_objects[:4]])))
    for item in helper_preconditions[:2]:
        conditions.append(item)
    for item in trigger_hints[:2]:
        conditions.append(item)
    return conditions[:6]


def infer_milestone_hints(function_name: str, parameter_roles: List[Dict[str, str]],
                          helper_calls: List[Dict[str, str]], state_fields: List[Dict[str, Any]],
                          field_conditions: List[Dict[str, Any]], input_model: Dict[str, Any],
                          workload_model: Dict[str, Any], sink_role: Dict[str, Any],
                          required_support_objects: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    """Infer generic milestone states that must be satisfied before the sink is plausibly live."""
    milestones = []
    seen = set()

    def add(name: str, kind: str, reason: str, evidence: List[str], expectation: str) -> None:
        key = (name, kind)
        if key in seen:
            return
        seen.add(key)
        milestones.append({
            'name': name,
            'kind': kind,
            'required': True,
            'reason': reason,
            'evidence': [item for item in evidence if item][:4],
            'harness_expectation': expectation,
        })

    setup_helpers = [item.get('name') for item in helper_calls if item.get('phase') == 'setup']
    update_helpers = [item.get('name') for item in helper_calls if item.get('phase') in ['update', 'consume']]
    state_targets = ['{}.{}'.format(item.get('owner', 'state'), item.get('field', 'field')) for item in state_fields[:4]]
    field_targets = [item.get('target') for item in field_conditions[:4]]
    support_names = [item.get('name') for item in required_support_objects[:4]]
    token_haystack = ' '.join([
        (function_name or '').lower(),
        ' '.join([(item.get('name') or '').lower() for item in helper_calls]),
        ' '.join([item.lower() for item in state_targets]),
        ' '.join([(item or '').lower() for item in field_targets]),
        ' '.join([(item or '').lower() for item in support_names]),
    ])

    if any(role.get('role') == 'state' for role in parameter_roles) or state_fields or setup_helpers:
        add(
            'state-created',
            'object-lifecycle',
            'the sink relies on initialized library-owned state or handles',
            setup_helpers + state_targets,
            'Create or initialize valid library-owned state before feeding fuzz-controlled bytes into the entry API',
        )

    if input_model.get('primary') == 'structured-format':
        add(
            'structured-input-accepted',
            'container-parse',
            'the sink only becomes relevant after the library accepts a minimally valid container or prefix',
            support_names,
            'Construct a minimally valid container or prefix before mutating later sections aggressively',
        )

    if 'chunked-stream' in workload_model.get('operators', []) or 'streaming-or-incremental' in input_model.get('secondary', []):
        add(
            'incremental-feed-established',
            'incremental-feed',
            'the sink path appears to progress through repeated feed, update, or process steps',
            update_helpers,
            'Use bounded repeated feed or update calls instead of relying on one opaque bulk invocation',
        )

    if any(token in token_haystack for token in ['row', 'rows', 'frame', 'block', 'record', 'chunk']):
        add(
            'work-unit-produced',
            'work-unit',
            'the sink reads row, block, record, or chunk state that usually exists only after upstream processing',
            state_targets + field_targets,
            'Shape the workload so the public API produces at least one decoded or transformed work unit before expecting the sink',
        )

    if any(token in token_haystack for token in ['transform', 'quantize', 'convert', 'scale', 'expand']):
        add(
            'transform-ready',
            'transform-gating',
            'the sink appears gated on transform configuration or conversion setup',
            support_names + field_targets,
            'Enable transform-related state with valid support objects only after parser and state setup are valid',
        )

    if sink_role.get('role') == 'cleanup':
        add(
            'cleanup-state-reached',
            'cleanup-lifecycle',
            'cleanup-oriented sinks require a valid or partially initialized object state before finalization',
            setup_helpers + update_helpers,
            'Exercise cleanup after at least one valid or partially initialized state transition created by public APIs',
        )

    return milestones[:6]


def build_sink_live_predicates(function_name: str, milestone_hints: List[Dict[str, Any]],
                               sink_activation_conditions: List[str], input_model: Dict[str, Any],
                               workload_model: Dict[str, Any], state_fields: List[Dict[str, Any]],
                               required_support_objects: List[Dict[str, str]]) -> List[str]:
    """Summarize what must become true before the sink is plausibly live."""
    predicates = []

    for milestone in milestone_hints[:4]:
        expectation = milestone.get('harness_expectation')
        if expectation:
            predicates.append(expectation + '.')

    if input_model.get('primary') == 'structured-format':
        predicates.append('Earlier parser or container milestones must be satisfied before sink-focused bytes matter.')

    if 'chunked-stream' in workload_model.get('operators', []):
        predicates.append('A single bulk call is usually weaker than bounded repeated feed operations for making the sink region live.')

    if any(item.get('field') in ['row', 'rows', 'bit_depth'] or 'row' in (item.get('field') or '').lower() for item in state_fields):
        predicates.append('The sink appears to depend on a produced row, block, or equivalent work unit rather than just accepted input bytes.')

    if required_support_objects:
        predicates.append('Support objects must remain valid while sink-adjacent transforms or helpers execute: {}.'.format(
            ', '.join([item.get('name') for item in required_support_objects[:4]])
        ))

    for item in sink_activation_conditions[:2]:
        predicates.append(item)

    unique = []
    seen = set()
    for item in predicates:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique[:8]


def build_active_data_plan(function_name: str, input_model: Dict[str, Any], workload_model: Dict[str, Any],
                           state_fields: List[Dict[str, Any]], sensitive_controls: List[Dict[str, Any]],
                           required_support_objects: List[Dict[str, str]], milestone_hints: List[Dict[str, Any]],
                           field_conditions: List[Dict[str, Any]], trigger_relations: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Infer where fuzz entropy should go after milestone satisfaction is stable."""
    mutable_regions = []
    stabilized_regions = []
    derived_regions = []
    consistency_constraints = []
    entropy_guidance = []
    seen_mutable = set()
    seen_stable = set()
    seen_derived = set()

    def add_region(bucket: List[Dict[str, str]], seen: set, name: str, kind: str, priority: str, reason: str):
        if name in seen:
            return
        seen.add(name)
        bucket.append({
            'name': name,
            'kind': kind,
            'priority': priority,
            'reason': reason,
        })

    if input_model.get('primary') == 'structured-format':
        add_region(stabilized_regions, seen_stable, 'container-skeleton', 'container', 'high',
                   'keep the prefix, header layout, and structural framing valid so parsing reaches sink-adjacent logic')
        add_region(derived_regions, seen_derived, 'container-lengths', 'derived-lengths', 'high',
                   'container size, chunk length, or framing fields must remain consistent with emitted payload data')
        consistency_constraints.append('Container lengths, checksums, and framing fields must be recomputed from the emitted body instead of fuzzed independently.')

    if 'chunked-stream' in workload_model.get('operators', []):
        add_region(derived_regions, seen_derived, 'chunk-boundaries', 'derived-chunking', 'medium',
                   'incremental feeds should use bounded chunk sizes derived from control bytes while preserving valid ordering')
        consistency_constraints.append('Chunk sizes and feed ordering must stay bounded and internally consistent with the supplied payload buffer.')

    work_unit_terms = ['row', 'rows', 'scanline', 'frame', 'block', 'record', 'chunk', 'pixel', 'image']
    if any(any(term in ((field.get('field') or '').lower()) for term in work_unit_terms) for field in state_fields):
        add_region(mutable_regions, seen_mutable, 'decoded-work-unit', 'row-or-block-data', 'high',
                   'the sink reads produced rows, blocks, chunks, or image data, so fuzz entropy should reach that post-parse data path')
        consistency_constraints.append('The size and layout of decoded work units must stay consistent with image, frame, or record metadata.')

    for support in required_support_objects[:4]:
        name = support.get('name', 'support-object')
        kind = support.get('kind', 'support-object')
        priority = 'high' if kind in ['table', 'config'] else 'medium'
        add_region(mutable_regions, seen_mutable, name, kind, priority,
                   support.get('reason', 'this support object influences sink-adjacent behavior'))

    if sensitive_controls:
        add_region(mutable_regions, seen_mutable, 'bounded-controls', 'selector-or-control', 'medium',
                   'a small number of control values strongly influence sink reachability and should be fuzzed within valid ranges')
        entropy_guidance.append('Use a small bounded prefix for high-signal selectors or controls, then spend most remaining entropy on sink-relevant mutable regions.')

    for relation in trigger_relations or []:
        dependent = relation.get('dependent') or 'derived-bound-target'
        controller = relation.get('controller') or 'control'
        if _is_public_mutable_region_name(dependent):
            add_region(mutable_regions, seen_mutable, dependent, 'derived-bound-target', 'high',
                       'this value participates in an inferred trigger relation controlled by {}'.format(controller))
            consistency_constraints.append('Preserve valid setup and support-object invariants while varying {} against {}.'.format(dependent, controller))
        entropy_guidance.append(relation.get('harness_expectation', 'Bias inputs toward the inferred trigger relation.'))

    if any(item.get('kind') == 'transform-gating' for item in milestone_hints):
        add_region(mutable_regions, seen_mutable, 'transform-config', 'bounded-controls', 'high',
                   'transform-gating milestones indicate that valid transform configuration strongly affects whether the sink becomes live')

    if not mutable_regions:
        add_region(mutable_regions, seen_mutable, 'primary-payload', 'buffer', 'high',
                   'no more specific sink-adjacent mutable region was inferred, so the main payload remains the best fuzz target')

    if input_model.get('primary') == 'structured-format':
        entropy_guidance.append('Do not spend most entropy on trailing garbage after a fully valid container; mutate bytes that survive parsing and influence sink-adjacent state.')
    if any(region.get('name') == 'decoded-work-unit' for region in mutable_regions):
        entropy_guidance.append('Prefer mutating post-parse work-unit contents over unrelated trailing bytes or permanently fixed structural headers.')
    if any(region.get('kind') in ['table', 'config'] for region in mutable_regions):
        entropy_guidance.append('Support objects such as tables, palettes, histograms, or transform config should be fuzzed within valid bounds instead of kept entirely constant.')

    for item in field_conditions[:4]:
        target = item.get('target', '')
        if any(token in target.lower() for token in ['size', 'len', 'count', 'width', 'height', 'depth', 'offset']):
            consistency_constraints.append('Derived size-like field {} must stay consistent with the constructed buffers or work units.'.format(target))

    unique_constraints = []
    seen_constraints = set()
    for item in consistency_constraints:
        if item in seen_constraints:
            continue
        seen_constraints.add(item)
        unique_constraints.append(item)

    unique_guidance = []
    seen_guidance = set()
    for item in entropy_guidance:
        if item in seen_guidance:
            continue
        seen_guidance.add(item)
        unique_guidance.append(item)

    return {
        'mutable_regions': mutable_regions[:8],
        'stabilized_regions': stabilized_regions[:6],
        'derived_regions': derived_regions[:6],
        'consistency_constraints': unique_constraints[:8],
        'entropy_guidance': unique_guidance[:6],
    }


def summarize_api_roles(parameter_roles: List[Dict[str, str]], helper_calls: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Summarize the API family semantics visible from the function body."""
    roles = []
    if any(role.get('role') == 'state' for role in parameter_roles):
        roles.append({'role': 'stateful', 'reason': 'target function accepts explicit context or handle parameters'})
    if any(role.get('role') == 'input-buffer' for role in parameter_roles):
        roles.append({'role': 'buffer-consuming', 'reason': 'target function accepts caller-provided data buffers'})
    if any(role.get('role') == 'control' for role in parameter_roles):
        roles.append({'role': 'mode-driven', 'reason': 'one or more parameters act as flags, modes, or operation selectors'})
    if any(call.get('phase') == 'update' for call in helper_calls):
        roles.append({'role': 'incremental', 'reason': 'nearby helper calls imply multi-step feed or update semantics'})
    return roles


def summarize_workload_constraints(workload_model: Dict[str, Any], exploration_policy: List[Dict[str, str]]) -> List[str]:
    """Produce short declarative constraints about how the workload should be constructed."""
    constraints = []
    operators = workload_model.get('operators', [])
    if 'repeated-records' in operators:
        constraints.append('Construct multiple bounded logical entries from compact control bytes plus payload data.')
    if 'chunked-stream' in operators:
        constraints.append('Preserve incremental ordering and bounded chunk sizes when feeding data through the API.')
    if 'control-biased' in operators:
        constraints.append('Bias a small selector space toward valid branch-driving controls rather than fuzzing all parameters uniformly.')
    if any(item.get('policy') == 'stabilize' for item in exploration_policy):
        constraints.append('Stabilize low-signal parameters so the fuzzer concentrates on likely trigger controls and workload shape.')
    return constraints


def extract_function_source(source_file: Path, function_name: str, context_lines: int = 50) -> str:
    """Extract the source code of a specific function."""
    try:
        content = source_file.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""

    span = _find_function_definition_span(content, function_name)
    if span:
        line_start = span[0]
        body_close = span[1]
        context_start = content.rfind('\n', 0, line_start)
        for _ in range(4):
            if context_start <= 0:
                context_start = 0
                break
            context_start = content.rfind('\n', 0, context_start)
        snippet_start = 0 if context_start <= 0 else context_start + 1
        return content[snippet_start:body_close]

    lines = content.splitlines()
    line_pattern = re.compile(r'\b' + re.escape(function_name) + r'\b\s*\(')
    for i, line in enumerate(lines):
        if line_pattern.search(line):
            start = max(0, i - 5)
            end = min(len(lines), i + context_lines)
            return '\n'.join(lines[start:end])
    return ""


def extract_smart_excerpt(source_file, function_name, max_chars=2000):
    """Extract a compact excerpt: signature + key control-flow lines.

    Returns at most *max_chars* characters.  The excerpt prioritises the
    function signature, early branching/dispatch, and any lines that
    reference common vulnerability patterns (free, alloc, bounds, etc.).
    """
    try:
        if hasattr(source_file, 'read_text'):
            content = source_file.read_text(encoding="utf-8", errors="ignore")
        else:
            content = open(str(source_file), 'r', encoding='utf-8', errors='ignore').read()
    except Exception:
        return ""

    span = _find_function_definition_span(content, function_name)
    if not span:
        # Fall back to regex-based extraction
        lines = content.splitlines()
        pat = re.compile(r'\b' + re.escape(function_name) + r'\b\s*\(')
        for i, line in enumerate(lines):
            if pat.search(line):
                start = max(0, i - 2)
                end = min(len(lines), i + 40)
                return '\n'.join(lines[start:end])[:max_chars]
        return ""

    func_text = content[span[0]:span[1]]
    if len(func_text) <= max_chars:
        return func_text

    lines = func_text.splitlines()
    # Always keep signature (first few lines until opening brace)
    sig_end = 0
    for idx, ln in enumerate(lines):
        sig_end = idx
        if '{' in ln:
            break
    sig_lines = lines[:sig_end + 1]

    # Score remaining lines by importance
    important_re = re.compile(
        r'\b(if|switch|case|for|while|return|goto|free|realloc|malloc|calloc|'
        r'memcpy|memmove|assert|sizeof|NULL|break)\b|->|&&|\|\|',
        re.IGNORECASE,
    )
    scored = []
    for idx, ln in enumerate(lines[sig_end + 1:], start=sig_end + 1):
        stripped = ln.strip()
        if not stripped:
            continue
        s = 1
        if important_re.search(stripped):
            s += 3
        # Bonus for lines referencing other functions (call sites)
        if re.search(r'\b[a-zA-Z_]\w*\s*\(', stripped) and not stripped.startswith('//'):
            s += 2
        scored.append((s, idx, ln))

    scored.sort(key=lambda x: -x[0])

    # Greedily pick lines in original order until budget
    budget = max_chars - sum(len(l) + 1 for l in sig_lines)
    picked_indices = set()
    for _s, idx, ln in scored:
        cost = len(ln) + 1
        if cost > budget:
            continue
        picked_indices.add(idx)
        budget -= cost
        if budget <= 0:
            break

    result_lines = list(sig_lines)
    prev_idx = sig_end
    for idx in sorted(picked_indices):
        if idx > prev_idx + 1:
            result_lines.append('    // ...')
        result_lines.append(lines[idx])
        prev_idx = idx
    result_lines.append('}')

    return '\n'.join(result_lines)[:max_chars]


def extract_parameter_conditions(source_code: str, param_names: List[str]) -> List[Dict]:
    """
    Extract conditions involving parameters.
    
    Finds patterns like:
    - if (param > value)
    - if (param == value)
    - if (param & flag)
    - switch(param)
    - switch(state->mode) - struct member switches
    """
    conditions = []
    
    if_conditions = _extract_keyword_paren_contents(source_code, 'if')
    switch_expressions = _extract_keyword_paren_contents(source_code, 'switch')

    for param in param_names:
        comp_pattern = re.compile(
            r'(?<![A-Za-z0-9_>.])' + re.escape(param) + r'\b\s*(==|!=|<=|>=|<|>|&)\s*([^&|]+(?:\([^\)]*\)[^&|]*)?)'
        )
        for condition_text in if_conditions:
            for match in comp_pattern.finditer(condition_text):
                value = _normalize_condition_value(match.group(2))
                if not value:
                    continue
                conditions.append({
                    'parameter': param,
                    'operator': match.group(1),
                    'value': value,
                    'type': 'comparison'
                })

        for expression in switch_expressions:
            if expression.strip() == param:
                conditions.append({
                    'parameter': param,
                    'type': 'switch',
                    'values': []
                })
    
    # Also find struct member switches like switch(state->mode)
    struct_switch_pattern = re.compile(r'^\w+(?:->|\.)\w+$')
    for expression in switch_expressions:
        struct_member = expression.strip()
        if struct_switch_pattern.match(struct_member):
            conditions.append({
                'parameter': struct_member,
                'type': 'switch',
                'values': []
            })
    
    return conditions


def extract_state_machine(source_code: str) -> Dict:
    """
    Extract state machine information.
    
    Looks for:
    - enum states
    - state variable assignments
    - switch(state) patterns
    """
    states = {
        'enum_names': [],
        'state_variables': [],
        'transitions': []
    }
    
    # Find enum definitions (likely states)
    enum_pattern = re.compile(r'enum\s+(\w+)\s*\{([^}]+)\}')
    for match in enum_pattern.finditer(source_code):
        enum_name = match.group(1)
        enum_values = match.group(2)
        # Extract enum members
        members = [m.strip() for m in enum_values.split(',') if m.strip() and not m.strip().startswith('//')]
        states['enum_names'].append({
            'name': enum_name,
            'members': members[:20]  # Limit to first 20
        })
    
    # Find state-like variable assignments
    # Pattern: state = VALUE or state = ...
    state_assign = re.compile(r'(\w*state\w*)\s*=\s*(\w+)', re.IGNORECASE)
    for match in state_assign.finditer(source_code):
        states['state_variables'].append({
            'variable': match.group(1),
            'value': match.group(2)
        })
    
    return states


def extract_format_checks(source_code: str) -> List[Dict]:
    """
    Extract format/magic byte checks.
    
    Finds patterns like:
    - if (buf[0] == 0x1f && buf[1] == 0x8b)
    - if (memcmp(buf, "\x89PNG", 4) == 0)
    - magic number comparisons
    """
    checks = []
    
    # Find byte comparisons that look like magic checks
    # Pattern: buf[N] == 0xXX
    byte_check = re.compile(r'(\w+)\s*\[\s*(\d+)\s*\]\s*==\s*(0x[0-9a-fA-F]+|\d+)')
    magic_bytes = {}
    for match in byte_check.finditer(source_code):
        buf_name = match.group(1)
        idx = int(match.group(2))
        val = match.group(3)
        if buf_name not in magic_bytes:
            magic_bytes[buf_name] = {}
        magic_bytes[buf_name][idx] = val
    
    for buf_name, bytes_dict in magic_bytes.items():
        if len(bytes_dict) >= 2:  # At least 2 bytes = potential magic
            checks.append({
                'type': 'byte_sequence',
                'buffer': buf_name,
                'expected_bytes': bytes_dict
            })
    
    # Find memcmp checks
    memcmp_check = re.compile(r'memcmp\s*\(\s*(\w+)\s*,\s*"([^"]+)"\s*,\s*(\d+)\s*\)')
    for match in memcmp_check.finditer(source_code):
        checks.append({
            'type': 'memcmp',
            'buffer': match.group(1),
            'expected': match.group(2),
            'length': match.group(3)
        })
    
    return checks


def extract_switch_branches(source_code: str) -> List[Dict]:
    """
    Extract switch/case branches - these indicate different code paths.
    Handles both simple variables (switch(mode)) and struct members (switch(state->mode)).
    """
    branches = []
    
    # Find switch statements with simple variable names
    switch_pattern = re.compile(
        r'switch\s*\(\s*(\w+)\s*\)\s*\{([\s\S]*?)(?=\n\s*\}(?:\s*\n|\s*$))'
    )
    
    for match in switch_pattern.finditer(source_code):
        var_name = match.group(1)
        body = match.group(2)
        
        # Extract case values
        case_pattern = re.compile(r'case\s+(-?\d+|0x[0-9a-fA-F]+|\w+):')
        cases = [c.group(1) for c in case_pattern.finditer(body)]
        
        # Check for default
        has_default = 'default:' in body
        
        branches.append({
            'variable': var_name,
            'cases': cases,
            'has_default': has_default,
            'num_paths': len(cases) + (1 if has_default else 0)
        })
    
    # Find struct member switches like switch(state->mode)
    struct_switch_pattern = re.compile(
        r'switch\s*\(\s*(\w+(?:->|\.|\->)\w+)\s*\)'
    )
    for match in struct_switch_pattern.finditer(source_code):
        struct_member = match.group(1)
        # Find the switch body by looking for matching braces
        start_pos = match.end()
        brace_count = 0
        switch_body_start = source_code.find('{', start_pos)
        if switch_body_start == -1:
            continue
        pos = switch_body_start
        while pos < len(source_code):
            if source_code[pos] == '{':
                brace_count += 1
            elif source_code[pos] == '}':
                brace_count -= 1
                if brace_count == 0:
                    break
            pos += 1
        body = source_code[switch_body_start+1:pos]
        
        # Extract case values
        case_pattern = re.compile(r'case\s+(-?\d+|0x[0-9a-fA-F]+|\w+):')
        cases = [c.group(1) for c in case_pattern.finditer(body)]
        has_default = 'default:' in body
        
        if cases:
            branches.append({
                'variable': struct_member,
                'cases': cases,
                'has_default': has_default,
                'num_paths': len(cases) + (1 if has_default else 0)
            })
    
    return branches


def find_related_init_functions(source_code: str, function_name: str, debug: bool = False) -> List[Dict]:
    """
    Find same-family setup or registration functions related to the target function.
    """
    related_funcs = []
    seen = set()
    lowered_function = (function_name or '').lower()
    setup_tokens = ['init', 'open', 'create', 'setup', 'begin', 'start']
    registration_tokens = ['get', 'set', 'register', 'attach', 'assign', 'config', 'load']

    def tokenize(name):
        cleaned = re.sub(r'[^A-Za-z0-9_]+', '_', name or '')
        expanded = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', cleaned)
        return [item.lower() for item in expanded.split('_') if item]

    def classify_relation(name):
        tokens = tokenize(name)
        if any(token in tokens for token in setup_tokens):
            return 'init'
        if any(token in tokens for token in registration_tokens):
            return 'register'
        return 'setup'

    signature_pattern = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(([^;{}()]*(?:\([^)]*\)[^;{}()]*)*)\)\s*(?:\{|;)', re.MULTILINE)
    for match in signature_pattern.finditer(source_code):
        func_name = match.group(1)
        if not func_name or func_name == function_name:
            continue
        lowered_name = func_name.lower()
        if lowered_function not in lowered_name:
            continue
        tokens = tokenize(func_name)
        if not any(token in tokens for token in setup_tokens + registration_tokens):
            continue
        if func_name in seen:
            continue
        seen.add(func_name)
        params = match.group(2).strip()
        related_funcs.append({
            'name': func_name,
            'params': params,
            'relation': classify_relation(func_name),
        })
        if debug:
            print("[DEBUG] vuln_analyzer: Found related setup function: {}({}) [{}]".format(func_name, params, related_funcs[-1]['relation']))

    related_funcs.sort(key=lambda item: (
        0 if item.get('relation') == 'init' else 1,
        len(item.get('name', '')),
        item.get('name', ''),
    ))
    return related_funcs[:8]


def extract_constants_and_enums(source_code: str) -> Dict[str, Any]:
    """
    Extract #define constants and enum values that might be relevant.
    """
    constants = {
        'defines': [],
        'enums': []
    }
    
    # Find #define with numeric values
    define_pattern = re.compile(r'#define\s+(\w+)\s+(-?\d+|0x[0-9a-fA-F]+)')
    for match in define_pattern.finditer(source_code):
        constants['defines'].append({
            'name': match.group(1),
            'value': match.group(2)
        })
    
    # Find enum values
    enum_pattern = re.compile(r'enum\s*\{([^}]+)\}')
    for match in enum_pattern.finditer(source_code):
        enum_body = match.group(1)
        for item in enum_body.split(','):
            item = item.strip()
            if item and not item.startswith('//'):
                # Parse: NAME or NAME = VALUE
                eq_match = re.match(r'(\w+)\s*=\s*(.+)', item)
                if eq_match:
                    constants['enums'].append({
                        'name': eq_match.group(1),
                        'value': eq_match.group(2).strip()
                    })
                elif item:
                    constants['enums'].append({'name': item, 'value': 'auto'})
    
    return constants


# ─────────── LLM-based sink analysis (replaces heuristic classifiers) ───────────

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


def llm_classify_sink_analysis(function_name, source_code, parameter_roles,
                               helper_calls=None, state_fields=None,
                               cache_dir=None):
    """Use the LLM to classify vulnerability context from the sink function.

    Replaces the heuristic classification chain (build_input_model,
    infer_sensitive_controls, infer_workload_model, infer_required_support_objects,
    infer_milestone_hints) with a single LLM call that reads the source and
    produces semantic classifications.

    Returns a dict with any subset of:
      - input_model
      - sensitive_controls
      - workload_model
      - required_support_objects
      - milestone_hints
    Returns {} on failure.
    """
    try:
        from llm_adapters.openai import run_openai_json
    except ImportError:
        return {}

    import os
    if not (os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_API_TOKEN")):
        return {}

    model, api_base = _load_llm_config()

    # Build concise parameter list
    param_list = '\n'.join(
        '- {} ({}) [role: {}]'.format(
            p.get('name', '?'), p.get('type', '?'), p.get('role', '?'))
        for p in (parameter_roles or [])[:15]
    )

    helper_text = ''
    if helper_calls:
        helper_text = '\nHELPER FUNCTIONS called nearby:\n' + '\n'.join(
            '- {} [phase: {}]'.format(h.get('name', '?'), h.get('phase', '?'))
            for h in helper_calls[:15]
        )

    state_text = ''
    if state_fields:
        state_text = '\nSTATE FIELDS accessed:\n' + '\n'.join(
            '- {}.{} [kind: {}]'.format(
                f.get('owner', '?'), f.get('field', '?'), f.get('kind', '?'))
            for f in state_fields[:15]
        )

    prompt = """You are a vulnerability researcher analyzing a C/C++ function to determine how a fuzz harness should be constructed. Your analysis must be SPECIFIC to this function - avoid generic boilerplate.

FUNCTION: {name}

SOURCE CODE:
```c
{source}
```

PARAMETERS (heuristic classification - may be wrong):
{params}
{helpers}{state}

Analyze the source code and determine:
1. What kind of input does the calling chain ultimately process? Look at types used (XML_Char, png_byte, z_stream, etc.), function names called, struct fields, and data flow patterns.
2. Which parameters actually matter for reaching vulnerable code? ONLY include parameters the caller controls, NOT internal struct fields.
3. What libraries/objects must be set up before this function is reachable?
4. What processing model does the code follow?
5. What milestones must be reached for this code path to be exercised?

Return a JSON object:
{{
  "input_model": {{
    "primary": "structured-format" or "raw-buffer" or "semantic-arguments",
    "format_type": "XML" or "JSON" or "PNG" or "TIFF" or "ZIP" or "gzip" or "unknown",
    "secondary": ["from: magic-or-container-header, mode-selection, stateful-object, direct-api-arguments, streaming-or-incremental, numeric-controls, parser-lifecycle, post-parse-work-units"],
    "evidence": ["1-2 sentence reasons for your classification"]
  }},
  "sensitive_controls": [
    {{"target": "name", "source_kind": "parameter" or "field", "score": 1, "reasons": ["why this matters for trigger"]}}
  ],
  "workload_model": {{
    "operators": ["from: repeated-records, chunked-stream, control-biased, bounded-buffer, structured-container, direct-buffer"],
    "evidence": ["reasons"]
  }},
  "required_support_objects": [
    {{"name": "object_name", "kind": "type", "reason": "why needed before this function runs"}}
  ],
  "milestone_hints": [
    {{"name": "milestone_name", "kind": "category", "reason": "why needed", "harness_expectation": "what the harness should do"}}
  ]
}}

IMPORTANT:
- For input_model, look at what DATA the function processes (XML elements? image rows? raw bytes?) to determine the format, not just parameter types.
- For sensitive_controls, only include parameters visible to the PUBLIC caller. Internal struct state like parser->m_encoding or state->mode are NOT caller-controllable.
- For required_support_objects, only include objects the caller must explicitly create. Do NOT include internal allocations the library manages.
- For milestone_hints, only include milestones that are SPECIFIC to this code path. Do not include generic lifecycle milestones.""".format(
        name=function_name,
        source=source_code[:4000],
        params=param_list,
        helpers=helper_text,
        state=state_text,
    )

    # Cache check
    cache_file = None
    if cache_dir:
        cache_dir = Path(cache_dir)
        key = hashlib.sha256(
            (function_name + source_code[:2000]).encode()
        ).hexdigest()[:16]
        cache_file = cache_dir / 'llm_sink_analysis_{}.json'.format(key)
        if cache_file.exists():
            try:
                cached = json.loads(cache_file.read_text(encoding="utf-8"))
                if cached.get('input_model'):
                    print("[llm_sink_analysis] Using cached analysis for {}".format(
                        function_name))
                    return cached
            except Exception:
                pass

    try:
        tmp_dir = Path(tempfile.mkdtemp(prefix="rf_sink_analysis_"))
        prompt_file = tmp_dir / "prompt_sink_analysis.md"
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
            print("[llm_sink_analysis] LLM call failed: {}".format(msg),
                  file=sys.stderr)
            return {}

        result = json.loads(out_file.read_text(encoding="utf-8"))
    except Exception as exc:
        print("[llm_sink_analysis] Error: {}".format(exc), file=sys.stderr)
        return {}

    # Validate and extract
    analysis = {}
    if 'input_model' in result and isinstance(result['input_model'], dict):
        im = result['input_model']
        if im.get('primary') in ('structured-format', 'raw-buffer', 'semantic-arguments'):
            analysis['input_model'] = im
    if 'sensitive_controls' in result and isinstance(result['sensitive_controls'], list):
        analysis['sensitive_controls'] = result['sensitive_controls'][:10]
    if 'workload_model' in result and isinstance(result['workload_model'], dict):
        analysis['workload_model'] = result['workload_model']
    if 'required_support_objects' in result and isinstance(result['required_support_objects'], list):
        analysis['required_support_objects'] = result['required_support_objects'][:6]
    if 'milestone_hints' in result and isinstance(result['milestone_hints'], list):
        analysis['milestone_hints'] = result['milestone_hints'][:8]

    # Cache
    if cache_file and analysis:
        try:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps(analysis, indent=2), encoding="utf-8")
        except Exception:
            pass

    print("[llm_sink_analysis] LLM classified {} - input_model: {}".format(
        function_name,
        analysis.get('input_model', {}).get('primary', '?')))
    return analysis


def analyze_vulnerable_function(source_file: Path, function_name: str, debug: bool = True) -> Dict[str, Any]:
    """
    Main entry point: analyze a vulnerable function and extract insights.
    
    Returns a dict with:
    - source_snippet: the function's source code
    - parameter_conditions: conditions involving parameters
    - state_machine: state machine info
    - format_checks: magic byte checks
    - switch_branches: different code paths
    - constants: relevant constants
    - related_init_functions: init functions that set up state
    - parameter_roles: semantic roles of parameters
    - helper_calls: nearby helper functions that imply lifecycle
    - state_fields: state or buffer fields touched by the function
    - input_model: how the harness should shape fuzz input
    - execution_hints: concrete harness-generation guidance
    - insights: human-readable insights for the LLM
    """
    if debug:
        print("[DEBUG] vuln_analyzer: Analyzing {} in {}".format(function_name, source_file))
    
    source_code = extract_function_source(source_file, function_name)
    
    if not source_code:
        if debug:
            print("[DEBUG] vuln_analyzer: Could not extract source for {}".format(function_name))
        return {
            'error': 'Could not extract source for {}'.format(function_name),
            'source_file': str(source_file)
        }
    
    if debug:
        print("[DEBUG] vuln_analyzer: Extracted {} bytes of source code".format(len(source_code)))
    
    # Also read the entire source file for context (enums, related functions)
    try:
        full_file_content = source_file.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        full_file_content = source_code
    
    analysis_source = _strip_comments_and_literals(source_code)
    parameter_roles = extract_parameter_roles(source_code, function_name)
    if not parameter_roles and full_file_content is not source_code:
        parameter_roles = extract_parameter_roles(full_file_content, function_name)
    parameter_names = [role.get('name') for role in parameter_roles if role.get('name')]
    param_conds = extract_parameter_conditions(analysis_source, parameter_names)
    switch_branches = extract_switch_branches(analysis_source)
    format_checks = extract_format_checks(analysis_source)
    helper_calls = extract_helper_calls(analysis_source, function_name)
    state_fields = extract_state_fields(source_code)
    field_conditions = extract_field_conditions(analysis_source)
    loop_features = extract_loop_features(analysis_source, parameter_roles)
    
    # Extract state machine from FULL FILE (enums are usually outside functions)
    state_machine = extract_state_machine(full_file_content)
    
    # Extract constants from FULL FILE
    constants = extract_constants_and_enums(full_file_content)
    
    # Find related init functions (e.g., inflateInit2 for inflate)
    related_init_funcs = find_related_init_functions(full_file_content, function_name, debug)
    input_model = build_input_model(parameter_roles, format_checks, switch_branches, state_fields, helper_calls)
    workload_model = infer_workload_model(parameter_roles, helper_calls, state_fields, field_conditions, loop_features)
    sensitive_controls = infer_sensitive_controls(parameter_roles, param_conds, switch_branches, field_conditions, state_fields)
    exploration_policy = build_exploration_policy(parameter_roles, sensitive_controls, workload_model)
    execution_hints = build_execution_hints(function_name, parameter_roles, helper_calls, format_checks,
                                           switch_branches, state_fields, workload_model, sensitive_controls,
                                           exploration_policy)
    api_roles = summarize_api_roles(parameter_roles, helper_calls)
    workload_constraints = summarize_workload_constraints(workload_model, exploration_policy)
    sink_role = infer_sink_role(function_name, helper_calls)
    failure_path_indicators = extract_failure_path_indicators(analysis_source)
    cleanup_preconditions = summarize_cleanup_preconditions(field_conditions, state_fields)
    ownership_transitions = summarize_ownership_transitions(helper_calls, field_conditions)
    trigger_hints = build_trigger_hints(function_name, sink_role, failure_path_indicators,
                                        cleanup_preconditions, ownership_transitions)
    required_support_objects = infer_required_support_objects(function_name, helper_calls, state_fields, field_conditions, input_model, parameter_roles)
    semantic_contract = infer_semantic_contract(function_name, parameter_roles, helper_calls, state_fields,
                                                field_conditions, related_init_funcs)
    for item in semantic_contract.get('support_object_construction', []):
        name = item.get('name')
        if not name:
            continue
        if any(existing.get('name') == name for existing in required_support_objects):
            continue
        required_support_objects.append({
            'name': name,
            'kind': item.get('kind', 'support-object'),
            'reason': item.get('reason', 'support-object construction is required before the sink becomes live'),
        })
    helper_preconditions = build_helper_preconditions(parameter_roles, helper_calls, required_support_objects, input_model, sink_role)
    helper_preconditions.extend(semantic_contract.get('setup_requirements', []))
    helper_preconditions = helper_preconditions[:8]
    trigger_relations = infer_trigger_relations(function_name, parameter_roles, param_conds, field_conditions, state_fields, analysis_source)
    trigger_controls = summarize_trigger_controls(sensitive_controls, trigger_relations)
    relation_requirements = build_setup_and_invariant_requirements(parameter_roles, helper_preconditions, trigger_relations)
    sink_activation_conditions = build_sink_activation_conditions(input_model, workload_model, required_support_objects,
                                                                 helper_preconditions, trigger_hints)
    sink_activation_conditions.extend(semantic_contract.get('sink_activation_conditions', []))
    sink_activation_conditions = sink_activation_conditions[:6]
    milestone_hints = infer_milestone_hints(function_name, parameter_roles, helper_calls, state_fields,
                                            field_conditions, input_model, workload_model, sink_role,
                                            required_support_objects)
    milestone_hints.extend(semantic_contract.get('milestone_hints', []))
    milestone_hints = milestone_hints[:8]
    sink_live_predicates = build_sink_live_predicates(function_name, milestone_hints,
                                                      sink_activation_conditions, input_model,
                                                      workload_model, state_fields,
                                                      required_support_objects)
    active_data_plan = build_active_data_plan(function_name, input_model, workload_model,
                                              state_fields, sensitive_controls,
                                              required_support_objects, milestone_hints,
                                              field_conditions, trigger_relations)
    
    analysis = {
        'function_name': function_name,
        'source_file': str(source_file),
        'source_snippet': source_code[:5000],  # Limit size
        'parameter_conditions': param_conds,
        'state_machine': state_machine,
        'format_checks': format_checks,
        'switch_branches': switch_branches,
        'constants': constants,
        'related_init_functions': related_init_funcs,
        'parameter_roles': parameter_roles,
        'helper_calls': helper_calls,
        'state_fields': state_fields,
        'field_conditions': field_conditions,
        'loop_features': loop_features,
        'input_model': input_model,
        'workload_model': workload_model,
        'sensitive_controls': sensitive_controls,
        'exploration_policy': exploration_policy,
        'execution_hints': execution_hints,
        'api_roles': api_roles,
        'workload_constraints': workload_constraints,
        'sink_role': sink_role,
        'failure_path_indicators': failure_path_indicators,
        'cleanup_preconditions': cleanup_preconditions,
        'ownership_transitions': ownership_transitions,
        'trigger_hints': trigger_hints,
        'trigger_relations': trigger_relations,
        'trigger_controls': trigger_controls,
        'required_support_objects': required_support_objects,
        'semantic_contract': semantic_contract,
        'required_setup_calls': semantic_contract.get('required_setup_calls', []),
        'activation_predicates': semantic_contract.get('activation_predicates', []),
        'support_object_construction': semantic_contract.get('support_object_construction', []),
        'support_object_field_constraints': semantic_contract.get('support_object_field_constraints', []),
        'helper_preconditions': helper_preconditions,
        'setup_requirements': (relation_requirements.get('setup_requirements', []) + semantic_contract.get('setup_requirements', []))[:8],
        'invariant_requirements': (relation_requirements.get('invariant_requirements', []) + semantic_contract.get('invariant_requirements', []))[:8],
        'sink_activation_conditions': sink_activation_conditions,
        'milestone_hints': milestone_hints,
        'sink_live_predicates': sink_live_predicates,
        'active_data_plan': active_data_plan,
    }

    # ── LLM-based classification override ──
    # The heuristic classifiers above use keyword-matching which produces
    # frequent misclassifications (e.g. raw-buffer for XML parsers, lookup-
    # table false positives, sink-internal params in sensitive_controls).
    # Ask the LLM to re-classify from the source code and override when it
    # produces a valid result.
    llm_overrides = llm_classify_sink_analysis(
        function_name,
        source_code,
        parameter_roles,
        helper_calls=helper_calls,
        state_fields=state_fields,
        cache_dir=None,
    )
    _LLM_OVERRIDE_KEYS = [
        'input_model', 'sensitive_controls', 'workload_model',
        'required_support_objects', 'milestone_hints',
    ]
    if llm_overrides:
        for key in _LLM_OVERRIDE_KEYS:
            if key in llm_overrides:
                analysis[key] = llm_overrides[key]
                if debug:
                    print("[DEBUG] vuln_analyzer: LLM override for {}".format(key))

    # Generate human-readable insights
    analysis['insights'] = generate_insights(analysis)
    
    if debug:
        print("[DEBUG] vuln_analyzer: Found {} parameter conditions".format(len(analysis['parameter_conditions'])))
        print("[DEBUG] vuln_analyzer: Found {} switch branches".format(len(analysis['switch_branches'])))
        print("[DEBUG] vuln_analyzer: Found {} state enums".format(len(analysis['state_machine'].get('enum_names', []))))
        print("[DEBUG] vuln_analyzer: Found {} format checks".format(len(analysis['format_checks'])))
        print("[DEBUG] vuln_analyzer: Found {} parameter roles".format(len(analysis['parameter_roles'])))
        print("[DEBUG] vuln_analyzer: Generated {} insights:".format(len(analysis['insights'])))
        for insight in analysis['insights']:
            print("[DEBUG]   - {}".format(insight))
    
    return analysis


def generate_insights(analysis: Dict) -> List[str]:
    """
    Generate human-readable insights from the analysis.
    These will be included in the LLM prompt.
    """
    insights = []
    role_map = dict((item.get('name'), item.get('role')) for item in analysis.get('parameter_roles', []) if item.get('name'))
    guidance_conditions = _select_guidance_parameter_conditions(analysis.get('parameter_conditions', []), role_map)
    
    # Parameter conditions
    for cond in guidance_conditions:
        if cond['type'] == 'comparison':
            parameter_name = cond.get('parameter')
            parameter_role = role_map.get(parameter_name)
            cond_value = cond.get('value')
            if parameter_role in ['input-buffer', 'output-buffer', 'size', 'support-buffer'] and _is_null_like_value(cond_value):
                continue
            insights.append(
                "Parameter '{}' {} {} enables a different code path".format(
                    cond['parameter'], cond['operator'], cond['value'])
            )
        elif cond['type'] == 'switch':
            insights.append(
                "Parameter '{}' has {} possible values: {}".format(
                    cond['parameter'], len(cond['values']), ', '.join(cond['values'][:10]))
            )
    
    # State machine
    state_info = analysis.get('state_machine', {})
    if state_info.get('enum_names'):
        for enum in state_info['enum_names'][:3]:
            insights.append(
                "State machine detected: {} with states: {}".format(
                    enum['name'], ', '.join(enum['members'][:10]))
            )
    
    # Format checks
    for check in analysis.get('format_checks', []):
        if check['type'] == 'byte_sequence':
            bytes_str = ', '.join(['[{}]={}'.format(k, v) for k, v in check['expected_bytes'].items()])
            insights.append("Format check on '{}': {}".format(check['buffer'], bytes_str))
        elif check['type'] == 'memcmp':
            insights.append("Format check: memcmp for '{}' ({} bytes)".format(check['expected'], check['length']))
    
    # Switch branches
    for branch in analysis.get('switch_branches', []):
        if branch['num_paths'] > 1:
            insights.append(
                "Switch on '{}' has {} different paths - vary this parameter".format(
                    branch['variable'], branch['num_paths'])
            )
    
    # Constants
    constants = analysis.get('constants', {})
    relevant_defines = [d for d in constants.get('defines', []) 
                       if any(kw in d['name'].upper() for kw in ['MAX', 'MIN', 'MODE', 'FLAG', 'TYPE', 'STATE'])]
    if relevant_defines:
        const_strs = ['{}={}'.format(d['name'], d['value']) for d in relevant_defines[:5]]
        insights.append('Relevant constants: {}'.format(', '.join(const_strs)))
    
    # Related init functions
    init_funcs = analysis.get('related_init_functions', [])
    if init_funcs:
        init_names = ['{}(...)'.format(item['name']) for item in init_funcs[:3]]
        insights.append('Related init functions found: {}'.format(', '.join(init_names)))
        insights.append("IMPORTANT: Init functions often have variants with additional mode/flag parameters (e.g., Init2, InitEx). Check headers for all variants.")

    parameter_roles = analysis.get('parameter_roles', [])
    control_params = [role['name'] for role in parameter_roles if role.get('role') == 'control']
    if control_params:
        insights.append('Control parameters detected: {}.'.format(', '.join(control_params[:6])))

    input_model = analysis.get('input_model', {})
    if input_model.get('primary') == 'structured-format':
        insights.append('The vulnerable path expects structured input, not arbitrary raw bytes.')
    if 'stateful-object' in input_model.get('secondary', []):
        insights.append('The vulnerable path depends on initialized state objects or handles.')

    helper_calls = analysis.get('helper_calls', [])
    setup_helpers = [call['name'] for call in helper_calls if call.get('phase') == 'setup']
    cleanup_helpers = [call['name'] for call in helper_calls if call.get('phase') == 'cleanup']
    if setup_helpers:
        insights.append('Setup helpers appear nearby: {}.'.format(', '.join(setup_helpers[:5])))
    if cleanup_helpers:
        insights.append('Cleanup helpers appear nearby: {}.'.format(', '.join(cleanup_helpers[:5])))

    sensitive_controls = analysis.get('sensitive_controls', [])
    if sensitive_controls:
        insights.append('Most sensitive controls inferred from the sink: {}.'.format(', '.join([item.get('target') for item in sensitive_controls[:4]])))

    workload_model = analysis.get('workload_model', {})
    if workload_model.get('operators'):
        insights.append('Suggested workload shaping: {}.'.format(', '.join(workload_model.get('operators', [])[:4])))

    workload_constraints = analysis.get('workload_constraints', [])
    for constraint in workload_constraints[:3]:
        insights.append(constraint)

    sink_role = analysis.get('sink_role', {})
    if sink_role.get('role') == 'cleanup':
        insights.append('The vulnerable sink is cleanup-oriented, so harnesses should reach it after multiple object states, including partial-failure states when possible.')

    trigger_hints = analysis.get('trigger_hints', [])
    for hint in trigger_hints[:3]:
        insights.append(hint)

    required_support_objects = analysis.get('required_support_objects', [])
    if required_support_objects:
        insights.append('Required support objects inferred near the sink: {}.'.format(', '.join([item.get('name') for item in required_support_objects[:4]])))

    for item in analysis.get('sink_activation_conditions', [])[:2]:
        insights.append(item)

    milestone_hints = analysis.get('milestone_hints', [])
    if milestone_hints:
        insights.append('Required milestones before the sink is plausibly live: {}.'.format(
            ', '.join([item.get('name') for item in milestone_hints[:4]])
        ))

    for item in analysis.get('sink_live_predicates', [])[:3]:
        insights.append(item)

    active_data_plan = analysis.get('active_data_plan', {})
    if active_data_plan.get('mutable_regions'):
        insights.append('Highest-value mutable regions after milestone satisfaction: {}.'.format(
            ', '.join([item.get('name') for item in active_data_plan.get('mutable_regions', [])[:4]])
        ))
    for item in active_data_plan.get('entropy_guidance', [])[:2]:
        insights.append(item)
    
    return insights


def analyze_source_file(source_file: Path) -> Dict[str, Any]:
    """
    Analyze a source file for patterns without knowing the function name.
    """
    try:
        content = source_file.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return {'error': 'Could not read {}'.format(source_file)}
    
    return {
        'source_file': str(source_file),
        'state_machine': extract_state_machine(content),
        'format_checks': extract_format_checks(content),
        'switch_branches': extract_switch_branches(content),
        'constants': extract_constants_and_enums(content),
    }


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Analyze vulnerable function source code")
    parser.add_argument("--source", required=True, help="Source file path")
    parser.add_argument("--function", required=True, help="Function name to analyze")
    parser.add_argument("--output", help="Output file for analysis JSON")
    args = parser.parse_args()
    
    source_path = Path(args.source)
    if not source_path.exists():
        print("Error: Source file not found: {}".format(source_path))
        exit(1)
    
    analysis = analyze_vulnerable_function(source_path, args.function)
    
    if args.output:
        Path(args.output).write_text(json.dumps(analysis, indent=2))
        print("Analysis written to {}".format(args.output))
    else:
        print(json.dumps(analysis, indent=2))