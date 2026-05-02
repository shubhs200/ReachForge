#!/usr/bin/env python3
"""Recover semantic support contracts around vulnerable sinks.

This module stays generic: it scores sink-gating predicates, lifts likely setup
APIs, and reconstructs support-object field obligations from the analyzer's
existing helper, field, and state summaries.
"""
import re
from typing import Any, Dict, List, Optional


NULL_LIKE_VALUES = {'null', 'nullptr', 'z_null', '0'}
SIZE_FIELD_TOKENS = ['max', 'size', 'len', 'length', 'count', 'capacity', 'limit']
POINTER_FIELD_TOKENS = ['buf', 'buffer', 'data', 'row', 'rows', 'extra', 'table', 'palette', 'image', 'out', 'dst', 'src']
GENERIC_STATE_OWNERS = {'state', 'strm', 'stream', 'ctx', 'context', 'self', 'this'}
_IO_BOOKKEEPING_FIELDS = {
    'next_in', 'next_out', 'avail_in', 'avail_out', 'msg', 'adler', 'data_type',
    'total_in', 'total_out', 'opaque', 'zalloc', 'zfree', 'reserved', 'length',
}
_STATE_MACHINE_FIELDS = {
    'mode', 'wrap', 'flags', 'check', 'state', 'status', 'phase', 'stage', 'step',
}
DIRECT_STATE_FIELDS = _IO_BOOKKEEPING_FIELDS | _STATE_MACHINE_FIELDS
SETUP_NAME_TOKENS = {'init', 'open', 'create', 'setup', 'begin', 'start'}
REGISTRATION_NAME_TOKENS = {'get', 'set', 'register', 'attach', 'assign', 'config', 'load'}


def _split_field_target(target: str) -> List[str]:
    pieces = re.split(r'(?:->|\.)', (target or '').strip())
    return [piece for piece in pieces if piece]


def _field_tail(target: str) -> str:
    parts = _split_field_target(target)
    return parts[-1] if parts else ''


def _is_null_like(value: str) -> bool:
    return (value or '').strip().lower() in NULL_LIKE_VALUES


def _has_lowercase(name: str) -> bool:
    return any(ch.islower() for ch in (name or ''))


def _tokenize_identifier(name: str) -> List[str]:
    cleaned = re.sub(r'[^A-Za-z0-9_]+', '_', name or '')
    expanded = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', cleaned)
    return [item.lower() for item in expanded.split('_') if item]


def _shared_prefix(a: str, b: str) -> int:
    size = min(len(a or ''), len(b or ''))
    count = 0
    for idx in range(size):
        if a[idx].lower() != b[idx].lower():
            break
        count += 1
    return count


_BARE_ALLOCATOR_NAMES = {
    'allocate', 'deallocate', 'reallocate',
    'malloc', 'calloc', 'realloc', 'free',
    'new', 'delete',
}


def _is_public_setup_name(name: str, function_name: str) -> bool:
    lowered = (name or '').strip()
    if not lowered:
        return False
    if lowered.lower() == (function_name or '').lower():
        return False
    if not _has_lowercase(lowered):
        return False
    # Bare allocator / deallocator names (often internal hook function
    # pointers like cJSON hooks.allocate) are not public setup APIs.
    if lowered.lower() in _BARE_ALLOCATOR_NAMES:
        return False
    return True


# Names that typically represent internal struct-chain intermediaries
# (children of the primary state object) that the harness should never
# construct manually.  These appear in deep field-access patterns like
# ctxt->input->buf->buffer but are created automatically by the library's
# own init/create APIs.
_INTERNAL_INTERMEDIARY_NAMES = frozenset([
    'in', 'input', 'output', 'buf', 'buffer', 'raw',
    'stream', 'reader', 'writer', 'internal',
    'priv', 'private', 'impl', 'pending',
])


def _is_internal_intermediary(name: str, all_parts: List[str]) -> bool:
    """Return True if *name* looks like a library-internal struct-chain node.

    Heuristic: if the access chain has 3+ segments (e.g. ctxt->input->buf)
    AND the resolved owner is in the well-known intermediary set, it is very
    likely an internal object that the library creates on its own.
    Even with 2 segments, if the owner itself is a known intermediary *and*
    is NOT one of the function's own parameter names, suppress it.
    """
    if name.lower() in _INTERNAL_INTERMEDIARY_NAMES and len(all_parts) >= 3:
        return True
    return False


def _resolve_support_object(predicate: Dict[str, Any]) -> Optional[Dict[str, str]]:
    parts = _split_field_target(predicate.get('target', ''))
    if len(parts) < 2:
        return None

    owner = parts[-2]
    tail = parts[-1]
    owner_lower = owner.lower()
    tail_lower = tail.lower()

    if owner_lower in GENERIC_STATE_OWNERS:
        if tail_lower in DIRECT_STATE_FIELDS:
            return None
        if _is_null_like(predicate.get('value', '')) and predicate.get('operator') in {'!=', '=='}:
            # If the tail itself is an internal intermediary name (e.g.
            # state->input != NULL from a 2-part chain), suppress it too.
            if tail_lower in _INTERNAL_INTERMEDIARY_NAMES:
                return None
            return {'name': tail, 'field': ''}
        return None

    # Suppress internal struct-chain intermediaries (e.g. in->buffer,
    # buf->encoder from ctxt->input->buf->encoder chains).
    if _is_internal_intermediary(owner, parts):
        return None

    return {'name': owner, 'field': tail}


def _is_contract_relevant_predicate(condition: Dict[str, Any]) -> bool:
    target = condition.get('target', '')
    parts = _split_field_target(target)
    if len(parts) < 2:
        return False

    owner = parts[-2].lower()
    tail = parts[-1].lower()
    operator = condition.get('operator', '')
    value = condition.get('value', '')

    if owner in GENERIC_STATE_OWNERS and tail in _IO_BOOKKEEPING_FIELDS:
        return False
    if owner in GENERIC_STATE_OWNERS and tail in SIZE_FIELD_TOKENS:
        return False
    if owner in GENERIC_STATE_OWNERS and operator in {'<', '>', '<=', '>='}:
        return False
    if owner in GENERIC_STATE_OWNERS and operator in {'==', '!='} and not _is_null_like(value) and tail not in _STATE_MACHINE_FIELDS:
        return False
    return True


def _score_predicate(condition: Dict[str, Any]) -> int:
    target = condition.get('target', '')
    operator = condition.get('operator', '')
    value = condition.get('value', '')
    tail = _field_tail(target).lower()
    score = 0

    if operator == '!=' and _is_null_like(value):
        score += 5
    elif operator in ['==', '!=']:
        score += 2
    elif operator in ['<', '>', '<=', '>=']:
        score += 1

    if any(token in tail for token in POINTER_FIELD_TOKENS):
        score += 3
    if any(token in tail for token in SIZE_FIELD_TOKENS):
        score += 2
    if tail in _STATE_MACHINE_FIELDS:
        score += 3
    if target.count('->') + target.count('.') >= 2:
        score += 2

    return score


def _dedupe_dicts(items: List[Dict[str, Any]], key_fields: List[str]) -> List[Dict[str, Any]]:
    unique = []
    seen = set()
    for item in items:
        key = tuple(item.get(field) for field in key_fields)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def _dedupe_text(items: List[str]) -> List[str]:
    unique = []
    seen = set()
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique


def _is_size_field_name(name: str) -> bool:
    tokens = _tokenize_identifier(name)
    return any(token in SIZE_FIELD_TOKENS for token in tokens)


# Tokens that identify callback / function-pointer fields rather than data
# buffers.  These should NOT get the "vary the encoded length" constraint.
_CALLBACK_FIELD_TOKENS = frozenset([
    'callback', 'handler', 'hook', 'func', 'fn',
    # SAX-style event names
    'start', 'end', 'document', 'element', 'characters', 'comment',
    'processing', 'instruction', 'warning', 'error', 'fatal',
    'cdata', 'entity', 'notation', 'attribute', 'namespace',
    'reference', 'declaration',
    # Common compound callback names tokenized
    'enddocument', 'startdocument', 'startelement', 'endelement',
    'characters', 'getentity', 'setdocumentlocator',
])


def _is_buffer_like_field(name: str) -> bool:
    """Return True when *name* plausibly refers to a data-buffer field.

    Rejects:
    - fields that look like callback / function-pointer names
    - size-like fields (handled separately)
    Returns True for names that match POINTER_FIELD_TOKENS or that are
    not recognized as something else (conservative default).
    """
    tokens = _tokenize_identifier(name)
    # Reject callback / handler names — they are not buffers.
    if any(token in _CALLBACK_FIELD_TOKENS for token in tokens):
        return False
    # Also reject if the concatenated lowered name contains a callback token.
    joined = ''.join(tokens)
    if any(cb in joined for cb in ('callback', 'handler', 'enddocument',
                                    'startdocument', 'startelement',
                                    'endelement')):
        return False
    if any(token in POINTER_FIELD_TOKENS for token in tokens):
        return True
    # Default: a field that doesn't match known buffer tokens is NOT a
    # buffer.  The old fallback (anything that isn't a size field is a
    # buffer) was far too broad — it treated structural pointers like
    # doc, parent, entities, and enum fields like type as buffers.
    return False


def _semantic_match_score(candidate_tokens: List[str], semantic_tokens: List[str]) -> int:
    score = 0
    for candidate in candidate_tokens:
        for semantic in semantic_tokens:
            if candidate == semantic:
                score += 3
            elif _shared_prefix(candidate, semantic) >= 4:
                score += 2
    return score


def _infer_related_setup_calls(function_name: str,
                              related_init_functions: List[Dict[str, Any]],
                              support_objects: Dict[str, Dict[str, Any]]) -> List[Dict[str, str]]:
    inferred = []
    support_tokens = []
    for payload in support_objects.values():
        support_tokens.extend(_tokenize_identifier(payload.get('name', '')))
        for field_name in payload.get('required_fields', []):
            support_tokens.extend(_tokenize_identifier(field_name))
    support_tokens = [item for item in support_tokens if item]

    for helper in related_init_functions or []:
        name = helper.get('name')
        if not name or not _is_public_setup_name(name, function_name):
            continue
        name_tokens = _tokenize_identifier(name)
        param_tokens = _tokenize_identifier(helper.get('params', ''))
        relation = (helper.get('relation') or helper.get('phase') or '').lower()
        score = 0
        if relation == 'init' or any(token in SETUP_NAME_TOKENS for token in name_tokens):
            score += 6
        if relation == 'register' or any(token in REGISTRATION_NAME_TOKENS for token in name_tokens):
            score += 4
        semantic_score = _semantic_match_score(name_tokens + param_tokens, support_tokens)
        score += semantic_score
        if semantic_score == 0 and relation == 'register':
            score -= 3
        if score < 4:
            continue
        reason = 'same-family initializer likely establishes preconditions for {}'.format(function_name or 'the sink')
        if relation == 'register' or any(token in REGISTRATION_NAME_TOKENS for token in name_tokens):
            reason = 'same-family registration helper likely binds support-object state required before {} becomes live'.format(function_name or 'the target API')
        inferred.append({
            'name': name,
            'phase': 'setup',
            'reason': reason,
            'score': score,
        })

    inferred.sort(key=lambda item: (-item.get('score', 0), item.get('name', '')))
    return [{k: v for k, v in item.items() if k != 'score'} for item in inferred[:6]]


def _augment_required_fields(required_fields: List[str], observed_fields: List[str]) -> List[str]:
    augmented = []
    seen = set()
    for field_name in required_fields or []:
        if field_name not in seen:
            augmented.append(field_name)
            seen.add(field_name)
        for observed in observed_fields or []:
            if observed in seen or observed == field_name or not _is_size_field_name(observed):
                continue
            if _semantic_match_score(_tokenize_identifier(observed), _tokenize_identifier(field_name)) < 2:
                continue
            augmented.append(observed)
            seen.add(observed)
    return augmented


def _build_support_constraints(object_name: str, required_fields: List[str], function_name: str) -> List[Dict[str, Any]]:
    constraints = []
    lowered_fields = {field.lower() for field in required_fields}

    size_fields = [field for field in required_fields if _is_size_field_name(field)]
    buffer_fields = [field for field in required_fields if field.lower() not in lowered_fields or not _is_size_field_name(field)]
    emitted_generic = False

    for field_name in required_fields:
        if _is_size_field_name(field_name):
            continue
        related_sizes = [field for field in size_fields if _semantic_match_score(_tokenize_identifier(field), _tokenize_identifier(field_name)) >= 2]
        if related_sizes:
            constraints.append({
                'object': object_name,
                'fields': [field_name] + related_sizes[:1],
                'constraint': 'When synthesizing structured input for {}, vary the encoded length or size of {}.{} around {}.{} including equality and off-by-one cases.'.format(
                    function_name or 'the target API', object_name, field_name, object_name, related_sizes[0]
                ),
            })
        elif _is_buffer_like_field(field_name):
            constraints.append({
                'object': object_name,
                'fields': [field_name],
                'constraint': 'When synthesizing structured input for {}, vary the encoded length or size that feeds {}.{} around the registered bound, including equality and off-by-one cases.'.format(
                    function_name or 'the target API', object_name, field_name
                ),
            })
            emitted_generic = True

    if not constraints and required_fields:
        constraints.append({
            'object': object_name,
            'fields': required_fields,
            'constraint': 'Populate {} fields on {} before the sink path is exercised.'.format(', '.join(required_fields), object_name),
        })
    elif required_fields and not emitted_generic:
        constraints.insert(0, {
            'object': object_name,
            'fields': required_fields,
            'constraint': 'Populate {} fields on {} before the sink path is exercised.'.format(', '.join(required_fields), object_name),
        })

    return constraints


def infer_semantic_contract(function_name: str,
                            parameter_roles: List[Dict[str, Any]],
                            helper_calls: List[Dict[str, Any]],
                            state_fields: List[Dict[str, Any]],
                            field_conditions: List[Dict[str, Any]],
                            related_init_functions: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    activation_predicates = []
    for condition in field_conditions or []:
        if not _is_contract_relevant_predicate(condition):
            continue
        score = _score_predicate(condition)
        if score < 4:
            continue
        activation_predicates.append({
            'target': condition.get('target'),
            'operator': condition.get('operator'),
            'value': condition.get('value'),
            'importance': 'high' if score >= 7 else 'medium',
            'score': score,
            'reason': 'sink execution appears gated on this field predicate',
        })
    activation_predicates.sort(key=lambda item: (-item.get('score', 0), item.get('target') or ''))
    activation_predicates = _dedupe_dicts(activation_predicates, ['target', 'operator', 'value'])[:8]

    grouped_support_fields = {}
    for predicate in activation_predicates:
        resolved = _resolve_support_object(predicate)
        if not resolved:
            continue
        object_name = resolved.get('name')
        field_name = resolved.get('field')
        if not object_name:
            continue
        bucket = grouped_support_fields.setdefault(object_name, {
            'name': object_name,
            'kind': 'state-linked-support-object',
            'required_fields': [],
            'evidence': [],
        })
        bucket['evidence'].append(predicate.get('target'))
        if field_name and field_name not in bucket['required_fields']:
            bucket['required_fields'].append(field_name)

    for field in state_fields or []:
        owner = field.get('owner')
        field_name = field.get('field')
        if owner not in grouped_support_fields or not field_name:
            continue
        tail = field_name.lower()
        if any(token in tail for token in SIZE_FIELD_TOKENS + POINTER_FIELD_TOKENS):
            if field_name not in grouped_support_fields[owner]['required_fields']:
                grouped_support_fields[owner]['required_fields'].append(field_name)
        if field_name:
            grouped_support_fields[owner].setdefault('observed_fields', [])
            if field_name not in grouped_support_fields[owner]['observed_fields']:
                grouped_support_fields[owner]['observed_fields'].append(field_name)

    support_object_construction = []
    support_object_field_constraints = []
    invariant_requirements = []
    for object_name, payload in grouped_support_fields.items():
        required_fields = _augment_required_fields(payload.get('required_fields', []), payload.get('observed_fields', []))[:4]
        support_object_construction.append({
            'name': object_name,
            'kind': payload.get('kind', 'support-object'),
            'required_fields': required_fields,
            'reason': 'field-gated predicates imply this support object must be constructed and kept valid before the sink path becomes live',
            'expectation': 'Construct {} and populate {} before invoking {}.'.format(
                object_name,
                ', '.join(required_fields) if required_fields else 'its required fields',
                function_name or 'the target API',
            ),
        })
        if required_fields:
            constraints = _build_support_constraints(object_name, required_fields, function_name)
            support_object_field_constraints.extend(constraints)
            invariant_requirements.extend([item.get('constraint') for item in constraints if item.get('constraint')])

    # NOTE: helper_calls are callees OF the sink function (its internal
    # implementation).  They must NOT be promoted to required_setup_calls
    # because the sink already calls them.  Only same-family init/register
    # functions from related_init_functions should become setup calls.
    helper_candidates = []
    helper_candidates.extend(_infer_related_setup_calls(
        function_name,
        related_init_functions or [],
        grouped_support_fields,
    ))
    required_setup_calls = _dedupe_dicts(helper_candidates, ['name'])[:6]

    setup_requirements = []
    for call in required_setup_calls[:4]:
        setup_requirements.append('Call {} before invoking {} so sink-gating state is established through documented public lifecycle steps.'.format(
            call.get('name'), function_name or 'the target API'))
    for item in support_object_construction[:3]:
        setup_requirements.append(item.get('expectation'))

    sink_activation_conditions = []
    if activation_predicates:
        sink_activation_conditions.append('The sink remains inactive until these field predicates become true: {}.'.format(
            ', '.join(['{} {} {}'.format(item.get('target'), item.get('operator'), item.get('value')) for item in activation_predicates[:3]])
        ))
    if support_object_construction:
        sink_activation_conditions.append('Support objects must stay non-null and field-complete while sink-adjacent helpers execute: {}.'.format(
            ', '.join([item.get('name') for item in support_object_construction[:4]])
        ))

    milestone_hints = []
    if required_setup_calls or support_object_construction:
        milestone_hints.append({
            'name': 'support-contract-satisfied',
            'kind': 'support-contract',
            'required': True,
            'reason': 'the sink appears gated on setup APIs and support-object registration rather than raw payload bytes alone',
            'evidence': [item.get('name') for item in required_setup_calls[:3]] + [item.get('name') for item in support_object_construction[:3]],
            'harness_expectation': 'Satisfy the setup-call and support-object contract before expecting sink-focused mutations to matter.',
        })

    parameter_support_names = [item.get('name') for item in parameter_roles or [] if item.get('role') == 'support-buffer']
    for support_name in parameter_support_names:
        if support_name not in [item.get('name') for item in support_object_construction]:
            support_object_construction.append({
                'name': support_name,
                'kind': 'support-buffer',
                'required_fields': [],
                'reason': 'the public API signature exposes this support buffer explicitly',
                'expectation': 'Keep {} valid and internally consistent while exercising {}.'.format(support_name, function_name or 'the target API'),
            })

    return {
        'activation_predicates': activation_predicates,
        'required_setup_calls': required_setup_calls,
        'support_object_construction': support_object_construction[:6],
        'support_object_field_constraints': support_object_field_constraints[:6],
        'setup_requirements': _dedupe_text([item for item in setup_requirements if item])[:8],
        'invariant_requirements': _dedupe_text([item for item in invariant_requirements if item])[:6],
        'sink_activation_conditions': _dedupe_text([item for item in sink_activation_conditions if item])[:6],
        'milestone_hints': milestone_hints[:3],
    }