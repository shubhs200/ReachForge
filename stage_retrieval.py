#!/usr/bin/env python3
"""Lightweight stage-evidence retrieval for wrapper-path planning.

This is a narrow first RAG layer: it retrieves small source snippets around
deferred configuration and callback placement so the planner can refine stage
placement and prompt guidance without relying on hardcoded library rules.
"""
import os
import re
from pathlib import Path


SOURCE_EXTS = {'.c', '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp'}
IGNORED_DIR_PARTS = {'oss-fuzz', '__pycache__', 'build', 'dist', '.git', 'node_modules'}
LOW_PRIORITY_DIR_PARTS = {
    'contrib', 'test', 'tests', 'example', 'examples', 'fuzz',
    # Language-binding / wrapper directories are never harness-relevant.
    'python', 'ruby', 'java', 'csharp', 'go', 'rust',
    'bindings', 'binding', 'wrappers', 'wrapper', 'swig',
}
POST_PARSE_TOKENS = ['update_info', 'get_ihdr', 'get_header', 'progressive_ptr', 'info_ptr', 'row_info', 'rowbytes', 'color_type', 'bit_depth']
TRANSFORM_TOKENS = ['transform', 'quant', 'quantize', 'palette', 'gamma', 'color', 'background', 'expand', 'convert', 'scale']


def _tokenize_identifier(name):
    cleaned = re.sub(r'[^A-Za-z0-9_]+', '_', name or '')
    expanded = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', cleaned)
    return [item.lower() for item in expanded.split('_') if item]


def _find_matching_brace(text, open_index):
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


def _extract_function_blocks(text):
    blocks = []
    pattern = re.compile(r'^[\t ]*[A-Za-z_][A-Za-z0-9_\s\*:&<>\[\]]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{]*\)\s*\{', re.M)
    for match in pattern.finditer(text or ''):
        open_index = text.find('{', match.end() - 1)
        if open_index == -1:
            continue
        close_index = _find_matching_brace(text, open_index)
        if close_index == -1:
            continue
        blocks.append({
            'name': match.group(1),
            'start': match.start(),
            'end': close_index + 1,
            'body': text[match.start():close_index + 1],
        })
    return blocks


def _function_for_offset(functions, offset):
    for block in functions:
        if block['start'] <= offset < block['end']:
            return block
    return None


def _read_text(path):
    try:
        return Path(path).read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return ''


def _iter_source_files(project_root, preferred_files):
    seen = set()
    for item in preferred_files:
        if not item:
            continue
        path = Path(item)
        if path.exists() and path.is_file() and path.suffix.lower() in SOURCE_EXTS:
            resolved = str(path.resolve())
            if resolved in seen:
                continue
            seen.add(resolved)
            yield path

    root = Path(project_root or '')
    if not root.exists():
        return
    count = 0
    for path in root.rglob('*'):
        if count >= 240:
            break
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTS:
            continue
        if any(part in IGNORED_DIR_PARTS for part in path.parts):
            continue
        resolved = str(path.resolve())
        if resolved in seen:
            continue
        seen.add(resolved)
        yield path
        count += 1


def _is_callback_like_name(name):
    lowered = (name or '').lower()
    if 'callback' in lowered:
        return True
    if re.search(r'(^|_)(?:cb|fn)$', lowered):
        return True
    if re.search(r'(^|_)(?:info|row|end|read_status|user_chunk)_(?:cb|fn)$', lowered):
        return True
    if 'progressive' in lowered and re.search(r'(?:cb|fn)$', lowered):
        return True
    return False


def _is_low_priority_path(path):
    p = Path(path)
    if any(part in LOW_PRIORITY_DIR_PARTS for part in p.parts):
        return True
    # Also flag source files whose stem contains 'test' or 'fuzz' even if
    # they are not under a dedicated test/ directory (e.g. pngtest.c).
    stem = p.stem.lower()
    if any(token in stem for token in ('test', 'fuzz', 'example', 'demo', 'bench')):
        return True
    return False


def _score_function_block(block, path, wrapper_tokens, config_tokens, support_tokens):
    name = (block.get('name') or '').lower()
    body = (block.get('body') or '').lower()
    score = 0
    if _is_callback_like_name(name):
        score += 5
    if any(token in body for token in POST_PARSE_TOKENS):
        score += 4
    if any(token in name for token in wrapper_tokens):
        score += 3
    if any(token in body for token in wrapper_tokens):
        score += 3
    if any(token in body for token in config_tokens):
        score += 3
    if any(token in body for token in support_tokens):
        score += 2
    if any(token in name for token in TRANSFORM_TOKENS):
        score += 1
    if _is_low_priority_path(path):
        score -= 5
    return score


def _placement_kind(block):
    name = (block.get('name') or '').lower()
    body = (block.get('body') or '').lower()
    if _is_callback_like_name(name):
        return 'post-parse-callback'
    if any(token in body for token in POST_PARSE_TOKENS):
        return 'post-parse-transition'
    return 'deferred-config'


def _clip_snippet(text, limit_lines):
    lines = (text or '').splitlines()
    if len(lines) > limit_lines:
        return '\n'.join(lines[:limit_lines])
    return text


def _unique_tokens(items):
    unique = []
    seen = set()
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique


def _collect_search_tokens(vuln_context, support_names, config_names, path_names):
    tokens = []
    for name in config_names or []:
        tokens.extend(_tokenize_identifier(name))
    for name in support_names or []:
        tokens.extend(_tokenize_identifier(name))
    tokens.extend(_tokenize_identifier(vuln_context.get('function_name')))
    for item in (vuln_context.get('active_data_plan') or {}).get('mutable_regions', [])[:6]:
        tokens.extend(_tokenize_identifier(item.get('name')))
        tokens.extend(_tokenize_identifier(item.get('kind')))
    for item in vuln_context.get('state_fields', [])[:6]:
        tokens.extend(_tokenize_identifier(item.get('owner')))
        tokens.extend(_tokenize_identifier(item.get('field')))
    for name in path_names or []:
        tokens.extend(_tokenize_identifier(name))
    return _unique_tokens([item for item in tokens if len(item) >= 3])


def _block_matches_tokens(block, search_tokens):
    if not search_tokens:
        return False
    haystack = ' '.join([(block.get('name') or '').lower(), (block.get('body') or '').lower()])
    return any(token in haystack for token in search_tokens)


def _append_fallback_evidence(evidence, seen, path, functions, wrapper_tokens, config_tokens, support_tokens, search_tokens, api_name):
    for block in functions:
        if not _block_matches_tokens(block, search_tokens):
            continue
        score = _score_function_block(block, path, wrapper_tokens, config_tokens, support_tokens)
        if any(token in (block.get('body') or '').lower() or token in (block.get('name') or '').lower() for token in search_tokens):
            score += 2
        if score < 6:
            continue
        key = (str(path), block.get('name'), api_name)
        if key in seen:
            continue
        seen.add(key)
        evidence.append({
            'file': str(path),
            'function': block.get('name'),
            'api': api_name,
            'stage': 'transform',
            'placement': _placement_kind(block),
            'score': score,
            'snippet': _clip_snippet(block.get('body', ''), 24),
        })


def _is_registration_site(block_body, block_name):
    """Return True if a source function looks like a callback registration site
    rather than an actual execution site (callback body).

    Registration sites store function-pointer arguments into state without
    executing transform work themselves.
    """
    if not block_body:
        return False
    body = block_body.lower()
    name = (block_name or '').lower()
    # If the function stores function pointers into struct fields it is a
    # registration site, not a transform execution site.
    fn_stores = len(re.findall(r'->\s*[a-z_]+_fn\s*=', body))
    fn_stores += len(re.findall(r'->\s*(?:info|row|end|read|write)_fn\s*=', body))
    if fn_stores >= 2:
        return True
    # Functions whose name contains 'set_' + a registration keyword and whose
    # body is very short are almost certainly registration helpers.
    if re.search(r'set_.*(?:read|write|progressive|callback|fn)', name) and body.count('\n') < 20:
        return True
    return False


def retrieve_stage_evidence(project_root, vuln_context, public_api_name, path_names, stage_contracts):
    transform_stage = (stage_contracts or {}).get('transform', {})
    config_names = [item.get('name') for item in transform_stage.get('required_setup_calls', []) if item.get('name')]
    support_names = [item.get('name') for item in transform_stage.get('support_object_construction', []) if item.get('name')]
    if not project_root and not vuln_context.get('source_file'):
        return {'evidence': [], 'placement_hints': [], 'placement_candidates': []}
    search_tokens = _collect_search_tokens(vuln_context, support_names, config_names, path_names)
    if not config_names and not support_names and not search_tokens:
        return {'evidence': [], 'placement_hints': [], 'placement_candidates': []}

    wrapper_tokens = []
    for name in path_names or []:
        wrapper_tokens.extend(_tokenize_identifier(name))
    wrapper_tokens = [item for item in wrapper_tokens if item]
    config_tokens = []
    for name in config_names:
        config_tokens.extend(_tokenize_identifier(name))
    support_tokens = []
    for name in support_names:
        support_tokens.extend(_tokenize_identifier(name))

    preferred_files = [vuln_context.get('source_file')]
    evidence = []
    seen = set()
    for path in _iter_source_files(project_root, preferred_files):
        text = _read_text(path)
        if not text:
            continue
        lowered = text.lower()
        if config_names and not any(name.lower() in lowered for name in config_names) and not any(token in lowered for token in search_tokens):
            continue
        functions = _extract_function_blocks(text)
        for config_name in config_names:
            for match in re.finditer(r'\b' + re.escape(config_name) + r'\s*\(', text):
                block = _function_for_offset(functions, match.start())
                if not block:
                    continue
                key = (str(path), block.get('name'), config_name)
                if key in seen:
                    continue
                seen.add(key)
                score = _score_function_block(block, path, wrapper_tokens, config_tokens, support_tokens)
                evidence.append({
                    'file': str(path),
                    'function': block.get('name'),
                    'api': config_name,
                    'stage': 'transform',
                    'placement': _placement_kind(block),
                    'score': score,
                    'snippet': _clip_snippet(block.get('body', ''), 24),
                })
        if not config_names or not evidence:
            fallback_api = config_names[0] if config_names else (vuln_context.get('function_name') or support_names[0] if support_names else 'deferred_transform')
            _append_fallback_evidence(evidence, seen, path, functions, wrapper_tokens, config_tokens, support_tokens, search_tokens, fallback_api)

    evidence.sort(key=lambda item: (-item.get('score', 0), item.get('function', ''), item.get('api', '')))
    evidence = evidence[:6]

    placement_hints = []
    placement_candidates = []
    for item in evidence:
        func_name = item.get('function') or 'callback_or_transition'
        placement = item.get('placement')
        if placement == 'post-parse-callback':
            placement_hints.append('Emit deferred transform configuration in a real callback such as {} after parser state is established.'.format(func_name))
            placement_candidates.append(func_name)
        elif placement == 'post-parse-transition':
            placement_hints.append('Emit deferred transform configuration at a post-parse transition such as {} after parser milestones are satisfied.'.format(func_name))
            placement_candidates.append(func_name)

    unique_hints = []
    seen_hints = set()
    for item in placement_hints:
        if item in seen_hints:
            continue
        seen_hints.add(item)
        unique_hints.append(item)

    unique_candidates = []
    seen_candidates = set()
    for item in placement_candidates:
        if item in seen_candidates:
            continue
        seen_candidates.add(item)
        unique_candidates.append(item)

    # Separate registration sites (functions that store function pointers)
    # from actual execution sites (callbacks, transform bodies).
    filtered_candidates = []
    registration_sites = []
    for item in evidence:
        func_name = item.get('function')
        if not func_name:
            continue
        body = item.get('snippet') or ''
        if _is_registration_site(body, func_name):
            if func_name not in registration_sites:
                registration_sites.append(func_name)
        else:
            if func_name not in filtered_candidates:
                filtered_candidates.append(func_name)

    # Prefer actual execution sites; keep registration sites as secondary
    # hints so the harness knows HOW to register.
    final_candidates = filtered_candidates[:4]
    for item in registration_sites:
        if len(final_candidates) < 4 and item not in final_candidates:
            final_candidates.append(item)

    return {
        'evidence': evidence,
        'placement_hints': unique_hints[:4],
        'placement_candidates': final_candidates[:4],
    }