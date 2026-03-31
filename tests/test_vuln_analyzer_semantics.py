#!/usr/bin/env python3
import os
import tempfile
import unittest
from pathlib import Path

from vuln_analyzer import (
    build_input_model,
    build_active_data_plan,
    build_execution_hints,
    extract_function_source,
    extract_field_conditions,
    extract_helper_calls,
    extract_loop_features,
    extract_parameter_conditions,
    extract_parameter_roles,
    extract_state_fields,
    infer_required_support_objects,
    infer_sensitive_controls,
    infer_trigger_relations,
    infer_workload_model,
    generate_insights,
    summarize_trigger_controls,
)
from harness_plan import build_construction_plan, build_execution_plan, build_trigger_plan, normalize_vuln_context


OLD_STYLE_DEF = '''
int deflate(strm, flush)
z_streamp strm;
int flush;
{
    if (strm->state == Z_NULL) return Z_STREAM_ERROR;
    return flush;
}
'''


COMMENTY_DEF = '''
/* Returns Z_OK if things are Better and files.Better is mentioned in docs. */
int deflate(strm, flush)
z_streamp strm;
int flush;
{
    if (strm->state == Z_NULL) return Z_STREAM_ERROR;
    strm->avail_in = 3;
    return flush;
}
'''


STREAMY_DEF = '''
int deflate(strm, flush)
z_streamp strm;
int flush;
{
    deflate_state *s = strm->state;
    if (s == Z_NULL) return Z_STREAM_ERROR;
    if (flush == Z_FINISH) return 1;
    if (s->wrap == 2 && s->gzhead != Z_NULL && s->gzhead->text) return 2;
    if (strm->avail_out == 0) return 0;
    return flush;
}
'''


DICTIONARY_HELPER_DEF = '''
int helper(strm, dictionary, dictLength)
z_streamp strm;
Bytef *dictionary;
uInt dictLength;
{
    if (dictionary != Z_NULL) return 1;
    if (dictLength != Z_NULL) return 2;
    return 0;
}
'''


CONTROL_GUARD_DEF = '''
int deflate(z_streamp strm, int flush) {
    if (flush > Z_BLOCK || flush < 0) return Z_STREAM_ERROR;
    if (strm->state == FINISH_STATE && flush != Z_FINISH) return Z_BUF_ERROR;
    if (flush == Z_FULL_FLUSH) return 1;
    return 0;
}
'''


FULL_FILE_OLD_STYLE = '''
local int helper(x)
int x;
{
    return x;
}

int deflate(strm, flush)
z_streamp strm;
int flush;
{
    if (strm->state == Z_NULL) return Z_STREAM_ERROR;
    return flush;
}
'''


AMBIGUOUS_FUNCTIONS = '''
int deflateSetDictionary(strm, dictionary, dictLength)
z_streamp strm;
const Bytef *dictionary;
uInt dictLength;
{
    return dictLength == 0;
}

int deflate(strm, flush)
z_streamp strm;
int flush;
{
    return flush;
}
'''


OFFSET_DRIFT_SOURCE = '''
int helper_before(z_streamp strm) {
    deflateEnd(strm);
    return 0;
}

/* comment mentioning deflate(fake, values) before the real definition */
const char *banner = "deflate(not_a_real_signature)";

int deflate(z_streamp strm, int flush) {
    return flush;
}
'''


class VulnAnalyzerSemanticsTests(unittest.TestCase):

    def test_old_style_c_parameters_are_recovered(self):
        roles = extract_parameter_roles(OLD_STYLE_DEF, 'deflate')
        by_name = {item['name']: item for item in roles}
        self.assertEqual(by_name['strm']['role'], 'state')
        self.assertEqual(by_name['flush']['role'], 'control')

    def test_state_fields_ignore_comment_prose(self):
        fields = extract_state_fields(COMMENTY_DEF)
        names = set(['{}.{}'.format(item['owner'], item['field']) for item in fields])
        self.assertIn('strm.state', names)
        self.assertIn('strm.avail_in', names)
        self.assertNotIn('files.Better', names)
        self.assertNotIn('function.Returns', names)

    def test_stream_controls_stay_public(self):
        roles = extract_parameter_roles(STREAMY_DEF, 'deflate')
        parameter_names = [item['name'] for item in roles]
        parameter_conditions = extract_parameter_conditions(STREAMY_DEF, parameter_names)
        state_fields = extract_state_fields(STREAMY_DEF)
        field_conditions = extract_field_conditions(STREAMY_DEF)
        sensitive_controls = infer_sensitive_controls(roles, parameter_conditions, [], field_conditions, state_fields)
        trigger_relations = infer_trigger_relations('deflate', roles, parameter_conditions, field_conditions, state_fields, STREAMY_DEF)
        trigger_controls = summarize_trigger_controls(sensitive_controls, trigger_relations)

        self.assertIn('flush', trigger_controls)
        self.assertNotIn('Z_FINISH', trigger_controls)
        self.assertNotIn('s->wrap', trigger_controls)
        self.assertNotIn('strm.avail_out', trigger_controls)

    def test_optional_internal_metadata_is_not_required_support(self):
        roles = extract_parameter_roles(STREAMY_DEF, 'deflate')
        state_fields = extract_state_fields(STREAMY_DEF)
        field_conditions = extract_field_conditions(STREAMY_DEF)
        helper_calls = extract_helper_calls(STREAMY_DEF, 'deflate')
        support_objects = infer_required_support_objects(
            'deflate', helper_calls, state_fields, field_conditions,
            {'primary': 'raw-buffer', 'secondary': ['stateful-object']}, roles)
        names = set([item['name'] for item in support_objects])

        self.assertNotIn('metadata-structure', names)

    def test_active_data_plan_ignores_constant_and_internal_dependents(self):
        active_data_plan = build_active_data_plan(
            'deflate',
            {'primary': 'raw-buffer', 'secondary': ['stateful-object']},
            {'operators': ['control-biased'], 'evidence': []},
            [],
            [{'target': 'flush', 'source_kind': 'parameter', 'score': 4, 'reasons': ['comparison']}],
            [],
            [],
            [],
            [
                {
                    'kind': 'boundary-value',
                    'controller': 'flush',
                    'dependent': 'Z_FINISH',
                    'harness_expectation': 'Bias flush toward Z_FINISH.',
                },
                {
                    'kind': 'boundary-value',
                    'controller': 'len',
                    'dependent': 's->w_size',
                    'harness_expectation': 'Bias len near s->w_size.',
                },
            ])
        names = set([item['name'] for item in active_data_plan['mutable_regions']])
        constraints = '\n'.join(active_data_plan['consistency_constraints'])

        self.assertNotIn('Z_FINISH', names)
        self.assertNotIn('s->w_size', names)
        self.assertNotIn('varying Z_FINISH against flush', constraints)
        self.assertNotIn('varying s->w_size against len', constraints)

    def test_execution_hints_prefer_public_controls(self):
        hints = build_execution_hints(
            'deflate',
            [],
            [{'name': 'deflateInit2_', 'phase': 'setup'}],
            [],
            [],
            [{'owner': 'strm', 'field': 'state', 'reads': 2, 'kind': 'control-state'}],
            {'operators': ['control-biased'], 'evidence': []},
            [
                {'target': 's->wrap', 'source_kind': 'field', 'score': 8, 'reasons': []},
                {'target': 'level', 'source_kind': 'parameter', 'score': 6, 'reasons': []},
                {'target': 'strategy', 'source_kind': 'parameter', 'score': 6, 'reasons': []},
            ],
            [])
        joined = '\n'.join(hints)

        self.assertIn('level, strategy', joined)
        self.assertNotIn('s->wrap, level', joined)

    def test_normalize_vuln_context_prunes_weak_support_objects(self):
        context = normalize_vuln_context(
            {
                'input_model': {'primary': 'raw-buffer', 'secondary': ['stateful-object'], 'evidence': []},
                'parameter_roles': [],
                'required_support_objects': [
                    {'name': 'metadata-structure', 'kind': 'metadata', 'reason': 'metadata-oriented paths require valid metadata or descriptor structures'}
                ],
                'helper_preconditions': ['Provide a valid metadata for metadata-structure instead of null placeholders.'],
                'setup_requirements': ['Provide a valid metadata for metadata-structure instead of null placeholders.'],
                'sink_activation_conditions': ['Supporting objects must be valid before enabling transform or metadata helpers: metadata-structure.'],
                'sink_live_predicates': ['Support objects must remain valid while sink-adjacent transforms or helpers execute: metadata-structure.'],
                'active_data_plan': {
                    'mutable_regions': [
                        {'name': 'metadata-structure', 'kind': 'metadata', 'priority': 'medium', 'reason': 'metadata-oriented paths require valid metadata or descriptor structures'}
                    ],
                    'stabilized_regions': [],
                    'derived_regions': [],
                    'consistency_constraints': [],
                    'entropy_guidance': [],
                },
            },
            'deflate',
            {})

        self.assertEqual(context.get('required_support_objects'), [])
        self.assertEqual(context.get('helper_preconditions'), [])
        self.assertEqual(context.get('setup_requirements'), [])
        self.assertEqual(context.get('sink_activation_conditions'), [])
        self.assertEqual(context.get('sink_live_predicates'), [])
        self.assertEqual(context.get('active_data_plan', {}).get('mutable_regions'), [])

    def test_old_style_parameters_can_be_recovered_from_full_file(self):
        roles = extract_parameter_roles(FULL_FILE_OLD_STYLE, 'deflate')
        by_name = {item['name']: item for item in roles}

        self.assertEqual(by_name['strm']['role'], 'state')
        self.assertEqual(by_name['flush']['role'], 'control')

    def test_stream_state_fields_infer_incremental_models(self):
        state_fields = [
            {'owner': 'strm', 'field': 'avail_in', 'reads': 3, 'kind': 'size-state'},
            {'owner': 'strm', 'field': 'avail_out', 'reads': 3, 'kind': 'size-state'},
            {'owner': 'strm', 'field': 'next_in', 'reads': 2, 'kind': 'buffer-state'},
        ]
        input_model = build_input_model([], [], [], state_fields, [])
        workload_model = infer_workload_model([], [], state_fields, [], {'loop_count': 0, 'count_controlled_loops': [], 'buffer_loops': [], 'record_like_params': []})

        self.assertIn('streaming-or-incremental', input_model.get('secondary', []))
        self.assertIn('chunked-stream', workload_model.get('operators', []))

    def test_null_boundary_buffer_and_size_params_are_not_promoted(self):
        roles = extract_parameter_roles(DICTIONARY_HELPER_DEF, 'helper')
        parameter_names = [item['name'] for item in roles]
        parameter_conditions = extract_parameter_conditions(DICTIONARY_HELPER_DEF, parameter_names)
        sensitive_controls = infer_sensitive_controls(roles, parameter_conditions, [], [], [])
        trigger_relations = infer_trigger_relations('helper', roles, parameter_conditions, [], [], DICTIONARY_HELPER_DEF)
        trigger_controls = summarize_trigger_controls(sensitive_controls, trigger_relations)

        self.assertFalse(any(item.get('target') == 'dictionary' for item in sensitive_controls))
        self.assertFalse(any(item.get('target') == 'dictLength' for item in sensitive_controls))
        self.assertEqual(trigger_relations, [])
        self.assertEqual(trigger_controls, [])

    def test_null_boundary_buffer_and_size_params_are_not_reported_as_insights(self):
        roles = extract_parameter_roles(DICTIONARY_HELPER_DEF, 'helper')
        parameter_names = [item['name'] for item in roles]
        parameter_conditions = extract_parameter_conditions(DICTIONARY_HELPER_DEF, parameter_names)

        insights = generate_insights({
            'parameter_roles': roles,
            'parameter_conditions': parameter_conditions,
        })

        self.assertEqual(insights, [])

    def test_condition_values_are_normalized_before_planning(self):
        conditions = extract_parameter_conditions(CONTROL_GUARD_DEF, ['flush'])
        values = [item.get('value') for item in conditions if item.get('type') == 'comparison']

        self.assertIn('Z_FINISH', values)
        self.assertNotIn('Z_FINISH)', values)

    def test_control_range_guards_do_not_dominate_trigger_relations(self):
        roles = extract_parameter_roles(CONTROL_GUARD_DEF, 'deflate')
        parameter_conditions = extract_parameter_conditions(CONTROL_GUARD_DEF, ['flush'])
        trigger_relations = infer_trigger_relations('deflate', roles, parameter_conditions, [], [], CONTROL_GUARD_DEF)

        dependents = [item.get('dependent') for item in trigger_relations]
        self.assertNotIn('Z_BLOCK', dependents)
        self.assertNotIn('0', dependents)
        self.assertIn('Z_FULL_FLUSH', dependents)

    def test_control_equalities_outrank_inequality_exclusions_in_guidance(self):
        roles = extract_parameter_roles(CONTROL_GUARD_DEF, 'deflate')
        parameter_conditions = extract_parameter_conditions(CONTROL_GUARD_DEF, ['flush'])
        trigger_relations = infer_trigger_relations('deflate', roles, parameter_conditions, [], [], CONTROL_GUARD_DEF)
        insights = generate_insights({
            'parameter_roles': roles,
            'parameter_conditions': parameter_conditions,
        })

        dependents = [item.get('dependent') for item in trigger_relations]
        self.assertNotIn('Z_FINISH', dependents)
        self.assertIn('Z_FULL_FLUSH', dependents)
        self.assertFalse(any('Z_FINISH' in item and '!=' in item for item in insights))
        self.assertTrue(any('Z_FULL_FLUSH' in item for item in insights))

    def test_internal_bound_does_not_drive_helper_size_hypothesis(self):
        roles = [
            {'name': 'strm', 'role': 'state'},
            {'name': 'dictionary', 'role': 'input-buffer'},
            {'name': 'dictLength', 'role': 'size'},
        ]
        state_fields = [
            {'owner': 's', 'field': 'level', 'reads': 2, 'kind': 'numeric-state'},
        ]

        trigger_relations = infer_trigger_relations('deflate', roles, [], [], state_fields, '')
        trigger_controls = summarize_trigger_controls([], trigger_relations)

        self.assertEqual(trigger_relations, [])
        self.assertEqual(trigger_controls, [])

    def test_role_mismatch_prefers_sink_body_roles_and_prunes_stale_text(self):
        vuln_context = {
            'parameter_roles': [
                {'name': 'strm', 'role': 'state', 'type': 'z_streamp'},
                {'name': 'flush', 'role': 'control', 'type': 'int'},
            ],
            'parameter_conditions': [
                {'parameter': 'flush', 'operator': '==', 'value': 'Z_FINISH', 'type': 'comparison'},
            ],
            'switch_branches': [],
            'input_model': {
                'primary': 'raw-buffer',
                'secondary': ['stateful-object', 'streaming-or-incremental'],
                'evidence': [],
            },
            'workload_model': {
                'operators': ['chunked-stream', 'control-biased'],
                'evidence': [],
            },
            'execution_hints': [
                'Keep size parameters bounded and consistent with the supplied buffers: dictLength.',
            ],
            'insights': [
                "Parameter 'dictLength' != Z_NULL enables a different code path",
            ],
            'exploration_policy': [
                {'target': 'dictionary', 'kind': 'input-buffer', 'policy': 'shape-from-payload', 'rationale': 'helper-derived'},
                {'target': 'dictLength', 'kind': 'size', 'policy': 'derive-bounded', 'rationale': 'helper-derived'},
            ],
            'sensitive_controls': [],
            'trigger_controls': [],
            'trigger_relations': [],
            'setup_requirements': [],
            'invariant_requirements': [],
            'state_fields': [],
            'active_data_plan': {
                'mutable_regions': [],
                'stabilized_regions': [],
                'derived_regions': [],
                'consistency_constraints': [],
                'entropy_guidance': [],
            },
        }
        public_signatures = {
            'deflate': [
                ('z_streamp', 'strm'),
                ('Bytef *', 'dictionary'),
                ('uInt *', 'dictLength'),
            ],
        }

        normalized = normalize_vuln_context(vuln_context, 'deflate', public_signatures)
        execution_plan = build_execution_plan(
            {'affected-function': 'deflate'},
            'deflate',
            ['deflate'],
            {'deflate': 'deflate'},
            normalized,
            public_signatures,
            {'deflate'},
        )

        self.assertEqual([item.get('name') for item in normalized.get('parameter_roles', [])], ['strm', 'flush'])
        self.assertEqual([item.get('name') for item in execution_plan.get('parameter_roles', [])], ['strm', 'flush'])
        self.assertFalse(any('dictLength' in item for item in normalized.get('execution_hints', [])))
        self.assertFalse(any('dictLength' in item for item in normalized.get('insights', [])))
        self.assertEqual(execution_plan.get('trigger_controls'), ['flush'])
        self.assertFalse(any(item.get('target') == 'dictLength' for item in execution_plan.get('exploration_policy', [])))

    def test_extract_function_source_uses_exact_name_match(self):
        handle = tempfile.NamedTemporaryFile('w', delete=False, suffix='.c')
        try:
            handle.write(AMBIGUOUS_FUNCTIONS)
            handle.close()
            snippet = extract_function_source(handle.name and __import__('pathlib').Path(handle.name), 'deflate')
            self.assertIn('int deflate(strm, flush)', snippet)
            self.assertNotIn('int deflateSetDictionary(strm, dictionary, dictLength)', snippet)
        finally:
            os.unlink(handle.name)

    def test_header_registration_contract_upgrades_to_structured_input(self):
        vuln_context = {
            'function_name': 'inflate',
            'input_model': {
                'primary': 'semantic-arguments',
                'secondary': ['mode-selection', 'stateful-object'],
                'evidence': ['the sink is driven by scalar controls and support-object contents'],
            },
            'workload_model': {'operators': ['control-biased'], 'evidence': []},
            'parameter_roles': [
                {'name': 'strm', 'role': 'state', 'type': 'z_streamp'},
                {'name': 'flush', 'role': 'control', 'type': 'int'},
            ],
            'required_setup_calls': [
                {'name': 'inflateInit2_', 'phase': 'setup', 'reason': 'initializer'},
                {'name': 'inflateGetHeader', 'phase': 'setup', 'reason': 'header registration'},
            ],
            'activation_predicates': [
                {'target': 'state->head', 'operator': '!=', 'value': 'Z_NULL'},
                {'target': 'head->extra', 'operator': '!=', 'value': 'Z_NULL'},
            ],
            'support_object_construction': [
                {'name': 'head', 'kind': 'state-linked-support-object', 'required_fields': ['extra', 'name', 'comment']},
            ],
            'support_object_field_constraints': [],
            'state_fields': [{'owner': 'strm', 'field': 'msg', 'reads': 1, 'kind': 'state'}],
            'setup_requirements': [],
            'invariant_requirements': [],
            'exploration_policy': [],
            'sensitive_controls': [{'target': 'flush', 'source_kind': 'parameter', 'score': 23, 'reasons': ['comparison']}],
            'setup_state_profiles': [],
            'trigger_relations': [],
            'trigger_controls': ['flush'],
            'workload_constraints': [],
            'execution_hints': [],
            'insights': [],
            'sink_live_predicates': [],
            'sink_activation_conditions': [],
            'milestone_hints': [],
            'required_support_objects': [],
            'helper_calls': [],
            'sink_role': {'role': 'invoke', 'evidence': []},
            'failure_path_indicators': {'error_calls': []},
            'cleanup_preconditions': [],
            'ownership_transitions': [],
            'trigger_hints': [],
            'active_data_plan': {
                'mutable_regions': [],
                'stabilized_regions': [],
                'derived_regions': [],
                'consistency_constraints': [],
                'entropy_guidance': [],
            },
        }
        public_signatures = {
            'inflate': [
                ('z_streamp', 'strm'),
                ('int', 'flush'),
            ],
        }

        normalized = normalize_vuln_context(vuln_context, 'inflate', public_signatures)
        execution_plan = build_execution_plan(
            {'affected-function': 'inflate'},
            'inflate',
            ['inflate'],
            {'inflate': 'inflate'},
            normalized,
            public_signatures,
            {'inflate'},
        )
        trigger_plan = build_trigger_plan({'affected-function': 'inflate'}, 'inflate', execution_plan, normalized)
        construction_plan = build_construction_plan({'affected-function': 'inflate'}, 'inflate', execution_plan, trigger_plan, normalized)

        self.assertEqual(execution_plan.get('input_model', {}).get('primary'), 'structured-format')
        self.assertIn('magic-or-container-header', execution_plan.get('input_model', {}).get('secondary', []))
        self.assertIn('structured-container', execution_plan.get('workload_model', {}).get('operators', []))
        self.assertTrue(construction_plan.get('requires_container_synthesis'))
        self.assertTrue(any(item.get('kind') == 'container-parse' for item in execution_plan.get('milestone_plan', [])))

    def test_wrapper_entry_prefers_public_signature_and_progressive_path_becomes_structured(self):
        vuln_context = {
            'function_name': 'png_do_quantize',
            'input_model': {
                'primary': 'semantic-arguments',
                'secondary': ['stateful-object', 'direct-api-arguments'],
                'evidence': ['the sink is driven by support-object contents more than direct raw bytes'],
            },
            'workload_model': {'operators': ['control-biased'], 'evidence': []},
            'parameter_roles': [
                {'name': 'row_info', 'role': 'state', 'type': 'png_row_infop'},
                {'name': 'row', 'role': 'value', 'type': 'png_bytep'},
                {'name': 'palette_lookup', 'role': 'support-buffer', 'type': 'png_const_bytep'},
                {'name': 'quantize_lookup', 'role': 'value', 'type': 'png_const_bytep'},
            ],
            'required_setup_calls': [
                {'name': 'png_set_quantize', 'phase': 'setup', 'reason': 'quantize configuration is required before the quantize sink is meaningful'},
            ],
            'activation_predicates': [],
            'support_object_construction': [
                {'name': 'palette_lookup', 'kind': 'support-buffer', 'required_fields': []},
            ],
            'support_object_field_constraints': [],
            'state_fields': [
                {'owner': 'row_info', 'field': 'color_type', 'reads': 5, 'kind': 'control-state'},
                {'owner': 'row_info', 'field': 'bit_depth', 'reads': 3, 'kind': 'state'},
            ],
            'setup_requirements': [],
            'invariant_requirements': [],
            'exploration_policy': [],
            'sensitive_controls': [{'target': 'palette_lookup', 'source_kind': 'parameter', 'score': 3, 'reasons': ['comparison']}],
            'setup_state_profiles': [],
            'trigger_relations': [
                {'kind': 'boundary-value', 'controller': 'palette_lookup', 'dependent': 'NULL', 'harness_expectation': 'Bias palette_lookup toward edge values around NULL because the sink compares them directly.', 'priority': 'medium'},
            ],
            'trigger_controls': ['palette_lookup'],
            'workload_constraints': [],
            'execution_hints': [],
            'insights': [],
            'sink_live_predicates': [],
            'sink_activation_conditions': [],
            'milestone_hints': [],
            'required_support_objects': [{'name': 'palette_lookup', 'kind': 'table', 'reason': 'explicit support buffer'}],
            'helper_calls': [],
            'sink_role': {'role': 'invoke', 'evidence': []},
            'failure_path_indicators': {'error_calls': []},
            'cleanup_preconditions': [],
            'ownership_transitions': [],
            'trigger_hints': [],
            'active_data_plan': {
                'mutable_regions': [],
                'stabilized_regions': [],
                'derived_regions': [],
                'consistency_constraints': [],
                'entropy_guidance': [],
            },
        }
        public_signatures = {
            'png_process_data': [
                ('png_structrp', 'png_ptr'),
                ('png_inforp', 'info_ptr'),
                ('png_bytep', 'buffer'),
                ('png_size_t', 'buffer_size'),
            ],
        }

        normalized = normalize_vuln_context(vuln_context, 'png_process_data', public_signatures)
        execution_plan = build_execution_plan(
            {'affected-function': 'png_do_quantize'},
            'png_process_data',
            ['png_process_data', 'png_process_some_data', 'png_push_read_IDAT', 'png_process_IDAT_data', 'png_push_process_row', 'png_do_read_transformations', 'png_do_quantize'],
            {
                'png_process_data': 'png_process_data',
                'png_process_some_data': 'png_process_some_data',
                'png_push_read_IDAT': 'png_push_read_IDAT',
                'png_process_IDAT_data': 'png_process_IDAT_data',
                'png_push_process_row': 'png_push_process_row',
                'png_do_read_transformations': 'png_do_read_transformations',
                'png_do_quantize': 'png_do_quantize',
            },
            normalized,
            public_signatures,
            {'png_process_data'},
        )

        self.assertEqual([item.get('name') for item in execution_plan.get('parameter_roles', [])], ['png_ptr', 'info_ptr', 'buffer', 'buffer_size'])
        self.assertEqual(execution_plan.get('input_model', {}).get('primary'), 'structured-format')
        self.assertIn('structured-container', execution_plan.get('workload_model', {}).get('operators', []))
        self.assertTrue(any(item.get('kind') == 'container-parse' for item in execution_plan.get('milestone_plan', [])))
        self.assertTrue(any(item.get('name') == 'container-skeleton' for item in execution_plan.get('active_data_plan', {}).get('stabilized_regions', [])))
        self.assertEqual(execution_plan.get('direct_stages'), ['entry', 'parse'])
        self.assertEqual(execution_plan.get('deferred_stages'), ['transform', 'sink'])
        self.assertEqual(execution_plan.get('required_setup_calls', []), [])
        self.assertEqual(execution_plan.get('support_object_construction', []), [])
        self.assertNotIn('palette_lookup', execution_plan.get('trigger_controls', []))
        self.assertFalse(any('palette_lookup' in item for item in execution_plan.get('sink_live_predicates', [])))
        self.assertFalse(any('palette_lookup' in item for item in execution_plan.get('coverage_goals', [])))
        structured_milestone = [item for item in execution_plan.get('milestone_plan', []) if item.get('name') == 'structured-input-accepted'][0]
        self.assertFalse(any('palette_lookup' in item for item in structured_milestone.get('evidence', [])))
        self.assertEqual([item.get('name') for item in execution_plan.get('stage_contracts', {}).get('transform', {}).get('required_setup_calls', [])], ['png_set_quantize'])
        self.assertEqual([item.get('name') for item in execution_plan.get('stage_contracts', {}).get('transform', {}).get('support_object_construction', [])], ['palette_lookup'])
        self.assertEqual(execution_plan.get('stage_contracts', {}).get('transform', {}).get('execution_site_kind'), 'callback-or-post-parse-transition')
        self.assertEqual(execution_plan.get('stage_contracts', {}).get('transform', {}).get('must_consume_support_objects'), ['palette_lookup'])
        self.assertIn('structured-input-accepted', execution_plan.get('stage_contracts', {}).get('transform', {}).get('required_after_milestones', []))
        self.assertEqual(execution_plan.get('stage_contracts', {}).get('parse', {}).get('support_object_construction', []), [])
        self.assertTrue(any(item.get('phase') == 'configure-transform' for item in execution_plan.get('call_sequence', [])))

        trigger_plan = build_trigger_plan({'affected-function': 'png_do_quantize'}, 'png_process_data', execution_plan, normalized)
        construction_plan = build_construction_plan({'affected-function': 'png_do_quantize'}, 'png_process_data', execution_plan, trigger_plan, normalized)
        self.assertEqual(construction_plan.get('support_objects', []), [])
        self.assertEqual(construction_plan.get('helper_preconditions', []), [])
        self.assertEqual(construction_plan.get('sink_activation_conditions', []), [])

    def test_stage_retrieval_adds_post_parse_transform_placement_hints(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source_path = root / 'pngrtran.c'
            source_path.write_text('''
void png_do_quantize(png_row_infop row_info, png_bytep row, png_const_bytep palette_lookup, png_const_bytep quantize_lookup) {
    if (palette_lookup != NULL) {
        row_info->color_type = PNG_COLOR_TYPE_RGB;
    }
}

void InfoCallback(png_structp png_ptr, png_infop info_ptr) {
    png_color palette[256];
    png_uint_16 histogram[256];
    png_set_quantize(png_ptr, palette, 256, 256, histogram, 1);
    png_read_update_info(png_ptr, info_ptr);
}
''', encoding='utf-8')

            vuln_context = {
                'project_root': str(root),
                'source_file': str(source_path),
                'function_name': 'png_do_quantize',
                'input_model': {
                    'primary': 'semantic-arguments',
                    'secondary': ['stateful-object', 'direct-api-arguments'],
                    'evidence': ['the sink is driven by support-object contents more than direct raw bytes'],
                },
                'workload_model': {'operators': ['control-biased'], 'evidence': []},
                'parameter_roles': [
                    {'name': 'row_info', 'role': 'state', 'type': 'png_row_infop'},
                    {'name': 'row', 'role': 'value', 'type': 'png_bytep'},
                    {'name': 'palette_lookup', 'role': 'support-buffer', 'type': 'png_const_bytep'},
                    {'name': 'quantize_lookup', 'role': 'value', 'type': 'png_const_bytep'},
                ],
                'required_setup_calls': [],
                'activation_predicates': [],
                'support_object_construction': [
                    {'name': 'palette_lookup', 'kind': 'support-buffer', 'required_fields': []},
                ],
                'support_object_field_constraints': [],
                'state_fields': [
                    {'owner': 'row_info', 'field': 'color_type', 'reads': 5, 'kind': 'control-state'},
                    {'owner': 'row_info', 'field': 'bit_depth', 'reads': 3, 'kind': 'state'},
                ],
                'setup_requirements': [],
                'invariant_requirements': [],
                'exploration_policy': [],
                'sensitive_controls': [{'target': 'palette_lookup', 'source_kind': 'parameter', 'score': 3, 'reasons': ['comparison']}],
                'setup_state_profiles': [],
                'trigger_relations': [
                    {'kind': 'boundary-value', 'controller': 'palette_lookup', 'dependent': 'NULL', 'harness_expectation': 'Bias palette_lookup toward edge values around NULL because the sink compares them directly.', 'priority': 'medium'},
                ],
                'trigger_controls': ['palette_lookup'],
                'workload_constraints': [],
                'execution_hints': [],
                'insights': [],
                'sink_live_predicates': [],
                'sink_activation_conditions': [],
                'milestone_hints': [],
                'required_support_objects': [{'name': 'palette_lookup', 'kind': 'table', 'reason': 'explicit support buffer'}],
                'helper_calls': [],
                'sink_role': {'role': 'invoke', 'evidence': []},
                'failure_path_indicators': {'error_calls': []},
                'cleanup_preconditions': [],
                'ownership_transitions': [],
                'trigger_hints': [],
                'active_data_plan': {
                    'mutable_regions': [
                        {'name': 'palette-or-lookup-table', 'kind': 'table', 'priority': 'high', 'reason': 'quantization requires a valid palette or lookup table'},
                    ],
                    'stabilized_regions': [],
                    'derived_regions': [],
                    'consistency_constraints': [],
                    'entropy_guidance': [],
                },
            }
            public_signatures = {
                'png_process_data': [
                    ('png_structrp', 'png_ptr'),
                    ('png_inforp', 'info_ptr'),
                    ('png_bytep', 'buffer'),
                    ('png_size_t', 'buffer_size'),
                ],
            }

            normalized = normalize_vuln_context(vuln_context, 'png_process_data', public_signatures)
            execution_plan = build_execution_plan(
                {'affected-function': 'png_do_quantize'},
                'png_process_data',
                ['png_process_data', 'png_process_some_data', 'png_push_read_IDAT', 'png_process_IDAT_data', 'png_push_process_row', 'png_do_read_transformations', 'png_do_quantize'],
                {
                    'png_process_data': 'png_process_data',
                    'png_process_some_data': 'png_process_some_data',
                    'png_push_read_IDAT': 'png_push_read_IDAT',
                    'png_process_IDAT_data': 'png_process_IDAT_data',
                    'png_push_process_row': 'png_push_process_row',
                    'png_do_read_transformations': 'png_do_read_transformations',
                    'png_do_quantize': 'png_do_quantize',
                },
                normalized,
                public_signatures,
                {'png_process_data'},
            )

            retrieved = execution_plan.get('retrieved_stage_evidence', {})
            self.assertTrue(retrieved.get('evidence'))
            self.assertTrue(any(item.get('function') == 'InfoCallback' for item in retrieved.get('evidence', [])))
            self.assertTrue(any('InfoCallback' in item for item in retrieved.get('placement_hints', [])))
            self.assertEqual(execution_plan.get('stage_contracts', {}).get('transform', {}).get('execution_site_kind'), 'callback')
            self.assertIn('InfoCallback', execution_plan.get('stage_contracts', {}).get('transform', {}).get('execution_site_candidates', []))
            transform_step = [item for item in execution_plan.get('call_sequence', []) if item.get('phase') == 'configure-transform'][0]
            self.assertIn('InfoCallback', transform_step.get('candidates', []))
            self.assertEqual(transform_step.get('execution_site_kind'), 'callback')

    def test_extract_function_source_ignores_offset_drift_from_comments_and_literals(self):
        handle = tempfile.NamedTemporaryFile('w', delete=False, suffix='.c')
        try:
            handle.write(OFFSET_DRIFT_SOURCE)
            handle.close()
            snippet = extract_function_source(handle.name and __import__('pathlib').Path(handle.name), 'deflate')
            self.assertIn('int deflate(z_streamp strm, int flush)', snippet)
            self.assertNotIn('deflateEnd(strm);', snippet)
        finally:
            os.unlink(handle.name)

    def test_stage_retrieval_does_not_misclassify_plain_info_functions_as_callbacks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source_path = root / 'pngread.c'
            source_path.write_text('''
void png_read_info(png_structp png_ptr, png_infop info_ptr) {
    png_get_IHDR(png_ptr, info_ptr, 0, 0, 0, 0, 0, 0, 0);
    png_read_update_info(png_ptr, info_ptr);
}

void transform_info_imp(png_structp png_ptr, png_infop info_ptr) {
    png_read_update_info(png_ptr, info_ptr);
}
''', encoding='utf-8')

            vuln_context = {
                'project_root': str(root),
                'source_file': str(source_path),
                'function_name': 'png_do_quantize',
                'input_model': {'primary': 'semantic-arguments', 'secondary': ['stateful-object'], 'evidence': []},
                'workload_model': {'operators': ['control-biased'], 'evidence': []},
                'parameter_roles': [],
                'required_setup_calls': [],
                'activation_predicates': [],
                'support_object_construction': [{'name': 'palette_lookup', 'kind': 'support-buffer', 'required_fields': []}],
                'support_object_field_constraints': [],
                'state_fields': [{'owner': 'row_info', 'field': 'color_type', 'reads': 5, 'kind': 'control-state'}],
                'setup_requirements': [],
                'invariant_requirements': [],
                'exploration_policy': [],
                'sensitive_controls': [],
                'setup_state_profiles': [],
                'trigger_relations': [],
                'trigger_controls': [],
                'workload_constraints': [],
                'execution_hints': [],
                'insights': [],
                'sink_live_predicates': [],
                'sink_activation_conditions': [],
                'milestone_hints': [],
                'required_support_objects': [{'name': 'palette_lookup', 'kind': 'table', 'reason': 'explicit support buffer'}],
                'helper_calls': [],
                'sink_role': {'role': 'invoke', 'evidence': []},
                'failure_path_indicators': {'error_calls': []},
                'cleanup_preconditions': [],
                'ownership_transitions': [],
                'trigger_hints': [],
                'active_data_plan': {'mutable_regions': [{'name': 'palette-or-lookup-table', 'kind': 'table', 'priority': 'high', 'reason': 'quantization requires a valid palette'}], 'stabilized_regions': [], 'derived_regions': [], 'consistency_constraints': [], 'entropy_guidance': []},
            }
            public_signatures = {
                'png_process_data': [
                    ('png_structrp', 'png_ptr'),
                    ('png_inforp', 'info_ptr'),
                    ('png_bytep', 'buffer'),
                    ('png_size_t', 'buffer_size'),
                ],
            }

            normalized = normalize_vuln_context(vuln_context, 'png_process_data', public_signatures)
            execution_plan = build_execution_plan(
                {'affected-function': 'png_do_quantize'},
                'png_process_data',
                ['png_process_data', 'png_process_some_data', 'png_push_read_IDAT', 'png_process_IDAT_data', 'png_push_process_row', 'png_do_read_transformations', 'png_do_quantize'],
                {
                    'png_process_data': 'png_process_data',
                    'png_process_some_data': 'png_process_some_data',
                    'png_push_read_IDAT': 'png_push_read_IDAT',
                    'png_process_IDAT_data': 'png_process_IDAT_data',
                    'png_push_process_row': 'png_push_process_row',
                    'png_do_read_transformations': 'png_do_read_transformations',
                    'png_do_quantize': 'png_do_quantize',
                },
                normalized,
                public_signatures,
                {'png_process_data'},
            )

            retrieved = execution_plan.get('retrieved_stage_evidence', {})
            self.assertTrue(retrieved.get('evidence'))
            self.assertTrue(all(item.get('placement') != 'post-parse-callback' for item in retrieved.get('evidence', [])))
            self.assertEqual(execution_plan.get('stage_contracts', {}).get('transform', {}).get('execution_site_kind'), 'post-parse-transition')

    def test_support_buffer_null_guard_does_not_become_trigger_relation(self):
        """When a support-buffer parameter has a != NULL guard in the sink,
        the planner must NOT create a boundary-value trigger relation biasing
        the buffer pointer toward NULL — the interesting fuzzing is the buffer
        contents, not whether the pointer is null."""
        from vuln_analyzer import infer_trigger_relations

        parameter_roles = [
            {'name': 'row_info', 'role': 'state', 'type': 'png_row_infop'},
            {'name': 'row', 'role': 'value', 'type': 'png_bytep'},
            {'name': 'palette_lookup', 'role': 'support-buffer', 'type': 'png_const_bytep'},
            {'name': 'quantize_lookup', 'role': 'value', 'type': 'png_const_bytep'},
        ]
        parameter_conditions = [
            {'parameter': 'palette_lookup', 'type': 'comparison', 'value': 'NULL', 'operator': '!='},
        ]
        field_conditions = [
            {'target': 'row_info->color_type', 'operator': '==', 'value': 'PNG_COLOR_TYPE_RGB', 'type': 'comparison'},
        ]
        state_fields = [
            {'owner': 'row_info', 'field': 'color_type', 'kind': 'control-state', 'reads': 5},
            {'owner': 'row_info', 'field': 'bit_depth', 'kind': 'state', 'reads': 3},
        ]
        source = 'if (palette_lookup != NULL) { sp = row; }'

        relations = infer_trigger_relations('png_do_quantize', parameter_roles, parameter_conditions, field_conditions, state_fields, source)

        palette_rels = [r for r in relations if r.get('controller') == 'palette_lookup']
        self.assertEqual(palette_rels, [], 'Support-buffer NULL guard should not become a boundary-value trigger relation')

    def test_sink_internal_support_buffer_demoted_behind_wrapper_path(self):
        """When the sink is behind a structured wrapper path (parser_like +
        incremental), a support-buffer parameter inferred from the sink
        signature should be classified to the 'sink' stage (informational),
        not 'transform' (obligation the harness must satisfy)."""
        from harness_plan import _classify_stage_item

        item = {
            'name': 'palette_lookup',
            'kind': 'support-buffer',
            'reason': 'the public api signature exposes this support buffer explicitly',
            'expectation': '',
            'required_fields': [],
        }
        # Wrapper path: parser_like + incremental + work_unit — typical
        # progressive parser pattern.
        wrapper_traits = {
            'parser_like': True,
            'incremental_like': True,
            'work_unit_like': True,
            'transform_like': True,
        }
        stage = _classify_stage_item(item, 'support_object_construction', wrapper_traits)
        self.assertEqual(stage, 'sink',
                         'Sink-internal support-buffer should stay on sink stage behind wrapper path')

        # Without wrapper path the item should NOT be demoted.
        flat_traits = {'parser_like': False, 'incremental_like': False, 'work_unit_like': False}
        flat_stage = _classify_stage_item(item, 'support_object_construction', flat_traits)
        self.assertEqual(flat_stage, 'parse',
                         'Without wrapper path, support-buffer stays on parse stage')

    def test_low_priority_path_catches_filename_test_token(self):
        """_is_low_priority_path should flag files whose stem contains 'test'
        even when the file is NOT under a test/ directory."""
        from stage_retrieval import _is_low_priority_path

        self.assertTrue(_is_low_priority_path('/src/libpng/pngtest.c'),
                        'pngtest.c should be flagged as low-priority')
        self.assertTrue(_is_low_priority_path('/src/mylib/fuzz_target.c'),
                        'fuzz_target.c should be flagged')
        self.assertFalse(_is_low_priority_path('/src/libpng/pngrtran.c'),
                         'Normal source file should not be flagged')
        self.assertFalse(_is_low_priority_path('/src/libpng/pngrutil.c'),
                         'Normal source file should not be flagged')
        # test/ directory should still be caught
        self.assertTrue(_is_low_priority_path('/src/test/runner.c'),
                        'File under test/ should be flagged')

    def test_registration_site_separated_from_execution_site(self):
        """retrieve_stage_evidence should prefer actual callback bodies over
        registration functions (functions that store fn pointers into structs)
        in placement_candidates."""
        from stage_retrieval import _is_registration_site

        # A registration function stores pointers into struct fields.
        reg_body = """
void png_set_progressive_read_fn(png_structrp png_ptr,
    png_voidp progressive_ptr, png_progressive_info_ptr info_fn,
    png_progressive_row_ptr row_fn, png_progressive_end_ptr end_fn) {
    png_ptr->info_fn = info_fn;
    png_ptr->row_fn = row_fn;
    png_ptr->end_fn = end_fn;
    png_ptr->progressive_ptr = progressive_ptr;
}"""
        self.assertTrue(_is_registration_site(reg_body, 'png_set_progressive_read_fn'),
                        'Registration function should be identified')

        # A callback body does actual transform work.
        callback_body = """
void info_callback(png_structp png_ptr, png_infop info_ptr) {
    png_color palette[256];
    png_set_quantize(png_ptr, palette, 256, 256, NULL, 1);
    png_read_update_info(png_ptr, info_ptr);
}"""
        self.assertFalse(_is_registration_site(callback_body, 'info_callback'),
                         'Callback body should NOT be classified as registration site')

    def test_simple_one_shot_parser_does_not_get_chunked_stream_or_setup_bloat(self):
        """A simple JSON parser like cJSON with a short direct call path
        (cJSON_ParseWithLengthOpts -> parse_value -> parse_string) should NOT
        get chunked-stream workload, incremental-feed milestones, or bogus
        'allocate'/'deallocate' setup requirements.  The correct harness is
        just: cJSON_ParseWithLength(data, size) + cleanup."""
        # Simulate the source of a simple parser sink (parse_string-like)
        source = '''
static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer) {
    const unsigned char *input_pointer = buffer_at_offset(input_buffer);
    unsigned char *output_pointer = NULL;
    unsigned char *output = NULL;

    if (buffer_at_offset(input_buffer)[0] != '\"') { goto fail; }

    {
        size_t allocation_length = 0;
        size_t skipped_bytes = 0;
        while (((size_t)(input_end - (const unsigned char*)input_buffer->content) < input_buffer->length)) {
            if (input_pointer[0] == '\"') { goto success; }
            if (input_pointer[0] == '\\\\') {
                skipped_bytes++;
                input_pointer++;
            }
            input_pointer++;
        }
        allocation_length = (size_t)(input_end - (const unsigned char*)input_buffer->content) - skipped_bytes;
        output = (unsigned char*)input_buffer->hooks.allocate(allocation_length + sizeof(""));
        if (output == NULL) { goto fail; }
    }

success:
    item->valuestring = (char*)output;
    item->type = cJSON_String;
    input_buffer->offset = (size_t)(input_end - input_buffer->content);
    return true;

fail:
    if (output != NULL) { input_buffer->hooks.deallocate(output); }
    return false;
}
'''
        # 1. Helper calls: allocate/deallocate should be SKIPPED
        helpers = extract_helper_calls(source, 'parse_string')
        helper_names = [h.get('name') for h in helpers]
        self.assertNotIn('allocate', helper_names,
                         'Internal allocator hook should be in HELPER_SKIP_NAMES')
        self.assertNotIn('deallocate', helper_names,
                         'Internal deallocator hook should be in HELPER_SKIP_NAMES')

        # 2. Workload model: should NOT have chunked-stream
        parameter_roles = [
            {'name': 'item', 'role': 'state', 'type': 'cJSON *'},
            {'name': 'input_buffer', 'role': 'state', 'type': 'parse_buffer *'},
        ]
        state_fields = [
            {'owner': 'input_buffer', 'field': 'content', 'reads': 5, 'kind': 'state'},
            {'owner': 'input_buffer', 'field': 'length', 'reads': 3, 'kind': 'size-state'},
            {'owner': 'input_buffer', 'field': 'offset', 'reads': 3, 'kind': 'state'},
            {'owner': 'input_buffer', 'field': 'hooks', 'reads': 2, 'kind': 'state'},
            {'owner': 'item', 'field': 'type', 'reads': 1, 'kind': 'control-state'},
        ]
        field_conditions = []
        loop_features = extract_loop_features(source, parameter_roles)
        workload = infer_workload_model(parameter_roles, helpers, state_fields, field_conditions, loop_features)
        self.assertNotIn('chunked-stream', workload.get('operators', []),
                         'One-shot parser should not get chunked-stream workload')

        # 3. Milestones: should NOT have incremental-feed
        from vuln_analyzer import infer_milestone_hints
        input_model = build_input_model(parameter_roles, helpers, field_conditions, state_fields, [])
        milestones = infer_milestone_hints(
            'parse_string', parameter_roles, helpers, state_fields, field_conditions,
            input_model, workload, {'role': 'consume', 'evidence': []}, [])
        milestone_kinds = [m.get('kind') for m in milestones]
        self.assertNotIn('incremental-feed', milestone_kinds,
                         'One-shot parser should not get incremental-feed milestone')

    def test_phase_classification_cleanup_before_setup(self):
        """Helper calls whose names contain both cleanup and alloc tokens
        (e.g. 'deallocate') should be classified as cleanup, not setup."""
        helpers = extract_helper_calls(
            'void foo() { bar_deallocate(ptr); baz_free_context(ctx); qux_allocate_buffer(n); }',
            'foo')
        by_name = {h['name']: h['phase'] for h in helpers}
        self.assertEqual(by_name.get('bar_deallocate'), 'cleanup',
                         'deallocate should be cleanup, not setup')
        self.assertEqual(by_name.get('baz_free_context'), 'cleanup',
                         'free_context should be cleanup')
        self.assertEqual(by_name.get('qux_allocate_buffer'), 'setup',
                         'allocate_buffer should still be setup (no cleanup token)')


if __name__ == '__main__':
    unittest.main()