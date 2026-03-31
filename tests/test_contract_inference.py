#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

from contract_inference import infer_semantic_contract
from prompt_harness import build_harness_prompt
from harness_validator import validate_harness_source


class ContractInferenceTests(unittest.TestCase):

    def test_infers_setup_calls_and_support_object_fields(self):
        contract = infer_semantic_contract(
            'inflate',
            parameter_roles=[
                {'name': 'strm', 'role': 'state', 'type': 'z_streamp'},
                {'name': 'head', 'role': 'support-buffer', 'type': 'gz_headerp'},
            ],
            helper_calls=[
                {'name': 'INITBITS', 'phase': 'setup'},
                {'name': 'inflate', 'phase': 'update'},
            ],
            state_fields=[
                {'owner': 'state', 'field': 'head', 'kind': 'control-state'},
                {'owner': 'head', 'field': 'extra', 'kind': 'buffer-state'},
                {'owner': 'head', 'field': 'extra_max', 'kind': 'size-state'},
            ],
            field_conditions=[
                {'target': 'state->head', 'operator': '!=', 'value': 'Z_NULL', 'type': 'comparison'},
                {'target': 'head->extra', 'operator': '!=', 'value': 'Z_NULL', 'type': 'comparison'},
            ],
            related_init_functions=[
                {'name': 'inflateInit2_', 'params': 'z_streamp strm, int windowBits, const char *version, int stream_size', 'relation': 'init'},
                {'name': 'inflateGetHeader', 'params': 'z_streamp strm, gz_headerp head', 'relation': 'register'},
            ],
        )

        setup_names = [item.get('name') for item in contract.get('required_setup_calls', [])]
        support_items = {item.get('name'): item for item in contract.get('support_object_construction', [])}

        self.assertIn('inflateGetHeader', setup_names)
        self.assertIn('inflateInit2_', setup_names)
        self.assertNotIn('INITBITS', setup_names)
        self.assertNotIn('inflate', setup_names)
        self.assertIn('head', support_items)
        self.assertNotIn('state', support_items)
        self.assertNotIn('strm', support_items)
        self.assertIn('extra', support_items['head'].get('required_fields', []))
        self.assertIn('extra_max', support_items['head'].get('required_fields', []))
        self.assertTrue(any('encoded length or size of head.extra around head.extra_max' in item for item in contract.get('invariant_requirements', [])))
        self.assertTrue(contract.get('activation_predicates'))

    def test_validator_rejects_missing_required_setup_call(self):
        plan = {
            'public_api_name': 'inflate',
            'vuln_entry': {'affected-function': 'inflate'},
            'execution_plan': {
                'entry_function': 'inflate',
                'parameter_roles': [
                    {'name': 'strm', 'role': 'state', 'type': 'z_streamp'},
                ],
                'state_fields': [{'owner': 'state', 'field': 'head', 'kind': 'control-state'}],
                'required_setup_calls': [
                    {'name': 'inflateGetHeader', 'phase': 'setup', 'reason': 'required to register gzip header state'},
                ],
                'setup_candidates': ['inflateInit2_'],
                'update_candidates': [],
                'workload_model': {'operators': []},
                'milestone_plan': [],
                'input_model': {'primary': 'structured-format', 'secondary': ['magic-or-container-header']},
                'sensitive_controls': [],
                'setup_state_profiles': [],
                'exploration_policy': [],
                'trigger_relations': [],
                'trigger_controls': [],
                'setup_requirements': [],
                'invariant_requirements': [],
                'active_data_plan': {'mutable_regions': [], 'stabilized_regions': [], 'derived_regions': [], 'consistency_constraints': [], 'entropy_guidance': []},
            },
            'vuln_context': {
                'failure_path_indicators': {'error_calls': []},
            },
            'construction_plan': {
                'support_object_construction': [],
            },
        }

        harness = """
extern \"C\" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  z_stream strm = {};
  inflateInit2_(&strm, 47, ZLIB_VERSION, sizeof(strm));
  return inflate(&strm, Z_NO_FLUSH);
}
"""

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            plan_path = tmp_path / 'plan.json'
            harness_path = tmp_path / 'fuzzer.cc'
            plan_path.write_text(json.dumps(plan), encoding='utf-8')
            harness_path.write_text(harness, encoding='utf-8')

            report = validate_harness_source(plan_path, harness_path)

        self.assertFalse(report['ok'])
        self.assertTrue(any('missing required setup or registration calls' in item for item in report['violations']))

    def test_infers_header_registration_without_helper_evidence(self):
        contract = infer_semantic_contract(
            'inflate',
            parameter_roles=[
                {'name': 'strm', 'role': 'state', 'type': 'z_streamp'},
            ],
            helper_calls=[],
            state_fields=[
                {'owner': 'head', 'field': 'extra', 'kind': 'buffer-state'},
                {'owner': 'head', 'field': 'name', 'kind': 'buffer-state'},
            ],
            field_conditions=[
                {'target': 'state->head', 'operator': '!=', 'value': 'Z_NULL', 'type': 'comparison'},
                {'target': 'head->extra', 'operator': '!=', 'value': 'Z_NULL', 'type': 'comparison'},
                {'target': 'head->name', 'operator': '!=', 'value': 'Z_NULL', 'type': 'comparison'},
            ],
            related_init_functions=[
                {'name': 'inflateInit2_', 'params': 'z_streamp strm, int windowBits, const char *version, int stream_size', 'relation': 'init'},
                {'name': 'inflateGetHeader', 'params': 'z_streamp strm, gz_headerp head', 'relation': 'register'},
            ],
        )

        setup_names = [item.get('name') for item in contract.get('required_setup_calls', [])]

        self.assertIn('inflateGetHeader', setup_names)
        self.assertIn('inflateInit2_', setup_names)

    def test_infers_size_siblings_for_header_fields(self):
        contract = infer_semantic_contract(
            'inflate',
            parameter_roles=[{'name': 'strm', 'role': 'state', 'type': 'z_streamp'}],
            helper_calls=[],
            state_fields=[
                {'owner': 'head', 'field': 'extra_max', 'kind': 'size-state'},
                {'owner': 'head', 'field': 'comm_max', 'kind': 'size-state'},
            ],
            field_conditions=[
                {'target': 'state->head', 'operator': '!=', 'value': 'Z_NULL', 'type': 'comparison'},
                {'target': 'head->extra', 'operator': '!=', 'value': 'Z_NULL', 'type': 'comparison'},
                {'target': 'head->comment', 'operator': '!=', 'value': 'Z_NULL', 'type': 'comparison'},
            ],
            related_init_functions=[{'name': 'inflateInit2_', 'params': 'z_streamp strm, int windowBits, const char *version, int stream_size', 'relation': 'init'}],
        )

        support_items = {item.get('name'): item for item in contract.get('support_object_construction', [])}
        head_fields = set(support_items['head'].get('required_fields', []))
        constraints = '\n'.join([item.get('constraint', '') for item in contract.get('support_object_field_constraints', [])])

        self.assertIn('extra_max', head_fields)
        self.assertIn('comm_max', head_fields)
        self.assertIn('encoded length or size of head.extra around head.extra_max', constraints)

    def test_validator_rejects_early_transform_call_and_empty_callback_body(self):
        plan = {
            'public_api_name': 'png_process_data',
            'vuln_entry': {'affected-function': 'png_do_quantize'},
            'execution_plan': {
                'entry_function': 'png_process_data',
                'parameter_roles': [
                    {'name': 'png_ptr', 'role': 'state', 'type': 'png_structrp'},
                    {'name': 'info_ptr', 'role': 'state', 'type': 'png_inforp'},
                    {'name': 'buffer', 'role': 'input-buffer', 'type': 'png_bytep'},
                    {'name': 'buffer_size', 'role': 'size', 'type': 'png_size_t'},
                ],
                'state_fields': [],
                'required_setup_calls': [],
                'setup_candidates': ['png_set_progressive_read_fn'],
                'update_candidates': [],
                'workload_model': {'operators': ['structured-container']},
                'milestone_plan': [
                    {'name': 'structured-input-accepted', 'kind': 'container-parse', 'required': True},
                    {'name': 'transform-stage-live', 'kind': 'transform-gating', 'required': True},
                ],
                'input_model': {'primary': 'structured-format', 'secondary': ['stateful-object']},
                'sensitive_controls': [],
                'setup_state_profiles': [],
                'exploration_policy': [],
                'trigger_relations': [],
                'trigger_controls': [],
                'setup_requirements': [],
                'invariant_requirements': [],
                'active_data_plan': {'mutable_regions': [], 'stabilized_regions': [], 'derived_regions': [], 'consistency_constraints': [], 'entropy_guidance': []},
                'stage_contracts': {
                    'entry': {},
                    'parse': {},
                    'transform': {
                        'required_setup_calls': [
                            {'name': 'png_set_quantize', 'phase': 'setup', 'reason': 'quantize configuration must execute after the parser reaches the info callback'}
                        ],
                        'support_object_construction': [
                            {'name': 'palette_lookup', 'kind': 'support-buffer', 'reason': 'palette buffer is consumed by deferred transform configuration'}
                        ],
                        'support_object_field_constraints': [],
                        'setup_requirements': [],
                        'sink_activation_conditions': [],
                        'milestone_hints': [
                            {'name': 'info-callback-entered', 'kind': 'callback', 'harness_expectation': 'run quantize setup in the info callback'}
                        ],
                    },
                    'sink': {},
                },
                'deferred_stages': ['transform', 'sink'],
                'retrieved_stage_evidence': {
                    'placement_candidates': ['InfoCallback'],
                    'placement_hints': ['InfoCallback executes png_set_quantize after parse milestones'],
                    'evidence': [{'function': 'InfoCallback', 'api': 'png_set_quantize', 'placement': 'callback'}],
                },
            },
            'vuln_context': {
                'failure_path_indicators': {'error_calls': []},
            },
            'construction_plan': {
                'support_object_construction': [],
            },
        }

        harness = """
void InfoCallback(png_structp png_ptr, png_infop info_ptr) {
}

extern \"C\" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  png_infop info_ptr = png_create_info_struct(png_ptr);
  png_color palette[256];
  png_uint_16 histogram[256];
  png_set_progressive_read_fn(png_ptr, info_ptr, InfoCallback, nullptr, nullptr);
  png_set_quantize(png_ptr, palette, 256, 256, histogram, 1);
  png_process_data(png_ptr, info_ptr, (png_bytep)data, size);
  return 0;
}
"""

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            plan_path = tmp_path / 'plan.json'
            harness_path = tmp_path / 'fuzzer.cc'
            plan_path.write_text(json.dumps(plan), encoding='utf-8')
            harness_path.write_text(harness, encoding='utf-8')

            report = validate_harness_source(plan_path, harness_path)

        self.assertFalse(report['ok'])
        self.assertTrue(any('callbacks are registered but do not execute the required transform work' in item for item in report['violations']))
        self.assertTrue(any('appear before the first public entry invocation' in item for item in report['violations']))

    def test_prompt_requires_explicit_deferred_stage_realization(self):
        plan = {
            'sink_usr': 'sink',
            'public_api_name': 'png_process_data',
            'wrapper_path': ['wrapper'],
            'usr_to_file': {'wrapper': 'pngread.c:10'},
            'usr_to_name': {'wrapper': 'png_process_data'},
            'vuln_entry': {
                'affected-file': 'pngrtran.c',
                'affected-function': 'png_do_quantize',
                'cwe-id': 'CWE-125',
            },
            'vuln_context': {
                'input_model': {'primary': 'structured-format', 'secondary': ['stateful-object'], 'evidence': []},
                'workload_model': {'operators': ['structured-container'], 'evidence': []},
                'parameter_roles': [],
                'sensitive_controls': [],
                'setup_state_profiles': [],
                'trigger_relations': [],
                'trigger_controls': [],
                'required_setup_calls': [],
                'activation_predicates': [],
                'support_object_construction': [],
                'support_object_field_constraints': [],
                'setup_requirements': [],
                'invariant_requirements': [],
                'exploration_policy': [],
                'sink_live_predicates': [],
                'active_data_plan': {'mutable_regions': [], 'stabilized_regions': [], 'derived_regions': [], 'consistency_constraints': [], 'entropy_guidance': []},
                'failure_path_indicators': {'error_calls': []},
            },
            'execution_plan': {
                'entry_function': 'png_process_data',
                'call_sequence': [{'phase': 'configure-transform', 'goal': 'later-stage transform', 'candidates': ['InfoCallback']}],
                'input_model': {'primary': 'structured-format', 'secondary': ['stateful-object']},
                'workload_model': {'operators': ['structured-container'], 'evidence': []},
                'parameter_roles': [],
                'sensitive_controls': [],
                'setup_state_profiles': [],
                'trigger_relations': [],
                'trigger_controls': [],
                'required_setup_calls': [],
                'activation_predicates': [],
                'support_object_construction': [],
                'support_object_field_constraints': [],
                'setup_requirements': [],
                'invariant_requirements': [],
                'exploration_policy': [],
                'input_segments': [],
                'milestone_plan': [{'name': 'info-callback-entered', 'kind': 'callback', 'required': True}],
                'sink_live_predicates': [],
                'active_data_plan': {'mutable_regions': [], 'stabilized_regions': [], 'derived_regions': [], 'consistency_constraints': [], 'entropy_guidance': []},
                'constraints': [],
                'coverage_goals': [],
                'stage_contracts': {
                    'entry': {'required_setup_calls': [], 'activation_predicates': [], 'support_object_construction': [], 'support_object_field_constraints': [], 'setup_requirements': [], 'sink_activation_conditions': [], 'milestone_hints': []},
                    'parse': {'required_setup_calls': [], 'activation_predicates': [], 'support_object_construction': [], 'support_object_field_constraints': [], 'setup_requirements': [], 'sink_activation_conditions': [], 'milestone_hints': []},
                    'transform': {
                        'required_setup_calls': [{'name': 'png_set_quantize', 'reason': 'must run after info is available'}],
                        'activation_predicates': [],
                        'support_object_construction': [{'name': 'palette_lookup', 'kind': 'support-buffer', 'expectation': 'construct it at the deferred transform site'}],
                        'support_object_field_constraints': [],
                        'setup_requirements': [],
                        'sink_activation_conditions': [],
                        'milestone_hints': [{'name': 'info-callback-entered', 'kind': 'callback', 'harness_expectation': 'run transform setup there'}],
                    },
                    'sink': {'required_setup_calls': [], 'activation_predicates': [], 'support_object_construction': [], 'support_object_field_constraints': [], 'setup_requirements': [], 'sink_activation_conditions': [], 'milestone_hints': []},
                },
                'deferred_stages': ['transform', 'sink'],
                'retrieved_stage_evidence': {
                    'placement_candidates': ['InfoCallback'],
                    'placement_hints': ['InfoCallback executes png_set_quantize after the parser reaches info-ready state'],
                    'evidence': [{'function': 'InfoCallback', 'api': 'png_set_quantize', 'placement': 'callback'}],
                },
            },
            'trigger_plan': {'sink_role': 'invoke'},
            'construction_plan': {
                'support_objects': [],
                'required_setup_calls': [],
                'support_object_construction': [],
                'support_object_field_constraints': [],
                'helper_preconditions': [],
                'sink_activation_conditions': [],
                'milestone_requirements': [],
                'active_data_plan': {'mutable_regions': [], 'stabilized_regions': [], 'derived_regions': [], 'consistency_constraints': [], 'entropy_guidance': []},
                'valid_prefix_requirements': [],
                'late_malformed_regions': [],
                'forbidden_shortcuts': [],
            },
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            root = tmp_path / 'root'
            out = tmp_path / 'out'
            plan_path = tmp_path / 'plan.json'
            (root / 'pngread.c').parent.mkdir(parents=True, exist_ok=True)
            (root / 'pngread.c').write_text('void png_process_data(void) {}', encoding='utf-8')
            (root / 'pngrtran.c').write_text('void png_do_quantize(void) {}', encoding='utf-8')
            plan_path.write_text(json.dumps(plan), encoding='utf-8')

            prompt_path = build_harness_prompt(root, plan_path, out)
            prompt_text = prompt_path.read_text(encoding='utf-8')

        self.assertIn('Deferred Stage Realization', prompt_text)
        self.assertIn('choose one concrete callback or post-parse site', prompt_text)
        self.assertIn('Do not register a callback or transition hook for deferred transform work and then leave its body empty', prompt_text)

    def test_validator_warns_on_dead_staged_support_state(self):
        plan = {
            'public_api_name': 'png_process_data',
            'vuln_entry': {'affected-function': 'png_do_quantize'},
            'execution_plan': {
                'entry_function': 'png_process_data',
                'parameter_roles': [
                    {'name': 'png_ptr', 'role': 'state', 'type': 'png_structrp'},
                    {'name': 'info_ptr', 'role': 'state', 'type': 'png_inforp'},
                    {'name': 'buffer', 'role': 'input-buffer', 'type': 'png_bytep'},
                    {'name': 'buffer_size', 'role': 'size', 'type': 'png_size_t'},
                ],
                'state_fields': [],
                'required_setup_calls': [],
                'setup_candidates': ['png_set_progressive_read_fn'],
                'update_candidates': [],
                'workload_model': {'operators': ['structured-container', 'chunked-stream']},
                'milestone_plan': [
                    {'name': 'structured-input-accepted', 'kind': 'container-parse', 'required': True},
                    {'name': 'incremental-feed-established', 'kind': 'incremental-feed', 'required': True},
                    {'name': 'transform-stage-live', 'kind': 'transform-gating', 'required': True},
                ],
                'input_model': {'primary': 'structured-format', 'secondary': ['stateful-object']},
                'sensitive_controls': [],
                'setup_state_profiles': [],
                'exploration_policy': [],
                'trigger_relations': [],
                'trigger_controls': [],
                'setup_requirements': [],
                'invariant_requirements': [],
                'active_data_plan': {'mutable_regions': [], 'stabilized_regions': [], 'derived_regions': [], 'consistency_constraints': [], 'entropy_guidance': []},
                'stage_contracts': {
                    'entry': {},
                    'parse': {},
                    'transform': {
                        'required_setup_calls': [{'name': 'png_set_quantize', 'reason': 'configure quantization in the callback'}],
                        'support_object_construction': [{'name': 'palette_lookup', 'kind': 'support-buffer', 'reason': 'palette must be supplied'}],
                        'support_object_field_constraints': [],
                        'setup_requirements': [],
                        'sink_activation_conditions': [],
                        'milestone_hints': [],
                        'execution_site_kind': 'callback',
                        'execution_site_candidates': ['InfoCallback'],
                        'required_after_milestones': ['structured-input-accepted'],
                        'must_consume_support_objects': ['palette_lookup'],
                    },
                    'sink': {},
                },
                'deferred_stages': ['transform', 'sink'],
                'retrieved_stage_evidence': {
                    'placement_candidates': ['InfoCallback'],
                    'placement_hints': ['InfoCallback executes later-stage transform work'],
                    'evidence': [{'function': 'InfoCallback', 'api': 'png_set_quantize', 'placement': 'post-parse-callback'}],
                },
            },
            'vuln_context': {
                'failure_path_indicators': {'error_calls': []},
            },
            'construction_plan': {
                'requires_container_synthesis': True,
                'support_object_construction': [],
            },
        }

        harness = """
typedef unsigned char uint8_t;
typedef unsigned long size_t;
typedef void* png_structp;
typedef void* png_infop;
typedef unsigned char* png_bytep;

struct FuzzCtx {
  unsigned char palette[256];
  unsigned char trans[256];
};

void InfoCallback(png_structp png_ptr, png_infop info_ptr) {
  (void)png_ptr;
  (void)info_ptr;
}

extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzCtx ctx;
  for (size_t i = 0; i < 16 && i < size; ++i) {
    ctx.trans[i] = data[i];
    ctx.palette[i] = data[i];
  }
  png_set_progressive_read_fn(nullptr, &ctx, InfoCallback, nullptr, nullptr);
  while (size > 0) {
    png_process_data(nullptr, nullptr, (png_bytep)data, 1);
    ++data;
    --size;
  }
  return 0;
}
"""

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            plan_path = tmp_path / 'plan.json'
            harness_path = tmp_path / 'fuzzer.cc'
            plan_path.write_text(json.dumps(plan), encoding='utf-8')
            harness_path.write_text(harness, encoding='utf-8')

            report = validate_harness_source(plan_path, harness_path)

        self.assertTrue(any('never consumed by any helper or transform call' in item for item in report['warnings']))

    def test_generic_registration_candidate_is_selected_from_family_helpers(self):
        contract = infer_semantic_contract(
            'decode',
            parameter_roles=[{'name': 'ctx', 'role': 'state', 'type': 'decoder_ctx *'}],
            helper_calls=[],
            state_fields=[
                {'owner': 'header', 'field': 'payload_len', 'kind': 'size-state'},
            ],
            field_conditions=[
                {'target': 'ctx->header', 'operator': '!=', 'value': 'NULL', 'type': 'comparison'},
                {'target': 'header->payload', 'operator': '!=', 'value': 'NULL', 'type': 'comparison'},
            ],
            related_init_functions=[
                {'name': 'decodeInit', 'params': 'decoder_ctx *ctx', 'relation': 'init'},
                {'name': 'decodeRegisterHeader', 'params': 'decoder_ctx *ctx, decoder_header *header', 'relation': 'register'},
                {'name': 'decodeSetMode', 'params': 'decoder_ctx *ctx, int mode', 'relation': 'register'},
            ],
        )

        setup_names = [item.get('name') for item in contract.get('required_setup_calls', [])]

        self.assertIn('decodeInit', setup_names)
        self.assertIn('decodeRegisterHeader', setup_names)
        self.assertNotIn('decodeSetMode', setup_names)

    def test_validator_resolves_library_registration_to_actual_callbacks(self):
        """Placement candidates that are library functions (not defined in the
        harness) should NOT be flagged as empty callbacks.  Instead, the
        validator should trace their function-pointer arguments to find the
        actual harness-defined callbacks and check those."""
        plan = {
            'public_api_name': 'png_process_data',
            'vuln_entry': {'affected-function': 'png_do_quantize'},
            'execution_plan': {
                'entry_function': 'png_process_data',
                'parameter_roles': [
                    {'name': 'png_ptr', 'role': 'state', 'type': 'png_structrp'},
                    {'name': 'info_ptr', 'role': 'state', 'type': 'png_inforp'},
                    {'name': 'buffer', 'role': 'input-buffer', 'type': 'png_bytep'},
                    {'name': 'buffer_size', 'role': 'size', 'type': 'png_size_t'},
                ],
                'state_fields': [],
                'required_setup_calls': [],
                'setup_candidates': ['png_set_progressive_read_fn'],
                'update_candidates': [],
                'workload_model': {'operators': ['structured-container']},
                'milestone_plan': [
                    {'name': 'structured-input-accepted', 'kind': 'container-parse', 'required': True},
                    {'name': 'transform-stage-live', 'kind': 'transform-gating', 'required': True},
                ],
                'input_model': {'primary': 'structured-format', 'secondary': ['stateful-object']},
                'sensitive_controls': [],
                'setup_state_profiles': [],
                'exploration_policy': [],
                'trigger_relations': [],
                'trigger_controls': [],
                'setup_requirements': [],
                'invariant_requirements': [],
                'active_data_plan': {'mutable_regions': [], 'stabilized_regions': [], 'derived_regions': [], 'consistency_constraints': [], 'entropy_guidance': []},
                'stage_contracts': {
                    'entry': {},
                    'parse': {},
                    'transform': {
                        'required_setup_calls': [],
                        'execution_site_candidates': ['png_set_progressive_read_fn', 'png_build_grayscale_palette'],
                        'support_object_construction': [
                            {'name': 'palette_lookup', 'kind': 'support-buffer', 'reason': 'palette buffer consumed'}
                        ],
                        'support_object_field_constraints': [],
                        'setup_requirements': [],
                        'sink_activation_conditions': [],
                        'milestone_hints': [],
                    },
                    'sink': {},
                },
                'deferred_stages': ['transform', 'sink'],
                'retrieved_stage_evidence': {
                    'placement_candidates': ['png_set_progressive_read_fn'],
                    'placement_hints': [],
                    'evidence': [],
                },
            },
            'vuln_context': {
                'failure_path_indicators': {'error_calls': []},
            },
            'construction_plan': {
                'support_object_construction': [],
            },
        }

        harness = """
static void info_callback(png_structp png_ptr, png_infop info_ptr) {
    png_set_quantize(png_ptr, palette, 256, 256, histogram, 1);
    png_read_update_info(png_ptr, info_ptr);
}

static void row_callback(png_structp png_ptr, png_bytep row, png_uint_32 row_num, int pass) {
    (void)row; (void)row_num; (void)pass;
}

static void end_callback(png_structp png_ptr, png_infop info_ptr) {
    (void)info_ptr;
}

extern \"C\" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
    png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, 0, 0, 0);
    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (setjmp(png_jmpbuf(png_ptr))) { png_destroy_read_struct(&png_ptr, &info_ptr, 0); return 0; }
    png_set_progressive_read_fn(png_ptr, &st, info_callback, row_callback, end_callback);
    png_build_grayscale_palette(8, grayscale_pal);
    png_process_data(png_ptr, info_ptr, (png_bytep)data, size);
    png_destroy_read_struct(&png_ptr, &info_ptr, 0);
    return 0;
}
"""

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            plan_path = tmp_path / 'plan.json'
            harness_path = tmp_path / 'fuzzer.cc'
            plan_path.write_text(json.dumps(plan), encoding='utf-8')
            harness_path.write_text(harness, encoding='utf-8')

            report = validate_harness_source(plan_path, harness_path)

        # png_set_progressive_read_fn and png_build_grayscale_palette are
        # library functions; the validator should NOT flag them as empty
        # callbacks.
        self.assertFalse(
            any('callbacks are registered but do not execute' in v for v in report.get('violations', [])),
            'Library registration functions should not be flagged as empty callbacks'
        )

    def test_validator_null_helper_regex_does_not_span_function_bodies(self):
        """Verify that _find_suspicious_null_helper_calls does not
        match a function DEFINITION and then span into its body to
        find an inner nullptr, which was the old DOTALL bug."""
        plan = {
            'public_api_name': 'process_data',
            'vuln_entry': {'affected-function': 'do_quantize'},
            'execution_plan': {
                'entry_function': 'process_data',
                'parameter_roles': [],
                'state_fields': [],
                'required_setup_calls': [],
                'setup_candidates': [],
                'update_candidates': [],
                'workload_model': {'operators': []},
                'milestone_plan': [],
                'input_model': {'primary': 'structured-format', 'secondary': []},
                'sensitive_controls': [],
                'setup_state_profiles': [],
                'exploration_policy': [],
                'trigger_relations': [],
                'trigger_controls': [],
                'setup_requirements': [],
                'invariant_requirements': [],
                'active_data_plan': {'mutable_regions': [], 'stabilized_regions': [], 'derived_regions': [], 'consistency_constraints': [], 'entropy_guidance': []},
                'stage_contracts': {},
                'deferred_stages': [],
                'retrieved_stage_evidence': {},
            },
            'vuln_context': {
                'failure_path_indicators': {'error_calls': []},
            },
            'construction_plan': {
                'support_object_construction': [
                    {'name': 'palette_lookup', 'kind': 'support-buffer'}
                ],
            },
        }

        harness = """
static void configure_quantize_after_parse(struct state *st) {
    if (st == nullptr) return;
    set_quantize(st->ptr, st->palette, 256, 256, st->histogram, 1);
    set_transform_info(st->ptr, st, nullptr, 3);
}

extern \"C\" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
    struct state st;
    configure_quantize_after_parse(&st);
    process_data(st.ptr, data, size);
    return 0;
}
"""

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            plan_path = tmp_path / 'plan.json'
            harness_path = tmp_path / 'fuzzer.cc'
            plan_path.write_text(json.dumps(plan), encoding='utf-8')
            harness_path.write_text(harness, encoding='utf-8')

            report = validate_harness_source(plan_path, harness_path)

        # configure_quantize_after_parse(&st) should NOT be flagged —
        # the call itself has no nullptr args.
        suspicious = [v for v in report.get('violations', []) if 'configure_quantize_after_parse' in v]
        self.assertEqual(suspicious, [], 'Function definition should not be cross-matched into body')

        # set_transform_info(st->ptr, st, nullptr, 3) — 1 null out of 4 args — should also NOT be flagged.
        transform_info_flagged = [v for v in report.get('violations', []) if 'set_transform_info' in v]
        self.assertEqual(transform_info_flagged, [], 'Single nullptr in multi-arg call should not trigger')


    # ------------------------------------------------------------------
    # Regression tests for internal-intermediary suppression (Bug 1)
    # ------------------------------------------------------------------
    def test_internal_intermediary_suppressed_from_support_objects(self):
        """Struct-chain intermediaries like ``input``, ``buf`` that come from
        deep field-access patterns (ctxt->input->buf->buffer) should NOT
        appear as harness-level support objects."""
        contract = infer_semantic_contract(
            'xmlParseChunk',
            parameter_roles=[
                {'name': 'ctxt', 'role': 'state', 'type': 'xmlParserCtxtPtr'},
            ],
            helper_calls=[],
            state_fields=[
                {'owner': 'input', 'field': 'buf', 'kind': 'control-state'},
                {'owner': 'buf', 'field': 'buffer', 'kind': 'buffer-state'},
            ],
            field_conditions=[
                # ctxt->input != NULL (2-part, state->intermediary)
                {'target': 'ctxt->input', 'operator': '!=', 'value': 'NULL', 'type': 'comparison'},
                # input->buf (3-part chain: ctxt->input->buf)
                {'target': 'ctxt->input->buf', 'operator': '!=', 'value': 'NULL', 'type': 'comparison'},
                # buf->buffer (3-part chain: ctxt->input->buf->buffer)
                {'target': 'input->buf->buffer', 'operator': '!=', 'value': 'NULL', 'type': 'comparison'},
            ],
            related_init_functions=[
                {'name': 'xmlCreatePushParserCtxt', 'params': 'xmlSAXHandlerPtr sax, void *user_data, const char *chunk, int size, const char *filename', 'relation': 'init'},
            ],
        )

        support_names = {item.get('name') for item in contract.get('support_object_construction', [])}
        # None of these internal intermediaries should be promoted.
        self.assertNotIn('input', support_names,
                         "'input' is an internal intermediary, should not be a support object")
        self.assertNotIn('buf', support_names,
                         "'buf' is an internal intermediary, should not be a support object")
        self.assertNotIn('in', support_names,
                         "'in' is an internal intermediary, should not be a support object")

    # ------------------------------------------------------------------
    # Regression tests for callback-field constraint rejection (Bug 2)
    # ------------------------------------------------------------------
    def test_callback_fields_not_given_buffer_constraints(self):
        """SAX callback fields like ``endDocument`` or ``startElement`` must NOT
        receive the 'vary the encoded length' buffer-length constraints."""
        contract = infer_semantic_contract(
            'xmlParseChunk',
            parameter_roles=[
                {'name': 'ctxt', 'role': 'state', 'type': 'xmlParserCtxtPtr'},
            ],
            helper_calls=[],
            state_fields=[
                {'owner': 'sax', 'field': 'endDocument', 'kind': 'control-state'},
                {'owner': 'sax', 'field': 'startElement', 'kind': 'control-state'},
                {'owner': 'sax', 'field': 'characters', 'kind': 'control-state'},
                {'owner': 'header', 'field': 'extra', 'kind': 'buffer-state'},
                {'owner': 'header', 'field': 'extra_max', 'kind': 'size-state'},
            ],
            field_conditions=[
                {'target': 'ctxt->sax', 'operator': '!=', 'value': 'NULL', 'type': 'comparison'},
                {'target': 'sax->endDocument', 'operator': '!=', 'value': 'NULL', 'type': 'comparison'},
                {'target': 'sax->startElement', 'operator': '!=', 'value': 'NULL', 'type': 'comparison'},
                {'target': 'sax->characters', 'operator': '!=', 'value': 'NULL', 'type': 'comparison'},
                {'target': 'ctxt->header', 'operator': '!=', 'value': 'NULL', 'type': 'comparison'},
                {'target': 'header->extra', 'operator': '!=', 'value': 'NULL', 'type': 'comparison'},
            ],
            related_init_functions=[
                {'name': 'xmlCreatePushParserCtxt', 'params': 'xmlSAXHandlerPtr sax, void *user_data, const char *chunk, int size, const char *filename', 'relation': 'init'},
            ],
        )

        constraints_text = '\n'.join(
            item.get('constraint', '') for item in contract.get('support_object_field_constraints', [])
        )
        # Callback fields must never get the "vary the encoded length" buffer constraints
        buffer_constraints = [
            item.get('constraint', '') for item in contract.get('support_object_field_constraints', [])
            if 'vary the encoded length' in item.get('constraint', '')
        ]
        buffer_text = '\n'.join(buffer_constraints)
        self.assertNotIn('endDocument', buffer_text,
                         "'endDocument' is a callback, should not have buffer-length constraints")
        self.assertNotIn('startElement', buffer_text,
                         "'startElement' is a callback, should not have buffer-length constraints")
        self.assertNotIn('characters', buffer_text,
                         "'characters' is a callback, should not have buffer-length constraints")
        # But genuine buffer fields still SHOULD have constraints
        self.assertIn('extra', constraints_text,
                      "'extra' is a real buffer field — should still have constraints")

    # ------------------------------------------------------------------
    # Regression tests for sink-internal callees NOT promoted (Bug: over-complex harness)
    # ------------------------------------------------------------------
    def test_sink_internal_callees_not_promoted_to_setup_calls(self):
        """Helper calls found INSIDE the sink function must NOT become
        required_setup_calls — they are the sink's own implementation."""
        contract = infer_semantic_contract(
            'xmlAddEntity',
            parameter_roles=[
                {'name': 'doc', 'role': 'value', 'type': 'xmlDocPtr'},
                {'name': 'name', 'role': 'input-buffer', 'type': 'const xmlChar'},
                {'name': 'type', 'role': 'control', 'type': 'int'},
            ],
            # These are callees OF the sink, extracted from the sink body.
            helper_calls=[
                {'name': 'xmlHashCreateDict', 'phase': 'setup'},
                {'name': 'xmlCreateEntity', 'phase': 'setup'},
                {'name': 'xmlFreeEntity', 'phase': 'cleanup'},
                {'name': 'xmlEntitiesWarn', 'phase': 'other'},
            ],
            state_fields=[
                {'owner': 'dtd', 'field': 'doc', 'kind': 'state'},
                {'owner': 'dtd', 'field': 'entities', 'kind': 'state'},
            ],
            field_conditions=[
                {'target': 'dtd->doc', 'operator': '!=', 'value': 'NULL', 'type': 'comparison'},
            ],
            related_init_functions=[],
        )

        setup_names = [item.get('name') for item in contract.get('required_setup_calls', [])]
        # Sink-internal callees must NOT appear as setup calls.
        self.assertNotIn('xmlHashCreateDict', setup_names,
                         "xmlHashCreateDict is a sink callee, not a setup API")
        self.assertNotIn('xmlCreateEntity', setup_names,
                         "xmlCreateEntity is a sink callee, not a setup API")
        self.assertNotIn('xmlFreeEntity', setup_names,
                         "xmlFreeEntity is a cleanup callee, not a setup API")

    # ------------------------------------------------------------------
    # Regression test for structural-pointer fields NOT getting buffer
    # constraints (Bug: doc gets 'vary encoded length')
    # ------------------------------------------------------------------
    def test_structural_pointer_fields_no_buffer_constraints(self):
        """Fields like ``doc`` (a struct pointer) should NOT receive
        'vary the encoded length' buffer constraints."""
        contract = infer_semantic_contract(
            'xmlAddEntity',
            parameter_roles=[
                {'name': 'doc', 'role': 'value', 'type': 'xmlDocPtr'},
            ],
            helper_calls=[],
            state_fields=[
                {'owner': 'dtd', 'field': 'doc', 'kind': 'state'},
                {'owner': 'dtd', 'field': 'entities', 'kind': 'state'},
            ],
            field_conditions=[
                {'target': 'dtd->doc', 'operator': '!=', 'value': 'NULL', 'type': 'comparison'},
            ],
            related_init_functions=[],
        )

        buffer_constraints = [
            item.get('constraint', '') for item in contract.get('support_object_field_constraints', [])
            if 'vary the encoded length' in item.get('constraint', '')
        ]
        buffer_text = '\n'.join(buffer_constraints)
        self.assertNotIn('dtd.doc', buffer_text,
                         "'doc' is a struct pointer, not a buffer — no length-vary constraint")


if __name__ == '__main__':
    unittest.main()