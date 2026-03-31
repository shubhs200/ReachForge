#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from harness_validator import validate_harness_source
import harness_runner


PLAN = {
    'public_api_name': 'png_set_PLTE',
    'vuln_entry': {
        'affected-function': 'png_set_PLTE',
    },
    'execution_plan': {
        'entry_function': 'png_set_PLTE',
        'trigger_relations': [
            {
                'kind': 'setup-state-bound-hypothesis',
                'controller': 'setup-state-control',
                'dependent': 'num_palette',
                'priority': 'high',
                'state_targets': ['png_ptr', 'info_ptr'],
                'support_objects': ['palette'],
                'harness_expectation': 'Before invoking png_set_PLTE, use at least one valid pre-sink state-configuration call on png_ptr, info_ptr to establish or vary the legal range of num_palette; then exercise num_palette near that derived bound while keeping palette internally consistent.',
            }
        ],
        'parameter_roles': [
            {'name': 'png_ptr', 'role': 'state', 'type': 'png_structrp'},
            {'name': 'info_ptr', 'role': 'state', 'type': 'png_inforp'},
            {'name': 'palette', 'role': 'support-buffer', 'type': 'png_const_colorp'},
            {'name': 'num_palette', 'role': 'size', 'type': 'int'},
        ],
        'setup_state_profiles': [
            {
                'name': 'liveness-ranked-setup-control',
                'priority': 'high',
                'ranking_rationale': 'Prefer pre-sink setup controls that keep palette semantically live while changing the legal range of num_palette.',
                'preferred_properties': [
                    'Vary the smallest number of valid pre-sink setup controls that still changes the legal range of num_palette.',
                    'Prefer setup choices that keep palette semantically active while num_palette is exercised near its derived bound.',
                ],
            }
        ],
        'setup_requirements': [
            'Use at least one valid pre-sink state-configuration call on png_ptr, info_ptr before invoking png_set_PLTE so setup-established bounds can vary with the sink arguments.'
        ],
        'sensitive_controls': [
            {'target': 'num_palette', 'source_kind': 'parameter', 'score': 2, 'reasons': ['explicit size parameter in the public API signature']},
        ],
    },
    'vuln_context': {
        'failure_path_indicators': {'error_calls': []},
    },
    'construction_plan': {
        'support_objects': [
            {'name': 'palette', 'kind': 'table', 'reason': 'the public API explicitly requires this support buffer or table argument'}
        ]
    }
}


BROAD_HARNESS = """
extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int setup_ctrl = size ? data[0] : 0;
  png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  png_infop info_ptr = png_create_info_struct(png_ptr);
  int color_type;
  switch (setup_ctrl % 4) {
    case 0: color_type = PNG_COLOR_TYPE_PALETTE; break;
    case 1: color_type = PNG_COLOR_TYPE_RGB; break;
    case 2: color_type = PNG_COLOR_TYPE_RGB_ALPHA; break;
    default: color_type = PNG_COLOR_TYPE_GRAY; break;
  }
  int bit_depth = 8;
  png_set_IHDR(png_ptr, info_ptr, 1, 1, bit_depth, color_type, PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);
  int max_palette = (color_type == PNG_COLOR_TYPE_PALETTE) ? (1 << bit_depth) : 256;
  int num_palette = size > 1 ? (data[1] % (max_palette + 1)) : max_palette;
  png_color palette[256];
  png_set_PLTE(png_ptr, info_ptr, palette, num_palette);
  return 0;
}
"""


FOCUSED_HARNESS = """
extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int setup_depth = size ? data[0] : 0;
  png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  png_infop info_ptr = png_create_info_struct(png_ptr);
  int bit_depth;
  switch (setup_depth & 3) {
    case 0: bit_depth = 1; break;
    case 1: bit_depth = 2; break;
    case 2: bit_depth = 4; break;
    default: bit_depth = 8; break;
  }
  png_set_IHDR(png_ptr, info_ptr, 1, 1, bit_depth, PNG_COLOR_TYPE_PALETTE, PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);
  int max_palette = 1 << bit_depth;
  int num_palette = max_palette - 1;
  png_color palette[256];
  png_set_PLTE(png_ptr, info_ptr, palette, num_palette);
  return 0;
}
"""


class SetupStateRankingTests(unittest.TestCase):

    def test_focused_setup_scores_higher_than_broad_mode_switch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            plan_path = tmp_path / 'plan.json'
            broad_path = tmp_path / 'broad.cc'
            focused_path = tmp_path / 'focused.cc'

            plan_path.write_text(json.dumps(PLAN), encoding='utf-8')
            broad_path.write_text(BROAD_HARNESS, encoding='utf-8')
            focused_path.write_text(FOCUSED_HARNESS, encoding='utf-8')

            broad_report = validate_harness_source(plan_path, broad_path)
            focused_report = validate_harness_source(plan_path, focused_path)

            self.assertGreater(focused_report['score'], broad_report['score'])
            self.assertTrue(any('broad setup-mode families' in item for item in broad_report['warnings']))

    def test_bound_coupling_requires_setup_variable_in_bound(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            plan_path = tmp_path / 'plan.json'
            weak_path = tmp_path / 'weak.cc'
            strong_path = tmp_path / 'strong.cc'

            weak_harness = """
extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    int color_sel = size ? data[0] : 0;
    int num_sel = size > 1 ? data[1] : 0;
    png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
    png_infop info_ptr = png_create_info_struct(png_ptr);
    int color_type = (color_sel & 1) ? PNG_COLOR_TYPE_PALETTE : PNG_COLOR_TYPE_RGB;
    int bit_depth = 8;
    png_set_IHDR(png_ptr, info_ptr, 1, 1, bit_depth, color_type, PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);
    int max_palette = 256;
    int num_palette = num_sel % (max_palette + 1);
    png_color palette[256];
    png_set_PLTE(png_ptr, info_ptr, palette, num_palette);
    return 0;
}
"""

            strong_harness = """
extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    int setup_depth = size ? data[0] : 0;
    int relation_bias = size > 1 ? data[1] : 0;
    png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
    png_infop info_ptr = png_create_info_struct(png_ptr);
    int bit_depth;
    switch (setup_depth & 3) {
        case 0: bit_depth = 1; break;
        case 1: bit_depth = 2; break;
        case 2: bit_depth = 4; break;
        default: bit_depth = 8; break;
    }
    png_set_IHDR(png_ptr, info_ptr, 1, 1, bit_depth, PNG_COLOR_TYPE_PALETTE, PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);
    int max_palette = 1 << bit_depth;
    int num_palette = (relation_bias & 1) ? max_palette : (max_palette - 1);
    png_color palette[256];
    png_set_PLTE(png_ptr, info_ptr, palette, num_palette);
    return 0;
}
"""

            plan_path.write_text(json.dumps(PLAN), encoding='utf-8')
            weak_path.write_text(weak_harness, encoding='utf-8')
            strong_path.write_text(strong_harness, encoding='utf-8')

            weak_report = validate_harness_source(plan_path, weak_path)
            strong_report = validate_harness_source(plan_path, strong_path)

            self.assertFalse(weak_report['ok'])
            self.assertTrue(strong_report['ok'])
            self.assertTrue(any('does not appear to depend on any setup-controlled identifier' in item for item in weak_report['violations']))
            self.assertTrue(any(item.get('ok') for item in strong_report.get('relation_diagnostics', [])))

    def test_candidate_selection_prefers_relation_success(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            plan_path = tmp_path / 'plan.json'
            candidates_dir = tmp_path / 'candidates'
            prompt_a = tmp_path / 'a.md'
            prompt_b = tmp_path / 'b.md'
            plan_path.write_text(json.dumps(PLAN), encoding='utf-8')
            prompt_a.write_text('a', encoding='utf-8')
            prompt_b.write_text('b', encoding='utf-8')

            reports = [
                {
                    'ok': True,
                    'score': 92,
                    'violations': [],
                    'warnings': ['weak relation'],
                    'relation_diagnostics': [{'ok': False}],
                },
                {
                    'ok': True,
                    'score': 92,
                    'violations': [],
                    'warnings': ['broad setup'],
                    'relation_diagnostics': [{'ok': True}],
                },
            ]

            def fake_run_openai_json(prompt_path, candidate_src, model=None, api_base=None):
                Path(candidate_src).write_text('int main() { return 0; }', encoding='utf-8')
                return True, ''

            with mock.patch('llm_adapters.openai.run_openai_json', side_effect=fake_run_openai_json), \
                    mock.patch('harness_validator.validate_harness_source', side_effect=reports):
                candidate_reports = harness_runner.select_best_candidate(
                    plan_path,
                    candidates_dir,
                    [('first', prompt_a), ('second', prompt_b)],
                    model='dummy',
                    api_base='dummy'
                )

            self.assertEqual(candidate_reports[0]['name'], 'second')


if __name__ == '__main__':
    unittest.main()