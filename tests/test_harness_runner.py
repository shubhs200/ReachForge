#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import harness_runner


class RunSeedCorpusValidationTests(unittest.TestCase):

    def test_seed_validation_uses_bounded_runs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            seeds_path = out_dir / 'seeds.json'
            plan_path = out_dir / 'plan.json'
            harness_binary = out_dir / 'vuln_fuzzer'

            seeds_path.write_text(json.dumps({
                'seeds': [
                    {'name': 'first', 'content': 'AA', 'encoding': 'hex'},
                    {'name': 'second', 'content': 'BB', 'encoding': 'hex'},
                ]
            }), encoding='utf-8')
            plan_path.write_text(json.dumps({}), encoding='utf-8')
            harness_binary.write_text('', encoding='utf-8')

            completed = mock.Mock(returncode=0, stdout='ok', stderr='')
            with mock.patch('harness_runner.subprocess.run', return_value=completed) as run_mock:
                report = harness_runner.run_seed_corpus_validation(harness_binary, out_dir, plan_path)

            self.assertTrue(report['ok'])
            self.assertEqual(report['seed_count'], 2)

            command = run_mock.call_args[0][0]
            self.assertEqual(command[0], str(harness_binary))
            self.assertIn('-runs=2', command)
            self.assertIn('-timeout=5', command)
            self.assertEqual(command[-1], str(out_dir / 'corpus'))


if __name__ == '__main__':
    unittest.main()