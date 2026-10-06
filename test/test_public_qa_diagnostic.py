"""Pure fixture checks only; no GPU, model inference or runtime proof."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('public_qa_diagnostic', ROOT / 'scripts/evaluate-public-qa-diagnostic.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture_rows():
    result = []
    for i in range(64):
        context = '서울은 도시다.'
        question = '도시는?'
        answers = [] if i % 2 else [{'text': '서울', 'answer_start': 0}]
        result.append({'id': 'fixture_'+str(i), 'split': 'heldout', 'upstreamSplit': 'dev', 'upstreamRevision': runner.SOURCE_REVISION, 'language': 'ko', 'sourceLicense': 'CC-BY-SA-4.0', 'upstreamAnnotation': {'kind': 'human_authored_question_answer_spans'}, 'localHumanReviewPerformed': False, 'context': context, 'contextSha256': hashlib.sha256(context.encode()).hexdigest(), 'question': question, 'answers': answers, 'isImpossible': bool(i % 2), 'originalQa': {'question': question, 'answers': answers, 'is_impossible': bool(i % 2)}, 'contextSelection': 'full_original_context_no_answer_based_crop'})
    return result


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='evidscope-diagnostic-test-')
        self.directory = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def dataset(self, mutate=None):
        rows = fixture_rows()
        if mutate:
            mutate(rows)
        data = self.directory / 'data.jsonl'
        data.write_text(''.join(json.dumps(row, ensure_ascii=False)+'\n' for row in rows), encoding='utf-8')
        digest = runner.sha256_file(data)
        metadata = {'mode': 'public_qa_diagnostic', 'diagnosticOnly': True, 'datasetSha256': digest, 'sourcePins': runner.SOURCE_PINS, 'localHumanReviewPerformed': False, 'qualityClaimAllowed': False, 'promotionAllowed': False, 'selection': {'fullContextPreserved': True, 'answerBasedCropping': False}, 'trainingOverlap': {'id': 0, 'family': 0, 'context': 0}, 'rowIds': [row['id'] for row in rows]}
        manifest = self.directory / 'manifest.json'
        manifest_digest = write_json(manifest, metadata)
        return data, manifest, digest, manifest_digest

    def candidate(self, stage='stage1'):
        directory = self.directory / 'candidate'
        directory.mkdir()
        (directory / 'adapter_model.safetensors').write_bytes(b'fixture adapter is not a real model')
        step = 40 if stage == 'stage2' else 20
        identity = {'baseRepository': 'fdtn-ai/Foundation-Sec-8B-Reasoning', 'baseRevision': runner.BASE_REVISION, 'baseArtifactLockSha256': runner.LOCK_SHA, 'stage': 'public_qa_' + stage}
        write_json(directory / 'training-receipt.json', {'status': 'trained_public_qa_' + stage, 'identity': identity, 'globalStep': step, 'promotionAllowed': False, 'qualityClaimAllowed': False})
        files = [{'path': p.name, 'bytes': p.stat().st_size, 'sha256': runner.sha256_file(p)} for p in sorted(directory.iterdir())]
        marker = {'schemaVersion': 1, 'globalStep': step, 'identity': identity, 'files': files}
        digest = write_json(directory / 'candidate-complete.json', marker)
        return directory, digest, runner.sha256_file(directory / 'adapter_model.safetensors')

    def test_valid_fixture_input_binding(self):
        args = self.dataset()
        rows, _ = runner.verify_data(*args)
        self.assertEqual(len(rows), 64)

    def test_input_digest_tamper_rejected(self):
        data, manifest, digest, manifest_digest = self.dataset()
        data.write_bytes(data.read_bytes()+b' ')
        with self.assertRaisesRegex(ValueError, 'input_hash_mismatch'):
            runner.verify_data(data, manifest, digest, manifest_digest)

    def test_manifest_claim_tamper_rejected_even_with_fixture_digest(self):
        data, manifest, digest, _ = self.dataset()
        metadata = json.loads(manifest.read_text(encoding='utf-8'))
        metadata['promotionAllowed'] = True
        new_digest = write_json(manifest, metadata)
        with self.assertRaisesRegex(ValueError, 'claim_boundary_invalid'):
            runner.verify_data(data, manifest, digest, new_digest)

    def test_source_pin_change_rejected(self):
        data, manifest, digest, _ = self.dataset()
        metadata = json.loads(manifest.read_text(encoding='utf-8'))
        metadata['sourcePins']['heldout'] = '0'*64
        new_digest = write_json(manifest, metadata)
        with self.assertRaisesRegex(ValueError, 'manifest_invalid'):
            runner.verify_data(data, manifest, digest, new_digest)

    def test_family_overlap_claim_rejected(self):
        data, manifest, digest, _ = self.dataset()
        metadata = json.loads(manifest.read_text(encoding='utf-8'))
        metadata['trainingOverlap']['family'] = 1
        new_digest = write_json(manifest, metadata)
        with self.assertRaisesRegex(ValueError, 'scope_invalid'):
            runner.verify_data(data, manifest, digest, new_digest)

    def test_row_id_duplicates_rejected(self):
        with self.assertRaisesRegex(ValueError, 'rows_invalid'):
            runner.verify_data(*self.dataset(lambda rows: rows[1].update(id=rows[0]['id'])))

    def test_original_question_change_rejected(self):
        with self.assertRaisesRegex(ValueError, 'original_changed'):
            runner.verify_data(*self.dataset(lambda rows: rows[0].update(question='새 질문')))

    def test_context_edit_rejected(self):
        with self.assertRaisesRegex(ValueError, 'context_changed'):
            runner.verify_data(*self.dataset(lambda rows: rows[0].update(context='변조')))

    def test_fake_local_review_rejected(self):
        with self.assertRaisesRegex(ValueError, 'annotation_invalid'):
            runner.verify_data(*self.dataset(lambda rows: rows[0].update(localHumanReviewPerformed=True)))

    def test_valid_candidate_fixture_inventory(self):
        candidate, marker, adapter = self.candidate()
        self.assertEqual(runner.verify_candidate_directory(candidate, marker, adapter)['globalStep'], 20)

    def test_stage2_requires_exact_step_stage_and_adapter(self):
        candidate, marker, adapter = self.candidate('stage2')
        self.assertEqual(runner.verify_candidate_directory(candidate, marker, adapter, expected_stage='stage2')['globalStep'], 40)
        with self.assertRaisesRegex(ValueError, 'step_invalid'):
            runner.verify_candidate_directory(candidate, marker, adapter)
        with self.assertRaisesRegex(ValueError, 'adapter_changed'):
            runner.verify_candidate_directory(candidate, marker, 'f'*64, expected_stage='stage2')
        with self.assertRaisesRegex(ValueError, 'source_stage_invalid'):
            runner.verify_candidate_directory(candidate, marker, adapter, expected_stage='anything')

    def test_stage1_candidate_cannot_be_selected_as_stage2(self):
        candidate, marker, adapter = self.candidate()
        with self.assertRaisesRegex(ValueError, 'step_invalid'):
            runner.verify_candidate_directory(candidate, marker, adapter, expected_stage='stage2')

    def test_stage2_pins_match_workload_and_claim_is_bound_after_receipt_creation(self):
        source = (ROOT / 'scripts/public-qa-diagnostic-workload.mjs').read_text(encoding='utf-8')
        for value in runner.STAGE2_PINS.values():
            self.assertIn(value, source)
        tree = ast.parse((ROOT / 'scripts/evaluate-public-qa-diagnostic.py').read_text(encoding='utf-8'))
        evaluate = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'evaluate')
        receipt_line = next(node.lineno for node in ast.walk(evaluate) if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'receipt' for target in node.targets))
        verification_line = next(node.lineno for node in ast.walk(evaluate) if isinstance(node, ast.Assign) and any(isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and target.value.id == 'receipt' and isinstance(target.slice, ast.Constant) and target.slice.value == 'sourceTrainingVerificationSha256' for target in node.targets))
        self.assertGreater(verification_line, receipt_line)

    def test_candidate_adapter_tamper_rejected(self):
        candidate, marker, adapter = self.candidate()
        (candidate / 'adapter_model.safetensors').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'artifact_changed'):
            runner.verify_candidate_directory(candidate, marker, adapter)

    def test_candidate_extra_file_rejected(self):
        candidate, marker, adapter = self.candidate()
        (candidate / 'unexpected.txt').write_text('extra')
        with self.assertRaisesRegex(ValueError, 'inventory_mismatch'):
            runner.verify_candidate_directory(candidate, marker, adapter)

    def test_candidate_marker_tamper_rejected(self):
        candidate, marker, adapter = self.candidate()
        (candidate / 'candidate-complete.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'marker_changed'):
            runner.verify_candidate_directory(candidate, marker, adapter)

    def test_candidate_other_base_rejected(self):
        candidate, _, adapter = self.candidate()
        marker_path = candidate / 'candidate-complete.json'
        value = json.loads(marker_path.read_text())
        value['identity']['baseRevision'] = 'other-base'
        receipt_path = candidate / 'training-receipt.json'
        receipt = json.loads(receipt_path.read_text())
        receipt['identity'] = value['identity']
        write_json(receipt_path, receipt)
        for item in value['files']:
            if item['path'] == receipt_path.name:
                item.update(bytes=receipt_path.stat().st_size, sha256=runner.sha256_file(receipt_path))
        marker = write_json(marker_path, value)
        with self.assertRaisesRegex(ValueError, 'base_identity_invalid'):
            runner.verify_candidate_directory(candidate, marker, adapter)

    def test_candidate_inventory_traversal_rejected(self):
        candidate, _, adapter = self.candidate()
        marker_path = candidate / 'candidate-complete.json'
        value = json.loads(marker_path.read_text())
        value['files'][0]['path'] = '../outside'
        marker = write_json(marker_path, value)
        with self.assertRaisesRegex(ValueError, 'path_escape'):
            runner.verify_candidate_directory(candidate, marker, adapter)

    def test_prompt_uses_full_context_and_no_gold_metadata(self):
        row = fixture_rows()[0]
        row['answers'] = [{'text': 'HIDDEN_GOLD_SENTINEL'}]
        row['originalQa'] = {'secret': 'HIDDEN_ORIGINAL_SENTINEL'}
        messages = runner.messages_for(row)
        body = json.loads(messages[1]['content'])
        self.assertEqual(body, {'question': row['question'], 'document': row['context']})
        self.assertNotIn('HIDDEN_', json.dumps(messages))
        self.assertEqual(len(messages), 2)

    def test_prompt_system_matches_training_system_exactly(self):
        tree = ast.parse((ROOT / 'scripts/train-public-qa.py').read_text(encoding='utf-8'))
        value = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'SYSTEM' for target in node.targets))
        self.assertEqual(runner.SYSTEM, value)

    def test_preadmission_includes_boundary_and_excludes_without_cropping(self):
        calls = []
        class TokenizerFixture:
            def apply_chat_template(self, messages, **kwargs):
                calls.append(messages)
                return [1]*(896 if len(calls) == 1 else 897)
        rows = fixture_rows()[:2]
        inputs, admission = runner.preadmit(rows, TokenizerFixture())
        self.assertEqual(list(inputs), [rows[0]['id']])
        self.assertEqual(admission[1]['exclusionReason'], 'full_context_token_budget_exceeded')
        self.assertEqual(json.loads(calls[1][1]['content'])['document'], rows[1]['context'])

    def test_output_must_be_new_direct_child(self):
        target = self.directory / 'public-qa-diagnostic-test'
        self.assertEqual(runner.output_path(target, self.directory), target)
        target.mkdir()
        with self.assertRaisesRegex(ValueError, 'must_be_new_child'):
            runner.output_path(target, self.directory)
        with self.assertRaisesRegex(ValueError, 'must_be_new_child'):
            runner.output_path(self.directory / '..' / 'public-qa-escape', self.directory)

    def test_measured_timeout_limit_and_stop_flags(self):
        normal = runner.measured_response('raw text', 1.5, 400, 20)
        self.assertEqual(normal['content'], 'raw text')
        self.assertFalse(normal['timedOut'])
        self.assertFalse(normal['tokenLimitReached'])
        stopped = runner.measured_response('partial', 120, 400, 128, True)
        self.assertTrue(stopped['timedOut'])
        self.assertTrue(stopped['tokenLimitReached'])
        self.assertEqual(stopped['error'], 'termination_requested')


if __name__ == '__main__':
    unittest.main()
