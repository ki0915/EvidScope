"""CPU fixtures for admission and consumed-tensor binding; no model execution."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cont = load('continuation_tests_helper', 'public-qa-grounding-continuation.py')
qa = load('continuation_tests_qa', 'train-public-qa.py')


class Tensor:
    def __init__(self, value):
        self.value = value
    def detach(self):
        return self
    def cpu(self):
        return self
    def tolist(self):
        return deepcopy(self.value)


class ContinuationTests(unittest.TestCase):
    def setUp(self):
        (ROOT / '.test-runs').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='continuation-cpu-', dir=ROOT / '.test-runs')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.original = []
        for split, impossible, count in [('train', False, 440), ('train', True, 200),
                                         ('validation', False, 32), ('validation', True, 32)]:
            for _ in range(count):
                index = len(self.original)
                context = f'공개 문서 {index}는 한국의 자료이며 답은 서울이다.'
                question = '문서가 제시한 답은?' if not impossible else '문서에 없는 기관의 설립자는?'
                answers = [] if impossible else [{'text': '서울', 'answer_start': context.index('서울')}]
                self.original.append({'id': f'fixture_{index:04d}', 'familyId': f'family_{index:04d}',
                    'contextSha256': cont.hashlib.sha256(context.encode()).hexdigest(), 'context': context,
                    'question': question, 'answers': answers, 'isImpossible': impossible, 'split': split,
                    'upstreamSplit': 'train', 'upstreamRevision': qa.REVISION, 'language': 'ko',
                    'sourceLicense': 'CC-BY-SA-4.0', 'upstreamAnnotation': {'kind': 'human_authored_question_answer_spans'},
                    'originalQa': {'question': question, 'answers': deepcopy(answers), 'is_impossible': impossible}})
        self.rows = [{**deepcopy(row), 'stage': cont.STAGE, 'contextSelection': 'full_original_context',
                      'localHumanReviewPerformed': False, 'privacyScreen': dict(cont.PRIVACY)} for row in self.original]
        self.manifest = {'stage': cont.STAGE, 'counts': {'train': 640, 'validation': 64},
                         'labelCounts': {'train': {'answerable': 440, 'impossible': 200},
                                         'validation': {'answerable': 32, 'impossible': 32}},
                         'sampler': dict(cont.SAMPLER), 'selection': dict(cont.SELECTION),
                         'previousExposureOverlap': {'id': 0, 'family': 0, 'context': 0},
                         'heldoutUsed': False, 'localHumanReviewPerformed': False,
                         'qualityClaimAllowed': False, 'promotionAllowed': False,
                         'rowIds': [row['id'] for row in self.rows], 'sourceFiles': dict(cont.SOURCE_FILES)}
        self.sources = {'sourceManifest': {'revision': qa.REVISION, 'license': 'CC-BY-SA-4.0'},
                        'sourceTrain': self.original[:640], 'sourceValidation': self.original[640:],
                        'oldTraining': [], 'diagnostic': [], 'previousGrounding': []}
        self.pins = {}
        self.write_sources()
        self.patch_pins = patch.dict(cont.SOURCE_PINS, self.pins)
        self.patch_pins.start()
        self.addCleanup(self.patch_pins.stop)
        self.manifest['sourcePins'] = dict(self.pins)
        self.train_rows = self.rows[:640]
        self.encoded = [{'input_ids': [7, index + 10, 2], 'attention_mask': [1, 1, 1],
                         'labels': [-100, index + 10, 2]} for index in range(640)]

    def write_sources(self):
        for key, filename in cont.SOURCE_FILES.items():
            value = self.sources[key]
            content = json.dumps(value, ensure_ascii=False) if key == 'sourceManifest' else '\n'.join(json.dumps(row, ensure_ascii=False) for row in value) + '\n'
            (self.root / filename).write_text(content, encoding='utf-8')
            self.pins[key] = cont.sha256_file(self.root / filename)

    def admit(self):
        return cont.verify_grounding_data(self.rows, self.manifest, self.root / 'manifest.json')

    def recorder(self):
        return cont.ExposureRecorder(self.train_rows, self.encoded, self.root / 'training-exposure.json', 'a' * 64)

    def batch(self, index):
        return {key: Tensor([deepcopy(value)]) for key, value in self.encoded[index].items()}

    def test_source_rows_and_sampler_are_admitted_without_model_import(self):
        self.admit()
        self.assertEqual(cont.stratified_order(self.train_rows), cont.stratified_order(self.train_rows))
        order = cont.stratified_order(self.train_rows)
        self.assertEqual(len(set(order)), 640)
        for start in range(0, 640, 16):
            self.assertEqual(sum(self.train_rows[i]['isImpossible'] for i in order[start:start + 16]), 5)
        self.assertEqual(sum(self.train_rows[i]['isImpossible'] for i in order[:320]), 100)

    def test_original_full_context_overflow_is_rejected(self):
        self.original[0]['context'] += ' 긴 원문' * 200
        self.original[0]['contextSha256'] = cont.hashlib.sha256(self.original[0]['context'].encode()).hexdigest()
        self.rows[0].update(context=self.original[0]['context'], contextSha256=self.original[0]['contextSha256'])
        self.write_sources()
        with patch.dict(cont.SOURCE_PINS, self.pins):
            self.manifest['sourcePins'] = dict(self.pins)
            with self.assertRaisesRegex(ValueError, 'context_limit'):
                self.admit()

    def test_content_annotation_duplicate_and_other_split_fail(self):
        original = deepcopy(self.rows)
        for mutate, error in [
                (lambda: self.rows[0].update(context='변조'), 'original_row_changed'),
                (lambda: self.rows[0].update(isImpossible=True), 'original_row_changed'),
                (lambda: self.rows.__setitem__(1, deepcopy(self.rows[0])), 'original_row_changed'),
                (lambda: self.rows[0].update(split='heldout'), 'original_row_changed')]:
            self.rows = deepcopy(original)
            mutate()
            with self.assertRaisesRegex(ValueError, error):
                self.admit()

    def test_prior_exposure_by_family_context_or_id_is_rejected(self):
        row = self.rows[0]
        for key in ('id', 'familyId', 'contextSha256'):
            prior = {'id': 'other', 'familyId': 'other', 'contextSha256': 'other'}
            prior[key] = row[key]
            self.sources['previousGrounding'] = [prior]
            self.write_sources()
            with patch.dict(cont.SOURCE_PINS, self.pins):
                self.manifest['sourcePins'] = dict(self.pins)
                with self.assertRaisesRegex(ValueError, 'previous_exposure_leakage'):
                    self.admit()

    def test_unmodified_original_pii_is_not_admitted(self):
        self.original[0]['context'] += ' contact@example.org'
        self.original[0]['contextSha256'] = cont.hashlib.sha256(self.original[0]['context'].encode()).hexdigest()
        self.rows[0].update(context=self.original[0]['context'], contextSha256=self.original[0]['contextSha256'])
        self.write_sources()
        with patch.dict(cont.SOURCE_PINS, self.pins):
            self.manifest['sourcePins'] = dict(self.pins)
            with self.assertRaisesRegex(ValueError, 'privacy_pattern'):
                self.admit()

    def test_policy_balance_and_changed_source_cannot_self_attest(self):
        for key, value, error in [('sampler', {**cont.SAMPLER, 'seed': 43}, 'sampling_policy'),
                                  ('labelCounts', {'train': {'answerable': 320, 'impossible': 320}}, 'balance'),
                                  ('heldoutUsed', True, 'claim_boundary')]:
            old = self.manifest[key]
            self.manifest[key] = value
            with self.assertRaisesRegex(ValueError, error):
                self.admit()
            self.manifest[key] = old
        (self.root / 'source-train.jsonl').write_text('{}\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'source_changed'):
            self.admit()

    def test_actual_consumption_and_checkpoint_binding_220_100(self):
        exposure = self.recorder()
        for position, index in enumerate(exposure.order[:320]):
            record = exposure.inspect(self.batch(index))
            self.assertEqual(exposure.document['processedMicrobatches'], position)
            exposure.completed(record)
            if (position + 1) % 16 == 0:
                exposure.optimizer_completed((position + 1) // 16)
            if position == 159:
                receipt = exposure.snapshot(self.root / 'checkpoint-10-exposure.json', 10)
                self.assertEqual(receipt['counts'], {'answerable': 110, 'impossible': 50})
        receipt = exposure.snapshot(self.root / 'candidate-exposure.json', 20)
        self.assertEqual(receipt['counts'], {'answerable': 220, 'impossible': 100})
        self.assertEqual(receipt['totalAdapterHistoryOptimizerUpdates'], 80)
        self.assertEqual(exposure.document['rows'][-1]['microbatch'], 320)
        self.assertEqual(exposure.document['rows'][0]['inputSha256'], cont.canonical_hash(self.encoded[exposure.order[0]]))
        with self.assertRaisesRegex(ValueError, 'step_budget'):
            exposure.inspect(self.batch(exposure.order[320]))

    def test_reordered_duplicate_tensor_label_and_forged_record_fail(self):
        exposure = self.recorder()
        first = exposure.order[0]
        with self.assertRaisesRegex(ValueError, 'tensor_row_mismatch'):
            exposure.inspect(self.batch(exposure.order[1]))
        batch = self.batch(first)
        batch['labels'].value[0][1] += 1
        with self.assertRaisesRegex(ValueError, 'tensor_row_mismatch'):
            exposure.inspect(batch)
        record = exposure.inspect(self.batch(first))
        with self.assertRaisesRegex(ValueError, 'unfinished_training_step'):
            exposure.inspect(self.batch(first))
        with self.assertRaisesRegex(ValueError, 'order_changed'):
            exposure.completed({**record, 'isImpossible': not record['isImpossible']})
        exposure.completed(record)
        with self.assertRaisesRegex(ValueError, 'tensor_row_mismatch'):
            exposure.inspect(self.batch(first))
        with self.assertRaisesRegex(ValueError, 'optimizer_exposure'):
            exposure.optimizer_completed(1)
        with self.assertRaisesRegex(ValueError, 'snapshot_step'):
            exposure.snapshot(self.root / 'bad.json', 1)

    def test_real_cpu_torch_tensors_bind_when_runtime_is_available(self):
        if importlib.util.find_spec('torch') is None:
            self.skipTest('Windows runtime has no torch; execute this binding check in the pinned CPU image.')
        import torch
        exposure = self.recorder()
        index = exposure.order[0]
        batch = {key: torch.tensor([value], dtype=torch.int64) for key, value in self.encoded[index].items()}
        record = exposure.inspect(batch)
        self.assertEqual(record['inputSha256'], cont.canonical_hash(self.encoded[index]))
        exposure.completed(record)
        wrong = {key: torch.tensor([value], dtype=torch.int64) for key, value in self.encoded[index].items()}
        with self.assertRaisesRegex(ValueError, 'tensor_row_mismatch'):
            exposure.inspect(wrong)

    def test_target_contract_rejects_different_source_steps_lr_and_reuse(self):
        source_dir = ROOT / '.local/training/runs/public-qa-grounding-20261005-r4/candidate'
        identity = deepcopy(json.loads((source_dir / 'candidate-complete.json').read_text(encoding='utf-8'))['identity'])
        source_identity = deepcopy(identity)
        identity.update(stage=cont.STAGE, learningRate=cont.LEARNING_RATE, sampler=dict(cont.SAMPLER))
        document = {'schemaVersion': 1, 'kind': 'adapter_only_warmstart_stratified_public_qa_continuation',
                    'sourceRunId': cont.SOURCE_RUN, 'sourceGlobalStep': 20, 'sourceOptimizerHistoryUpdates': 60,
                    'sourcePins': dict(cont.PINS), 'sourceIdentity': source_identity,
                    'targetRunId': 'public-qa-grounding-20261006-unit', 'targetIdentity': identity,
                    'optimizerReset': True, 'schedulerReset': True, 'targetOptimizerSteps': 20,
                    'sourceTrainingExecutionVerified': True, 'qualityClaimAllowed': False, 'promotionAllowed': False}
        provenance = self.root / 'provenance.json'
        (self.root / 'source-verification.json').write_bytes((ROOT / 'reports/public-qa-grounding-verification-20261005.json').read_bytes())
        (self.root / 'source-provenance.json').write_bytes((ROOT / '.local/public-training/grounding/20261005/public-qa-grounding-20261005-r4/provenance.json').read_bytes())
        def verify(doc, target=identity, output=None):
            provenance.write_text(json.dumps(doc), encoding='utf-8')
            return cont.verify_grounding_provenance(provenance, source_dir, target, output or self.root / 'new-output',
                                                   expected_digest=cont.sha256_file(provenance), enforce_paths=False)
        lineage = verify(document)
        self.assertEqual(lineage['sourceOptimizerUpdates'], 60)
        self.assertEqual(lineage['sourceGlobalStep'], 20)
        self.assertFalse(lineage['optimizerStateLoaded'])
        for key, value, error in [('sourceRunId', 'other', 'source_provenance'),
                                  ('sourceGlobalStep', 60, 'source_provenance'),
                                  ('sourceOptimizerHistoryUpdates', 20, 'source_provenance'),
                                  ('optimizerReset', False, 'reset_boundary')]:
            with self.assertRaisesRegex(ValueError, error):
                verify({**document, key: value})
        for key, value in [('learningRate', 0.0001), ('maxSteps', 40), ('rank', 16)]:
            altered = {**identity, key: value}
            with self.assertRaisesRegex(ValueError, 'target_identity'):
                verify({**document, 'targetIdentity': altered}, altered)
        (self.root / 'existing-output').mkdir()
        with self.assertRaisesRegex(ValueError, 'reuse_forbidden'):
            verify(document, output=self.root / 'existing-output')
        (self.root / 'source-verification.json').write_text('{}', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'source_evidence_changed'):
            verify(document)


if __name__ == '__main__':
    unittest.main()
