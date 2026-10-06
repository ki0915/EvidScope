"""CPU evidence guards for the frozen paired generation runner; no GPU calls."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
spec = importlib.util.spec_from_file_location('fresh_runner', ROOT/'scripts/evaluate-public-qa-fresh.py')
fresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fresh)

DATA_ROOT = ROOT/'.local/public-training/grounding-continuation/20261006/fresh-evaluation'
SOURCE_ROOT = ROOT/'.local/training/runs/public-qa-grounding-20261006-r3/candidate'
REPORT = ROOT/'reports/public-qa-grounding-continuation-verification-20261006.json'
PROVENANCE = ROOT/'.local/public-training/grounding-continuation/20261006/public-qa-grounding-20261006-r3/provenance.json'
CRI = ROOT/'.local/training/public-qa-run/continuation-preparation-20261006-r3/cri-inspect.json'


class FakeTokenizer:
    def __init__(self, long_question=None):
        self.long_question = long_question
        self.seen = []

    def apply_chat_template(self, messages, *, tokenize, add_generation_prompt):
        assert tokenize is True and add_generation_prompt is True
        self.seen.append(messages)
        user = json.loads(messages[1]['content'])
        return list(range(897 if user['question'] == self.long_question else 896))


class FreshTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows, cls.metadata = fresh.verify_data(DATA_ROOT/'data.jsonl', DATA_ROOT/'manifest.json')
        cls.report = fresh.read_json(REPORT)

    def binding(self):
        return {'schemaVersion':1,'mode':fresh.MODE,'stage':fresh.STAGE,'runId':'public-qa-fresh-20261006-r1','sourceRunId':fresh.SOURCE_RUN,'sourceGlobalStep':20,'sourceOptimizerHistoryUpdates':80,'sourceTrainingExecutionVerified':True,'diagnosticOnly':True,'qualityClaimAllowed':False,'promotionAllowed':False,'localHumanReviewPerformed':False,'evaluationScope':fresh.SCOPE,'baselineExecutedThisRun':True,'executionOrder':['baseline','candidate'],'baselineKind':'fixed_reasoning_base_without_adapter','datasetSha256':fresh.DATA_SHA,'manifestSha256':fresh.MANIFEST_SHA,'rows':128,'artifactLockSha256':fresh.OLD.LOCK_SHA,'candidateIdentity':self.report['identity'],**fresh.SOURCE_PINS}

    def verify(self, binding):
        (ROOT/'.test-runs').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='fresh-cpu-',dir=ROOT/'.test-runs') as temporary:
            path = Path(temporary)/'binding.json'
            path.write_text(json.dumps(binding,ensure_ascii=False),encoding='utf-8')
            return fresh.verify_binding(path,REPORT,PROVENANCE,CRI,SOURCE_ROOT,fresh.sha256_file(path))

    def test_actual_frozen_source_and_candidate(self):
        self.assertEqual(len(self.rows),128)
        self.assertEqual(self.verify(self.binding())['sourceOptimizerHistoryUpdates'],80)
        self.assertNotIn('torch', fresh.__dict__)

    def test_answer_and_impossible_labels_never_enter_prompt(self):
        original = self.rows[0]
        altered = copy.deepcopy(original)
        altered.update(answers=[{'text':'SECRET_LABEL_ONLY','answer_start':0}],isImpossible=not original['isImpossible'],originalQa={'question':'SECRET_ORIGINAL_ONLY'},familyId='SECRET_FAMILY_ONLY')
        self.assertEqual(fresh.OLD.messages_for(original),fresh.OLD.messages_for(altered))
        user = json.loads(fresh.OLD.messages_for(original)[1]['content'])
        self.assertEqual(set(user),{'question','document'})
        self.assertEqual(user['document'],original['context'])

    def test_full_admission_boundary_and_actual_prompt_binding(self):
        tokenizer = FakeTokenizer()
        inputs, records = fresh.preadmit(self.rows,tokenizer)
        fresh.require_all_admitted(self.rows,inputs,records)
        self.assertTrue(all(r['inputTokens']+128 == 1024 for r in records))
        self.assertEqual(records[0]['inputIdsSha256'],fresh.canonical_hash(inputs[self.rows[0]['id']]))
        self.assertEqual(records[0]['promptSha256'],fresh.canonical_hash(tokenizer.seen[0]))
        over = FakeTokenizer(self.rows[-1]['question'])
        inputs, records = fresh.preadmit(self.rows,over)
        self.assertEqual(len(inputs),127)
        with self.assertRaisesRegex(ValueError,'all_128'):
            fresh.require_all_admitted(self.rows,inputs,records)
        self.assertEqual(len(over.seen),128)

    def test_admission_identity_reordering_rejected(self):
        inputs, records = fresh.preadmit(self.rows,FakeTokenizer())
        records[0], records[1] = records[1], records[0]
        with self.assertRaisesRegex(ValueError,'identity_mismatch'):
            fresh.require_all_admitted(self.rows,inputs,records)

    def test_base_then_candidate_exact_sequence(self):
        plan = fresh.generation_plan(self.rows)
        self.assertEqual(len(plan),256)
        self.assertEqual(plan[:128],[('baseline',row['id']) for row in self.rows])
        self.assertEqual(plan[128:],[('candidate',row['id']) for row in self.rows])

    def test_observed_adapter_state_and_wrong_side_rejected(self):
        class Module:
            def __init__(self, disabled):
                self.disable_adapters = disabled
        class Model:
            def __init__(self, states):
                self.states = states
            def modules(self):
                return [Module(state) for state in self.states]
        self.assertTrue(fresh.observe_adapter_state(Model([True,True]),'baseline')['allAdapterModulesDisabled'])
        self.assertTrue(fresh.observe_adapter_state(Model([False,False]),'candidate')['allAdapterModulesEnabled'])
        for model, side in ((Model([False]),'baseline'),(Model([True]),'candidate'),(Model([True,False]),'baseline'),(Model([]),'candidate')):
            with self.assertRaisesRegex(ValueError,'adapter_state_mismatch'):
                fresh.observe_adapter_state(model,side)

    def test_binding_scope_and_claim_mutations(self):
        mutations = {'sourceRunId':'public-qa-grounding-20261006-r2','sourceOptimizerHistoryUpdates':60,'rows':64,'baselineExecutedThisRun':False,'executionOrder':['candidate','baseline'],'promotionAllowed':True,'artifactLockSha256':'0'*64,'sourceControllerSha256':'0'*64,'criInspectionSha256':'0'*64}
        for key, value in mutations.items():
            with self.subTest(key=key):
                binding = self.binding()
                binding[key] = value
                with self.assertRaises(ValueError):
                    self.verify(binding)

    def test_source_report_finite_and_history_guards(self):
        # Candidate validation is independently callable; the top-level verifier
        # additionally pins the exact independently generated report bytes.
        for mutate in ('finite','history','base'):
            report, binding = copy.deepcopy(self.report), self.binding()
            if mutate == 'finite':
                report['adapterTensorVerification']['allFinite'] = False
            elif mutate == 'history':
                binding['candidateIdentity'] = copy.deepcopy(binding['candidateIdentity'])
                binding['candidateIdentity']['stage'] = 'public_qa_grounding_v1'
            else:
                binding['candidateIdentity'] = copy.deepcopy(binding['candidateIdentity'])
                binding['candidateIdentity']['baseRevision'] = 'another_base'
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                fresh.verify_candidate_directory(SOURCE_ROOT,binding,report)

    def test_preserved_original_spans_and_privacy(self):
        for kind in ('span','privacy','duplicate','too_long'):
            rows, metadata = copy.deepcopy(self.rows), copy.deepcopy(self.metadata)
            if kind == 'span':
                rows[0]['answers'][0]['answer_start'] += 1
                rows[0]['originalQa']['answers'] = rows[0]['answers']
            elif kind == 'privacy':
                rows[0]['question'] += ' abc@example.com'
                rows[0]['originalQa']['question'] = rows[0]['question']
            elif kind == 'duplicate':
                rows[1]['familyId'] = rows[0]['familyId']
            else:
                rows[0]['context'] += 'x'*651
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                fresh.validate_rows(rows,metadata)

    def test_modified_pinned_data_and_new_output_guard(self):
        (ROOT/'.test-runs').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='fresh-guards-',dir=ROOT/'.test-runs') as temporary:
            directory = Path(temporary)
            data = directory/'data.jsonl'
            data.write_bytes((DATA_ROOT/'data.jsonl').read_bytes()+b'\n')
            with self.assertRaisesRegex(ValueError,'hash_mismatch'):
                fresh.verify_data(data,DATA_ROOT/'manifest.json')
            output = directory/'public-qa-fresh-cpu'
            self.assertEqual(fresh.OLD.output_path(output,root=directory),output)
            output.mkdir()
            with self.assertRaisesRegex(ValueError,'new_child'):
                fresh.OLD.output_path(output,root=directory)

    def test_cli_exact_defaults(self):
        args = fresh.parser().parse_args(['--output','/checkpoints/fresh-evaluations/public-qa-fresh-cpu'])
        self.assertEqual(args.data,'/data/fresh/data.jsonl')
        self.assertEqual(args.cri_inspection,'/bindings/cri-inspect.json')
        self.assertEqual(args.adapter_dir,'/adapters/candidate')
        self.assertFalse(args.token_check)


if __name__ == '__main__':
    unittest.main()
