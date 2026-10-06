"""Pure fixture admission checks; no model calls or execution-success proof."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
spec=importlib.util.spec_from_file_location('grounding_diagnostic',ROOT/'scripts/evaluate-public-qa-grounding.py')
runner=importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

class GroundingDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
    def tearDown(self):
        self.temp.cleanup()
    def fixture(self,mutate_report=None,mutate_binding=None):
        old=runner.legacy_runner()
        adapter=self.root/'candidate'
        adapter.mkdir()
        (adapter/'adapter_model.safetensors').write_bytes(b'fixture-only-not-model')
        provenance=self.root/'provenance.json'
        provenance.write_text('{"fixtureOnly":true}',encoding='utf-8')
        identity={'stage':'public_qa_grounding_v1','baseRevision':old.BASE_REVISION}
        candidate={'artifactSha256':'a'*64,'identity':identity}
        report={'verified':True,'actualTrainingExecutionVerified':True,'trainingRunCompleted':True,'terminationConfirmed':True,'runId':'public-qa-grounding-fixture-r2','globalStep':20,'actualOptimizerUpdates':20,'sourceOptimizerUpdates':40,'totalAdapterHistoryOptimizerUpdates':60,'optimizerStateRestored':False,'schedulerStateRestored':False,'qualityClaimAllowed':False,'promotionAllowed':False,'artifactSha256':candidate['artifactSha256'],'adapterSha256':runner.sha256_file(adapter/'adapter_model.safetensors'),'identity':identity,'controllerSha256':'b'*64}
        if mutate_report:
            mutate_report(report)
        verification=self.root/'verification.json'
        verification.write_text(json.dumps(report),encoding='utf-8')
        binding={'schemaVersion':1,'mode':'public_qa_grounding_diagnostic','sourceRunId':'public-qa-grounding-fixture-r2','sourceGlobalStep':20,'sourceOptimizerHistoryUpdates':60,'diagnosticOnly':True,'qualityClaimAllowed':False,'promotionAllowed':False,'evaluationScope':'retrospective_regression_diagnosis_on_previously_observed_64_rows','baselineExecutedThisRun':False,'priorResponsesSha256':runner.PRIOR_RESPONSES_SHA,'priorVerificationSha256':runner.PRIOR_VERIFICATION_SHA,'datasetSha256':old.DATA_SHA,'manifestSha256':old.MANIFEST_SHA,'artifactLockSha256':old.LOCK_SHA,'rows':64,'sourceVerificationSha256':runner.sha256_file(verification),'provenanceSha256':runner.sha256_file(provenance),'candidateMarkerSha256':candidate['artifactSha256'],'adapterSha256':report['adapterSha256'],'candidateIdentity':identity,'sourceControllerSha256':report['controllerSha256']}
        if mutate_binding:
            mutate_binding(binding)
        path=self.root/'binding.json'
        path.write_text(json.dumps(binding),encoding='utf-8')
        return (path,verification,provenance,adapter,runner.sha256_file(path)),candidate
    def test_reference_metadata_preserves_retrospective_and_candidate_only_scope(self):
        args,candidate=self.fixture()
        with patch.object(runner,'grounding_runner',return_value=SimpleNamespace(verify_grounding_artifacts=lambda *_:candidate)):
            binding=runner.verify_binding(*args)
        self.assertFalse(binding['baselineExecutedThisRun'])
        self.assertEqual(binding['sourceRunId'],'public-qa-grounding-fixture-r2')
    def test_training_failure_cannot_be_admitted_as_generation_source(self):
        args,candidate=self.fixture(mutate_report=lambda r:r.update(actualTrainingExecutionVerified=False))
        with patch.object(runner,'grounding_runner',return_value=SimpleNamespace(verify_grounding_artifacts=lambda *_:candidate)),self.assertRaisesRegex(ValueError,'source_execution_unverified'):
            runner.verify_binding(*args)
    def test_changed_reference_and_false_new_baseline_claim_rejected(self):
        args,_=self.fixture(mutate_binding=lambda b:b.update(baselineExecutedThisRun=True))
        with self.assertRaisesRegex(ValueError,'claim_invalid'):
            runner.verify_binding(*args)
    def test_foreign_adapter_digest_cannot_share_training_execution_receipt(self):
        args,candidate=self.fixture(mutate_binding=lambda b:b.update(adapterSha256='c'*64))
        with patch.object(runner,'grounding_runner',return_value=SimpleNamespace(verify_grounding_artifacts=lambda *_:candidate)),self.assertRaisesRegex(ValueError,'candidate_changed'):
            runner.verify_binding(*args)
    def test_full_context_preadmission_is_identical_to_prior_runner(self):
        old=runner.legacy_runner()
        self.assertEqual(old.MAX_OUTPUT,128)
        self.assertEqual(old.CONTEXT_BUDGET,1024)
        self.assertEqual(old.TIMEOUT,120)
        messages=old.messages_for({'question':'질문','context':'문서','isImpossible':True,'answers':[{'text':'비밀'}]})
        self.assertNotIn('비밀',json.dumps(messages,ensure_ascii=False))

if __name__=='__main__':
    unittest.main()
