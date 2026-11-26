"""CPU-only contract tests. Unit records are never exported as training proof."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
spec = importlib.util.spec_from_file_location('fresh_balanced_cpu',ROOT/'scripts/evaluate-public-qa-fresh.py')
fresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fresh)


class BalancedFreshTests(unittest.TestCase):
    def binding(self):
        return {'schemaVersion':1,'runId':fresh.BALANCED_RUN,'mode':fresh.MODE,'stage':fresh.BALANCED_STAGE,'sourceRunId':fresh.BALANCED_SOURCE,'sourceGlobalStep':20,'sourceOptimizerHistoryUpdates':100,'sourceTrainingExecutionVerified':True,'diagnosticOnly':True,'qualityClaimAllowed':False,'promotionAllowed':False,'localHumanReviewPerformed':False,'evaluationScope':fresh.SCOPE,'baselineExecutedThisRun':True,'executionOrder':['baseline','candidate'],'baselineKind':'fixed_reasoning_base_without_adapter','rows':128,'datasetSha256':fresh.BALANCED_DATA_SHA,'manifestSha256':fresh.BALANCED_MANIFEST_SHA,'artifactLockSha256':fresh.OLD.LOCK_SHA,**fresh.SOURCE_PINS,'criInspectionSha256':None,'sourceCompletionKind':'controller_normal_exit','candidateIdentity':{'stage':'public_qa_grounding_balanced_v1'}}

    def unit_records(self,directory):
        binding = self.binding()
        identity = binding['candidateIdentity']
        report = {key:True for key in ('verified','verificationPassed','actualTrainingExecutionVerified','sourceTrainingExecutionVerified','trainingRunCompleted','terminationConfirmed')}
        report.update(syntheticFixture=False,runId=fresh.BALANCED_SOURCE,globalStep=20,actualOptimizerUpdates=20,optimizerUpdatesThisRun=20,sourceOptimizerUpdates=80,totalAdapterHistoryOptimizerUpdates=100,optimizerStateRestored=False,schedulerStateRestored=False,qualityClaimAllowed=False,promotionAllowed=False,runtimeConfigMapSha256=binding['sourceRuntimeConfigMapSha256'],identity=identity,jobUid='unit-job',podUid='unit-pod')
        provenance = {'targetRunId':fresh.BALANCED_SOURCE,'targetIdentity':identity,'targetOptimizerSteps':20,'sourceOptimizerHistoryUpdates':80,'qualityClaimAllowed':False,'promotionAllowed':False}
        controller = {'runId':fresh.BALANCED_SOURCE,'terminationConfirmed':True,'jobUid':'unit-job','podUid':'unit-pod','state':'process_completed','exit':{'exitCode':0}}
        def write(name,value):
            path=directory/name;path.write_text(json.dumps(value),encoding='utf-8');return path
        controller_path = write('controller.json',controller)
        binding['sourceControllerSha256'] = fresh.sha256_file(controller_path)
        report['controllerSha256'] = binding['sourceControllerSha256']
        report_path = write('verification.json',report);provenance_path = write('provenance.json',provenance)
        binding.update(sourceVerificationSha256=fresh.sha256_file(report_path),provenanceSha256=fresh.sha256_file(provenance_path))
        return binding,report,report_path,provenance_path

    def test_r2_blind_uses_its_own_frozen_rows_without_label_prompts(self):
        root=ROOT/'.local/public-training/grounding-balanced/20261006/attempt-r2/blind-evaluation'
        rows,metadata=fresh.verify_data(root/'data.jsonl',root/'manifest.json',self.binding())
        self.assertEqual(len(rows),128)
        self.assertEqual(metadata['plannedTrainingRunId'],fresh.BALANCED_SOURCE)
        self.assertEqual(fresh.generation_plan(rows),[(side,row['id']) for side in ('baseline','candidate') for row in rows])
        changed=copy.deepcopy(rows[0]);changed['answers']=[{'text':'SECRET','answer_start':0}];changed['isImpossible']=not changed['isImpossible']
        self.assertEqual(fresh.OLD.messages_for(rows[0]),fresh.OLD.messages_for(changed))
        with self.assertRaisesRegex(ValueError,'hash_mismatch'):
            fresh.verify_data(root/'data.jsonl',root/'manifest.json')
        self.assertNotIn('torch',fresh.__dict__)

    def test_normal_exit_does_not_read_absent_cri_but_still_checks_candidate(self):
        with tempfile.TemporaryDirectory(prefix='balanced-fresh-unit-') as temporary:
            directory=Path(temporary);binding,_,report,provenance=self.unit_records(directory)
            with patch.object(fresh,'verify_candidate_directory') as candidate:
                self.assertEqual(fresh.verify_balanced_binding(binding,report,provenance,directory/'absent-cri.json',directory/'unit-candidate'),binding)
                candidate.assert_called_once()

    def test_fake_completed_flags_cannot_hide_wrong_optimizer_history(self):
        with tempfile.TemporaryDirectory(prefix='balanced-fresh-unit-') as temporary:
            directory=Path(temporary);binding,report,path,provenance=self.unit_records(directory)
            for key,value in (('actualOptimizerUpdates',19),('totalAdapterHistoryOptimizerUpdates',80),('trainingRunCompleted',False)):
                changed={**report,key:value};path.write_text(json.dumps(changed),encoding='utf-8');binding['sourceVerificationSha256']=fresh.sha256_file(path)
                with self.subTest(key=key),self.assertRaisesRegex(ValueError,'execution_unverified'):
                    fresh.verify_balanced_binding(binding,path,provenance,directory/'absent-cri.json',directory/'unit-candidate')

    def test_claimed_cri_reconciliation_cannot_use_missing_or_null_cri(self):
        binding=self.binding();binding['sourceCompletionKind']='cri_exit_reconciled'
        with self.assertRaisesRegex(ValueError,'source_pins_invalid'):
            fresh.evaluation_contract(binding)
        binding['criInspectionSha256']='a'*64
        with tempfile.TemporaryDirectory(prefix='balanced-fresh-unit-') as temporary:
            directory=Path(temporary);normal,_,report,provenance=self.unit_records(directory)
            normal.update(sourceCompletionKind='cri_exit_reconciled',criInspectionSha256='a'*64)
            with self.assertRaisesRegex(ValueError,'cri_changed'):
                fresh.verify_balanced_binding(normal,report,provenance,directory/'absent-cri.json',directory/'unit-candidate')


if __name__=='__main__':
    unittest.main()
