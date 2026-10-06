import importlib.util
import json
from pathlib import Path
import sys
import unittest
import math
from copy import deepcopy
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
grounding=load('grounding',ROOT/'scripts/public-qa-grounding.py')
qa=load('qa',ROOT/'scripts/train-public-qa.py')

class Tokenizer:
    eos_token_id=2
    def apply_chat_template(self,messages,**_):
        return json.dumps(messages,ensure_ascii=False)+'<think>'
    def encode(self,text,**_):
        return [ord(c)+3 for c in text]

class GroundingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory=ROOT/'.local/public-training/grounding/20261005/public-qa-grounding-20261005-r4'
        cls.rows=grounding.read_rows(cls.directory/'data.jsonl')
        cls.manifest=json.loads((cls.directory/'manifest.json').read_text(encoding='utf-8'))
    def test_real_balanced_rows_are_exact_source_members(self):
        self.assertEqual(len(self.rows),704)
        grounding.verify_grounding_data(self.rows,self.manifest,self.directory/'manifest.json')
    def test_changed_context_rejected_even_with_preserved_human_provenance(self):
        rows=deepcopy(self.rows)
        rows[0]['context']+=' 변조'
        with self.assertRaisesRegex(ValueError,'original_row_changed'):
            grounding.verify_grounding_data(rows,self.manifest,self.directory/'manifest.json')
    def test_full_context_overflow_never_crops_or_drops_a_row(self):
        row=deepcopy(self.rows[0])
        row['context']='긴 문서'*500
        row['answers']=[]
        row['isImpossible']=True
        with self.assertRaisesRegex(ValueError,'full_context_exceeds_token_budget'):
            qa.encode_row(Tokenizer(),row,full_context=True)
        self.assertLess(qa.encode_row(Tokenizer(),row)[1]['contextEnd'],len(row['context']))
    def test_authentic_impossible_target_remains_empty_json(self):
        row=next(r for r in self.rows if r['isImpossible'])
        encoded,receipt=qa.encode_row(Tokenizer(),row,full_context=True)
        self.assertEqual(receipt['contextStart'],0)
        self.assertEqual(receipt['contextEnd'],len(row['context']))
        self.assertEqual(qa.target(row),{'answer':'','evidenceQuote':'','abstained':True})
    def test_pinned_source_candidate_and_fresh_state_provenance(self):
        provenance=self.directory/'provenance.json'
        document=json.loads(provenance.read_text(encoding='utf-8'))
        lineage=grounding.verify_grounding_provenance(provenance,ROOT/'.local/training/runs/public-qa-stage2-lowmem-20261005-r4/candidate',document['targetIdentity'],Path('/checkpoints/runs')/document['targetRunId'],expected_digest=grounding.sha256_file(provenance),enforce_paths=False)
        self.assertEqual(lineage['sourceOptimizerUpdates'],40)
        self.assertEqual(lineage['optimizerUpdatesThisExperiment'],0)
        self.assertFalse(lineage['optimizerStateLoaded'])
        self.assertFalse(lineage['schedulerStateLoaded'])
        identity={**document['targetIdentity'],'baseRevision':'f'*40}
        with self.assertRaisesRegex(ValueError,'target_identity_invalid'):
            grounding.verify_grounding_provenance(provenance,ROOT/'.local/training/runs/public-qa-stage2-lowmem-20261005-r4/candidate',identity,'unused',expected_digest=grounding.sha256_file(provenance),enforce_paths=False)

    def test_nonfinite_adapter_can_never_be_sealed(self):
        class Parameter:
            requires_grad=True
            dtype='torch.float32'
            def __init__(self,value): self.value=value
            def detach(self): return self
        torch=SimpleNamespace(isfinite=lambda p:SimpleNamespace(all=lambda:SimpleNamespace(item=lambda:math.isfinite(p.value))))
        model=SimpleNamespace(named_parameters=lambda:[('model.q_proj.lora_A.weight',Parameter(1.0))])
        self.assertTrue(qa.verify_finite_adapter(model,torch)['passed'])
        model=SimpleNamespace(named_parameters=lambda:[('model.q_proj.lora_A.weight',Parameter(float('nan')))])
        with self.assertRaisesRegex(RuntimeError,'nonfinite_adapter'):
            qa.verify_finite_adapter(model,torch)
        model=SimpleNamespace(named_parameters=lambda:[('model.embedding.weight',Parameter(1.0))])
        with self.assertRaisesRegex(RuntimeError,'trainable_adapter_inventory'):
            qa.verify_finite_adapter(model,torch)

if __name__=='__main__':
    unittest.main()
