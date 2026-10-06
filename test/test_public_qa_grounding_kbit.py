"""CPU dtype preparation fixtures; real BF16 CUDA support requires GPU probe."""
import importlib.util
from pathlib import Path
import unittest
import torch
from test_public_qa_kbit import TinyFourBitFixture

spec=importlib.util.spec_from_file_location('grounding_kbit',Path(__file__).resolve().parents[1]/'scripts/public-qa-grounding-kbit.py')
helper=importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)

class GroundingKbitTests(unittest.TestCase):
    def test_bf16_frozen_vocab_and_fp32_norm_without_changing_nf4(self):
        model=TinyFourBitFixture()
        helper.prepare_grounding_bf16_kbit(model)
        self.assertEqual(model.embedding.weight.dtype,torch.bfloat16)
        self.assertEqual(model.head.weight.dtype,torch.bfloat16)
        self.assertEqual(model.norm.weight.dtype,torch.float32)
        self.assertEqual(model.quantized.quant_type,'nf4')
        self.assertTrue(all(not p.requires_grad for p in model.parameters()))
    def test_nonfinite_or_unquantized_base_rejected(self):
        model=TinyFourBitFixture()
        model.is_loaded_in_4bit=False
        with self.assertRaisesRegex(ValueError,'loaded_4bit'):
            helper.prepare_grounding_bf16_kbit(model)
        model=TinyFourBitFixture()
        with torch.no_grad():
            model.head.weight[0,0]=float('nan')
        with self.assertRaisesRegex(ValueError,'nonfinite'):
            helper.prepare_grounding_bf16_kbit(model)

if __name__=='__main__':
    unittest.main()
