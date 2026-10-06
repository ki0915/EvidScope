import importlib.util
from pathlib import Path
import unittest

import torch
from bitsandbytes.nn import Params4bit

spec = importlib.util.spec_from_file_location("public_qa_kbit", Path(__file__).resolve().parents[1] / "scripts/public-qa-kbit.py")
kbit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kbit)


class TinyRMSNorm(torch.nn.Module):
    def __init__(self):
        super().__init__()
        self.weight = torch.nn.Parameter(torch.ones(8, dtype=torch.float16))


class TinyFourBitFixture(torch.nn.Module):
    """CPU preparation fixture, not a claim of executing a real quantized model."""
    def __init__(self):
        super().__init__()
        self.is_loaded_in_4bit = True
        self.embedding = torch.nn.Embedding(32, 8, dtype=torch.float16)
        self.head = torch.nn.Linear(8, 32, bias=False, dtype=torch.float16)
        self.norm = TinyRMSNorm()
        self.quantized = Params4bit(torch.zeros(8, 8), requires_grad=False, quant_type="nf4")
        self.checkpoint_settings = None

    def enable_input_require_grads(self):
        self.embedding.register_forward_hook(lambda _module, _inputs, output: output.requires_grad_(True))

    def gradient_checkpointing_enable(self, **kwargs):
        self.checkpoint_settings = kwargs


class KbitPreparationTests(unittest.TestCase):
    def test_only_norm_upcast_preserves_frozen_vocab_storage_and_quantization(self):
        model = TinyFourBitFixture()
        embed_ptr, head_ptr, quant_ptr = model.embedding.weight.data_ptr(), model.head.weight.data_ptr(), model.quantized.data_ptr()
        self.assertIs(kbit.prepare_memory_efficient_kbit(model), model)
        self.assertEqual(model.norm.weight.dtype, torch.float32)
        self.assertEqual(model.embedding.weight.dtype, torch.float16)
        self.assertEqual(model.head.weight.dtype, torch.float16)
        self.assertEqual((model.embedding.weight.data_ptr(), model.head.weight.data_ptr(), model.quantized.data_ptr()), (embed_ptr, head_ptr, quant_ptr))
        self.assertTrue(all(not p.requires_grad for p in model.parameters()))
        self.assertEqual(model.quantized.quant_type, "nf4")
        self.assertEqual(model.checkpoint_settings, {"gradient_checkpointing_kwargs": {"use_reentrant": True}})
        output = model.embedding(torch.tensor([1, 2]))
        self.assertTrue(output.requires_grad)
        output.float().sum().backward()
        self.assertIsNone(model.embedding.weight.grad)

    def test_unquantized_model_is_rejected(self):
        model = TinyFourBitFixture()
        model.is_loaded_in_4bit = False
        with self.assertRaisesRegex(ValueError, "loaded_4bit"):
            kbit.prepare_memory_efficient_kbit(model)
        model.is_loaded_in_4bit = True
        del model.quantized
        with self.assertRaisesRegex(ValueError, "actual_4bit"):
            kbit.prepare_memory_efficient_kbit(model)

    def test_nonfinite_original_weights_cannot_pass_preparation(self):
        model = TinyFourBitFixture()
        with torch.no_grad():
            model.embedding.weight[0, 0] = float("nan")
        with self.assertRaisesRegex(ValueError, "nonfinite"):
            kbit.prepare_memory_efficient_kbit(model)


if __name__ == "__main__":
    unittest.main()
