"""CPU-only real Transformers/PyTorch test, intended for the pinned training image.

No downloads, CUDA, trainer execution, or source data/checkpoint mutations.
Missing runtime dependencies intentionally fail rather than silently skip.
"""
from functools import partial
import importlib.util
from pathlib import Path
import sys
import unittest

import torch
from torch.utils.data import DataLoader
from peft import LoraConfig, get_peft_model
from transformers import LlamaConfig, LlamaForCausalLM

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("public_qa", ROOT / "scripts/train-public-qa.py")
qa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qa)


class DynamicCollatorRuntimeTests(unittest.TestCase):
    def setUp(self):
        torch.set_num_threads(2)
        self.rows = [{"input_ids": [5, 6, 2], "attention_mask": [1, 1, 1], "labels": [-100, 6, 2]}, {"input_ids": [7, 8, 9, 10, 2], "attention_mask": [1] * 5, "labels": [-100, -100, 9, 10, 2]}]
        self.collator = partial(qa.collate_rows, pad_token_id=2)

    def tiny_lora_model(self):
        model = LlamaForCausalLM(LlamaConfig(vocab_size=32, hidden_size=8, intermediate_size=16, num_hidden_layers=1, num_attention_heads=1, num_key_value_heads=1, max_position_embeddings=16, pad_token_id=2, bos_token_id=1, eos_token_id=2, attention_dropout=0.0, use_cache=False))
        return get_peft_model(model, LoraConfig(r=2, lora_alpha=4, lora_dropout=0.0, target_modules=["q_proj", "k_proj", "v_proj", "o_proj"], bias="none", task_type="CAUSAL_LM"))

    def test_real_dataloader_and_default_collator_produce_selective_long_tensors(self):
        batches = list(DataLoader(self.rows, batch_size=1, collate_fn=self.collator))
        self.assertEqual([tuple(batch["input_ids"].shape) for batch in batches], [(1, 3), (1, 5)])
        for batch in batches:
            for key in ("input_ids", "attention_mask", "labels", "logits_to_keep", "shift_labels"):
                self.assertEqual(batch[key].dtype, torch.long)
        self.assertEqual(batches[0]["logits_to_keep"].tolist(), [0, 1])
        self.assertEqual(batches[0]["shift_labels"].tolist(), [[6, 2]])
        self.assertEqual(batches[1]["logits_to_keep"].tolist(), [1, 2, 3])
        self.assertEqual(batches[1]["shift_labels"].tolist(), [[9, 10, 2]])
        with self.assertRaisesRegex(ValueError, "batch_size_one_required"):
            next(iter(DataLoader(self.rows, batch_size=2, collate_fn=self.collator)))

    def test_selective_logits_match_full_loss_and_trainable_gradients_on_cpu(self):
        torch.manual_seed(42)
        model = self.tiny_lora_model()
        model.train()
        selective = self.collator([self.rows[1]])
        full = {key: selective[key] for key in ("input_ids", "attention_mask", "labels")}
        previous = model(**full)
        previous.loss.backward()
        gradients = {name: parameter.grad.clone() for name, parameter in model.named_parameters() if parameter.requires_grad and parameter.grad is not None}
        model.zero_grad(set_to_none=True)
        current = model(**selective)
        current.loss.backward()
        torch.testing.assert_close(current.loss, previous.loss, rtol=1e-6, atol=1e-7)
        torch.testing.assert_close(current.logits, previous.logits.index_select(1, selective["logits_to_keep"]), rtol=1e-6, atol=1e-7)
        for name, parameter in model.named_parameters():
            if name in gradients:
                torch.testing.assert_close(gradients[name], parameter.grad, rtol=1e-5, atol=1e-7)
        self.assertTrue(all(tensor.device.type == "cpu" for tensor in selective.values()))

    def test_zero_learning_rate_pilot_step_keeps_trainable_parameters_unchanged(self):
        torch.manual_seed(42)
        model = self.tiny_lora_model()
        model.train()
        trainable = {name: parameter for name, parameter in model.named_parameters() if parameter.requires_grad}
        original = {name: parameter.detach().clone() for name, parameter in trainable.items()}
        optimizer = torch.optim.AdamW(trainable.values(), lr=0)
        optimizer.zero_grad()
        model(**self.collator([self.rows[1]])).loss.backward()
        optimizer.step()
        for name, parameter in trainable.items():
            self.assertTrue(torch.equal(original[name], parameter.detach()), name)


if __name__ == "__main__":
    unittest.main()
