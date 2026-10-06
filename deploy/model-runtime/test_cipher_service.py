import importlib.util
from pathlib import Path
import unittest

def module(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

root = Path(__file__).parent
cipher = module("cipher", root / "cipher_service.py")
tls = module("frontend", root / "tls_frontend.py")
training = module("training", root.parent.parent / "scripts/train-foundation-lora.py")

class Tokenizer:
    def num_special_tokens_to_add(self, pair=False):
        return 2
    def encode(self, text, **_):
        return [ord(c) for c in text]
    def build_inputs_with_special_tokens(self, tokens):
        return [0, *tokens, 2]

class Tests(unittest.TestCase):
    def test_token_budget_overlap_and_unicode_tail(self):
        chunks = cipher.chunks_for_fields({"prompt": "a" * 1000 + "민"}, Tokenizer())
        self.assertTrue(all(len(c) <= 512 for c in chunks))
        self.assertEqual(chunks[0][-33:-1], chunks[1][1:33])
        seen = []
        def classify(ids):
            seen.extend(ids)
            return ("unsafe", "PII", .9) if ord("민") in ids else ("safe", None, .95)
        value = cipher.screen({"textFields": {"prompt": "a" * 1000 + "민"}}, Tokenizer(), classify)
        self.assertEqual(value["status"], "complete")
        self.assertEqual(value["safety"], "unsafe")
        self.assertEqual(value["categories"], ["PII"])
        self.assertNotIn("textFields", value)

    def test_long_input_is_explicitly_partial_not_safe(self):
        value = cipher.screen({"textFields": {"text": "a" * 6000}}, Tokenizer(), lambda _: ("safe", None, .99))
        self.assertEqual(value["processedChunks"], 8)
        self.assertGreater(value["totalChunks"], 8)
        self.assertEqual((value["status"], value["safety"], value["reason"]), ("partial", "unknown", "chunk_limit"))

    def test_deadline_and_invalid_input_never_claim_safe(self):
        ticks = iter([0, 11])
        value = cipher.screen({"textFields": {"prompt": "hello"}}, Tokenizer(), lambda _: self.fail("must not classify"), clock=lambda: next(ticks))
        self.assertEqual((value["status"], value["safety"]), ("timeout", "unknown"))
        value = cipher.screen({"textFields": {"text": "a" * 65537}}, Tokenizer(), lambda _: self.fail())
        self.assertEqual(value["reason"], "input_limit")
        self.assertEqual(cipher.screen({"textFields": {"text": ""}}, Tokenizer(), lambda _: self.fail())["reason"], "no_text")

    def test_privacy_worker_deadline_terminates_process(self):
        class Process:
            stopped = False
            def is_alive(self): return not self.stopped
            def terminate(self): self.stopped = True
            def join(self, _): pass
        class Connection:
            def send(self, _): pass
            def poll(self, _): return False
            def close(self): pass
        engine = cipher.Engine("unused")
        process = Process()
        engine.process, engine.connection = process, Connection()
        value = engine.run({"textFields": {"text": "ephemeral"}})
        self.assertEqual(value["status"], "timeout")
        self.assertTrue(process.stopped)
        self.assertIsNone(engine.process)

    def test_tls_routes_exclude_tools_and_arbitrary_proxy(self):
        self.assertFalse(tls.valid_request("/slots", {}))
        self.assertFalse(tls.valid_request("/v1/chat/completions", {"model": tls.PRIMARY, "messages": [{"role": "user", "content": "x"}], "stream": False, "max_tokens": 512, "tools": [{"type": "function"}]}))
        self.assertFalse(tls.valid_request("/v1/chat/completions", {"model": tls.PRIMARY, "messages": [{"role": "user", "content": "x"}], "stream": False, "max_tokens": 513}))

    def test_unreviewed_training_examples_fail_before_imports(self):
        value = training.admission([{"id": "unreviewed", "roleId": "evidence-organizer", "split": "tune", "synthetic": True, "humanReviewed": False}])
        self.assertFalse(value["admitted"])
        self.assertEqual(value["counts"], {"tune": 0, "validation": 0, "test": 0})

if __name__ == "__main__":
    unittest.main()
