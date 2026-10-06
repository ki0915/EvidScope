import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from training_artifacts import atomic_json, seal_checkpoint, verify_checkpoint, seal_candidate, verify_candidate, canonical_hash, inventory
spec=importlib.util.spec_from_file_location("paired",ROOT/"scripts/training-paired-eval.py")
paired=importlib.util.module_from_spec(spec);spec.loader.exec_module(paired)

class ArtifactsTests(unittest.TestCase):
    def test_inventory_order_is_portable_from_linux_to_windows(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in ("adapter_config.json", "README.md", "optimizer.pt"):
                (Path(directory) / name).write_bytes(b"same bytes")
            self.assertEqual([item["path"] for item in inventory(directory)], ["README.md", "adapter_config.json", "optimizer.pt"])
    def test_hash_numeric_subset_matches_javascript_and_rejects_unsupported_before_gpu(self):
        self.assertEqual(canonical_hash({"confidence":1.0}),canonical_hash({"confidence":1}))
        self.assertEqual(canonical_hash({"value":-0.0}),canonical_hash({"value":0}))
        for value in (0.7,9007199254740992,float("inf")):
            with self.assertRaisesRegex(ValueError,"numeric_format_unsupported"):canonical_hash({"value":value})
        self.assertEqual(paired.parse_output('{"confidence":0.7}'),{})
    def test_checkpoint_requires_complete_state_and_exact_resume_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);identity={"baseRevision":"a"*40,"datasetSha256":"b"*64}
            for name in ("adapter_config.json","adapter_model.safetensors","optimizer.pt","scheduler.pt","rng_state.pth"):(root/name).write_bytes(b"fixture")
            atomic_json(root/"trainer_state.json",{"global_step":10})
            seal_checkpoint(root,identity,10)
            self.assertEqual(verify_checkpoint(root,identity)["globalStep"],10)
            with self.assertRaisesRegex(ValueError,"identity_mismatch"):verify_checkpoint(root,{**identity,"datasetSha256":"c"*64})
            (root/"optimizer.pt").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError,"artifact_changed"):verify_checkpoint(root,identity)

    def test_partial_checkpoint_cannot_be_sealed_or_resumed(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory)/"adapter_model.safetensors.partial").write_bytes(b"partial")
            with self.assertRaisesRegex(ValueError,"partial_file"):seal_checkpoint(directory,{},10)
            with self.assertRaises(FileNotFoundError):verify_checkpoint(directory,{})

    def test_candidate_complete_marker_binds_receipt_and_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);identity={"baseRevision":"a"*40}
            for name in ("adapter_config.json","adapter_model.safetensors"):(root/name).write_bytes(b"fixture")
            atomic_json(root/"training-receipt.json",{"identity":identity,"globalStep":19,"status":"trained_candidate"})
            seal_candidate(root,identity,19,{})
            self.assertTrue(verify_candidate(root)["verified"])
            (root/"adapter_model.safetensors").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError,"artifact_changed"):verify_candidate(root)

    def test_synthetic_reviewed_data_never_becomes_real_quality_holdout(self):
        rows=[{"id":str(index),"split":"test","roleId":"evidence-organizer","synthetic":True,"humanReviewed":True} for index in range(100)]
        with self.assertRaisesRegex(ValueError,"nonsynthetic_heldout"):paired.heldout(rows,"evidence-organizer")
        self.assertEqual(paired.parse_output("<think>omitted</think>{\"summary\":\"한국어\"}"),{"summary":"한국어"})
        self.assertEqual(paired.parse_output("not JSON"),{})

if __name__=="__main__":unittest.main()
