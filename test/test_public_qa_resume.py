import copy
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from training_artifacts import seal_checkpoint, sha256_file, verify_checkpoint
spec = importlib.util.spec_from_file_location("public_qa_resume", ROOT / "scripts/public-qa-resume.py")
resume = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resume)


class ResumeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.checkpoint = self.root / "checkpoint-5"
        self.checkpoint.mkdir()
        self.source = {"stage": "public_qa_stage1", "maxSteps": 20, "baseRevision": "model-revision", "datasetSha256": "data-digest", "trainerSha256": "a" * 64, "artifactHelperSha256": "b" * 64, "bindingHelperSha256": "e" * 64}
        self.target = {**self.source, "trainerSha256": "c" * 64, "artifactHelperSha256": "d" * 64}
        for filename in ("adapter_config.json", "adapter_model.safetensors", "optimizer.pt", "scheduler.pt", "rng_state.pth", "scaler.pt", "training_args.bin"):
            (self.checkpoint / filename).write_bytes(b"test fixture, not torch state")
        (self.checkpoint / "trainer_state.json").write_text(json.dumps({"global_step": 5}))
        seal_checkpoint(self.checkpoint, self.source, 5)
        self.document = {"schemaVersion": 1, "sourceIdentity": self.source, "targetIdentity": self.target, "sourceCheckpointMarkerSha256": sha256_file(self.checkpoint / "checkpoint-complete.json"), "sourceRunId": "public-qa-stage1-20260922-r2", "sourceGlobalStep": 5, "allowedCodeChanges": {key: {"from": self.source[key], "to": self.target[key]} for key in ("trainerSha256", "artifactHelperSha256")}}
        self.provenance = self.root / "resume.json"

    def verify(self, document=None, target=None):
        self.provenance.write_text(json.dumps(document or self.document), encoding="utf-8")
        return resume.verify_resume_provenance(self.checkpoint, target or self.target, self.provenance, sha256_file(self.provenance))

    def test_explicit_transition_keeps_original_strict_identity(self):
        result = self.verify()
        self.assertEqual(result["sourceGlobalStep"], 5)
        self.assertEqual(result["sourceIdentity"], self.source)
        verify_checkpoint(self.checkpoint, self.source)
        with self.assertRaisesRegex(ValueError, "identity_mismatch"):
            verify_checkpoint(self.checkpoint, self.target)

    def test_unpinned_or_changed_provenance_rejected(self):
        self.verify()
        for pinned in (None, "0" * 64):
            with self.assertRaisesRegex(ValueError, "digest_mismatch"):
                resume.verify_resume_provenance(self.checkpoint, self.target, self.provenance, pinned)

    def test_model_data_or_helper_changes_rejected(self):
        for key in ("baseRevision", "datasetSha256", "bindingHelperSha256"):
            document = copy.deepcopy(self.document)
            document["targetIdentity"][key] = "changed"
            with self.assertRaisesRegex(ValueError, "noncode_identity_changed"):
                self.verify(document, document["targetIdentity"])

    def test_actual_target_or_code_pair_mismatch_rejected(self):
        document = copy.deepcopy(self.document)
        document["allowedCodeChanges"]["trainerSha256"]["to"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "code_pair_mismatch"):
            self.verify(document)
        with self.assertRaisesRegex(ValueError, "target_identity_mismatch"):
            self.verify(target={**self.target, "trainerSha256": "f" * 64})

    def test_extra_allowed_field_rejected(self):
        document = copy.deepcopy(self.document)
        document["allowedCodeChanges"]["baseRevision"] = {"from": "x", "to": "y"}
        with self.assertRaisesRegex(ValueError, "code_changes_invalid"):
            self.verify(document)

    def test_marker_or_checkpoint_tamper_rejected(self):
        document = copy.deepcopy(self.document)
        document["sourceCheckpointMarkerSha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "source_marker_changed"):
            self.verify(document)
        (self.checkpoint / "optimizer.pt").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "artifact_changed"):
            self.verify()

    def test_wrong_source_step_or_target_budget_rejected(self):
        for value in (4, True, 20):
            document = copy.deepcopy(self.document)
            document["sourceGlobalStep"] = value
            with self.assertRaisesRegex(ValueError, "source_scope_invalid"):
                self.verify(document)
        document = copy.deepcopy(self.document)
        document["targetIdentity"]["maxSteps"] = 40
        with self.assertRaisesRegex(ValueError, "identity_scope_invalid"):
            self.verify(document, document["targetIdentity"])

    def test_scaler_required_even_if_old_sealer_accepts_absence(self):
        (self.checkpoint / "scaler.pt").unlink()
        (self.checkpoint / "checkpoint-complete.json").unlink()
        seal_checkpoint(self.checkpoint, self.source, 5)
        self.document["sourceCheckpointMarkerSha256"] = sha256_file(self.checkpoint / "checkpoint-complete.json")
        with self.assertRaisesRegex(ValueError, "source_state_incomplete"):
            self.verify()

    def test_provenance_allows_exact_parent_checkpoint_with_new_output(self):
        lineage = {"sourceRunId": "public-qa-stage1-20260922-r2", "sourceGlobalStep": 5}
        source = "/checkpoints/runs/public-qa-stage1-20260922-r2/checkpoint-5"
        output = "/checkpoints/runs/public-qa-stage1-resumed"
        resume.validate_resume_paths(source, output, lineage)
        for wrong in (source.replace("r2", "r9"), source.replace("checkpoint-5", "checkpoint-4"), "/tmp/checkpoint-5"):
            with self.assertRaisesRegex(ValueError, "source_checkpoint_path_invalid"):
                resume.validate_resume_paths(wrong, output, lineage)
        with self.assertRaisesRegex(ValueError, "source_checkpoint_path_invalid"):
            resume.validate_resume_paths(source, str(Path(source).parent), lineage)

    def test_ordinary_resume_cannot_escape_its_output(self):
        output = "/checkpoints/runs/public-qa-current"
        resume.validate_resume_paths(output + "/checkpoint-5", output)
        with self.assertRaisesRegex(ValueError, "checkpoint_path_invalid"):
            resume.validate_resume_paths("/checkpoints/runs/another/checkpoint-5", output)
        with self.assertRaisesRegex(ValueError, "output_path_invalid"):
            resume.validate_resume_paths("/tmp/checkpoint-5", "/tmp")


class StageTwoExtensionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.checkpoint = self.root / "checkpoint-20"
        self.checkpoint.mkdir()
        self.source = {
            "artifactHelperSha256": "e93572ffaebdc2d26531c904708f538ba8157206fc9ba218ba7a7e5a96f6604e",
            "baseArtifactLockSha256": "c067d1fe680e8f6dc14c592ade49a1d791ea6cb15ecbefeda52a609d5d922949",
            "baseRepository": "fdtn-ai/Foundation-Sec-8B-Reasoning",
            "baseRevision": "63c930c82d7646226d33502bec5870019738400e",
            "batchSize": 1,
            "bindingHelperSha256": "e6494f4f6cb212a0ce656bd7762ad32d2b111c3ce462942dff1ae59a448f391d",
            "datasetSha256": "21b4b91ad0f755de666fe2ebe9077f301477da6420ffa0195cb53b5189d2822f",
            "gpuMemoryFraction": 0.65,
            "gradientAccumulationSteps": 16,
            "image": "docker.io/evidscope/public-qa-training@sha256:440dbe10ff4e651296c65ff88f132077a4cbbb19054536b33c0695fdb5224be8",
            "learningRate": 0.0001,
            "manifestSha256": "9eba08dc67ec2cbb258f199879a2b0610a4c2979e3699a50dafc6bfee52a32ec",
            "maxSteps": 20,
            "rank": 8,
            "seed": 42,
            "sequenceLength": 1024,
            "stage": "public_qa_stage1",
            "trainerSha256": "419a5e8116b140ca9ef48f051d688d093f87b318f06f5a1cf91e683d1b803839",
        }
        self.source_runtime_files = {
            "public_qa_cuda_runtime.py": "7729a61f03c54307c979fa0f2285d07d2a205a0a5a5650ed0bf8fef726a84b59",
            "public_qa_kbit.py": "4d386a7959512f359477277802eae8b22541e96f1657ca3a15f3d2e0c72f8ef7",
            "public_qa_memory_gate.py": "1f0097d98bf8cab73589163b09ad44fc8091a40ba9540ab9960b3e33ed157c0b",
            "public_qa_resume.py": "2daeb060005d431bf42744d9eedc9a9e1b1b210bc17ab88c8a9df995e2ae7236",
            "public_qa_thermal.py": "eb6db0d1d94d7e0efc790acf0345aa8eb509507444cf8016e5c418c9b63bea98",
            "resource-pilot.py": "e1ae1d1b7fc0bfa64d11f69f34c50fe44291f653a2fb2ecab9516d878fa9ad5d",
            "train-foundation-lora.py": "e6494f4f6cb212a0ce656bd7762ad32d2b111c3ce462942dff1ae59a448f391d",
            "train-public-qa.py": "419a5e8116b140ca9ef48f051d688d093f87b318f06f5a1cf91e683d1b803839",
            "training_artifacts.py": "e93572ffaebdc2d26531c904708f538ba8157206fc9ba218ba7a7e5a96f6604e",
        }
        self.runtime_paths = {
            "public_qa_cuda_runtime.py": ROOT / "scripts/public-qa-cuda-runtime.py",
            "public_qa_kbit.py": ROOT / "scripts/public-qa-kbit.py",
            "public_qa_memory_gate.py": ROOT / "scripts/public-qa-memory-gate.py",
            "public_qa_resume.py": ROOT / "scripts/public-qa-resume.py",
            "public_qa_thermal.py": ROOT / "scripts/public-qa-thermal.py",
            "resource-pilot.py": ROOT / "scripts/public-qa-resource-pilot.py",
            "train-foundation-lora.py": ROOT / "scripts/train-foundation-lora.py",
            "train-public-qa.py": ROOT / "scripts/train-public-qa.py",
            "training_artifacts.py": ROOT / "scripts/training_artifacts.py",
        }
        self.target_runtime_files = {
            name: sha256_file(path) if name in {"train-public-qa.py", "public_qa_resume.py", "resource-pilot.py"} else digest
            for name, digest in self.source_runtime_files.items()
            for path in (self.runtime_paths[name],)
        }
        self.target = {
            **self.source,
            "maxSteps": 40,
            "stage": "public_qa_stage2",
            "trainerSha256": self.target_runtime_files["train-public-qa.py"],
        }
        for filename in ("adapter_config.json", "adapter_model.safetensors", "optimizer.pt", "scheduler.pt", "rng_state.pth", "scaler.pt", "training_args.bin"):
            (self.checkpoint / filename).write_bytes(b"sealed stage-one fixture")
        (self.checkpoint / "trainer_state.json").write_text(json.dumps({"global_step": 20}))
        seal_checkpoint(self.checkpoint, self.source, 20)
        self.document = {
            "schemaVersion": 2,
            "sourceIdentity": self.source,
            "targetIdentity": self.target,
            "sourceCheckpointMarkerSha256": sha256_file(self.checkpoint / "checkpoint-complete.json"),
            "sourceRunId": "public-qa-resume-20260928-r1",
            "targetRunId": "public-qa-stage2-20260929-r1",
            "sourceGlobalStep": 20,
            "allowedCodeChanges": {
                "trainerSha256": {"from": self.source["trainerSha256"], "to": self.target["trainerSha256"]},
            },
            "sourceRuntimeSha256": "9f2023fb402e5975cd2a1f27eae927833f5ae29d8a3bd4709045dd4274e0e539",
            "sourceRuntimeFiles": self.source_runtime_files,
            "targetRuntimeFiles": self.target_runtime_files,
            "allowedRuntimeCodeChanges": {
                name: {"from": self.source_runtime_files[name], "to": self.target_runtime_files[name]}
                for name in ("train-public-qa.py", "public_qa_resume.py", "resource-pilot.py")
            },
            "extension": {
                "kind": "bounded_max_steps_extension",
                "fromStage": "public_qa_stage1",
                "toStage": "public_qa_stage2",
                "fromMaxSteps": 20,
                "toMaxSteps": 40,
                "reason": "trainer_dynamic_padding_selective_completion_logits_stage2_resume_verifier_and_resource_pilot",
            },
        }
        self.provenance = self.root / "stage2-resume.json"

    def verify(self, document=None, target=None):
        value = self.document if document is None else document
        self.provenance.write_text(json.dumps(value), encoding="utf-8")
        return resume.verify_resume_provenance(
            self.checkpoint,
            self.target if target is None else target,
            self.provenance,
            sha256_file(self.provenance),
        )

    def test_exact_stage_one_to_stage_two_extension_is_accepted(self):
        result = self.verify()
        self.assertEqual(result["sourceGlobalStep"], 20)
        self.assertEqual(result["sourceRunId"], "public-qa-resume-20260928-r1")
        self.assertEqual(result["targetRunId"], "public-qa-stage2-20260929-r1")
        self.assertEqual(result["extension"], self.document["extension"])
        self.assertEqual(result["sourceRuntimeSha256"], self.document["sourceRuntimeSha256"])
        self.assertEqual(result["targetRuntimeFiles"], self.target_runtime_files)

    def test_all_model_data_image_and_hyperparameter_pins_are_exact(self):
        immutable = set(self.source) - {"trainerSha256", "stage", "maxSteps"}
        for key in immutable:
            document = copy.deepcopy(self.document)
            value = document["targetIdentity"][key]
            document["targetIdentity"][key] = "changed" if not isinstance(value, (int, float)) else value + 1
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "extension_identity_changed"):
                self.verify(document, document["targetIdentity"])
        document = copy.deepcopy(self.document)
        document["targetIdentity"]["batchSize"] = True
        with self.assertRaisesRegex(ValueError, "extension_identity_changed"):
            self.verify(document, document["targetIdentity"])

    def test_source_identity_is_the_exact_completed_stage_one_run(self):
        for key in ("baseRevision", "datasetSha256", "image", "rank", "trainerSha256", "maxSteps", "stage"):
            document = copy.deepcopy(self.document)
            value = document["sourceIdentity"][key]
            document["sourceIdentity"][key] = "changed" if not isinstance(value, int) else value + 1
            document["allowedCodeChanges"]["trainerSha256"]["from"] = document["sourceIdentity"]["trainerSha256"]
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "extension_source_identity_invalid"):
                self.verify(document)

    def test_only_the_exact_trainer_digest_pair_is_an_allowed_code_change(self):
        document = copy.deepcopy(self.document)
        document["targetIdentity"]["artifactHelperSha256"] = "7" * 64
        document["allowedCodeChanges"]["artifactHelperSha256"] = {
            "from": self.source["artifactHelperSha256"],
            "to": "7" * 64,
        }
        with self.assertRaisesRegex(ValueError, "extension_code_changes_invalid"):
            self.verify(document, document["targetIdentity"])
        document = copy.deepcopy(self.document)
        document["allowedCodeChanges"]["trainerSha256"]["to"] = "8" * 64
        with self.assertRaisesRegex(ValueError, "extension_trainer_pair_mismatch"):
            self.verify(document)
        document = copy.deepcopy(self.document)
        document["targetIdentity"]["trainerSha256"] = self.source["trainerSha256"]
        document["allowedCodeChanges"]["trainerSha256"]["to"] = self.source["trainerSha256"]
        with self.assertRaisesRegex(ValueError, "extension_trainer_pair_mismatch"):
            self.verify(document, document["targetIdentity"])

    def test_runtime_source_is_exactly_the_historical_controller_configmap(self):
        document = copy.deepcopy(self.document)
        document["sourceRuntimeSha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "extension_source_runtime_invalid"):
            self.verify(document)
        document = copy.deepcopy(self.document)
        document["sourceRuntimeFiles"]["public_qa_thermal.py"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "extension_source_runtime_invalid"):
            self.verify(document)

    def test_runtime_changes_are_exactly_the_three_approved_files(self):
        for mutation in ("missing", "extra", "wrong_pair"):
            document = copy.deepcopy(self.document)
            if mutation == "missing":
                del document["allowedRuntimeCodeChanges"]["resource-pilot.py"]
            elif mutation == "extra":
                document["allowedRuntimeCodeChanges"]["public_qa_thermal.py"] = {
                    "from": self.source_runtime_files["public_qa_thermal.py"],
                    "to": "0" * 64,
                }
            else:
                document["allowedRuntimeCodeChanges"]["train-public-qa.py"]["to"] = "0" * 64
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "extension_runtime_changes_invalid"):
                self.verify(document)

    def test_unchanged_runtime_file_cannot_be_relabelled(self):
        document = copy.deepcopy(self.document)
        document["targetRuntimeFiles"]["public_qa_thermal.py"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "extension_runtime_changes_invalid"):
            self.verify(document)

    def test_every_current_runtime_file_is_hashed_from_disk(self):
        runtime = self.root / "runtime"
        runtime.mkdir()
        paths = {}
        for name, source in self.runtime_paths.items():
            target = runtime / name
            shutil.copyfile(source, target)
            paths[name] = target
        with mock.patch.object(resume, "_runtime_file_paths", return_value=paths, create=True):
            self.verify()
            (runtime / "public_qa_thermal.py").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "extension_runtime_file_changed"):
                self.verify()

    def test_target_trainer_identity_is_bound_to_runtime_trainer(self):
        document = copy.deepcopy(self.document)
        document["targetIdentity"]["trainerSha256"] = "8" * 64
        document["allowedCodeChanges"]["trainerSha256"]["to"] = "8" * 64
        with self.assertRaisesRegex(ValueError, "extension_trainer_runtime_mismatch"):
            self.verify(document, document["targetIdentity"])

    def test_extension_fields_and_reason_are_closed_enums(self):
        mutations = {
            "kind": "unbounded_extension",
            "fromStage": "public_qa_stage2",
            "toStage": "public_qa_stage3",
            "fromMaxSteps": 40,
            "toMaxSteps": 60,
            "reason": "more_training",
        }
        for key, value in mutations.items():
            document = copy.deepcopy(self.document)
            document["extension"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "extension_contract_invalid"):
                self.verify(document)
        document = copy.deepcopy(self.document)
        document["extension"]["extra"] = True
        with self.assertRaisesRegex(ValueError, "extension_contract_invalid"):
            self.verify(document)
        document = copy.deepcopy(self.document)
        document["extension"]["fromMaxSteps"] = 20.0
        with self.assertRaisesRegex(ValueError, "extension_contract_invalid"):
            self.verify(document)

    def test_stage_two_cannot_be_used_as_a_parent_for_another_extension(self):
        document = copy.deepcopy(self.document)
        document["sourceIdentity"] = self.target
        document["sourceGlobalStep"] = 40
        document["targetIdentity"] = {**self.target, "stage": "public_qa_stage3", "maxSteps": 60, "trainerSha256": "9" * 64}
        document["allowedCodeChanges"]["trainerSha256"] = {"from": self.target["trainerSha256"], "to": "9" * 64}
        document["extension"].update(fromStage="public_qa_stage2", toStage="public_qa_stage3", fromMaxSteps=40, toMaxSteps=60)
        with self.assertRaisesRegex(ValueError, "extension_source_identity_invalid|extension_contract_invalid"):
            self.verify(document, document["targetIdentity"])

    def test_step_twenty_checkpoint_must_be_complete_sealed_and_untampered(self):
        document = copy.deepcopy(self.document)
        document["sourceGlobalStep"] = 19
        with self.assertRaisesRegex(ValueError, "extension_source_scope_invalid"):
            self.verify(document)
        (self.checkpoint / "optimizer.pt").write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "artifact_changed"):
            self.verify()

    def test_resealed_checkpoint_without_full_resume_state_is_rejected(self):
        (self.checkpoint / "scaler.pt").unlink()
        (self.checkpoint / "checkpoint-complete.json").unlink()
        seal_checkpoint(self.checkpoint, self.source, 20)
        self.document["sourceCheckpointMarkerSha256"] = sha256_file(self.checkpoint / "checkpoint-complete.json")
        with self.assertRaisesRegex(ValueError, "source_state_incomplete"):
            self.verify()

    def test_stage_two_paths_bind_exact_parent_and_new_target_run(self):
        lineage = self.verify()
        source = "/checkpoints/runs/public-qa-resume-20260928-r1/checkpoint-20"
        target = "/checkpoints/runs/public-qa-stage2-20260929-r1"
        resume.validate_resume_paths(source, target, lineage)
        for wrong in (
            source.replace("checkpoint-20", "checkpoint-10"),
            source.replace("public-qa-resume-20260928-r1", "public-qa-other"),
            "/tmp/checkpoint-20",
        ):
            with self.subTest(source=wrong), self.assertRaisesRegex(ValueError, "source_checkpoint_path_invalid"):
                resume.validate_resume_paths(wrong, target, lineage)
        for wrong in (
            "/checkpoints/runs/public-qa-stage2-other",
            "/checkpoints/runs/public-qa-resume-20260928-r1",
            "/tmp/public-qa-stage2-20260929-r1",
        ):
            with self.subTest(target=wrong), self.assertRaisesRegex(ValueError, "target_output_path_invalid|output_path_invalid"):
                resume.validate_resume_paths(source, wrong, lineage)
        with mock.patch.object(Path, "exists", return_value=True), self.assertRaisesRegex(ValueError, "target_output_exists"):
            resume.validate_resume_paths(source, target, lineage)

    def test_v2_schema_rejects_extra_fields_and_wrong_run_ids(self):
        document = copy.deepcopy(self.document)
        document["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "provenance_schema_invalid"):
            self.verify(document)
        for key, value in (("sourceRunId", "public-qa-stage2-foreign"), ("targetRunId", "public-qa-resume-20260928-r1")):
            document = copy.deepcopy(self.document)
            document[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "extension_run_scope_invalid"):
                self.verify(document)


if __name__ == "__main__":
    unittest.main()
