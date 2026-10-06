"""Explicit, hash-pinned transitions for the bounded public QA stages.

This is an operator-recorded compatibility decision, not third-party approval.
The original checkpoint retains its original identity and strict verification.
"""
import hashlib
import json
from pathlib import Path
import re

from training_artifacts import sha256_file, verify_checkpoint


STAGE_TWO_SOURCE_RUN_ID = "public-qa-resume-20260928-r1"
STAGE_TWO_SOURCE_RUNTIME_SHA256 = "9f2023fb402e5975cd2a1f27eae927833f5ae29d8a3bd4709045dd4274e0e539"
STAGE_TWO_SOURCE_RUNTIME_FILES = {
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
STAGE_TWO_CHANGED_RUNTIME_FILES = {
    "train-public-qa.py", "public_qa_resume.py", "resource-pilot.py",
}
LOCAL_RUNTIME_FILE_NAMES = {
    "public_qa_cuda_runtime.py": "public-qa-cuda-runtime.py",
    "public_qa_kbit.py": "public-qa-kbit.py",
    "public_qa_memory_gate.py": "public-qa-memory-gate.py",
    "public_qa_resume.py": "public-qa-resume.py",
    "public_qa_thermal.py": "public-qa-thermal.py",
    "resource-pilot.py": "public-qa-resource-pilot.py",
    "train-foundation-lora.py": "train-foundation-lora.py",
    "train-public-qa.py": "train-public-qa.py",
    "training_artifacts.py": "training_artifacts.py",
}
STAGE_TWO_SOURCE_IDENTITY = {
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
STAGE_TWO_EXTENSION = {
    "kind": "bounded_max_steps_extension",
    "fromStage": "public_qa_stage1",
    "toStage": "public_qa_stage2",
    "fromMaxSteps": 20,
    "toMaxSteps": 40,
    "reason": "trainer_dynamic_padding_selective_completion_logits_stage2_resume_verifier_and_resource_pilot",
}
REQUIRED_RESUME_FILES = {
    "adapter_config.json", "adapter_model.safetensors", "trainer_state.json",
    "optimizer.pt", "scheduler.pt", "rng_state.pth", "scaler.pt",
    "training_args.bin",
}


def _same_json_value(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(_same_json_value(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(_same_json_value(a, b) for a, b in zip(left, right))
    return left == right


def _runtime_file_paths():
    root = Path(__file__).resolve().parent
    result = {}
    for runtime_name, local_name in LOCAL_RUNTIME_FILE_NAMES.items():
        runtime_path = root / runtime_name
        result[runtime_name] = runtime_path if runtime_path.is_file() else root / local_name
    return result


def _current_runtime_hashes():
    paths = _runtime_file_paths()
    if set(paths) != set(STAGE_TWO_SOURCE_RUNTIME_FILES):
        raise ValueError("resume_extension_runtime_inventory_invalid")
    result = {}
    for name in STAGE_TWO_SOURCE_RUNTIME_FILES:
        path = Path(paths[name])
        if not path.is_file():
            raise ValueError(f"resume_extension_runtime_file_missing:{name}")
        result[name] = sha256_file(path)
    return result


def validate_resume_paths(checkpoint_path, output_path, lineage=None):
    checkpoint, output = Path(checkpoint_path).resolve(), Path(output_path).resolve()
    root = Path("/checkpoints").resolve()
    if not output.is_relative_to(root):
        raise ValueError("training_output_path_invalid")
    if lineage is None:
        if not checkpoint.is_relative_to(output):
            raise ValueError("checkpoint_path_invalid")
    elif lineage.get("schemaVersion") == 2:
        source_id = lineage.get("sourceRunId", "")
        target_id = lineage.get("targetRunId", "")
        if source_id != STAGE_TWO_SOURCE_RUN_ID or lineage.get("sourceGlobalStep") != 20:
            raise ValueError("resume_source_scope_invalid")
        expected_checkpoint = root / "runs" / source_id / "checkpoint-20"
        expected_output = root / "runs" / target_id
        if checkpoint != expected_checkpoint:
            raise ValueError("resume_source_checkpoint_path_invalid")
        if output != expected_output or target_id == source_id:
            raise ValueError("resume_target_output_path_invalid")
        if output.exists():
            raise ValueError("resume_target_output_exists")
    else:
        source_id = lineage.get("sourceRunId", "")
        if not re.fullmatch(r"public-qa-[a-z0-9-]{1,35}", source_id) or lineage.get("sourceGlobalStep") != 5:
            raise ValueError("resume_source_scope_invalid")
        expected = root / "runs" / source_id / "checkpoint-5"
        if checkpoint != expected or output.is_relative_to(expected.parent):
            raise ValueError("resume_source_checkpoint_path_invalid")


def _verify_checkpoint(checkpoint_path, source, marker_sha256, source_step):
    checkpoint = Path(checkpoint_path)
    if not isinstance(marker_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", marker_sha256) or sha256_file(checkpoint / "checkpoint-complete.json") != marker_sha256:
        raise ValueError("resume_source_marker_changed")
    marker = verify_checkpoint(checkpoint, source)
    if not REQUIRED_RESUME_FILES <= {item["path"] for item in marker["files"]} or marker["globalStep"] != source_step:
        raise ValueError("resume_source_state_incomplete")
    return marker


def _verify_initial_resume(checkpoint_path, target_identity, document, digest):
    fields = {"schemaVersion", "sourceIdentity", "targetIdentity", "sourceCheckpointMarkerSha256", "sourceRunId", "sourceGlobalStep", "allowedCodeChanges"}
    if set(document) != fields or document["schemaVersion"] != 1:
        raise ValueError("resume_provenance_schema_invalid")
    source, target = document["sourceIdentity"], document["targetIdentity"]
    if not isinstance(source, dict) or not isinstance(target, dict) or target != target_identity:
        raise ValueError("resume_target_identity_mismatch")
    if set(source) != set(target) or source.get("stage") != "public_qa_stage1" or target.get("stage") != "public_qa_stage1" or source.get("maxSteps") != 20 or target.get("maxSteps") != 20:
        raise ValueError("resume_identity_scope_invalid")
    allowed = {"trainerSha256", "artifactHelperSha256"}
    changes = document["allowedCodeChanges"]
    if not isinstance(changes, dict) or set(changes) != allowed:
        raise ValueError("resume_code_changes_invalid")
    for key in source:
        if key not in allowed:
            if source[key] != target[key]:
                raise ValueError("resume_noncode_identity_changed")
        else:
            if not all(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) for value in (source[key], target[key])) or source[key] == target[key] or changes[key] != {"from": source[key], "to": target[key]}:
                raise ValueError("resume_code_pair_mismatch")
    if type(document["sourceGlobalStep"]) is not int or document["sourceGlobalStep"] != 5 or not isinstance(document["sourceRunId"], str) or not re.fullmatch(r"public-qa-[a-z0-9-]{1,35}", document["sourceRunId"]):
        raise ValueError("resume_source_scope_invalid")
    marker = _verify_checkpoint(checkpoint_path, source, document["sourceCheckpointMarkerSha256"], document["sourceGlobalStep"])
    return {"provenanceSha256": digest, "sourceRunId": document["sourceRunId"], "sourceCheckpointMarkerSha256": document["sourceCheckpointMarkerSha256"], "sourceGlobalStep": marker["globalStep"], "sourceIdentity": source}


def _verify_stage_two_extension(checkpoint_path, target_identity, document, digest):
    fields = {
        "schemaVersion", "sourceIdentity", "targetIdentity",
        "sourceCheckpointMarkerSha256", "sourceRunId", "targetRunId",
        "sourceGlobalStep", "allowedCodeChanges", "sourceRuntimeSha256",
        "sourceRuntimeFiles", "targetRuntimeFiles",
        "allowedRuntimeCodeChanges", "extension",
    }
    if set(document) != fields or document.get("schemaVersion") != 2:
        raise ValueError("resume_provenance_schema_invalid")
    source, target = document["sourceIdentity"], document["targetIdentity"]
    if not _same_json_value(source, STAGE_TWO_SOURCE_IDENTITY):
        raise ValueError("resume_extension_source_identity_invalid")
    if not isinstance(target, dict) or not _same_json_value(target, target_identity) or set(target) != set(source):
        raise ValueError("resume_target_identity_mismatch")
    changes = document["allowedCodeChanges"]
    if not isinstance(changes, dict) or set(changes) != {"trainerSha256"}:
        raise ValueError("resume_extension_code_changes_invalid")
    if document["sourceRuntimeSha256"] != STAGE_TWO_SOURCE_RUNTIME_SHA256 or not _same_json_value(document["sourceRuntimeFiles"], STAGE_TWO_SOURCE_RUNTIME_FILES):
        raise ValueError("resume_extension_source_runtime_invalid")
    target_runtime = document["targetRuntimeFiles"]
    runtime_changes = document["allowedRuntimeCodeChanges"]
    if not isinstance(target_runtime, dict) or set(target_runtime) != set(STAGE_TWO_SOURCE_RUNTIME_FILES) or not all(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) for value in target_runtime.values()):
        raise ValueError("resume_extension_runtime_changes_invalid")
    if not isinstance(runtime_changes, dict) or set(runtime_changes) != STAGE_TWO_CHANGED_RUNTIME_FILES:
        raise ValueError("resume_extension_runtime_changes_invalid")
    for name, source_digest in STAGE_TWO_SOURCE_RUNTIME_FILES.items():
        target_digest = target_runtime[name]
        if name in STAGE_TWO_CHANGED_RUNTIME_FILES:
            expected_change = {"from": source_digest, "to": target_digest}
            if target_digest == source_digest or not _same_json_value(runtime_changes[name], expected_change):
                raise ValueError("resume_extension_runtime_changes_invalid")
        elif target_digest != source_digest:
            raise ValueError("resume_extension_runtime_changes_invalid")
    current_runtime = _current_runtime_hashes()
    for name, runtime_digest in target_runtime.items():
        if current_runtime[name] != runtime_digest:
            raise ValueError(f"resume_extension_runtime_file_changed:{name}")
    expected_target = {
        **source,
        "stage": "public_qa_stage2",
        "maxSteps": 40,
        "trainerSha256": target.get("trainerSha256"),
    }
    if not _same_json_value(target, expected_target):
        raise ValueError("resume_extension_identity_changed")
    trainer_pair = (source["trainerSha256"], target["trainerSha256"])
    if not all(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) for value in trainer_pair) or trainer_pair[0] == trainer_pair[1]:
        raise ValueError("resume_extension_trainer_pair_mismatch")
    if not _same_json_value(changes["trainerSha256"], {"from": trainer_pair[0], "to": trainer_pair[1]}):
        raise ValueError("resume_extension_trainer_pair_mismatch")
    if target["trainerSha256"] != target_runtime["train-public-qa.py"]:
        raise ValueError("resume_extension_trainer_runtime_mismatch")
    if not _same_json_value(document["extension"], STAGE_TWO_EXTENSION):
        raise ValueError("resume_extension_contract_invalid")
    if type(document["sourceGlobalStep"]) is not int or document["sourceGlobalStep"] != 20:
        raise ValueError("resume_extension_source_scope_invalid")
    source_run = document["sourceRunId"]
    target_run = document["targetRunId"]
    if source_run != STAGE_TWO_SOURCE_RUN_ID or not isinstance(target_run, str) or not re.fullmatch(r"public-qa-stage2-[a-z0-9-]{1,28}", target_run) or target_run == source_run:
        raise ValueError("resume_extension_run_scope_invalid")
    marker = _verify_checkpoint(checkpoint_path, source, document["sourceCheckpointMarkerSha256"], 20)
    return {
        "schemaVersion": 2,
        "provenanceSha256": digest,
        "sourceRunId": source_run,
        "targetRunId": target_run,
        "sourceCheckpointMarkerSha256": document["sourceCheckpointMarkerSha256"],
        "sourceGlobalStep": marker["globalStep"],
        "sourceIdentity": source,
        "sourceRuntimeSha256": document["sourceRuntimeSha256"],
        "sourceRuntimeFiles": document["sourceRuntimeFiles"],
        "targetRuntimeFiles": target_runtime,
        "allowedRuntimeCodeChanges": runtime_changes,
        "extension": document["extension"],
    }


def verify_resume_provenance(checkpoint_path, target_identity, provenance_path, expected_sha256):
    raw = Path(provenance_path).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256) or digest != expected_sha256:
        raise ValueError("resume_provenance_digest_mismatch")
    document = json.loads(raw)
    if not isinstance(document, dict):
        raise ValueError("resume_provenance_schema_invalid")
    if document.get("schemaVersion") == 1:
        return _verify_initial_resume(checkpoint_path, target_identity, document, digest)
    if document.get("schemaVersion") == 2:
        return _verify_stage_two_extension(checkpoint_path, target_identity, document, digest)
    raise ValueError("resume_provenance_schema_invalid")
