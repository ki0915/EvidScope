"""Authentic balanced public QA admission and explicit adapter-only warmstart."""
import hashlib
import json
import os
from pathlib import Path
import re
from training_artifacts import sha256_file, inventory

STAGE = 'public_qa_grounding_v1'
SOURCE_RUN = 'public-qa-stage2-lowmem-20261005-r4'
BASE_REVISION = '63c930c82d7646226d33502bec5870019738400e'
PINS = {'marker': 'a6f152d43c2ae481277650b094a8c416f9c99bbe74ea962fd6ed2bf485b899ea', 'adapter': 'd7ab9fe25bed50ef85d8038f3493edfff3c1e492aa26f16945842935298f0c19', 'controller': '10a6f18485608964af7674bc3ac51b97cb5f07258e99fbef767c4337774a06f6', 'verification': '5a69fa9345c234f57f29787285a7cec8aec852392226cbbf7fc6d076447db3e9'}
SOURCE_PINS = {'sourceManifest': 'c412bc1f048a33351be60ce8a4395bcf9d5a160d58047decc380a8c2197db14c', 'sourceTrain': 'e050f9d529ce8932714b5a4fcb7e6e599b76c2ef8ef7c2108a8ba06173b1a855', 'sourceValidation': 'f0ab6e2774ea94926cabe6ef281a353f304717b7ed0845ab3ce5134c823b20ad', 'oldTraining': '21b4b91ad0f755de666fe2ebe9077f301477da6420ffa0195cb53b5189d2822f', 'diagnostic': '50561634095f758781c4695fcc30e2d7bd7cf7d9b937d8c10174a3e927c837f9'}
SOURCE_FILES = {'sourceManifest':'source-manifest.json','sourceTrain':'source-train.jsonl','sourceValidation':'source-validation.jsonl','oldTraining':'old-training.jsonl','diagnostic':'diagnostic.jsonl'}

def require(value, message):
    if not value:
        raise ValueError(message)

def read_rows(path):
    return [json.loads(line) for line in Path(path).read_text(encoding='utf-8').splitlines() if line.strip()]

def verify_grounding_data(rows, manifest, manifest_path):
    require(manifest.get('stage') == STAGE and manifest.get('sourcePins') == SOURCE_PINS and manifest.get('sourceFiles') == SOURCE_FILES, 'grounding_dataset_identity_invalid')
    require(manifest.get('counts') == {'train':640,'validation':64} and manifest.get('labelCounts') == {'train':{'answerable':320,'impossible':320},'validation':{'answerable':32,'impossible':32}}, 'grounding_balance_invalid')
    require(manifest.get('selection') == {'maxContextCodepoints':650,'fullContextPreserved':True,'answerBasedCropping':False,'actualTokenizerPreadmissionRequired':True} and manifest.get('previousExposureOverlap') == {'id':0,'family':0,'context':0}, 'grounding_context_policy_invalid')
    require(manifest.get('heldoutUsed') is False and manifest.get('localHumanReviewPerformed') is False and manifest.get('qualityClaimAllowed') is False and manifest.get('promotionAllowed') is False, 'grounding_claim_boundary_invalid')
    root = Path(manifest_path).resolve().parent
    paths = {key:root/name for key,name in SOURCE_FILES.items()}
    for key,path in paths.items():
        require(path.is_file() and not path.is_symlink() and sha256_file(path) == SOURCE_PINS[key], 'grounding_source_changed:'+key)
    original = {row['id']:row for key in ('sourceTrain','sourceValidation') for row in read_rows(paths[key])}
    exclusions = read_rows(paths['oldTraining']) + read_rows(paths['diagnostic'])
    forbidden = {key:{r[key] for r in exclusions} for key in ('id','familyId','contextSha256')}
    seen, families, contexts = set(), {}, {}
    for row in rows:
        source = {key:value for key,value in row.items() if key not in ('stage','contextSelection','localHumanReviewPerformed','privacyScreen')}
        require(row.get('id') not in seen and source == original.get(row.get('id')), 'grounding_original_row_changed')
        require(row.get('stage') == STAGE and row.get('contextSelection') == 'full_original_context' and row.get('privacyScreen') == {'kind':'basic_email_mobile_resident_id_regex','passed':True,'comprehensivePrivacyReview':False}, 'grounding_row_policy_invalid')
        require(len(row['context']) <= 650 and len(row['question']) <= 240, 'grounding_context_limit_invalid')
        require(not any(row[key] in forbidden[key] for key in forbidden), 'grounding_previous_exposure_leakage')
        for key,mapping in [('familyId',families),('contextSha256',contexts)]:
            require(row[key] not in mapping or mapping[row[key]] == row['split'], 'grounding_split_leakage')
            mapping[row[key]] = row['split']
        seen.add(row['id'])
    for split, per_label in [('train',320),('validation',32)]:
        for impossible in (True,False):
            require(sum(r['split']==split and r['isImpossible'] is impossible for r in rows)==per_label, 'grounding_actual_balance_invalid')
    return manifest

def verify_source_candidate(directory):
    root = Path(directory)
    require(root.is_dir() and not root.is_symlink() and sha256_file(root/'candidate-complete.json') == PINS['marker'], 'grounding_source_marker_changed')
    marker = json.loads((root/'candidate-complete.json').read_text(encoding='utf-8'))
    require(marker.get('schemaVersion') == 1 and marker.get('globalStep') == 40 and marker.get('files') == inventory(root,{'candidate-complete.json'}), 'grounding_source_inventory_changed')
    require(sha256_file(root/'adapter_model.safetensors') == PINS['adapter'], 'grounding_source_adapter_changed')
    receipt = json.loads((root/'training-receipt.json').read_text(encoding='utf-8'))
    require(receipt.get('identity') == marker.get('identity') and receipt.get('globalStep') == 40 and receipt.get('status') == 'trained_public_qa_stage2' and receipt.get('trainingRunCompleted') is True and receipt.get('promotionAllowed') is False and receipt.get('qualityClaimAllowed') is False, 'grounding_source_receipt_invalid')
    require(marker['identity'].get('stage') == 'public_qa_stage2' and marker['identity'].get('baseRevision') == BASE_REVISION, 'grounding_source_base_invalid')
    return marker

def verify_grounding_provenance(provenance_path, adapter_path, identity, output_path, expected_digest=None, enforce_paths=True):
    path = Path(provenance_path)
    expected_digest = expected_digest or os.environ.get('EVIDSCOPE_GROUNDING_PROVENANCE_SHA256')
    require(not path.is_symlink() and sha256_file(path) == expected_digest, 'grounding_provenance_changed')
    document = json.loads(path.read_text(encoding='utf-8'))
    require(set(document) == {'schemaVersion','kind','sourceRunId','sourceGlobalStep','sourcePins','sourceIdentity','targetRunId','targetIdentity','optimizerReset','schedulerReset','targetOptimizerSteps','sourceTrainingExecutionVerified','qualityClaimAllowed','promotionAllowed'}, 'grounding_provenance_schema_invalid')
    require(document.get('schemaVersion') == 1 and document.get('kind') == 'adapter_only_warmstart_new_balanced_public_qa' and document.get('sourceRunId') == SOURCE_RUN and document.get('sourceGlobalStep') == 40 and document.get('sourcePins') == PINS, 'grounding_source_provenance_invalid')
    require(document.get('targetIdentity') == identity and identity.get('stage') == STAGE and identity.get('maxSteps') == 20 and identity.get('rank') == 8 and identity.get('sequenceLength') == 1024 and identity.get('baseRevision') == BASE_REVISION and identity.get('batchSize') == 1 and identity.get('gradientAccumulationSteps') == 16, 'grounding_target_identity_invalid')
    require(identity.get('precision') == 'bf16' and identity.get('modelDtype') == 'bfloat16' and identity.get('quantComputeDtype') == 'bfloat16', 'grounding_bf16_precision_identity_required')
    require(document.get('optimizerReset') is True and document.get('schedulerReset') is True and document.get('targetOptimizerSteps') == 20 and document.get('sourceTrainingExecutionVerified') is True and document.get('promotionAllowed') is False and document.get('qualityClaimAllowed') is False, 'grounding_reset_boundary_invalid')
    run_id = document.get('targetRunId','')
    require(re.fullmatch(r'public-qa-grounding-[a-z0-9-]{1,28}',run_id), 'grounding_target_run_invalid')
    if enforce_paths:
        require(Path(adapter_path).resolve() == Path('/warmstart/candidate') and Path(output_path).resolve() == Path('/checkpoints/runs')/run_id and not Path(output_path).exists(), 'grounding_path_scope_invalid')
    marker = verify_source_candidate(adapter_path)
    require(marker['identity'] == document['sourceIdentity'], 'grounding_source_identity_changed')
    require(all(identity.get(key) == marker['identity'].get(key) for key in ('baseRepository','baseRevision','baseArtifactLockSha256','rank','sequenceLength','batchSize','gradientAccumulationSteps')), 'grounding_base_or_adapter_incompatible')
    return {**document,'provenanceSha256':sha256_file(path),'sourceOptimizerUpdates':40,'optimizerUpdatesThisExperiment':0,'sourceStateLoaded':'adapter_only','optimizerStateLoaded':False,'schedulerStateLoaded':False}

def verify_grounding_artifacts(directory, provenance_path):
    root = Path(directory)
    marker = json.loads((root/'candidate-complete.json').read_text(encoding='utf-8'))
    receipt = json.loads((root/'training-receipt.json').read_text(encoding='utf-8'))
    provenance = json.loads(Path(provenance_path).read_text(encoding='utf-8'))
    require(marker.get('schemaVersion') == 1 and marker.get('globalStep') == 20 and marker.get('identity') == provenance.get('targetIdentity') and marker.get('files') == inventory(root,{'candidate-complete.json'}), 'grounding_candidate_changed')
    require(receipt.get('status') == 'trained_'+STAGE and receipt.get('identity') == marker['identity'] and receipt.get('globalStep') == 20 and receipt.get('trainingRunCompleted') is True and receipt.get('promotionAllowed') is False and receipt.get('qualityClaimAllowed') is False, 'grounding_candidate_receipt_invalid')
    require(marker['identity'].get('precision') == 'bf16' and marker['identity'].get('modelDtype') == 'bfloat16' and marker['identity'].get('quantComputeDtype') == 'bfloat16', 'grounding_candidate_precision_invalid')
    finite = receipt.get('adapterFiniteCheck',{})
    require(finite.get('passed') is True and type(finite.get('tensorCount')) is int and finite['tensorCount'] > 0 and finite.get('nonFiniteTensorCount') == 0 and finite.get('beforeCandidateSealing') is True and isinstance(finite.get('dtypes'),list) and finite['dtypes'], 'grounding_candidate_finite_check_missing')
    lineage=receipt.get('groundingLineage',{})
    require(lineage.get('provenanceSha256') == sha256_file(provenance_path) and lineage.get('sourceGlobalStep') == 40 and lineage.get('optimizerUpdatesThisExperiment') == 20 and lineage.get('optimizerStateLoaded') is False and lineage.get('schedulerStateLoaded') is False, 'grounding_candidate_lineage_invalid')
    return {'verified':True,'artifactSha256':sha256_file(root/'candidate-complete.json'),'globalStep':20,'sourceOptimizerUpdates':40,'optimizerUpdatesThisExperiment':20,'identity':marker['identity'],'qualityClaimAllowed':False,'promotionAllowed':False}
