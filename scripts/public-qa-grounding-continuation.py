"""Pinned fresh public QA continuation with observable stratified consumption.

No model, torch, CUDA or network imports occur in this admission module.
Source globalStep=20 and adapter history=60 are deliberately distinct.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re

from training_artifacts import atomic_json, canonical_hash, inventory, sha256_file

STAGE = 'public_qa_grounding_continuation_v1'
SOURCE_RUN = 'public-qa-grounding-20261005-r4'
BASE_REVISION = '63c930c82d7646226d33502bec5870019738400e'
SOURCE_HISTORY = 60
LEARNING_RATE = 0.00003
SAMPLER = {'kind': 'stratified_optimizer_groups_v1', 'groupSize': 16,
           'answerablePerGroup': 11, 'impossiblePerGroup': 5, 'seed': 42}
PINS = {'marker': 'aa6b6fc1c7fa32f56507a4e31920acef3b46257ca90bf597c2a6e9e480fd1e60',
        'adapter': 'c3b836df159917cd9ababd61ed9f574ac5b77252b8ec058a66269b045c78d9f6',
        'controller': 'a376708b9932a6b1831568347b0ca2f1719c7707b8750b0f2e0025ffaca86617',
        'verification': 'c33c946a0c80b6bdba4bc8e738fd98d6e04cfbfa10887b2f39a8b28e613ec517',
        'provenance': 'b165e9f1b4d1fac016efa18825649cf21e13e86ff523105d2cb17ced900c5459'}
SOURCE_PINS = {'sourceManifest': 'c412bc1f048a33351be60ce8a4395bcf9d5a160d58047decc380a8c2197db14c',
               'sourceTrain': 'e050f9d529ce8932714b5a4fcb7e6e599b76c2ef8ef7c2108a8ba06173b1a855',
               'sourceValidation': 'f0ab6e2774ea94926cabe6ef281a353f304717b7ed0845ab3ce5134c823b20ad',
               'oldTraining': '21b4b91ad0f755de666fe2ebe9077f301477da6420ffa0195cb53b5189d2822f',
               'diagnostic': '50561634095f758781c4695fcc30e2d7bd7cf7d9b937d8c10174a3e927c837f9',
               'previousGrounding': 'a080f3ff03ce813d5f4e242512a6442ff148e2341613e227f8c03e2e29a8d4ea'}
SOURCE_FILES = {'sourceManifest': 'source-manifest.json', 'sourceTrain': 'source-train.jsonl',
                'sourceValidation': 'source-validation.jsonl', 'oldTraining': 'old-training.jsonl',
                'diagnostic': 'diagnostic.jsonl', 'previousGrounding': 'previous-grounding.jsonl'}
SELECTION = {'maxContextCodepoints': 650, 'fullContextPreserved': True,
             'answerBasedCropping': False, 'actualTokenizerPreadmissionRequired': True}
PRIVACY = {'kind': 'basic_email_mobile_resident_id_regex', 'passed': True,
           'comprehensivePrivacyReview': False}
PII = re.compile(r'[\w.+-]+@[\w.-]+\.[a-z]{2,}|\b01[016789][- .]?\d{3,4}[- .]?\d{4}\b|\b\d{6}[- ]?[1-8]\d{6}\b', re.I)


def require(value, message):
    if not value:
        raise ValueError(message)


def read_rows(path):
    return [json.loads(line) for line in Path(path).read_text(encoding='utf-8').splitlines() if line.strip()]


def plain_file(root, name):
    root = Path(root)
    path = root / name
    require(not root.is_symlink() and not path.is_symlink() and path.is_file()
            and path.resolve().parent == root.resolve(), 'continuation_source_path_invalid')
    return path


def verify_grounding_data(rows, manifest, manifest_path):
    require(manifest.get('stage') == STAGE and manifest.get('sourcePins') == SOURCE_PINS
            and manifest.get('sourceFiles') == SOURCE_FILES, 'continuation_dataset_identity_invalid')
    require(manifest.get('counts') == {'train': 640, 'validation': 64}
            and manifest.get('labelCounts') == {'train': {'answerable': 440, 'impossible': 200},
                                              'validation': {'answerable': 32, 'impossible': 32}},
            'continuation_balance_invalid')
    require(manifest.get('sampler') == SAMPLER and manifest.get('selection') == SELECTION
            and manifest.get('previousExposureOverlap') == {'id': 0, 'family': 0, 'context': 0},
            'continuation_sampling_policy_invalid')
    require(manifest.get('heldoutUsed') is False and manifest.get('localHumanReviewPerformed') is False
            and manifest.get('qualityClaimAllowed') is False and manifest.get('promotionAllowed') is False,
            'continuation_claim_boundary_invalid')
    root = Path(manifest_path).parent
    paths = {key: plain_file(root, name) for key, name in SOURCE_FILES.items()}
    for key, path in paths.items():
        require(sha256_file(path) == SOURCE_PINS[key], 'continuation_source_changed:' + key)
    source_manifest = json.loads(paths['sourceManifest'].read_text(encoding='utf-8'))
    require(source_manifest.get('revision') == '3efd98708a40ff49251fddde35453f8fbb11f536'
            and source_manifest.get('license') == 'CC-BY-SA-4.0', 'continuation_upstream_invalid')
    source_rows = [row for key in ('sourceTrain', 'sourceValidation') for row in read_rows(paths[key])]
    original = {row['id']: row for row in source_rows}
    require(len(original) == len(source_rows), 'continuation_source_duplicate_id')
    exposed = [row for key in ('oldTraining', 'diagnostic', 'previousGrounding') for row in read_rows(paths[key])]
    forbidden = {key: {row[key] for row in exposed} for key in ('id', 'familyId', 'contextSha256')}
    seen, families, contexts = set(), {}, {}
    for row in rows:
        original_part = {key: value for key, value in row.items()
                         if key not in ('stage', 'contextSelection', 'localHumanReviewPerformed', 'privacyScreen')}
        require(row.get('id') not in seen and original_part == original.get(row.get('id')),
                'continuation_original_row_changed')
        require(row.get('stage') == STAGE and row.get('contextSelection') == 'full_original_context'
                and row.get('localHumanReviewPerformed') is False and row.get('privacyScreen') == PRIVACY,
                'continuation_row_policy_invalid')
        require(row.get('split') in ('train', 'validation') and row.get('upstreamSplit') == 'train'
                and row.get('language') == 'ko' and row.get('sourceLicense') == 'CC-BY-SA-4.0'
                and row.get('upstreamRevision') == source_manifest['revision']
                and row.get('upstreamAnnotation', {}).get('kind') == 'human_authored_question_answer_spans',
                'continuation_row_provenance_invalid')
        require(isinstance(row.get('context'), str) and 0 < len(row['context']) <= 650
                and isinstance(row.get('question'), str) and 0 < len(row['question']) <= 240
                and type(row.get('isImpossible')) is bool, 'continuation_context_limit_invalid')
        require(hashlib.sha256(row['context'].encode()).hexdigest() == row['contextSha256']
                and row['question'] == row.get('originalQa', {}).get('question')
                and row['answers'] == row['originalQa'].get('answers')
                and row['isImpossible'] == row['originalQa'].get('is_impossible'),
                'continuation_original_annotation_invalid')
        require(not PII.search(row['question'] + '\n' + row['context']), 'continuation_privacy_pattern')
        if row['isImpossible']:
            require(row['answers'] == [], 'continuation_answer_span_invalid')
        else:
            require(bool(row['answers']) and len(row['answers'][0]['text']) <= 160
                    and all(isinstance(a.get('text'), str) and a['text']
                            and type(a.get('answer_start')) is int and a['answer_start'] >= 0
                            and row['context'][a['answer_start']:a['answer_start'] + len(a['text'])] == a['text']
                            for a in row['answers']), 'continuation_answer_span_invalid')
        require(not any(row[key] in forbidden[key] for key in forbidden),
                'continuation_previous_exposure_leakage')
        for key, mapping in (('familyId', families), ('contextSha256', contexts)):
            require(row[key] not in mapping or mapping[row[key]] == row['split'], 'continuation_split_leakage')
            mapping[row[key]] = row['split']
        seen.add(row['id'])
    require(len(rows) == 704 and manifest.get('rowIds') == [row['id'] for row in rows],
            'continuation_actual_row_inventory_invalid')
    for split, counts in (('train', {False: 440, True: 200}), ('validation', {False: 32, True: 32})):
        for impossible, count in counts.items():
            require(sum(row['split'] == split and row['isImpossible'] is impossible for row in rows) == count,
                    'continuation_actual_balance_invalid')
    return manifest


def previous_helper():
    path = Path(__file__).with_name('public_qa_grounding.py')
    if not path.is_file():
        path = Path(__file__).with_name('public-qa-grounding.py')
    spec = importlib.util.spec_from_file_location('previous_public_qa_grounding', path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return helper


def verify_grounding_provenance(provenance_path, adapter_path, identity, output_path,
                                expected_digest=None, enforce_paths=True):
    path = Path(provenance_path)
    digest = expected_digest or os.environ.get('EVIDSCOPE_GROUNDING_PROVENANCE_SHA256')
    require(not path.is_symlink() and sha256_file(path) == digest, 'continuation_provenance_changed')
    document = json.loads(path.read_text(encoding='utf-8'))
    require(set(document) == {'schemaVersion', 'kind', 'sourceRunId', 'sourceGlobalStep',
                             'sourceOptimizerHistoryUpdates', 'sourcePins', 'sourceIdentity', 'targetRunId',
                             'targetIdentity', 'optimizerReset', 'schedulerReset', 'targetOptimizerSteps',
                             'sourceTrainingExecutionVerified', 'qualityClaimAllowed', 'promotionAllowed'},
            'continuation_provenance_schema_invalid')
    require(document.get('schemaVersion') == 1
            and document.get('kind') == 'adapter_only_warmstart_stratified_public_qa_continuation'
            and document.get('sourceRunId') == SOURCE_RUN and document.get('sourceGlobalStep') == 20
            and document.get('sourceOptimizerHistoryUpdates') == SOURCE_HISTORY
            and document.get('sourcePins') == PINS, 'continuation_source_provenance_invalid')
    require(document.get('targetIdentity') == identity and identity.get('stage') == STAGE
            and identity.get('baseRepository') == 'fdtn-ai/Foundation-Sec-8B-Reasoning'
            and identity.get('baseRevision') == BASE_REVISION and identity.get('maxSteps') == 20
            and identity.get('rank') == 8 and identity.get('sequenceLength') == 1024
            and identity.get('batchSize') == 1 and identity.get('gradientAccumulationSteps') == 16
            and identity.get('seed') == 42 and identity.get('learningRate') == LEARNING_RATE
            and identity.get('gpuMemoryFraction') == 0.65 and identity.get('sampler') == SAMPLER,
            'continuation_target_identity_invalid')
    require(identity.get('precision') == 'bf16' and identity.get('modelDtype') == 'bfloat16'
            and identity.get('quantComputeDtype') == 'bfloat16'
            and identity.get('contextSelection') == 'full_original_context',
            'continuation_bf16_identity_required')
    require(document.get('optimizerReset') is True and document.get('schedulerReset') is True
            and document.get('targetOptimizerSteps') == 20
            and document.get('sourceTrainingExecutionVerified') is True
            and document.get('qualityClaimAllowed') is False and document.get('promotionAllowed') is False,
            'continuation_reset_boundary_invalid')
    run_id = document.get('targetRunId', '')
    require(re.fullmatch(r'public-qa-grounding-[a-z0-9-]{1,28}', run_id), 'continuation_target_run_invalid')
    if enforce_paths:
        require(Path(adapter_path).resolve() == Path('/warmstart/candidate')
                and Path(output_path).resolve() == Path('/checkpoints/runs') / run_id
                and not Path(output_path).exists(), 'continuation_path_scope_invalid')
    require(not Path(output_path).exists(), 'continuation_output_reuse_forbidden')
    source_verification = plain_file(path.parent, 'source-verification.json')
    source_provenance = plain_file(path.parent, 'source-provenance.json')
    require(sha256_file(source_verification) == PINS['verification']
            and sha256_file(source_provenance) == PINS['provenance'],
            'continuation_source_evidence_changed')
    marker_path = plain_file(adapter_path, 'candidate-complete.json')
    require(sha256_file(marker_path) == PINS['marker']
            and sha256_file(plain_file(adapter_path, 'adapter_model.safetensors')) == PINS['adapter'],
            'continuation_source_candidate_changed')
    proof = previous_helper().verify_grounding_artifacts(adapter_path, source_provenance)
    source = json.loads(source_verification.read_text(encoding='utf-8'))
    marker = json.loads(marker_path.read_text(encoding='utf-8'))
    require(all(source.get(key) is True for key in ('verificationPassed', 'verified',
            'actualTrainingExecutionVerified', 'sourceTrainingExecutionVerified', 'trainingRunCompleted',
            'terminationConfirmed')) and source.get('syntheticFixture') is False
            and source.get('runId') == SOURCE_RUN and source.get('globalStep') == 20
            and source.get('actualOptimizerUpdates') == 20 and source.get('sourceOptimizerUpdates') == 40
            and source.get('totalAdapterHistoryOptimizerUpdates') == SOURCE_HISTORY
            and source.get('controllerSha256') == PINS['controller']
            and source.get('artifactSha256') == PINS['marker'] and source.get('adapterSha256') == PINS['adapter']
            and source.get('identity') == marker.get('identity') == document.get('sourceIdentity')
            and source.get('qualityClaimAllowed') is False and source.get('promotionAllowed') is False,
            'continuation_source_execution_unverified')
    require(proof.get('verified') is True and proof.get('globalStep') == 20
            and proof.get('sourceOptimizerUpdates') == 40 and proof.get('optimizerUpdatesThisExperiment') == 20
            and proof.get('artifactSha256') == PINS['marker'], 'continuation_source_inventory_invalid')
    require(all(identity.get(key) == marker['identity'].get(key) for key in
                ('baseRepository', 'baseRevision', 'baseArtifactLockSha256', 'rank', 'sequenceLength',
                 'batchSize', 'gradientAccumulationSteps', 'image')),
            'continuation_source_base_incompatible')
    return {**document, 'provenanceSha256': sha256_file(path), 'sourceOptimizerUpdates': SOURCE_HISTORY,
            'optimizerUpdatesThisExperiment': 0, 'sourceStateLoaded': 'adapter_only',
            'optimizerStateLoaded': False, 'schedulerStateLoaded': False}


def stratified_order(rows, sampler=SAMPLER):
    require(sampler == SAMPLER and len(rows) == 640 and len({row['id'] for row in rows}) == 640
            and all(type(row.get('isImpossible')) is bool and row.get('split') == 'train' for row in rows),
            'continuation_sampler_rows_invalid')
    pools = {}
    for label, count in ((False, 440), (True, 200)):
        indices = [index for index, row in enumerate(rows) if row['isImpossible'] is label]
        require(len(indices) == count, 'continuation_sampler_balance_invalid')
        pools[label] = sorted(indices, key=lambda index: (
            hashlib.sha256(f"42|class|{int(label)}|{rows[index]['id']}".encode()).hexdigest(), rows[index]['id']))
    result = []
    for group in range(40):
        indices = pools[False][group * 11:(group + 1) * 11] + pools[True][group * 5:(group + 1) * 5]
        result.extend(sorted(indices, key=lambda index: (
            hashlib.sha256(f"42|group|{group}|{rows[index]['id']}".encode()).hexdigest(), rows[index]['id'])))
    require(len(set(result)) == 640, 'continuation_sampler_duplicate')
    return result


class ExposureRecorder:
    """Validate the actual CPU copy of each consumed training tensor, then record.

    Recording after training_step returns proves a completed forward/backward,
    separately from optimizer confirmations supplied by on_step_end.
    """
    def __init__(self, rows, encoded, path, dataset_sha256, sampler=SAMPLER):
        require(len(rows) == len(encoded), 'continuation_exposure_encoded_count')
        self.rows, self.encoded, self.path = rows, encoded, Path(path)
        self.pending = None
        self.order = stratified_order(rows, sampler)
        plan = [{'datasetIndex': index, 'rowId': rows[index]['id'], 'isImpossible': rows[index]['isImpossible']}
                for index in self.order]
        self.document = {'schemaVersion': 1, 'stage': STAGE, 'datasetSha256': dataset_sha256,
                         'sourceOptimizerHistoryUpdates': SOURCE_HISTORY, 'optimizerUpdatesThisExperiment': 0,
                         'totalAdapterHistoryOptimizerUpdates': SOURCE_HISTORY, 'sampler': dict(sampler),
                         'plannedOrderSha256': canonical_hash(plan), 'processedMicrobatches': 0,
                         'completedOptimizerGroups': 0, 'counts': {'answerable': 0, 'impossible': 0},
                         'groups': [], 'rows': [], 'qualityClaimAllowed': False, 'promotionAllowed': False}

    def inspect(self, batch):
        require(self.pending is None, 'continuation_unfinished_training_step')
        position = len(self.document['rows'])
        require(position < 320, 'continuation_exposure_step_budget_exceeded')
        index = self.order[position]
        actual = {}
        for key in ('input_ids', 'attention_mask', 'labels'):
            value = batch.get(key)
            require(value is not None and callable(getattr(value, 'detach', None)),
                    'continuation_actual_tensor_missing')
            actual[key] = value.detach().cpu().tolist()
            require(isinstance(actual[key], list) and len(actual[key]) == 1
                    and actual[key][0] == self.encoded[index][key], 'continuation_actual_tensor_row_mismatch')
        row = self.rows[index]
        record = {'microbatch': position + 1, 'optimizerGroup': position // 16 + 1,
                'positionInGroup': position % 16 + 1, 'datasetIndex': index, 'rowId': row['id'],
                'isImpossible': row['isImpossible'], 'inputSha256': canonical_hash({key: value[0] for key, value in actual.items()}),
                'tokenCount': len(actual['input_ids'][0]), 'forwardBackwardCompleted': True}
        self.pending = dict(record)
        return record

    def completed(self, record):
        require(record == self.pending and record['microbatch'] == len(self.document['rows']) + 1
                and record['datasetIndex'] == self.order[len(self.document['rows'])],
                'continuation_exposure_order_changed')
        self.document['rows'].append(record)
        self.pending = None
        self.document['processedMicrobatches'] = len(self.document['rows'])
        self.document['counts']['impossible' if record['isImpossible'] else 'answerable'] += 1
        atomic_json(self.path, self.document)

    def optimizer_completed(self, step):
        require(type(step) is int and 1 <= step <= 20
                and step == self.document['completedOptimizerGroups'] + 1
                and len(self.document['rows']) == step * 16, 'continuation_optimizer_exposure_mismatch')
        group = self.document['rows'][-16:]
        counts = {key: sum(row['isImpossible'] is value for row in group)
                  for key, value in (('answerable', False), ('impossible', True))}
        require(counts == {'answerable': 11, 'impossible': 5}
                and all(row['optimizerGroup'] == step for row in group), 'continuation_optimizer_group_balance')
        self.document['groups'].append({'optimizerGroup': step, 'microbatches': 16, **counts})
        self.document['completedOptimizerGroups'] = self.document['optimizerUpdatesThisExperiment'] = step
        self.document['totalAdapterHistoryOptimizerUpdates'] = SOURCE_HISTORY + step
        atomic_json(self.path, self.document)

    def snapshot(self, path, step):
        require(step == self.document['completedOptimizerGroups']
                and len(self.document['rows']) == step * 16, 'continuation_snapshot_step_mismatch')
        atomic_json(path, self.document)
        return {'path': 'training-exposure.json', 'sha256': sha256_file(path),
                'processedMicrobatches': len(self.document['rows']),
                'completedOptimizerGroups': step, 'counts': dict(self.document['counts']),
                'sourceOptimizerHistoryUpdates': SOURCE_HISTORY,
                'optimizerUpdatesThisExperiment': step, 'totalAdapterHistoryOptimizerUpdates': SOURCE_HISTORY + step,
                'actualTensorBindingChecked': True}
