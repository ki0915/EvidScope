"""Source80 adapter-only balanced public QA continuation; no model imports.

The source60 helper stays immutable. Its tensor inspection/completion mechanics
are reused without changing its pinned data, stage, sampler or source history.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
from training_artifacts import atomic_json, canonical_hash, inventory, sha256_file


def continuation_helper():
    path = Path(__file__).with_name('public_qa_grounding_continuation.py')
    if not path.is_file():
        path = Path(__file__).with_name('public-qa-grounding-continuation.py')
    spec = importlib.util.spec_from_file_location('balanced_continuation_mechanics', path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return helper


_previous = continuation_helper()
require, read_rows, plain_file = _previous.require, _previous.read_rows, _previous.plain_file
SELECTION = {**_previous.SELECTION, 'maxContextCodepoints': 700}
PRIVACY, PII = dict(_previous.PRIVACY), _previous.PII
STAGE = 'public_qa_grounding_balanced_v1'
SOURCE_RUN = 'public-qa-grounding-20261006-r3'
BASE_REVISION = '63c930c82d7646226d33502bec5870019738400e'
SOURCE_HISTORY = 80
LEARNING_RATE = 0.00003
SAMPLER = {'kind': 'balanced_optimizer_groups_v1', 'groupSize': 16,
           'answerablePerGroup': 8, 'impossiblePerGroup': 8, 'seed': 42}
PINS = {'marker': '4f25923e903e4f604401920035ac8d32fc6736874d57509f8be897340407d3eb',
        'adapter': '3de58b12eb5d6b46d4ad7a4ea53c008e5f070adcfe53a73826c0002e7495374e',
        'controller': 'bbb6504733765876abf85ff557f9726b762cbe565422672ee07ce4880c54409d',
        'verification': '2ee71ff2cc856ad62cbd03e4e892c76728624e622f0548167bf6c34be8732ca9',
        'provenance': '75e890ffb1b3381bdd59ffff454c4bdb253b854f2d83643511e90404c943d53a',
        'runtime': 'fd16f98282d570af43310e9920f017867509af910f14dc7dc8360878c283e934'}
SOURCE_PINS = {**_previous.SOURCE_PINS,
               'heldout': '681ceb8154dd4131c01679fcf8199e24d27c8d44e2abfe786588b2874bcb16e6',
               'continuation': '258ea70365b16ab31357467f3b32c66edca38b3ea0c6db46a11009ab79ed372b',
               'observedFresh': 'dc8a7bb0c9eb9de9abbc6f3cea39851453db8c60cc91602223f3a9aaeb628142'}
SOURCE_FILES = {**_previous.SOURCE_FILES, 'heldout': 'source-heldout.jsonl',
                'continuation': 'continuation.jsonl', 'observedFresh': 'observed-fresh.jsonl'}


def verify_grounding_data(rows, manifest, manifest_path):
    require(manifest.get('stage') == STAGE and manifest.get('sourcePins') == SOURCE_PINS
            and manifest.get('sourceFiles') == SOURCE_FILES, 'balanced_dataset_identity_invalid')
    require(manifest.get('counts') == {'train': 640, 'validation': 64}
            and manifest.get('labelCounts') == {'train': {'answerable': 320, 'impossible': 320},
                                              'validation': {'answerable': 32, 'impossible': 32}},
            'balanced_balance_invalid')
    require(manifest.get('sampler') == SAMPLER and manifest.get('selection') == SELECTION
            and manifest.get('previousExposureOverlap') == {'id': 0, 'family': 0, 'context': 0},
            'balanced_sampling_policy_invalid')
    require(manifest.get('heldoutUsed') is False and manifest.get('localHumanReviewPerformed') is False
            and manifest.get('qualityClaimAllowed') is False and manifest.get('promotionAllowed') is False,
            'balanced_claim_boundary_invalid')
    root = Path(manifest_path).parent
    paths = {key: plain_file(root, name) for key, name in SOURCE_FILES.items()}
    for key, path in paths.items():
        require(sha256_file(path) == SOURCE_PINS[key], 'balanced_source_changed:' + key)
    source_manifest = json.loads(paths['sourceManifest'].read_text(encoding='utf-8'))
    require(source_manifest.get('revision') == '3efd98708a40ff49251fddde35453f8fbb11f536'
            and source_manifest.get('license') == 'CC-BY-SA-4.0', 'balanced_upstream_invalid')
    source_rows = [row for key in ('sourceTrain', 'sourceValidation') for row in read_rows(paths[key])]
    original = {row['id']: row for row in source_rows}
    require(len(original) == len(source_rows), 'balanced_source_duplicate_id')
    exposed = [row for key in ('heldout', 'oldTraining', 'diagnostic', 'previousGrounding', 'continuation', 'observedFresh') for row in read_rows(paths[key])]
    forbidden = {key: {row[key] for row in exposed} for key in ('id', 'familyId', 'contextSha256')}
    seen, families, contexts = set(), {}, {}
    for row in rows:
        original_part = {key: value for key, value in row.items()
                         if key not in ('stage', 'contextSelection', 'localHumanReviewPerformed', 'privacyScreen')}
        require(row.get('id') not in seen and original_part == original.get(row.get('id')),
                'balanced_original_row_changed')
        require(row.get('stage') == STAGE and row.get('contextSelection') == 'full_original_context'
                and row.get('localHumanReviewPerformed') is False and row.get('privacyScreen') == PRIVACY,
                'balanced_row_policy_invalid')
        require(row.get('split') in ('train', 'validation') and row.get('upstreamSplit') == 'train'
                and row.get('language') == 'ko' and row.get('sourceLicense') == 'CC-BY-SA-4.0'
                and row.get('upstreamRevision') == source_manifest['revision']
                and row.get('upstreamAnnotation', {}).get('kind') == 'human_authored_question_answer_spans',
                'balanced_row_provenance_invalid')
        require(isinstance(row.get('context'), str) and 0 < len(row['context']) <= SELECTION['maxContextCodepoints']
                and isinstance(row.get('question'), str) and 0 < len(row['question']) <= 240
                and type(row.get('isImpossible')) is bool, 'balanced_context_limit_invalid')
        require(hashlib.sha256(row['context'].encode()).hexdigest() == row['contextSha256']
                and row['question'] == row.get('originalQa', {}).get('question')
                and row['answers'] == row['originalQa'].get('answers')
                and row['isImpossible'] == row['originalQa'].get('is_impossible'),
                'balanced_original_annotation_invalid')
        require(not PII.search(row['question'] + '\n' + row['context']), 'balanced_privacy_pattern')
        if row['isImpossible']:
            require(row['answers'] == [], 'balanced_answer_span_invalid')
        else:
            require(bool(row['answers']) and len(row['answers'][0]['text']) <= 160
                    and all(isinstance(a.get('text'), str) and a['text']
                            and type(a.get('answer_start')) is int and a['answer_start'] >= 0
                            and row['context'][a['answer_start']:a['answer_start'] + len(a['text'])] == a['text']
                            for a in row['answers']), 'balanced_answer_span_invalid')
        require(not any(row[key] in forbidden[key] for key in forbidden),
                'balanced_previous_exposure_leakage')
        for key, mapping in (('familyId', families), ('contextSha256', contexts)):
            require(row[key] not in mapping or mapping[row[key]] == row['split'], 'balanced_split_leakage')
            mapping[row[key]] = row['split']
        seen.add(row['id'])
    require(len(rows) == 704 and manifest.get('rowIds') == [row['id'] for row in rows],
            'balanced_actual_row_inventory_invalid')
    for split, counts in (('train', {False: 320, True: 320}), ('validation', {False: 32, True: 32})):
        for impossible, count in counts.items():
            require(sum(row['split'] == split and row['isImpossible'] is impossible for row in rows) == count,
                    'balanced_actual_balance_invalid')
    return manifest


def verify_source_artifacts(directory, provenance_path):
    root = Path(directory)
    marker = json.loads(plain_file(root, 'candidate-complete.json').read_text(encoding='utf-8'))
    receipt = json.loads(plain_file(root, 'training-receipt.json').read_text(encoding='utf-8'))
    provenance = json.loads(Path(provenance_path).read_text(encoding='utf-8'))
    require(marker.get('schemaVersion') == 1 and marker.get('globalStep') == 20
            and marker.get('identity') == provenance.get('targetIdentity')
            and marker.get('files') == inventory(root, {'candidate-complete.json'}), 'balanced_source_inventory_changed')
    require(receipt.get('status') == 'trained_' + _previous.STAGE
            and receipt.get('identity') == marker['identity'] and receipt.get('globalStep') == 20
            and receipt.get('trainingRunCompleted') is True and receipt.get('qualityClaimAllowed') is False
            and receipt.get('promotionAllowed') is False and receipt.get('localHumanReviewPerformed') is False
            and receipt.get('sourceOptimizerHistoryUpdates') == 60
            and receipt.get('optimizerUpdatesThisExperiment') == 20
            and receipt.get('totalAdapterHistoryOptimizerUpdates') == SOURCE_HISTORY,
            'balanced_source_receipt_invalid')
    finite = receipt.get('adapterFiniteCheck', {})
    require(finite.get('passed') is True and finite.get('tensorCount') == 256
            and finite.get('nonFiniteTensorCount') == 0 and finite.get('beforeCandidateSealing') is True,
            'balanced_source_finite_check_missing')
    lineage = receipt.get('groundingLineage', {})
    require(lineage.get('provenanceSha256') == sha256_file(provenance_path)
            and lineage.get('sourceGlobalStep') == 20 and lineage.get('sourceOptimizerHistoryUpdates') == 60
            and lineage.get('sourceOptimizerUpdates') == 60 and lineage.get('optimizerUpdatesThisExperiment') == 20
            and lineage.get('optimizerStateLoaded') is False and lineage.get('schedulerStateLoaded') is False,
            'balanced_source_lineage_invalid')
    exposure = json.loads(plain_file(root, 'training-exposure.json').read_text(encoding='utf-8'))
    require(receipt.get('trainingExposure', {}).get('sha256') == sha256_file(root / 'training-exposure.json')
            and exposure.get('stage') == _previous.STAGE and exposure.get('sampler') == _previous.SAMPLER
            and exposure.get('sourceOptimizerHistoryUpdates') == 60
            and exposure.get('optimizerUpdatesThisExperiment') == 20
            and exposure.get('totalAdapterHistoryOptimizerUpdates') == SOURCE_HISTORY
            and exposure.get('processedMicrobatches') == 320 and exposure.get('completedOptimizerGroups') == 20
            and exposure.get('counts') == {'answerable': 220, 'impossible': 100},
            'balanced_source_exposure_invalid')
    return {'verified': True, 'artifactSha256': sha256_file(root / 'candidate-complete.json'),
            'globalStep': 20, 'sourceOptimizerUpdates': 60, 'optimizerUpdatesThisExperiment': 20}


def verify_grounding_provenance(provenance_path, adapter_path, identity, output_path,
                                expected_digest=None, enforce_paths=True):
    path = Path(provenance_path)
    digest = expected_digest or os.environ.get('EVIDSCOPE_GROUNDING_PROVENANCE_SHA256')
    require(not path.is_symlink() and sha256_file(path) == digest, 'balanced_provenance_changed')
    document = json.loads(path.read_text(encoding='utf-8'))
    require(set(document) == {'schemaVersion', 'kind', 'sourceRunId', 'sourceGlobalStep',
                             'sourceOptimizerHistoryUpdates', 'sourcePins', 'sourceIdentity', 'targetRunId',
                             'targetIdentity', 'optimizerReset', 'schedulerReset', 'targetOptimizerSteps',
                             'sourceTrainingExecutionVerified', 'qualityClaimAllowed', 'promotionAllowed'},
            'balanced_provenance_schema_invalid')
    require(document.get('schemaVersion') == 1
            and document.get('kind') == 'adapter_only_warmstart_balanced_public_qa_continuation'
            and document.get('sourceRunId') == SOURCE_RUN and document.get('sourceGlobalStep') == 20
            and document.get('sourceOptimizerHistoryUpdates') == SOURCE_HISTORY
            and document.get('sourcePins') == PINS, 'balanced_source_provenance_invalid')
    require(document.get('targetIdentity') == identity and identity.get('stage') == STAGE
            and identity.get('baseRepository') == 'fdtn-ai/Foundation-Sec-8B-Reasoning'
            and identity.get('baseRevision') == BASE_REVISION and identity.get('maxSteps') == 20
            and identity.get('rank') == 8 and identity.get('sequenceLength') == 1024
            and identity.get('batchSize') == 1 and identity.get('gradientAccumulationSteps') == 16
            and identity.get('seed') == 42 and identity.get('learningRate') == LEARNING_RATE
            and identity.get('gpuMemoryFraction') == 0.65 and identity.get('sampler') == SAMPLER,
            'balanced_target_identity_invalid')
    require(identity.get('precision') == 'bf16' and identity.get('modelDtype') == 'bfloat16'
            and identity.get('quantComputeDtype') == 'bfloat16'
            and identity.get('contextSelection') == 'full_original_context',
            'balanced_bf16_identity_required')
    require(document.get('optimizerReset') is True and document.get('schedulerReset') is True
            and document.get('targetOptimizerSteps') == 20
            and document.get('sourceTrainingExecutionVerified') is True
            and document.get('qualityClaimAllowed') is False and document.get('promotionAllowed') is False,
            'balanced_reset_boundary_invalid')
    run_id = document.get('targetRunId', '')
    require(re.fullmatch(r'public-qa-balanced-[a-z0-9-]{1,28}', run_id), 'balanced_target_run_invalid')
    if enforce_paths:
        require(Path(adapter_path).resolve() == Path('/warmstart/candidate')
                and Path(output_path).resolve() == Path('/checkpoints/runs') / run_id
                and not Path(output_path).exists(), 'balanced_path_scope_invalid')
    require(not Path(output_path).exists(), 'balanced_output_reuse_forbidden')
    source_verification = plain_file(path.parent, 'source-verification.json')
    source_provenance = plain_file(path.parent, 'source-provenance.json')
    require(sha256_file(source_verification) == PINS['verification']
            and sha256_file(source_provenance) == PINS['provenance'],
            'balanced_source_evidence_changed')
    marker_path = plain_file(adapter_path, 'candidate-complete.json')
    require(sha256_file(marker_path) == PINS['marker']
            and sha256_file(plain_file(adapter_path, 'adapter_model.safetensors')) == PINS['adapter'],
            'balanced_source_candidate_changed')
    proof = verify_source_artifacts(adapter_path, source_provenance)
    source = json.loads(source_verification.read_text(encoding='utf-8'))
    marker = json.loads(marker_path.read_text(encoding='utf-8'))
    require(all(source.get(key) is True for key in ('verificationPassed', 'verified',
            'actualTrainingExecutionVerified', 'sourceTrainingExecutionVerified', 'trainingRunCompleted',
            'terminationConfirmed')) and source.get('syntheticFixture') is False
            and source.get('runId') == SOURCE_RUN and source.get('globalStep') == 20
            and source.get('actualOptimizerUpdates') == 20 and source.get('sourceOptimizerUpdates') == 60
            and source.get('totalAdapterHistoryOptimizerUpdates') == SOURCE_HISTORY
            and source.get('controllerSha256') == PINS['controller']
            and source.get('runtimeConfigMapSha256') == PINS['runtime']
            and source.get('artifactSha256') == PINS['marker'] and source.get('adapterSha256') == PINS['adapter']
            and source.get('identity') == marker.get('identity') == document.get('sourceIdentity')
            and source.get('qualityClaimAllowed') is False and source.get('promotionAllowed') is False,
            'balanced_source_execution_unverified')
    require(proof.get('verified') is True and proof.get('globalStep') == 20
            and proof.get('sourceOptimizerUpdates') == 60 and proof.get('optimizerUpdatesThisExperiment') == 20
            and proof.get('artifactSha256') == PINS['marker'], 'balanced_source_inventory_invalid')
    require(all(identity.get(key) == marker['identity'].get(key) for key in
                ('baseRepository', 'baseRevision', 'baseArtifactLockSha256', 'rank', 'sequenceLength',
                 'batchSize', 'gradientAccumulationSteps', 'image')),
            'balanced_source_base_incompatible')
    return {**document, 'provenanceSha256': sha256_file(path), 'sourceOptimizerUpdates': SOURCE_HISTORY,
            'optimizerUpdatesThisExperiment': 0, 'sourceStateLoaded': 'adapter_only',
            'optimizerStateLoaded': False, 'schedulerStateLoaded': False}


def stratified_order(rows, sampler=SAMPLER):
    require(sampler == SAMPLER and len(rows) == 640 and len({row['id'] for row in rows}) == 640
            and all(type(row.get('isImpossible')) is bool and row.get('split') == 'train' for row in rows),
            'balanced_sampler_rows_invalid')
    pools = {}
    for label, count in ((False, 320), (True, 320)):
        indices = [index for index, row in enumerate(rows) if row['isImpossible'] is label]
        require(len(indices) == count, 'balanced_sampler_balance_invalid')
        pools[label] = sorted(indices, key=lambda index: (
            hashlib.sha256(f"42|class|{int(label)}|{rows[index]['id']}".encode()).hexdigest(), rows[index]['id']))
    result = []
    for group in range(40):
        indices = pools[False][group * 8:(group + 1) * 8] + pools[True][group * 8:(group + 1) * 8]
        result.extend(sorted(indices, key=lambda index: (
            hashlib.sha256(f"42|group|{group}|{rows[index]['id']}".encode()).hexdigest(), rows[index]['id'])))
    require(len(set(result)) == 640, 'balanced_sampler_duplicate')
    return result


class ExposureRecorder(_previous.ExposureRecorder):
    """Reuse actual tensor and backward-completion checks with new pinned policy."""
    def __init__(self, rows, encoded, path, dataset_sha256, sampler=SAMPLER):
        require(len(rows) == len(encoded), 'balanced_exposure_encoded_count')
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
        record = super().inspect(batch)
        row = self.rows[record['datasetIndex']]
        record['rowIdentitySha256'] = canonical_hash({key: row[key] for key in
                                                    ('id', 'familyId', 'contextSha256', 'isImpossible')})
        self.pending = dict(record)
        return record

    def optimizer_completed(self, step):
        require(type(step) is int and 1 <= step <= 20
                and step == self.document['completedOptimizerGroups'] + 1
                and len(self.document['rows']) == step * 16, 'balanced_optimizer_exposure_mismatch')
        group = self.document['rows'][-16:]
        counts = {key: sum(row['isImpossible'] is value for row in group)
                  for key, value in (('answerable', False), ('impossible', True))}
        require(counts == {'answerable': 8, 'impossible': 8}
                and all(row['optimizerGroup'] == step for row in group), 'balanced_optimizer_group_balance')
        self.document['groups'].append({'optimizerGroup': step, 'microbatches': 16, **counts})
        self.document['completedOptimizerGroups'] = self.document['optimizerUpdatesThisExperiment'] = step
        self.document['totalAdapterHistoryOptimizerUpdates'] = SOURCE_HISTORY + step
        atomic_json(self.path, self.document)

    def snapshot(self, path, step):
        require(step == self.document['completedOptimizerGroups']
                and len(self.document['rows']) == step * 16, 'balanced_snapshot_step_mismatch')
        atomic_json(path, self.document)
        return {'path': 'training-exposure.json', 'sha256': sha256_file(path),
                'processedMicrobatches': len(self.document['rows']),
                'completedOptimizerGroups': step, 'counts': dict(self.document['counts']),
                'sourceOptimizerHistoryUpdates': SOURCE_HISTORY,
                'optimizerUpdatesThisExperiment': step, 'totalAdapterHistoryOptimizerUpdates': SOURCE_HISTORY + step,
                'actualTensorBindingChecked': True}
