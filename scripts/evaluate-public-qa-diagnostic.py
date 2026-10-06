"""Pinned public QA generation diagnosis; never training, approval or promotion."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import time

from training_artifacts import atomic_json, sha256_file

DATA_SHA = '50561634095f758781c4695fcc30e2d7bd7cf7d9b937d8c10174a3e927c837f9'
MANIFEST_SHA = '98224737c904da0c5c6abecf50c7238d8469c29877e76ffe92c10c003b9644d2'
CANDIDATE_SHA = '3b0905e517c7daf21bc4359fad5bde302d88e763633832d157aeec268ea228c1'
ADAPTER_SHA = '77a10c126058028f635e686143188d8f66100890cc9652698ca45454b17b8993'
CONTROLLER_SHA = 'a855afe3b260a20a0563dcff2ef01f066c4f4c4340552c66dda8fa27a229b36c'
STAGE2_PINS = {'marker': 'a6f152d43c2ae481277650b094a8c416f9c99bbe74ea962fd6ed2bf485b899ea', 'adapter': 'd7ab9fe25bed50ef85d8038f3493edfff3c1e492aa26f16945842935298f0c19', 'controller': '10a6f18485608964af7674bc3ac51b97cb5f07258e99fbef767c4337774a06f6', 'verification': '5a69fa9345c234f57f29787285a7cec8aec852392226cbbf7fc6d076447db3e9'}
LOCK_SHA = 'c067d1fe680e8f6dc14c592ade49a1d791ea6cb15ecbefeda52a609d5d922949'
BASE_REVISION = '63c930c82d7646226d33502bec5870019738400e'
SOURCE_REVISION = '3efd98708a40ff49251fddde35453f8fbb11f536'
IMAGE = 'docker.io/evidscope/public-qa-training@sha256:440dbe10ff4e651296c65ff88f132077a4cbbb19054536b33c0695fdb5224be8'
SYSTEM = '제공된 문서에서 질문의 답을 그대로 인용하세요. JSON으로 answer, evidenceQuote, abstained를 반환하세요. 문서에 답이 없으면 answer와 evidenceQuote는 빈 문자열, abstained는 true입니다.'
SOURCE_PINS = {'sourceManifest': 'c412bc1f048a33351be60ce8a4395bcf9d5a160d58047decc380a8c2197db14c', 'heldout': '681ceb8154dd4131c01679fcf8199e24d27c8d44e2abfe786588b2874bcb16e6', 'trainingManifest': '9eba08dc67ec2cbb258f199879a2b0610a4c2979e3699a50dafc6bfee52a32ec', 'trainingData': '21b4b91ad0f755de666fe2ebe9077f301477da6420ffa0195cb53b5189d2822f'}
MAX_OUTPUT = 128
CONTEXT_BUDGET = 1024
TIMEOUT = 120


def require(value, message):
    if not value:
        raise ValueError(message)


def plain_file(root, relative):
    root = Path(root).resolve(strict=True)
    path = root / relative
    require(not Path(relative).is_absolute() and path.resolve().is_relative_to(root), 'artifact_path_escape')
    require(not any(part.is_symlink() for part in [path, *list(path.parents)[:len(Path(relative).parts)-1]]), 'artifact_symlink_forbidden')
    require(path.is_file(), 'artifact_file_missing')
    return path


def verify_data(data, manifest, expected_data=DATA_SHA, expected_manifest=MANIFEST_SHA):
    require(not Path(data).is_symlink() and not Path(manifest).is_symlink(), 'dataset_symlink_forbidden')
    require(sha256_file(data) == expected_data and sha256_file(manifest) == expected_manifest, 'diagnostic_input_hash_mismatch')
    metadata = json.loads(Path(manifest).read_text(encoding='utf-8'))
    rows = [json.loads(line) for line in Path(data).read_text(encoding='utf-8').splitlines() if line.strip()]
    require(metadata.get('mode') == 'public_qa_diagnostic' and metadata.get('diagnosticOnly') is True and metadata.get('datasetSha256') == expected_data and metadata.get('sourcePins') == SOURCE_PINS, 'diagnostic_manifest_invalid')
    require(metadata.get('localHumanReviewPerformed') is False and metadata.get('promotionAllowed') is False and metadata.get('qualityClaimAllowed') is False, 'diagnostic_claim_boundary_invalid')
    require(metadata.get('selection', {}).get('fullContextPreserved') is True and metadata['selection'].get('answerBasedCropping') is False and metadata.get('trainingOverlap') == {'id': 0, 'family': 0, 'context': 0}, 'diagnostic_scope_invalid')
    require(len(rows) == 64 and len({r.get('id') for r in rows}) == 64 and [r.get('id') for r in rows] == metadata.get('rowIds'), 'diagnostic_rows_invalid')
    require(sum(r.get('isImpossible') is True for r in rows) == 32 and sum(r.get('isImpossible') is False for r in rows) == 32, 'diagnostic_balance_invalid')
    for row in rows:
        require(re.fullmatch(r'[a-zA-Z0-9_-]+', row['id']) and row.get('split') == 'heldout' and row.get('upstreamSplit') == 'dev' and row.get('upstreamRevision') == SOURCE_REVISION and row.get('language') == 'ko', 'diagnostic_row_provenance_invalid')
        require(row.get('sourceLicense') == 'CC-BY-SA-4.0' and row.get('upstreamAnnotation', {}).get('kind') == 'human_authored_question_answer_spans' and row.get('localHumanReviewPerformed') is False, 'diagnostic_annotation_invalid')
        require(isinstance(row.get('context'), str) and row['context'] and isinstance(row.get('question'), str) and row['question'] and hashlib.sha256(row['context'].encode()).hexdigest() == row.get('contextSha256'), 'diagnostic_context_changed')
        original = row.get('originalQa', {})
        require(row['question'] == original.get('question') and row.get('answers') == original.get('answers') and row['isImpossible'] == original.get('is_impossible'), 'diagnostic_original_changed')
        require(row.get('contextSelection') == 'full_original_context_no_answer_based_crop', 'diagnostic_context_selection_invalid')
    return rows, metadata


def verify_candidate_directory(directory, expected_marker=CANDIDATE_SHA, expected_adapter=ADAPTER_SHA, expected_lock=LOCK_SHA, expected_stage='stage1'):
    require(expected_stage in ('stage1', 'stage2'), 'diagnostic_source_stage_invalid')
    expected_step = 40 if expected_stage == 'stage2' else 20
    directory = Path(directory)
    require(not directory.is_symlink(), 'candidate_symlink_forbidden')
    marker_path = plain_file(directory, 'candidate-complete.json')
    require(sha256_file(marker_path) == expected_marker, 'candidate_marker_changed')
    marker = json.loads(marker_path.read_text(encoding='utf-8'))
    require(marker.get('schemaVersion') == 1 and marker.get('globalStep') == expected_step, 'candidate_step_invalid')
    listed = set()
    for item in marker['files']:
        require(item['path'] not in listed, 'candidate_duplicate_file')
        listed.add(item['path'])
        path = plain_file(directory, item['path'])
        require(path.stat().st_size == item['bytes'] and sha256_file(path) == item['sha256'], 'candidate_artifact_changed')
    actual = set()
    for path in directory.rglob('*'):
        require(not path.is_symlink(), 'candidate_symlink_forbidden')
        if path.is_file() and path.name != 'candidate-complete.json':
            actual.add(path.relative_to(directory).as_posix())
    require(actual == listed, 'candidate_inventory_mismatch')
    require(sha256_file(plain_file(directory, 'adapter_model.safetensors')) == expected_adapter, 'candidate_adapter_changed')
    receipt = json.loads(plain_file(directory, 'training-receipt.json').read_text(encoding='utf-8'))
    identity = marker.get('identity', {})
    require(receipt.get('status') == 'trained_public_qa_' + expected_stage and receipt.get('identity') == identity and receipt.get('globalStep') == expected_step and receipt.get('promotionAllowed') is False and receipt.get('qualityClaimAllowed') is False, 'candidate_receipt_invalid')
    require(identity.get('baseRepository') == 'fdtn-ai/Foundation-Sec-8B-Reasoning' and identity.get('baseRevision') == BASE_REVISION and identity.get('baseArtifactLockSha256') == expected_lock and identity.get('stage') == 'public_qa_' + expected_stage, 'candidate_base_identity_invalid')
    return marker


def verify_base(directory, full=True):
    lock_path = plain_file(directory, 'artifact-lock.json')
    require(sha256_file(lock_path) == LOCK_SHA, 'base_lock_changed')
    lock = json.loads(lock_path.read_text(encoding='utf-8'))
    require(lock.get('repository') == 'fdtn-ai/Foundation-Sec-8B-Reasoning' and lock.get('revision') == BASE_REVISION, 'base_identity_invalid')
    selected = lock['files'] if full else [item for item in lock['files'] if item['path'] in ('config.json', 'tokenizer.json', 'tokenizer_config.json', 'special_tokens_map.json')]
    require({'config.json', 'tokenizer.json', 'tokenizer_config.json'} <= {item['path'] for item in selected}, 'base_tokenizer_inventory_missing')
    for item in selected:
        require(sha256_file(plain_file(directory, item['path'])) == item['sha256'], 'base_artifact_changed')
    return lock


def messages_for(row):
    # Deliberately exclude answers, originalQa, isImpossible and annotation metadata.
    return [{'role': 'system', 'content': SYSTEM}, {'role': 'user', 'content': json.dumps({'question': row['question'], 'document': row['context']}, ensure_ascii=False)}]


def preadmit(rows, tokenizer):
    inputs, records = {}, []
    for row in rows:
        ids = tokenizer.apply_chat_template(messages_for(row), tokenize=True, add_generation_prompt=True)
        require(isinstance(ids, list) and ids and all(isinstance(i, int) for i in ids), 'tokenizer_input_invalid')
        admitted = len(ids) + MAX_OUTPUT <= CONTEXT_BUDGET
        records.append({'id': row['id'], 'inputTokens': len(ids), 'outputTokenBudget': MAX_OUTPUT, 'contextTokens': CONTEXT_BUDGET, 'contextSha256': row['contextSha256'], 'fullContextPreserved': True, 'admitted': admitted, 'exclusionReason': None if admitted else 'full_context_token_budget_exceeded'})
        if admitted:
            inputs[row['id']] = ids
    return inputs, records


def output_path(value, root=Path('/checkpoints/diagnostics')):
    raw = Path(value)
    require(not raw.is_symlink() and re.fullmatch(r'public-qa-[a-z0-9-]{1,50}', raw.name), 'diagnostic_output_invalid')
    resolved_root = root.resolve(strict=True)
    require(raw.resolve().parent == resolved_root and not raw.exists(), 'diagnostic_output_must_be_new_child')
    return raw


def measured_response(content, seconds, input_tokens, output_tokens, stopped=False):
    require(isinstance(content, str) and seconds >= 0 and input_tokens > 0 and output_tokens >= 0, 'response_measurement_invalid')
    return {'content': content, 'seconds': seconds, 'inputTokens': input_tokens, 'outputTokens': output_tokens, 'timedOut': seconds >= TIMEOUT, 'tokenLimitReached': output_tokens >= MAX_OUTPUT, **({'error': 'termination_requested'} if stopped else {})}


def evaluate(args):
    require(os.name == 'posix' and os.environ.get('EVIDSCOPE_ISOLATED') == '1' and Path('/etc/podinfo/uid').is_file(), 'isolated_evaluation_required')
    stage_two = args.source_stage == 'stage2'
    pins = STAGE2_PINS if stage_two else {'marker': CANDIDATE_SHA, 'adapter': ADAPTER_SHA, 'controller': CONTROLLER_SHA}
    if stage_two:
        for label, key in [('VERIFICATION', 'verification'), ('CANDIDATE', 'marker'), ('ADAPTER', 'adapter')]:
            require(os.environ.get('EVIDSCOPE_DIAGNOSTIC_' + label + '_SHA256') == pins[key], 'diagnostic_stage2_environment_binding_invalid')
    for name, expected in [('DATA', DATA_SHA), ('MANIFEST', MANIFEST_SHA), ('CONTROLLER', pins['controller'])]:
        require(os.environ.get('EVIDSCOPE_DIAGNOSTIC_' + name + '_SHA256') == expected, 'diagnostic_environment_binding_invalid')
    require(args.data_sha256 == DATA_SHA and args.manifest_sha256 == MANIFEST_SHA and os.environ.get('EVIDSCOPE_TRAINING_IMAGE') == IMAGE, 'diagnostic_execution_binding_invalid')
    rows, _ = verify_data(args.data, args.manifest)
    candidate = verify_candidate_directory(args.adapter_dir, expected_marker=pins['marker'], expected_adapter=pins['adapter'], expected_stage=args.source_stage)
    verify_base(args.model_dir, full=not args.token_check)
    directory = output_path(args.output)
    directory.mkdir()
    os.environ.update(HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1', HF_HUB_DISABLE_TELEMETRY='1', WANDB_DISABLED='true', TOKENIZERS_PARALLELISM='false')
    if not args.token_check:
        from public_qa_memory_gate import wait_for_controller
        from public_qa_cuda_runtime import prepare
        wait_for_controller()
        print(json.dumps({'cudaLinker': prepare()}), flush=True)
    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(args.model_dir, local_files_only=True, trust_remote_code=False)
    tokenizer.pad_token = tokenizer.eos_token
    inputs, admission = preadmit(rows, tokenizer)
    atomic_json(directory / 'preadmission.json', {'schemaVersion': 1, 'datasetSha256': DATA_SHA, 'manifestSha256': MANIFEST_SHA, 'beforeAnyModelCall': True, 'rows': admission, 'admitted': len(inputs), 'excluded': len(rows)-len(inputs), 'answerBasedCropping': False})
    if args.token_check:
        print(json.dumps({'tokenCheckOnly': True, 'modelCalls': 0, 'admitted': len(inputs), 'excluded': len(rows)-len(inputs), 'output': str(directory)}), flush=True)
        return
    require(inputs, 'all_contexts_exceed_token_budget')
    import torch
    from transformers import AutoModelForCausalLM, BitsAndBytesConfig, StoppingCriteria, StoppingCriteriaList
    from peft import PeftModel
    from public_qa_thermal import wait_for_thermal_budget
    require(torch.cuda.is_available() and torch.cuda.device_count() == 1, 'single_evaluation_gpu_required')
    torch.set_num_threads(2)
    torch.cuda.set_per_process_memory_fraction(.65, 0)
    properties = torch.cuda.get_device_properties(0)
    device_id = str(getattr(properties, 'uuid', ''))
    require(device_id, 'evaluation_device_identity_unavailable')
    stopped = {'requested': False}
    def stop(*_):
        stopped['requested'] = True
    previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGTERM, signal.SIGINT)}
    class RequestedStop(StoppingCriteria):
        def __call__(self, input_ids, scores, **kwargs):
            return stopped['requested']
    responses = {'schemaVersion': 1, 'mode': 'public_qa_diagnostic', 'datasetSha256': DATA_SHA, 'maxOutputTokens': MAX_OUTPUT, 'requestTimeoutSeconds': TIMEOUT, 'baseline': {}, 'candidate': {}}
    receipt = {'schemaVersion': 1, 'diagnosticOnly': True, 'source': 'isolated_public_qa_generation', 'datasetSha256': DATA_SHA, 'manifestSha256': MANIFEST_SHA, 'candidateMarkerSha256': pins['marker'], 'adapterSha256': pins['adapter'], 'baseArtifactLockSha256': LOCK_SHA, 'sourceTrainingControllerSha256': pins['controller'], 'sourceTrainingControllerFileReadInPod': False, 'controllerExecutionVerified': False, 'sourceTrainingExecutionVerified': stage_two, 'qualityClaimAllowed': False, 'promotionAllowed': False, 'localHumanReviewPerformed': False, 'podUid': Path('/etc/podinfo/uid').read_text().strip(), 'deviceId': device_id, 'image': IMAGE, 'modelCalls': 0, 'preparedRows': len(rows), 'admittedRows': len(inputs), 'excludedRows': len(rows)-len(inputs), 'state': 'initializing', 'resources': {'cpuLimit': 2, 'memoryLimitGiB': 12, 'gpuAllocatorFraction': .65, 'contextTokens': CONTEXT_BUDGET, 'maxOutputTokens': MAX_OUTPUT, 'requestTimeoutSeconds': TIMEOUT, 'seed': 42, 'doSample': False, 'quantization': 'NF4', 'samePromptsAndResources': True}, 'candidateIdentity': candidate['identity']}
    if stage_two:
        receipt['sourceTrainingVerificationSha256'] = pins['verification']
    (directory / 'rows').mkdir()
    def persist():
        atomic_json(directory / 'responses.json', responses)
        atomic_json(directory / 'progress.json', receipt)
    for record in admission:
        if not record['admitted']:
            excluded = {**measured_response('', 0, record['inputTokens'], 0), 'error': record['exclusionReason']}
            for side in ('baseline', 'candidate'):
                responses[side][record['id']] = excluded
    persist()
    try:
        require(not stopped['requested'], 'termination_requested')
        base = AutoModelForCausalLM.from_pretrained(args.model_dir, local_files_only=True, trust_remote_code=False, device_map={'': 0}, quantization_config=BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type='nf4', bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=torch.float16))
        model = PeftModel.from_pretrained(base, args.adapter_dir, is_trainable=False, local_files_only=True)
        model.eval()
        for parameter in model.parameters():
            parameter.requires_grad_(False)
        for side in ('baseline', 'candidate'):
            with (model.disable_adapter() if side == 'baseline' else contextlib.nullcontext()):
                for row in rows:
                    if row['id'] not in inputs:
                        continue
                    require(not stopped['requested'], 'termination_requested')
                    wait_for_thermal_budget(torch)
                    require(not stopped['requested'], 'termination_requested')
                    torch.manual_seed(42)
                    encoded = torch.tensor([inputs[row['id']]], dtype=torch.long, device='cuda')
                    attention = torch.ones_like(encoded)
                    started = time.monotonic()
                    receipt.update(state='generating', side=side, rowId=row['id'])
                    persist()
                    with torch.inference_mode():
                        generated = model.generate(input_ids=encoded, attention_mask=attention, max_new_tokens=MAX_OUTPUT, max_time=TIMEOUT, do_sample=False, pad_token_id=tokenizer.eos_token_id, stopping_criteria=StoppingCriteriaList([RequestedStop()]))
                    torch.cuda.synchronize()
                    elapsed = time.monotonic()-started
                    suffix = generated[0, encoded.shape[-1]:]
                    content = tokenizer.decode(suffix, skip_special_tokens=True)
                    value = measured_response(content, elapsed, encoded.shape[-1], len(suffix), stopped['requested'])
                    responses[side][row['id']] = value
                    receipt['modelCalls'] += 1
                    atomic_json(directory / 'rows' / (side+'-'+row['id']+'.json'), {'id': row['id'], 'side': side, **value})
                    receipt.update(cudaPeakAllocatedBytes=torch.cuda.max_memory_allocated(), cudaPeakReservedBytes=torch.cuda.max_memory_reserved())
                    persist()
                    print(json.dumps({'side': side, 'id': row['id'], 'modelCalls': receipt['modelCalls'], 'seconds': elapsed, 'outputTokens': len(suffix), 'timedOut': value['timedOut'], 'tokenLimitReached': value['tokenLimitReached']}), flush=True)
                    del generated, suffix, encoded, attention
                    torch.cuda.empty_cache()
        require(not stopped['requested'], 'termination_requested')
        receipt['state'] = 'generation_completed'
    except Exception as error:
        receipt.update(state='interrupted' if stopped['requested'] else 'error', errorType=type(error).__name__, error=str(error))
        raise
    finally:
        persist()
        receipt['responsesSha256'] = sha256_file(directory / 'responses.json')
        receipt['preadmissionSha256'] = sha256_file(directory / 'preadmission.json')
        atomic_json(directory / 'diagnostic-receipt.json', receipt)
        for sig, old in previous.items():
            signal.signal(sig, old)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--data', default='/data/diagnostic/data.jsonl')
    parser.add_argument('--manifest', default='/data/diagnostic/manifest.json')
    parser.add_argument('--model-dir', default='/models/foundation-base')
    parser.add_argument('--adapter-dir', default='/adapters/candidate')
    parser.add_argument('--output', required=True)
    parser.add_argument('--data-sha256', default=DATA_SHA)
    parser.add_argument('--manifest-sha256', default=MANIFEST_SHA)
    parser.add_argument('--source-stage', choices=('stage1', 'stage2'), default='stage1')
    parser.add_argument('--token-check', action='store_true')
    evaluate(parser.parse_args())
