"""Frozen, previously unobserved QA: paired base/source80 generation only.

No training, generated labels, automatic quality claim, or promotion. The
controller independently verifies source execution and this run's receipts.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import time

from training_artifacts import atomic_json, canonical_hash, inventory, sha256_file

MODE = 'public_qa_fresh_paired_evaluation'
STAGE = 'public_qa_grounding_continuation_fresh_evaluation_v1'
SCOPE = 'paired_generation_on_frozen_previously_unobserved_128_human_annotated_rows'
DATA_SHA = 'dc8a7bb0c9eb9de9abbc6f3cea39851453db8c60cc91602223f3a9aaeb628142'
MANIFEST_SHA = 'c131723029cd014d718974bb426098925f02f6d4ced914637791e3fb76596ed1'
SOURCE_RUN = 'public-qa-grounding-20261006-r3'
SOURCE_PINS = {
    'candidateMarkerSha256': '4f25923e903e4f604401920035ac8d32fc6736874d57509f8be897340407d3eb',
    'adapterSha256': '3de58b12eb5d6b46d4ad7a4ea53c008e5f070adcfe53a73826c0002e7495374e',
    'sourceControllerSha256': 'bbb6504733765876abf85ff557f9726b762cbe565422672ee07ce4880c54409d',
    'sourceVerificationSha256': '2ee71ff2cc856ad62cbd03e4e892c76728624e622f0548167bf6c34be8732ca9',
    'provenanceSha256': '75e890ffb1b3381bdd59ffff454c4bdb253b854f2d83643511e90404c943d53a',
    'sourceRuntimeConfigMapSha256': 'fd16f98282d570af43310e9920f017867509af910f14dc7dc8360878c283e934',
    'criInspectionSha256': '9751ae20dfea9f656d4643a70c1c2863acd4224913228a5d4117ff41e0e8b6b1',
}
PRIVACY = re.compile(r'[\w.+-]+@[\w.-]+\.[a-z]{2,}|\b01[016789][- .]?\d{3,4}[- .]?\d{4}\b|\b\d{6}[- ]?[1-8]\d{6}\b', re.I)


def legacy_runner():
    spec = importlib.util.spec_from_file_location('fresh_legacy_helpers', Path(__file__).with_name('evaluate-public-qa-diagnostic.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


OLD = legacy_runner()
require = OLD.require


def read_json(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'fresh_plain_file_required')
    return json.loads(path.read_text(encoding='utf-8'))


def validate_rows(rows, metadata):
    require(len(rows) == 128 and [r.get('id') for r in rows] == metadata.get('rowIds'), 'fresh_rows_invalid')
    require(metadata.get('counts') == {'total':128, 'answerable':64, 'impossible':64}, 'fresh_balance_invalid')
    for key in ('id', 'familyId', 'contextSha256'):
        require(len({r.get(key) for r in rows}) == 128, 'fresh_duplicate_'+key)
    require(sum(r.get('isImpossible') is True for r in rows) == 64 and sum(r.get('isImpossible') is False for r in rows) == 64, 'fresh_actual_balance_invalid')
    for row in rows:
        require(isinstance(row.get('id'), str) and re.fullmatch(r'[A-Za-z0-9_-]+', row['id']) and row.get('stage') == STAGE and row.get('split') == 'heldout' and row.get('upstreamSplit') == 'dev' and row.get('upstreamRevision') == OLD.SOURCE_REVISION and row.get('language') == 'ko', 'fresh_row_provenance_invalid')
        require(row.get('sourceLicense') == 'CC-BY-SA-4.0' and row.get('upstreamAnnotation', {}).get('kind') == 'human_authored_question_answer_spans' and row.get('localHumanReviewPerformed') is False, 'fresh_annotation_invalid')
        require(isinstance(row.get('context'), str) and 0 < len(row['context']) <= 650 and isinstance(row.get('question'), str) and 0 < len(row['question']) <= 240 and hashlib.sha256(row['context'].encode()).hexdigest() == row.get('contextSha256'), 'fresh_context_changed')
        original = row.get('originalQa', {})
        require(row['question'] == original.get('question') and row.get('answers') == original.get('answers') and row['isImpossible'] == original.get('is_impossible'), 'fresh_original_changed')
        answers = row.get('answers')
        require(isinstance(answers, list) and (answers == [] if row['isImpossible'] else len(answers) > 0), 'fresh_answer_invalid')
        for answer in answers:
            start, text = answer.get('answer_start'), answer.get('text')
            require(type(start) is int and start >= 0 and isinstance(text, str) and text and row['context'][start:start+len(text)] == text, 'fresh_answer_span_invalid')
        require(row.get('contextSelection') == 'full_original_context_no_answer_based_crop' and row.get('privacyScreen') == {'kind':'basic_email_mobile_resident_id_regex', 'passed':True, 'comprehensivePrivacyReview':False} and not PRIVACY.search(row['question']+'\n'+row['context']), 'fresh_privacy_or_selection_invalid')


def verify_data(data, manifest):
    require(not Path(data).is_symlink() and not Path(manifest).is_symlink() and sha256_file(data) == DATA_SHA and sha256_file(manifest) == MANIFEST_SHA, 'fresh_input_hash_mismatch')
    metadata = read_json(manifest)
    require(metadata.get('schemaVersion') == 1 and metadata.get('stage') == STAGE and metadata.get('datasetSha256') == DATA_SHA and metadata.get('sourceRevision') == OLD.SOURCE_REVISION and metadata.get('sourceHeldoutSha256') == OLD.SOURCE_PINS['heldout'], 'fresh_manifest_invalid')
    require(all(metadata.get(key) is False for key in ('trainingUsed','heldoutUsedForTraining','automaticallyGeneratedLabels','localHumanReviewPerformed','qualityClaimAllowed','promotionAllowed')) and metadata.get('originalHumanLabelsPreserved') is True and metadata.get('frozenBeforeContinuationTraining') is True, 'fresh_claim_boundary_invalid')
    selection = metadata.get('selection', {})
    require(selection.get('fullContextPreserved') is True and selection.get('answerBasedCropping') is False and selection.get('actualTokenizerPreadmissionRequired') is True and metadata.get('previousExposureOverlap') == {'id':0,'family':0,'context':0}, 'fresh_scope_invalid')
    rows = [json.loads(line) for line in Path(data).read_text(encoding='utf-8').splitlines() if line.strip()]
    validate_rows(rows, metadata)
    return rows, metadata


def verify_binding(binding_path, verification_path, provenance_path, cri_path, adapter_path, expected_digest):
    require(not Path(binding_path).is_symlink() and sha256_file(binding_path) == expected_digest, 'fresh_binding_changed')
    binding = read_json(binding_path)
    require(binding.get('schemaVersion') == 1 and binding.get('mode') == MODE and binding.get('stage') == STAGE and re.fullmatch(r'public-qa-fresh-[a-z0-9-]{1,28}', binding.get('runId', '')), 'fresh_binding_scope_invalid')
    require(binding.get('sourceRunId') == SOURCE_RUN and binding.get('sourceGlobalStep') == 20 and binding.get('sourceOptimizerHistoryUpdates') == 80 and binding.get('sourceTrainingExecutionVerified') is True, 'fresh_source_scope_invalid')
    require(binding.get('diagnosticOnly') is True and binding.get('qualityClaimAllowed') is False and binding.get('promotionAllowed') is False and binding.get('localHumanReviewPerformed') is False and binding.get('evaluationScope') == SCOPE and binding.get('baselineExecutedThisRun') is True and binding.get('executionOrder') == ['baseline','candidate'] and binding.get('baselineKind') == 'fixed_reasoning_base_without_adapter', 'fresh_claim_invalid')
    require(binding.get('datasetSha256') == DATA_SHA and binding.get('manifestSha256') == MANIFEST_SHA and binding.get('rows') == 128 and binding.get('artifactLockSha256') == OLD.LOCK_SHA and all(binding.get(key) == value for key, value in SOURCE_PINS.items()), 'fresh_reference_changed')
    for path, key in ((verification_path,'sourceVerificationSha256'),(provenance_path,'provenanceSha256'),(cri_path,'criInspectionSha256')):
        require(not Path(path).is_symlink() and sha256_file(path) == binding[key], 'fresh_source_file_changed')
    report, provenance, cri = read_json(verification_path), read_json(provenance_path), read_json(cri_path)
    require(all(report.get(key) is True for key in ('verified','verificationPassed','actualTrainingExecutionVerified','sourceTrainingExecutionVerified','trainingRunCompleted','terminationConfirmed')) and report.get('syntheticFixture') is False and report.get('runId') == SOURCE_RUN and report.get('globalStep') == 20 and report.get('actualOptimizerUpdates') == 20 and report.get('sourceOptimizerUpdates') == 60 and report.get('totalAdapterHistoryOptimizerUpdates') == 80 and report.get('optimizerStateRestored') is False and report.get('schedulerStateRestored') is False and report.get('qualityClaimAllowed') is False and report.get('promotionAllowed') is False, 'fresh_source_execution_unverified')
    require(report.get('controllerSha256') == binding['sourceControllerSha256'] and report.get('runtimeConfigMapSha256') == binding['sourceRuntimeConfigMapSha256'] and provenance.get('targetRunId') == SOURCE_RUN and provenance.get('targetIdentity') == binding.get('candidateIdentity') == report.get('identity') and provenance.get('targetOptimizerSteps') == 20 and provenance.get('sourceOptimizerHistoryUpdates') == 60 and provenance.get('qualityClaimAllowed') is False and provenance.get('promotionAllowed') is False, 'fresh_source_identity_changed')
    reconciliation, status = report.get('runtimeExitReconciliation', {}), cri.get('status', {})
    require(reconciliation.get('reconciliationPassed') is True and reconciliation.get('criInspectionSha256') == binding['criInspectionSha256'] and reconciliation.get('originalControllerSha256') == binding['sourceControllerSha256'] and status.get('state') == 'CONTAINER_EXITED' and status.get('exitCode') == 0 and status.get('reason') == 'Completed' and status.get('id') == reconciliation.get('containerId') and status.get('labels', {}).get('io.kubernetes.pod.uid') == report.get('podUid') == reconciliation.get('podUid') and status.get('imageRef') == OLD.IMAGE, 'fresh_source_cri_mismatch')
    verify_candidate_directory(adapter_path, binding, report)
    return binding


def verify_candidate_directory(directory, binding, report):
    directory = Path(directory)
    require(directory.is_dir() and not directory.is_symlink(), 'fresh_candidate_directory_invalid')
    marker_path = OLD.plain_file(directory, 'candidate-complete.json')
    require(sha256_file(marker_path) == binding['candidateMarkerSha256'] == report.get('artifactSha256'), 'fresh_candidate_marker_changed')
    marker = read_json(marker_path)
    require(marker.get('schemaVersion') == 1 and marker.get('globalStep') == 20 and marker.get('identity') == binding['candidateIdentity'] and marker.get('files') == inventory(directory, {'candidate-complete.json'}), 'fresh_candidate_inventory_changed')
    require(sha256_file(OLD.plain_file(directory, 'adapter_model.safetensors')) == binding['adapterSha256'] == report.get('adapterSha256'), 'fresh_candidate_adapter_changed')
    identity = marker['identity']
    require(identity.get('stage') == 'public_qa_grounding_continuation_v1' and identity.get('baseRevision') == OLD.BASE_REVISION and identity.get('baseRepository') == 'fdtn-ai/Foundation-Sec-8B-Reasoning' and identity.get('baseArtifactLockSha256') == OLD.LOCK_SHA and identity.get('modelDtype') == identity.get('quantComputeDtype') == 'bfloat16' and identity.get('image') == OLD.IMAGE, 'fresh_candidate_base_changed')
    receipt = read_json(OLD.plain_file(directory, 'training-receipt.json'))
    finite, verified_finite = receipt.get('adapterFiniteCheck', {}), report.get('adapterTensorVerification', {})
    require(receipt.get('status') == 'trained_public_qa_grounding_continuation_v1' and receipt.get('identity') == identity and receipt.get('globalStep') == 20 and receipt.get('totalAdapterHistoryOptimizerUpdates') == 80 and receipt.get('trainingRunCompleted') is True and receipt.get('qualityClaimAllowed') is False and receipt.get('promotionAllowed') is False, 'fresh_candidate_receipt_invalid')
    require(finite.get('passed') is True and finite.get('tensorCount') == 256 and finite.get('nonFiniteTensorCount') == 0 and finite.get('beforeCandidateSealing') is True and verified_finite.get('verified') is True and verified_finite.get('allFinite') is True and verified_finite.get('tensorCount') == 256 and verified_finite.get('dtype') == 'F32' and verified_finite.get('sha256') == binding['adapterSha256'], 'fresh_candidate_finite_unverified')
    require(sha256_file(OLD.plain_file(directory,'training-exposure.json')) == report.get('exposureReceiptSha256') == receipt.get('trainingExposure', {}).get('sha256'), 'fresh_candidate_exposure_changed')
    return marker


def preadmit(rows, tokenizer):
    inputs, records = OLD.preadmit(rows, tokenizer)
    for row, record in zip(rows, records):
        record['promptSha256'] = canonical_hash(OLD.messages_for(row))
        record['inputIdsSha256'] = canonical_hash(inputs[row['id']]) if row['id'] in inputs else None
    return inputs, records


def require_all_admitted(rows, inputs, records):
    require(len(rows) == len(inputs) == len(records) == 128 and all(record['admitted'] is True for record in records), 'fresh_all_128_rows_required_before_model_calls')
    require([record['id'] for record in records] == [row['id'] for row in rows] and set(inputs) == {row['id'] for row in rows}, 'fresh_admission_identity_mismatch')


def generation_plan(rows):
    return [(side, row['id']) for side in ('baseline', 'candidate') for row in rows]


def observe_adapter_state(model, side):
    require(side in ('baseline','candidate'), 'fresh_adapter_side_invalid')
    states = [module.disable_adapters for module in model.modules() if isinstance(getattr(module,'disable_adapters',None), bool)]
    require(states and all(state is (side == 'baseline') for state in states), 'fresh_observed_adapter_state_mismatch')
    return {'side':side,'adapterEnabled':side == 'candidate','observedAdapterModuleCount':len(states),'allAdapterModulesDisabled':all(states),'allAdapterModulesEnabled':not any(states)}


def cgroup_snapshot():
    root = Path('/sys/fs/cgroup')
    result = {}
    for name in ('memory.current','memory.peak','memory.max','memory.high','memory.events','memory.stat','cpu.max'):
        try:
            text = (root/name).read_text().strip()
            result[name] = dict(line.split() for line in text.splitlines()) if name in ('memory.events','memory.stat') else text
        except OSError as error:
            result[name] = {'unavailable': type(error).__name__}
    return result


def evaluate(args):
    require(os.name == 'posix' and os.environ.get('EVIDSCOPE_ISOLATED') == '1' and Path('/etc/podinfo/uid').is_file(), 'isolated_evaluation_required')
    binding = verify_binding(args.binding,args.verification,args.provenance,args.cri_inspection,args.adapter_dir,os.environ.get('EVIDSCOPE_FRESH_EVALUATION_BINDING_SHA256'))
    require(os.environ.get('EVIDSCOPE_TRAINING_IMAGE') == OLD.IMAGE, 'fresh_image_changed')
    for name, key in (('DATA','datasetSha256'),('MANIFEST','manifestSha256'),('CONTROLLER','sourceControllerSha256'),('VERIFICATION','sourceVerificationSha256'),('CANDIDATE','candidateMarkerSha256'),('ADAPTER','adapterSha256')):
        require(os.environ.get('EVIDSCOPE_DIAGNOSTIC_'+name+'_SHA256') == binding[key], 'fresh_environment_binding_invalid')
    rows, _ = verify_data(args.data,args.manifest)
    OLD.verify_base(args.model_dir, full=not args.token_check)
    directory = OLD.output_path(args.output, root=Path('/checkpoints/fresh-evaluations'))
    require(directory.name == binding['runId'], 'fresh_output_run_mismatch')
    directory.mkdir()
    os.environ.update(HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',HF_HUB_DISABLE_TELEMETRY='1',WANDB_DISABLED='true',TOKENIZERS_PARALLELISM='false')
    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(args.model_dir,local_files_only=True,trust_remote_code=False)
    tokenizer.pad_token = tokenizer.eos_token
    inputs, admission = preadmit(rows,tokenizer)
    atomic_json(directory/'preadmission.json',{'schemaVersion':1,'datasetSha256':DATA_SHA,'manifestSha256':MANIFEST_SHA,'beforeAnyModelCall':True,'modelCalls':0,'rows':admission,'admitted':len(inputs),'excluded':len(rows)-len(inputs),'answerBasedCropping':False})
    # Even token-check refuses a reduced set; no model can run before all 128 pass.
    require_all_admitted(rows,inputs,admission)
    if args.token_check:
        atomic_json(directory/'evaluation-receipt.json',{'schemaVersion':1,'mode':MODE,'state':'token_check_completed','bindingSha256':sha256_file(args.binding),'modelCalls':0,'admittedRows':128,'excludedRows':0,'preadmissionSha256':sha256_file(directory/'preadmission.json'),'qualityClaimAllowed':False,'promotionAllowed':False})
        print(json.dumps({'tokenCheckOnly':True,'modelCalls':0,'admitted':128,'excluded':0,'output':str(directory)}),flush=True)
        return
    from public_qa_memory_gate import wait_for_controller
    from public_qa_cuda_runtime import prepare
    wait_for_controller()
    print(json.dumps({'cudaLinker':prepare()}),flush=True)
    import torch
    from transformers import AutoModelForCausalLM, BitsAndBytesConfig, StoppingCriteria, StoppingCriteriaList
    from peft import PeftModel
    from public_qa_thermal import wait_for_thermal_budget
    require(torch.cuda.is_available() and torch.cuda.device_count() == 1 and torch.cuda.is_bf16_supported(), 'single_bf16_evaluation_gpu_required')
    torch.set_num_threads(2)
    torch.cuda.set_per_process_memory_fraction(.65,0)
    device_id = str(getattr(torch.cuda.get_device_properties(0),'uuid',''))
    require(device_id, 'evaluation_device_identity_unavailable')
    stopped = {'requested':False}
    def stop(*_):
        stopped['requested'] = True
    previous = {sig:signal.signal(sig,stop) for sig in (signal.SIGTERM,signal.SIGINT)}
    class RequestedStop(StoppingCriteria):
        def __call__(self,input_ids,scores,**kwargs):
            return stopped['requested']
    responses = {'schemaVersion':1,'mode':MODE,'datasetSha256':DATA_SHA,'maxOutputTokens':128,'requestTimeoutSeconds':120,'baseline':{},'candidate':{},'baselineExecutedThisRun':True,'evaluationScope':SCOPE}
    receipt = {'schemaVersion':1,'mode':MODE,'stage':STAGE,'runId':binding['runId'],'diagnosticOnly':True,'state':'initializing','bindingSha256':sha256_file(args.binding),'datasetSha256':DATA_SHA,'manifestSha256':MANIFEST_SHA,'baseArtifactLockSha256':OLD.LOCK_SHA,'candidateIdentity':binding['candidateIdentity'],**SOURCE_PINS,'sourceRunId':SOURCE_RUN,'sourceGlobalStep':20,'sourceOptimizerHistoryUpdates':80,'sourceTrainingExecutionVerified':True,'controllerExecutionVerified':False,'qualityClaimAllowed':False,'promotionAllowed':False,'localHumanReviewPerformed':False,'evaluationScope':SCOPE,'baselineKind':'fixed_reasoning_base_without_adapter','baselineExecutedThisRun':True,'executionOrder':['baseline','candidate'],'podUid':Path('/etc/podinfo/uid').read_text().strip(),'deviceId':device_id,'image':OLD.IMAGE,'modelCalls':0,'preparedRows':128,'admittedRows':128,'excludedRows':0,'sideMeasurements':{},'resources':{'cpuLimit':2,'memoryLimitGiB':12,'gpuAllocatorFraction':.65,'contextTokens':1024,'maxOutputTokens':128,'requestTimeoutSeconds':120,'seed':42,'doSample':False,'quantization':'NF4','precision':'bf16','modelDtype':'bfloat16','quantComputeDtype':'bfloat16','samePromptsAndResources':True},'cgroupBeforeLoad':cgroup_snapshot(),'limitations':['Sequential baseline-first evaluation; timing includes order and warm cache effects.','Pinned local source execution records are not independent hardware attestation.','No local human semantic review; public QA accuracy does not establish legal or financial quality.']}
    (directory/'rows').mkdir()
    def persist():
        atomic_json(directory/'responses.json',responses)
        atomic_json(directory/'progress.json',receipt)
    persist()
    admitted_by_id = {record['id']:record for record in admission}
    try:
        require(not stopped['requested'],'termination_requested')
        base = AutoModelForCausalLM.from_pretrained(args.model_dir,local_files_only=True,trust_remote_code=False,torch_dtype=torch.bfloat16,device_map={'':0},quantization_config=BitsAndBytesConfig(load_in_4bit=True,bnb_4bit_quant_type='nf4',bnb_4bit_use_double_quant=True,bnb_4bit_compute_dtype=torch.bfloat16))
        model = PeftModel.from_pretrained(base,args.adapter_dir,is_trainable=False,local_files_only=True)
        model.eval()
        for parameter in model.parameters():
            parameter.requires_grad_(False)
        require(model.get_base_model() is base and model.training is False and not any(parameter.requires_grad for parameter in model.parameters()), 'fresh_evaluation_model_lifecycle_invalid')
        receipt['modelLifecycle'] = {'sameLoadedBaseObject':True,'adapterLoadedOnce':True,'isTrainable':False,'modelTraining':False,'trainableParameterCount':0,'baseArtifactLockSha256':OLD.LOCK_SHA,'adapterSha256':binding['adapterSha256']}
        print(json.dumps({'freshModelLifecycle':receipt['modelLifecycle']}),flush=True)
        receipt['observedQuantComputeDtypes'] = sorted({str(module.compute_dtype) for module in model.modules() if getattr(module,'compute_dtype',None) is not None})
        require(receipt['observedQuantComputeDtypes'] == ['torch.bfloat16'], 'fresh_observed_quant_dtype_mismatch')
        receipt['cgroupAfterLoad'] = cgroup_snapshot()
        for side in ('baseline','candidate'):
            torch.cuda.reset_peak_memory_stats()
            side_started = time.monotonic()
            context = model.disable_adapter() if side == 'baseline' else contextlib.nullcontext()
            with context:
                adapter_state = observe_adapter_state(model,side)
                receipt.setdefault('adapterStates',{})[side] = adapter_state
                print(json.dumps({'freshAdapterState':adapter_state}),flush=True)
                for planned_side, row_id in generation_plan(rows):
                    if planned_side != side:
                        continue
                    require(not stopped['requested'],'termination_requested')
                    wait_for_thermal_budget(torch)
                    require(not stopped['requested'],'termination_requested')
                    torch.manual_seed(42)
                    encoded = torch.tensor([inputs[row_id]],dtype=torch.long,device='cuda')
                    attention = torch.ones_like(encoded)
                    # Bind actual model tensors to the admitted full-context inputs.
                    input_hash = canonical_hash(encoded.detach().cpu().tolist()[0])
                    require(input_hash == admitted_by_id[row_id]['inputIdsSha256'], 'fresh_actual_tensor_input_changed')
                    receipt.update(state='generating',side=side,rowId=row_id)
                    persist()
                    torch.cuda.synchronize()
                    started = time.monotonic()
                    with torch.inference_mode():
                        generated = model.generate(input_ids=encoded,attention_mask=attention,max_new_tokens=128,max_time=120,do_sample=False,pad_token_id=tokenizer.eos_token_id,stopping_criteria=StoppingCriteriaList([RequestedStop()]))
                    torch.cuda.synchronize()
                    elapsed = time.monotonic()-started
                    suffix = generated[0,encoded.shape[-1]:]
                    value = OLD.measured_response(tokenizer.decode(suffix,skip_special_tokens=True),elapsed,encoded.shape[-1],len(suffix),stopped['requested'])
                    value.update(inputIdsSha256=input_hash,promptSha256=admitted_by_id[row_id]['promptSha256'],callOrdinal=receipt['modelCalls']+1,adapterEnabled=side == 'candidate')
                    responses[side][row_id] = value
                    receipt['modelCalls'] += 1
                    atomic_json(directory/'rows'/(side+'-'+row_id+'.json'),{'id':row_id,'side':side,**value})
                    receipt['cudaPeakAllocatedBytes'] = max(receipt.get('cudaPeakAllocatedBytes',0),torch.cuda.max_memory_allocated())
                    receipt['cudaPeakReservedBytes'] = max(receipt.get('cudaPeakReservedBytes',0),torch.cuda.max_memory_reserved())
                    persist()
                    print(json.dumps({'side':side,'id':row_id,'modelCalls':receipt['modelCalls'],'inputIdsSha256':input_hash,'promptSha256':value['promptSha256'],'adapterEnabled':value['adapterEnabled'],'seconds':elapsed,'outputTokens':len(suffix),'timedOut':value['timedOut'],'tokenLimitReached':value['tokenLimitReached']}),flush=True)
                    del generated,suffix,encoded,attention
                    torch.cuda.empty_cache()
            receipt['sideMeasurements'][side] = {'modelCalls':len(responses[side]),'wallSeconds':time.monotonic()-side_started,'generationSeconds':sum(value['seconds'] for value in responses[side].values()),'cudaPeakAllocatedBytes':torch.cuda.max_memory_allocated(),'cudaPeakReservedBytes':torch.cuda.max_memory_reserved(),'cgroup':cgroup_snapshot()}
            persist()
        require(not stopped['requested'] and receipt['modelCalls'] == 256 and len(responses['baseline']) == len(responses['candidate']) == 128,'fresh_pair_incomplete')
        # Read-only source candidate must still match after both sides.
        verify_candidate_directory(args.adapter_dir,binding,read_json(args.verification))
        receipt['state'] = 'generation_completed'
    except Exception as error:
        receipt.update(state='interrupted' if stopped['requested'] else 'error',errorType=type(error).__name__,error=str(error))
        raise
    finally:
        try:
            persist()
            receipt.update(responsesSha256=sha256_file(directory/'responses.json'),preadmissionSha256=sha256_file(directory/'preadmission.json'),cgroupAfterGeneration=cgroup_snapshot())
            receipt['files'] = inventory(directory, {'evaluation-receipt.json'})
            atomic_json(directory/'evaluation-receipt.json',receipt)
        finally:
            for sig, handler in previous.items():
                signal.signal(sig,handler)


def parser():
    result = argparse.ArgumentParser()
    for name, default in (('data','/data/fresh/data.jsonl'),('manifest','/data/fresh/manifest.json'),('binding','/bindings/binding.json'),('verification','/bindings/verification.json'),('provenance','/bindings/provenance.json'),('cri-inspection','/bindings/cri-inspect.json'),('model-dir','/models/foundation-base'),('adapter-dir','/adapters/candidate')):
        result.add_argument('--'+name,default=default)
    result.add_argument('--output',required=True)
    result.add_argument('--token-check',action='store_true')
    return result


if __name__ == '__main__':
    evaluate(parser().parse_args())
