"""Candidate-only generation on previously observed rows; regression diagnosis."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import time

from training_artifacts import atomic_json, sha256_file

def legacy_runner():
    spec=importlib.util.spec_from_file_location('public_qa_diagnostic',Path(__file__).with_name('evaluate-public-qa-diagnostic.py'))
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def grounding_runner():
    path=Path(__file__).with_name('public_qa_grounding.py')
    if not path.is_file():
        path=Path(__file__).with_name('public-qa-grounding.py')
    spec=importlib.util.spec_from_file_location('public_qa_grounding',path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

PRIOR_RESPONSES_SHA='5f080bd286c92a564de11bc98584e354df37ad14e0a7e423a4908de2215c5fa9'
PRIOR_VERIFICATION_SHA='b649620af1f012e80e8a13e753aba3f5636876953938aebbeeadde823a23ab8b'

def verify_binding(binding_path,verification_path,provenance_path,adapter_path,expected_digest):
    old=legacy_runner()
    old.require(not Path(binding_path).is_symlink() and sha256_file(binding_path)==expected_digest,'grounding_diagnostic_binding_changed')
    binding=json.loads(Path(binding_path).read_text(encoding='utf-8'))
    old.require(binding.get('schemaVersion')==1 and binding.get('mode')=='public_qa_grounding_diagnostic' and re.fullmatch(r'public-qa-grounding-[a-z0-9-]{1,28}',binding.get('sourceRunId','')) and binding.get('sourceGlobalStep')==20 and binding.get('sourceOptimizerHistoryUpdates')==60,'grounding_diagnostic_source_scope_invalid')
    old.require(binding.get('diagnosticOnly') is True and binding.get('qualityClaimAllowed') is False and binding.get('promotionAllowed') is False and binding.get('evaluationScope')=='retrospective_regression_diagnosis_on_previously_observed_64_rows' and binding.get('baselineExecutedThisRun') is False,'grounding_diagnostic_claim_invalid')
    old.require(binding.get('priorResponsesSha256')==PRIOR_RESPONSES_SHA and binding.get('priorVerificationSha256')==PRIOR_VERIFICATION_SHA and binding.get('datasetSha256')==old.DATA_SHA and binding.get('manifestSha256')==old.MANIFEST_SHA and binding.get('artifactLockSha256')==old.LOCK_SHA and binding.get('rows')==64,'grounding_diagnostic_reference_changed')
    old.require(not Path(verification_path).is_symlink() and sha256_file(verification_path)==binding.get('sourceVerificationSha256') and not Path(provenance_path).is_symlink() and sha256_file(provenance_path)==binding.get('provenanceSha256'),'grounding_diagnostic_training_binding_changed')
    report=json.loads(Path(verification_path).read_text(encoding='utf-8'))
    candidate=grounding_runner().verify_grounding_artifacts(adapter_path,provenance_path)
    old.require(report.get('verified') is True and report.get('actualTrainingExecutionVerified') is True and report.get('trainingRunCompleted') is True and report.get('terminationConfirmed') is True and report.get('runId')==binding['sourceRunId'] and report.get('globalStep')==20 and report.get('actualOptimizerUpdates')==20 and report.get('sourceOptimizerUpdates')==40 and report.get('totalAdapterHistoryOptimizerUpdates')==60 and report.get('optimizerStateRestored') is False and report.get('schedulerStateRestored') is False and report.get('qualityClaimAllowed') is False and report.get('promotionAllowed') is False,'grounding_diagnostic_source_execution_unverified')
    old.require(candidate['artifactSha256']==binding.get('candidateMarkerSha256')==report.get('artifactSha256') and sha256_file(Path(adapter_path)/'adapter_model.safetensors')==binding.get('adapterSha256')==report.get('adapterSha256') and candidate['identity']==binding.get('candidateIdentity')==report.get('identity') and report.get('controllerSha256')==binding.get('sourceControllerSha256'),'grounding_diagnostic_candidate_changed')
    return binding

def evaluate(args):
    old=legacy_runner()
    old.require(os.name=='posix' and os.environ.get('EVIDSCOPE_ISOLATED')=='1' and Path('/etc/podinfo/uid').is_file(),'isolated_evaluation_required')
    binding=verify_binding(args.binding,args.verification,args.provenance,args.adapter_dir,os.environ.get('EVIDSCOPE_GROUNDING_DIAGNOSTIC_BINDING_SHA256'))
    old.require(os.environ.get('EVIDSCOPE_TRAINING_IMAGE')==old.IMAGE,'grounding_diagnostic_image_changed')
    for name,key in [('DATA','datasetSha256'),('MANIFEST','manifestSha256'),('CONTROLLER','sourceControllerSha256'),('VERIFICATION','sourceVerificationSha256'),('CANDIDATE','candidateMarkerSha256'),('ADAPTER','adapterSha256')]:
        old.require(os.environ.get('EVIDSCOPE_DIAGNOSTIC_'+name+'_SHA256')==binding[key],'grounding_diagnostic_environment_binding_invalid')
    rows,_=old.verify_data(args.data,args.manifest)
    old.verify_base(args.model_dir,full=not args.token_check)
    directory=old.output_path(args.output)
    directory.mkdir()
    os.environ.update(HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',HF_HUB_DISABLE_TELEMETRY='1',WANDB_DISABLED='true',TOKENIZERS_PARALLELISM='false')
    if not args.token_check:
        from public_qa_memory_gate import wait_for_controller
        from public_qa_cuda_runtime import prepare
        wait_for_controller()
        print(json.dumps({'cudaLinker':prepare()}),flush=True)
    from transformers import AutoTokenizer
    tokenizer=AutoTokenizer.from_pretrained(args.model_dir,local_files_only=True,trust_remote_code=False)
    tokenizer.pad_token=tokenizer.eos_token
    inputs,admission=old.preadmit(rows,tokenizer)
    atomic_json(directory/'preadmission.json',{'schemaVersion':1,'datasetSha256':old.DATA_SHA,'manifestSha256':old.MANIFEST_SHA,'beforeAnyModelCall':True,'rows':admission,'admitted':len(inputs),'excluded':len(rows)-len(inputs),'answerBasedCropping':False})
    if args.token_check:
        print(json.dumps({'tokenCheckOnly':True,'modelCalls':0,'admitted':len(inputs),'excluded':len(rows)-len(inputs),'output':str(directory)}),flush=True)
        return
    old.require(len(inputs)==64,'grounding_diagnostic_all_64_rows_required')
    import torch
    from transformers import AutoModelForCausalLM,BitsAndBytesConfig,StoppingCriteria,StoppingCriteriaList
    from peft import PeftModel
    from public_qa_thermal import wait_for_thermal_budget
    old.require(torch.cuda.is_available() and torch.cuda.device_count()==1,'single_evaluation_gpu_required')
    torch.set_num_threads(2)
    torch.cuda.set_per_process_memory_fraction(.65,0)
    device_id=str(getattr(torch.cuda.get_device_properties(0),'uuid',''))
    old.require(device_id,'evaluation_device_identity_unavailable')
    stopped={'requested':False}
    def stop(*_):
        stopped['requested']=True
    previous={sig:signal.signal(sig,stop) for sig in (signal.SIGTERM,signal.SIGINT)}
    class RequestedStop(StoppingCriteria):
        def __call__(self,input_ids,scores,**kwargs):
            return stopped['requested']
    responses={'schemaVersion':1,'mode':'public_qa_diagnostic','datasetSha256':old.DATA_SHA,'maxOutputTokens':old.MAX_OUTPUT,'requestTimeoutSeconds':old.TIMEOUT,'candidate':{},'baselineExecutedThisRun':False,'evaluationScope':binding['evaluationScope'],'priorResponsesSha256':PRIOR_RESPONSES_SHA}
    receipt={'schemaVersion':1,'mode':'public_qa_grounding_diagnostic','diagnosticOnly':True,'source':'isolated_grounding_candidate_generation','datasetSha256':old.DATA_SHA,'manifestSha256':old.MANIFEST_SHA,'bindingSha256':sha256_file(args.binding),'candidateMarkerSha256':binding['candidateMarkerSha256'],'adapterSha256':binding['adapterSha256'],'baseArtifactLockSha256':old.LOCK_SHA,'sourceTrainingControllerSha256':binding['sourceControllerSha256'],'sourceTrainingVerificationSha256':binding['sourceVerificationSha256'],'sourceTrainingExecutionVerified':True,'sourceRunId':binding['sourceRunId'],'sourceGlobalStep':20,'sourceOptimizerHistoryUpdates':60,'provenanceSha256':binding['provenanceSha256'],'priorResponsesSha256':PRIOR_RESPONSES_SHA,'priorVerificationSha256':PRIOR_VERIFICATION_SHA,'baselineExecutedThisRun':False,'evaluationScope':binding['evaluationScope'],'controllerExecutionVerified':False,'qualityClaimAllowed':False,'promotionAllowed':False,'localHumanReviewPerformed':False,'podUid':Path('/etc/podinfo/uid').read_text().strip(),'deviceId':device_id,'image':old.IMAGE,'modelCalls':0,'preparedRows':64,'admittedRows':64,'excludedRows':0,'state':'initializing','resources':{'cpuLimit':2,'memoryLimitGiB':12,'gpuAllocatorFraction':.65,'contextTokens':old.CONTEXT_BUDGET,'maxOutputTokens':old.MAX_OUTPUT,'requestTimeoutSeconds':old.TIMEOUT,'seed':42,'doSample':False,'quantization':'NF4','samePromptsAndResources':True},'candidateIdentity':binding['candidateIdentity']}
    (directory/'rows').mkdir()
    def persist():
        atomic_json(directory/'responses.json',responses)
        atomic_json(directory/'progress.json',receipt)
    persist()
    try:
        old.require(not stopped['requested'],'termination_requested')
        base=AutoModelForCausalLM.from_pretrained(args.model_dir,local_files_only=True,trust_remote_code=False,device_map={'':0},quantization_config=BitsAndBytesConfig(load_in_4bit=True,bnb_4bit_quant_type='nf4',bnb_4bit_use_double_quant=True,bnb_4bit_compute_dtype=torch.float16))
        model=PeftModel.from_pretrained(base,args.adapter_dir,is_trainable=False,local_files_only=True)
        model.eval()
        for parameter in model.parameters():
            parameter.requires_grad_(False)
        for row in rows:
            old.require(not stopped['requested'],'termination_requested')
            wait_for_thermal_budget(torch)
            old.require(not stopped['requested'],'termination_requested')
            torch.manual_seed(42)
            encoded=torch.tensor([inputs[row['id']]],dtype=torch.long,device='cuda')
            attention=torch.ones_like(encoded)
            started=time.monotonic()
            receipt.update(state='generating',side='candidate',rowId=row['id'])
            persist()
            with torch.inference_mode():
                generated=model.generate(input_ids=encoded,attention_mask=attention,max_new_tokens=old.MAX_OUTPUT,max_time=old.TIMEOUT,do_sample=False,pad_token_id=tokenizer.eos_token_id,stopping_criteria=StoppingCriteriaList([RequestedStop()]))
            torch.cuda.synchronize()
            elapsed=time.monotonic()-started
            suffix=generated[0,encoded.shape[-1]:]
            value=old.measured_response(tokenizer.decode(suffix,skip_special_tokens=True),elapsed,encoded.shape[-1],len(suffix),stopped['requested'])
            responses['candidate'][row['id']]=value
            receipt['modelCalls']+=1
            atomic_json(directory/'rows'/('candidate-'+row['id']+'.json'),{'id':row['id'],'side':'candidate',**value})
            receipt.update(cudaPeakAllocatedBytes=torch.cuda.max_memory_allocated(),cudaPeakReservedBytes=torch.cuda.max_memory_reserved())
            persist()
            print(json.dumps({'side':'candidate','id':row['id'],'modelCalls':receipt['modelCalls'],'seconds':elapsed,'outputTokens':len(suffix),'timedOut':value['timedOut'],'tokenLimitReached':value['tokenLimitReached']}),flush=True)
            del generated,suffix,encoded,attention
            torch.cuda.empty_cache()
        old.require(not stopped['requested'],'termination_requested')
        receipt['state']='generation_completed'
    except Exception as error:
        receipt.update(state='interrupted' if stopped['requested'] else 'error',errorType=type(error).__name__,error=str(error))
        raise
    finally:
        persist()
        receipt['responsesSha256']=sha256_file(directory/'responses.json')
        receipt['preadmissionSha256']=sha256_file(directory/'preadmission.json')
        atomic_json(directory/'diagnostic-receipt.json',receipt)
        for sig,previous_handler in previous.items():
            signal.signal(sig,previous_handler)

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--data',default='/data/diagnostic/data.jsonl')
    parser.add_argument('--manifest',default='/data/diagnostic/manifest.json')
    parser.add_argument('--binding',default='/bindings/binding.json')
    parser.add_argument('--verification',default='/bindings/verification.json')
    parser.add_argument('--provenance',default='/bindings/provenance.json')
    parser.add_argument('--model-dir',default='/models/foundation-base')
    parser.add_argument('--adapter-dir',default='/adapters/candidate')
    parser.add_argument('--output',required=True)
    parser.add_argument('--token-check',action='store_true')
    evaluate(parser.parse_args())
