import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {readFileSync,writeFileSync,mkdirSync,existsSync,unlinkSync} from 'node:fs';
import {resolve} from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {PUBLIC_QA_RESOURCE_PROFILE,publicQaStartDecision,publicQaContinueDecision} from '../src/public-qa-resource-policy.mjs';
import {QA_CONTEXT,QA_NAMESPACE,QA_NODE,QA_IMAGE,trainingJob,publicQaInputs,runtimeConfigMap} from './public-qa-workload.mjs';
import {enforceMemoryHigh} from './public-qa-memory-high.mjs';
import {publicQaDiagnosticInputs,diagnosticRuntimeConfigMap,diagnosticJob,assertDiagnosticMounts} from './public-qa-diagnostic-workload.mjs';
const execute=promisify(execFile),wait=ms=>new Promise(r=>setTimeout(r,ms));
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
async function command(program,args,options={}){return (await execute(program,args,{encoding:'utf8',windowsHide:true,timeout:15000,maxBuffer:4*1024*1024,...options})).stdout;}
// Windows can intermittently reject a local socket bind before a read reaches
// the API. Retry only this specific read failure; mutations and resource/scope
// failures are never replayed or interpreted as a successful observation.
export async function retryPublicQaRead(operation,{pause=wait,fallback}={}){
 for(let attempt=0;;attempt++){
  try{return await operation();}catch(error){
   const message=String(error.stderr||error.message||'');
   if(!/invalid pointer address|EFAULT|WSAEFAULT/iu.test(message))throw error;
   if(attempt>=2){if(fallback)return fallback();throw error;}
   await pause((attempt+1)*500);
  }
 }
}
const kubectl=(args,{retryRead=false,...options}={})=>{
 const execute=()=>command('kubectl',['--kubeconfig',QA_CONTEXT,'--request-timeout=10s',...args],options);
 const fallback=async()=>{
  const expected=JSON.parse(readFileSync('.local/training/gpu-node/gpu-readiness.json','utf8').replace(/^\uFEFF/,''));
  const node=JSON.parse(await command('docker',['exec',QA_NODE,'kubectl','--request-timeout=10s','get','node',QA_NODE,'-o','json']));
  if(expected.node!==QA_NODE||!expected.nodeUid||node.metadata.uid!==expected.nodeUid)throw Error('read_fallback_node_identity_changed');
  console.log(JSON.stringify({phase:'read_transport_fallback',nodeUid:node.metadata.uid,observedAt:new Date().toISOString()}));
  return command('docker',['exec',QA_NODE,'kubectl','--request-timeout=10s',...args],options);
 };
 return retryRead||args.includes('get')||args.includes('logs')?retryPublicQaRead(execute,{fallback}):execute();
};
const json=async args=>JSON.parse(await kubectl(args));
export async function measurePublicQa(pod){
 const cgCode="import json,pathlib; p=pathlib.Path('/sys/fs/cgroup'); e=dict(l.split() for l in (p/'memory.events').read_text().splitlines()); print(json.dumps({'memoryCurrentGiB':int((p/'memory.current').read_text())/1073741824,'memoryLimitGiB':int((p/'memory.max').read_text())/1073741824,'oomCount':int(e.get('oom',0)),'oomKillCount':int(e.get('oom_kill',0)),'cpuMax':(p/'cpu.max').read_text().strip(),'memoryStat':dict((k,int(v)) for k,v in (line.split() for line in (p/'memory.stat').read_text().splitlines()) if k in ('anon','file','file_mapped','file_dirty','inactive_file','active_file'))}))";
 const values=await Promise.all([command('powershell.exe',['-NoProfile','-NonInteractive','-File','scripts/public-qa-resource-probe.ps1']),command('wsl.exe',['--distribution','docker-desktop','--user','root','--','sh','-c','cat /proc/meminfo; cat /proc/pressure/memory']).then(raw=>({raw,observedAt:new Date().toISOString()})),...(pod?[kubectl(['-n',QA_NAMESPACE,'exec',pod,'--','python','-c',cgCode],{retryRead:true}).then(raw=>({...JSON.parse(raw),observedAt:new Date().toISOString()}))]:[])]);
 const sample=JSON.parse(values[0]),guest=values[1],available=/^MemAvailable:\s+(\d+) kB/m.exec(guest.raw),psi=/^full avg10=([\d.]+)/m.exec(guest.raw);
 if(!available||!psi)throw Error('guest_resource_probe_invalid');
 sample.guest={observedAt:guest.observedAt,memAvailableGiB:Number(available[1])/1048576,memoryFullAvg10:Number(psi[1])};
 if(pod){sample.cgroup=values[2];const [quota,period]=sample.cgroup.cpuMax.split(' ').map(Number);if(!Number.isFinite(quota)||quota/period>2)throw Error('cpu_cgroup_limit_invalid');}
 return sample;
}
function assertPod(pod,jobUid){
 const s=pod.spec,c=s.containers?.[0];
 if(pod.metadata.namespace!==QA_NAMESPACE||!pod.metadata.ownerReferences?.some(o=>o.uid===jobUid&&o.kind==='Job')||s.nodeName!==QA_NODE||s.hostNetwork||s.hostPID||s.hostIPC||s.automountServiceAccountToken!==false||s.runtimeClassName!=='nvidia'||s.containers.length!==1||c.image!==QA_IMAGE||c.resources.limits.cpu!=='2'||c.resources.limits.memory!=='12Gi'||String(c.resources.limits['nvidia.com/gpu'])!=='1'||c.securityContext.readOnlyRootFilesystem!==true||c.securityContext.allowPrivilegeEscalation!==false||!c.securityContext.capabilities.drop.includes('ALL')||s.securityContext.runAsUser!==10001||s.volumes.some(v=>v.hostPath||v.secret)||c.volumeMounts.some(v=>['base','data'].includes(v.name)&&v.readOnly!==true))throw Error('live_training_pod_scope_invalid');
}
// A process can exit between the Running observation and kubectl exec. Only a
// fresh termination status for this exact Pod/container may explain that failure.
export async function observePublicQaPod({pod,jobUid,diagnostic=false,diagnosticSourceRun,assertScope,measure=measurePublicQa,readPod=name=>json(['-n',QA_NAMESPACE,'get','pod',name,'-o','json']),pause=wait}){
 try{return {sample:await measure(pod.metadata.name)};}
 catch(error){
  const before=pod.status.containerStatuses?.find(c=>c.name===pod.spec.containers[0].name),cid=before?.containerID?.replace(/^containerd:\/\//,''),message=String(error.stderr||error.message||'');
  const delayedRuntimeExit=!!cid&&message.includes('task '+cid+' not found')&&/failed to (?:create )?exec/.test(message);
  for(let attempt=0;;attempt++){
  let current;try{current=await readPod(pod.metadata.name);}catch{throw error;}
  if(!pod.metadata.uid||current?.metadata?.uid!==pod.metadata.uid||current.metadata.name!==pod.metadata.name)throw Error('training_sample_failed_pod_identity_changed',{cause:error});
  assertPod(current,jobUid);
  if(assertScope)assertScope(current);
  if(diagnostic)assertDiagnosticMounts(current,diagnosticSourceRun);
  const name=pod.spec.containers[0].name,statuses=current.status?.containerStatuses||[],container=statuses.find(c=>c.name===name),ended=container?.state?.terminated;
  if(current.spec.restartPolicy!=='Never'||current.spec.containers[0].name!==name||statuses.length!==1||!container||before?.containerID&&container.containerID!==before.containerID||before?.restartCount!==undefined&&container.restartCount!==before.restartCount)throw Error('training_sample_failed_container_identity_changed',{cause:error});
  if(ended&&Number.isInteger(ended.exitCode)&&!container.state.running&&!container.state.waiting){
   if(ended.containerID&&before?.containerID&&ended.containerID!==before.containerID)throw Error('training_sample_failed_container_identity_changed',{cause:error});
   return {terminated:ended,terminalRecheck:{podUid:current.metadata.uid,podName:current.metadata.name,containerName:name,observedAt:new Date().toISOString(),sampleError:error.message,statusReads:attempt+1}};
  }
  // containerd can report a missing task just before kubelet publishes its
  // terminal status. Poll only that exact task, preserving all identity checks.
  if(!delayedRuntimeExit||!container.state.running||attempt>=3)throw error;
  await pause([250,500,1000][attempt]);
  }
 }
}
export async function runPublicQa({executeTraining=false,pilot=false,diagnostic=false,diagnosticStageTwo=false,grounding=false,groundingContinuation=false,groundingDiagnostic=false,freshEvaluation=false,interactiveUseApproved=false,resumeProvenancePath,runId=`public-qa-${Date.now()}`}={}){
 if(freshEvaluation&&(grounding||groundingContinuation||groundingDiagnostic||diagnostic||diagnosticStageTwo||pilot||resumeProvenancePath))throw Error('fresh_evaluation_cannot_use_other_execution_modes');
 if(groundingContinuation)grounding=true;
 if(groundingDiagnostic&&(grounding||diagnostic||pilot||resumeProvenancePath))throw Error('grounding_diagnostic_cannot_use_other_execution_modes');
 if(grounding&&(diagnostic||pilot||resumeProvenancePath))throw Error('grounding_cannot_use_other_execution_modes');
 if(diagnosticStageTwo&&!diagnostic)throw Error('stage2_requires_diagnostic_mode');
 if(diagnostic&&(pilot||resumeProvenancePath))throw Error('diagnostic_cannot_train_pilot_or_resume');
 if(!/^public-qa-[a-z0-9-]{1,35}$/.test(runId))throw Error('invalid_run_id');
 const root=resolve('.local/training/public-qa-run',runId);if((diagnostic||groundingDiagnostic||groundingContinuation||freshEvaluation)&&existsSync(root))throw Error(groundingContinuation?'continuation_run_directory_must_be_new':'diagnostic_run_directory_must_be_new');mkdirSync(root,{recursive:true});
 const report={schemaVersion:1,runId,startedAt:new Date().toISOString(),profile:PUBLIC_QA_RESOURCE_PROFILE,mode:diagnostic?'explicit_public_qa_diagnostic':'explicit_public_human_qa_stage1',automaticGovernanceGateClaimed:false,qualityClaimAllowed:false,promotionAllowed:false,trainingRunCompleted:false,startSamples:[],observations:[]};
 if(diagnostic||groundingDiagnostic||freshEvaluation)report.diagnosticOnly=true;
 report.interactiveUseApproved=interactiveUseApproved===true;
 if(interactiveUseApproved)report.explicitUserOverride={request:'이번 실행은 PC 사용 중에도 학습',scope:'this bounded manual run only',inputInterruptEnabled:false,maxStartGpuUtilizationPercent:80,resourceAndThermalStopsUnchanged:true};
 const save=()=>writeFileSync(resolve(root,'controller-receipt.json'),JSON.stringify(report,null,2)+'\n');
 let jobUid,podName,leaseOwned=false,aborted=false,terminationConfirmed=false,creationAttempted=false;
 let requestedResume,groundingWorkload,freshWorkload;
 const attemptId=randomUUID();report.controllerAttemptId=attemptId;
 const cancel=()=>{aborted=true;};process.on('SIGINT',cancel);process.on('SIGTERM',cancel);
 const lease=resolve('.local/training/manual-public-qa-active.json');
 try{
  if(resumeProvenancePath){
   const localPath=resolve(resumeProvenancePath),bytes=readFileSync(localPath),value=JSON.parse(bytes.toString('utf8')),digest=sha(bytes);
   requestedResume={bytes,sha256:digest,value,localPath};
   report.requestedResumeProvenance={sha256:digest,localPath,schemaVersion:value?.schemaVersion};
   if(pilot)throw Error('resource_pilot_cannot_resume_training');
  }
  if(grounding)groundingWorkload=await import(groundingContinuation?'./public-qa-grounding-continuation-workload.mjs':'./public-qa-grounding-workload.mjs');
  if(groundingDiagnostic)groundingWorkload=await import('./public-qa-grounding-diagnostic-workload.mjs');
  if(freshEvaluation)freshWorkload=await import('./public-qa-fresh-workload.mjs');
  report.inputs=freshEvaluation?await freshWorkload.publicQaFreshEvaluationInputs({runId}):groundingDiagnostic?await groundingWorkload.publicQaGroundingDiagnosticInputs():grounding?await groundingWorkload.publicQaGroundingInputs({runId}):diagnostic?publicQaDiagnosticInputs({stageTwo:diagnosticStageTwo}):publicQaInputs();
  if(requestedResume){const {bytes:_,...provenance}=requestedResume;report.inputs.resumeProvenance=provenance;}
  report.manifest=freshEvaluation?freshWorkload.freshEvaluationJob(runId,report.inputs):groundingDiagnostic?groundingWorkload.groundingDiagnosticJob(runId,report.inputs):grounding?groundingWorkload.groundingJob(runId,report.inputs):diagnostic?diagnosticJob(runId,report.inputs):trainingJob(runId,{resumeProvenance:report.inputs.resumeProvenance});
  if(freshEvaluation)report.mode='explicit_public_qa_fresh_evaluation';
  if(groundingDiagnostic)report.mode='explicit_public_qa_grounding_diagnostic';
  if(grounding)report.mode=groundingContinuation?'explicit_public_human_qa_grounding_continuation_v1':'explicit_public_human_qa_grounding_v1';
  if(report.manifest.metadata.annotations['evidscope.io/run-kind']==='explicit-public-human-qa-stage2')report.mode='explicit_public_human_qa_stage2';
  save();
  for(let i=0;i<3;i++){if(i)await wait(10500);if(aborted)throw Error('cancelled_before_start');const measured=await measurePublicQa();report.startSamples.push(measured);console.log(JSON.stringify({phase:'resource_preflight',sample:i+1,windows:measured.windows,gpu:measured.host.gpu,guest:measured.guest}));}
  report.admission=publicQaStartDecision(report.startSamples,{interactiveUseApproved});save();
  if(!report.admission.allowed||!executeTraining){report.state=report.admission.allowed?'ready_check_only':'blocked_resources';save();return report;}
  const isolation=JSON.parse(readFileSync('.local/training/gpu-node/network-readiness.json','utf8').replace(/^\uFEFF/,''));
  const gpu=JSON.parse(readFileSync('.local/training/gpu-node/gpu-readiness.json','utf8').replace(/^\uFEFF/,''));
  if(isolation.node!==QA_NODE||isolation.verified!==true||isolation.positive?.connected!==true||isolation.blocked?.connected!==false||isolation.allowedAgain?.connected!==true||isolation.clientUidBefore!==isolation.clientUidFinal)throw Error('measured_network_control_missing');
  report.measuredIsolation=isolation;report.gpuReadiness=gpu;
  // Accept only the same live dedicated node; controller additionally checks
  // the effective Pod and deny-all policy, not a fabricated boolean receipt.
  const node=await json(['get','node',QA_NODE,'-o','json']);if(Number(node.status.allocatable['nvidia.com/gpu'])!==1||gpu.allocatableGpu!=='1'||gpu.node!==QA_NODE||!gpu.nodeUid||node.metadata.uid!==gpu.nodeUid)throw Error('gpu_node_not_verified');
  const policy=await json(['-n',QA_NAMESPACE,'get','networkpolicy','public-qa-deny-all','-o','json']);if(policy.spec.egress?.length||policy.spec.ingress?.length||Object.keys(policy.spec.podSelector||{}).length||!['Ingress','Egress'].every(t=>policy.spec.policyTypes.includes(t)))throw Error('default_deny_not_effective');
  if(requestedResume){
   const {bytes,...provenance}=requestedResume;
   const resumeCode={apiVersion:'v1',kind:'ConfigMap',metadata:{name:`public-qa-resume-${provenance.sha256.slice(0,16)}`,namespace:QA_NAMESPACE},immutable:true,data:{'provenance.json':bytes.toString('utf8')}};
   const resumeCodePath=resolve(root,'resume-configmap.json');writeFileSync(resumeCodePath,JSON.stringify(resumeCode));await kubectl(['apply','-f',resumeCodePath]);
  }
  const codePath=resolve(root,'runtime-configmap.json');writeFileSync(codePath,JSON.stringify(freshEvaluation?freshWorkload.freshEvaluationRuntimeConfigMap():groundingDiagnostic?groundingWorkload.groundingDiagnosticRuntimeConfigMap():grounding?groundingWorkload.groundingRuntimeConfigMap():diagnostic?diagnosticRuntimeConfigMap():runtimeConfigMap()));await kubectl(['apply','-f',codePath]);
  report.manifest.metadata.annotations['evidscope.io/controller-attempt']=attemptId;
  if(pilot){const c=report.manifest.spec.template.spec.containers[0];c.command=['python','/runtime/resource-pilot.py'];c.args=['--mode','resource-pilot'];report.mode='explicit_zero_learning_rate_resource_pilot';report.pilotScriptSha256=sha(readFileSync('scripts/public-qa-resource-pilot.py'));}
  report.manifestSha256=sha(JSON.stringify(report.manifest));
  writeFileSync(lease,JSON.stringify({runId,context:QA_CONTEXT,createdAt:new Date().toISOString()}),{flag:'wx'});leaseOwned=true;
  const manifestPath=resolve(root,'job.json');writeFileSync(manifestPath,JSON.stringify(report.manifest,null,2));
  creationAttempted=true;
   const created=JSON.parse(await kubectl(['create','-f',manifestPath,'-o','json']));jobUid=created.metadata.uid;if(diagnostic||grounding||groundingDiagnostic||freshEvaluation)writeFileSync(resolve(root,'live-job.json'),JSON.stringify(created,null,2));report.jobUid=jobUid;report.state='created';save();
  const baseline=report.startSamples.at(-1);let previous=baseline,lastLog='',runningSince=Date.now();
  for(;;){
   const pods=await json(['-n',QA_NAMESPACE,'get','pods','-l',`job-name=${runId}`,'-o','json']);
   if(pods.items.length>1)throw Error('unexpected_training_pod_count');
   const pod=pods.items[0];
   if(pod){assertPod(pod,jobUid);if(diagnostic)assertDiagnosticMounts(pod,report.inputs.sourceRunId);if(grounding)groundingWorkload.assertGroundingMounts(pod,report.inputs);if(groundingDiagnostic)groundingWorkload.assertGroundingDiagnosticMounts(pod,report.inputs);if(freshEvaluation)freshWorkload.assertFreshEvaluationMounts(pod,report.inputs);podName=pod.metadata.name;report.podUid=pod.metadata.uid;report.podName=pod.metadata.name;report.livePodSpec=pod.spec;if(diagnostic||grounding||groundingDiagnostic||freshEvaluation)writeFileSync(resolve(root,'live-pod.json'),JSON.stringify(pod,null,2));
    const ended=pod.status.containerStatuses?.[0]?.state?.terminated;
    if(ended){report.exit=ended;report.state=ended.exitCode===0?'process_completed':'process_failed';break;}
    if(pod.status.phase==='Running'){
     if(!report.memoryHigh){
      report.memoryHigh=await enforceMemoryHigh({pod});save();
      await kubectl(['-n',QA_NAMESPACE,'exec',podName,'--','python','-c',"from pathlib import Path; Path('/tmp/controller-memory-ready').touch(exist_ok=False)"]);
      report.memoryHigh.markerReleased=true;save();
     }
     const observation=await observePublicQaPod({pod,jobUid,diagnostic,diagnosticSourceRun:report.inputs.sourceRunId,assertScope:freshEvaluation?current=>freshWorkload.assertFreshEvaluationMounts(current,report.inputs):grounding?current=>groundingWorkload.assertGroundingMounts(current,report.inputs):groundingDiagnostic?current=>groundingWorkload.assertGroundingDiagnosticMounts(current,report.inputs):undefined});
     if(observation.terminated){report.exit=observation.terminated;report.terminalRecheck=observation.terminalRecheck;report.state=report.exit.exitCode===0?'process_completed':'process_failed';break;}
     const sample=observation.sample;const decision=publicQaContinueDecision(sample,{previous,baseline,interactiveUseApproved});report.observations.push({sample,decision});previous=sample;
     if(!decision.allowed){report.state='stopped_by_resource_guard';report.stopReasons=decision.reasons;break;}
     const log=await kubectl(['-n',QA_NAMESPACE,'logs',podName,'--tail=12']);writeFileSync(resolve(root,'latest-training.log'),log);
     if(log!==lastLog){console.log(log.trim());lastLog=log;}
    }else if(Date.now()-runningSince>120000){throw Error('training_pod_start_timeout');}
   }
   if(aborted){report.state='cancelled';break;}
   if(Date.now()-runningSince>PUBLIC_QA_RESOURCE_PROFILE.maxRuntimeMs){report.state='deadline';break;}
   save();await wait(2000);
  }
 }catch(error){report.error=error.message;report.state='error';}
 finally{
  if(creationAttempted&&!jobUid){
   try{const raw=await kubectl(['-n',QA_NAMESPACE,'get','job',runId,'--ignore-not-found','-o','json']);
    if(raw.trim()){const recovered=JSON.parse(raw);if(recovered.metadata.annotations?.['evidscope.io/controller-attempt']!==attemptId)throw Error('unowned_job_at_requested_name');jobUid=recovered.metadata.uid;report.jobUid=jobUid;report.creationRecovered=true;}
    else terminationConfirmed=true;
   }catch(error){report.cleanupError=error.message;report.creationUncertain=true;}
  }
  if(jobUid){
   try{
    if(podName){try{writeFileSync(resolve(root,'training.log'),await kubectl(['-n',QA_NAMESPACE,'logs',podName]));}catch{}}
    const current=await json(['-n',QA_NAMESPACE,'get','job',runId,'-o','json']);if(current.metadata.uid!==jobUid)throw Error('job_uid_changed');
    await kubectl(['-n',QA_NAMESPACE,'delete','job',runId,'--cascade=foreground','--wait=true','--timeout=210s'],{timeout:220000});
    const left=await json(['-n',QA_NAMESPACE,'get','pods','-l',`job-name=${runId}`,'-o','json']);if(left.items.length)throw Error('training_pod_remaining');terminationConfirmed=true;
   }catch(error){report.cleanupError=error.message;}
  }else if(!creationAttempted)terminationConfirmed=true;
  report.terminationConfirmed=terminationConfirmed;report.finishedAt=new Date().toISOString();
  if(leaseOwned&&terminationConfirmed&&JSON.parse(readFileSync(lease)).runId===runId)unlinkSync(lease);
  save();process.removeListener('SIGINT',cancel);process.removeListener('SIGTERM',cancel);
 }
 console.log(JSON.stringify({runId,state:report.state,terminationConfirmed,receipt:resolve(root,'controller-receipt.json'),trainingRunCompleted:false,artifactVerificationRequired:report.exit?.exitCode===0}));return report;
}
export function publicQaControllerOptions(argv){
 const [mode,runId,interactive,resumeOption,resumePath,...extra]=argv;
 if(!['--check-only','--execute-explicit-request','--execute-resource-pilot','--execute-diagnostic','--execute-diagnostic-stage2','--execute-grounding','--execute-grounding-continuation','--execute-grounding-diagnostic','--execute-fresh-evaluation'].includes(mode))throw Error('explicit_execution_mode_required');
 if(interactive&&interactive!=='--allow-interactive-use')throw Error('unknown_execution_argument');
 if(resumeOption&&(resumeOption!=='--resume-provenance'||!resumePath||extra.length))throw Error('invalid_resume_arguments');
 if(['--execute-diagnostic','--execute-diagnostic-stage2'].includes(mode)&&resumeOption)throw Error('diagnostic_cannot_train_pilot_or_resume');
 if(['--execute-grounding','--execute-grounding-continuation'].includes(mode)&&resumeOption)throw Error('grounding_cannot_use_other_execution_modes');
 if(mode==='--execute-grounding-diagnostic'&&resumeOption)throw Error('grounding_diagnostic_cannot_use_other_execution_modes');
 if(mode==='--execute-fresh-evaluation'&&resumeOption)throw Error('fresh_evaluation_cannot_use_other_execution_modes');
 return {executeTraining:mode!=='--check-only',pilot:mode==='--execute-resource-pilot',diagnostic:['--execute-diagnostic','--execute-diagnostic-stage2'].includes(mode),diagnosticStageTwo:mode==='--execute-diagnostic-stage2',grounding:['--execute-grounding','--execute-grounding-continuation'].includes(mode),...(mode==='--execute-grounding-continuation'?{groundingContinuation:true}:{}),groundingDiagnostic:mode==='--execute-grounding-diagnostic',...(mode==='--execute-fresh-evaluation'?{freshEvaluation:true}:{}),interactiveUseApproved:interactive==='--allow-interactive-use',resumeProvenancePath:resumePath,...(runId?{runId}:{})};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){const r=await runPublicQa(publicQaControllerOptions(process.argv.slice(2)));process.exitCode=r.state==='process_completed'||r.state==='ready_check_only'?0:2;}
