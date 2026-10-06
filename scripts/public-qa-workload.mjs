import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';

export const QA_NAMESPACE='evidscope-training';
export const QA_NODE='k3d-evidscope-training-server-0';
export const QA_CONTEXT='.test-runs/evidscope-training/kubeconfig.yaml';
export const QA_BASE_REVISION='63c930c82d7646226d33502bec5870019738400e';
export const QA_IMAGE='docker.io/evidscope/public-qa-training@sha256:440dbe10ff4e651296c65ff88f132077a4cbbb19054536b33c0695fdb5224be8';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
export function runtimeConfigMap(){
 const data=Object.fromEntries(['train-public-qa.py','train-foundation-lora.py','training_artifacts.py'].map(name=>[name,readFileSync(`scripts/${name}`,'utf8')]));
 data['resource-pilot.py']=readFileSync('scripts/public-qa-resource-pilot.py','utf8');
 data['public_qa_cuda_runtime.py']=readFileSync('scripts/public-qa-cuda-runtime.py','utf8');
 data['public_qa_memory_gate.py']=readFileSync('scripts/public-qa-memory-gate.py','utf8');
 data['public_qa_kbit.py']=readFileSync('scripts/public-qa-kbit.py','utf8');
 data['public_qa_thermal.py']=readFileSync('scripts/public-qa-thermal.py','utf8');
 data['public_qa_resume.py']=readFileSync('scripts/public-qa-resume.py','utf8');
 const digest=sha(JSON.stringify(data));
 return {apiVersion:'v1',kind:'ConfigMap',metadata:{name:`public-qa-runtime-${digest.slice(0,16)}`,namespace:QA_NAMESPACE,annotations:{'evidscope.io/code-sha256':digest}},immutable:true,data};
}
export function publicQaInputs(){
 const data='.local/public-training/stage1/public-qa-stage1.jsonl',manifest='.local/public-training/stage1/public-qa-stage1.manifest.json';
 const lock=`.local/training/base/${QA_BASE_REVISION}/artifact-lock.json`;
 const bytes=readFileSync(data),review=JSON.parse(readFileSync(manifest)),base=JSON.parse(readFileSync(lock));
 if(sha(bytes)!==review.datasetSha256||base.revision!==QA_BASE_REVISION||review.counts.train!==320||review.counts.validation!==64)throw Error('public_qa_input_binding_invalid');
 const code=runtimeConfigMap();
 return {data,manifest,lock,datasetSha256:sha(bytes),manifestSha256:sha(readFileSync(manifest)),artifactLockSha256:sha(readFileSync(lock)),runtimeConfigMap:code.metadata.name,runtimeSha256:code.metadata.annotations['evidscope.io/code-sha256'],runtimeFiles:Object.fromEntries(Object.entries(code.data).map(([name,value])=>[name,sha(value)]))};
}
export function podSpec({gpu=false,readOnly=true}={}){
 return {automountServiceAccountToken:false,restartPolicy:'Never',terminationGracePeriodSeconds:180,nodeSelector:{'kubernetes.io/hostname':QA_NODE},securityContext:{runAsNonRoot:true,runAsUser:10001,runAsGroup:10001,fsGroup:10001,seccompProfile:{type:'RuntimeDefault'}},...(gpu?{runtimeClassName:'nvidia'}:{}),containers:[{name:'training',image:QA_IMAGE,imagePullPolicy:'Never',command:['python','-c','import time; time.sleep(7200)'],securityContext:{allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,capabilities:{drop:['ALL']}},resources:{requests:{cpu:gpu?'2':'100m',memory:gpu?'8Gi':'128Mi',...(gpu?{'nvidia.com/gpu':'1'}:{})},limits:{cpu:gpu?'2':'1',memory:gpu?'12Gi':'512Mi',...(gpu?{'nvidia.com/gpu':'1'}:{})}},volumeMounts:[{name:'base',mountPath:'/models/foundation-base',readOnly},{name:'data',mountPath:'/data',readOnly},{name:'checkpoints',mountPath:'/checkpoints'},{name:'tmp',mountPath:'/tmp'},{name:'podinfo',mountPath:'/etc/podinfo',readOnly:true}]}],volumes:[{name:'base',persistentVolumeClaim:{claimName:'public-qa-base'}},{name:'data',persistentVolumeClaim:{claimName:'public-qa-data'}},{name:'checkpoints',persistentVolumeClaim:{claimName:'public-qa-checkpoints'}},{name:'tmp',emptyDir:{sizeLimit:'1Gi'}},{name:'podinfo',downwardAPI:{items:[{path:'uid',fieldRef:{fieldPath:'metadata.uid'}}]}}]};
}
export function setupManifest(){
 const ns={apiVersion:'v1',kind:'Namespace',metadata:{name:QA_NAMESPACE,labels:{'pod-security.kubernetes.io/enforce':'restricted'}}};
 const deny={apiVersion:'networking.k8s.io/v1',kind:'NetworkPolicy',metadata:{name:'public-qa-deny-all',namespace:QA_NAMESPACE},spec:{podSelector:{},policyTypes:['Ingress','Egress'],ingress:[],egress:[]}};
 const claims=[['base','20Gi'],['data','1Gi'],['checkpoints','12Gi']].map(([name,size])=>({apiVersion:'v1',kind:'PersistentVolumeClaim',metadata:{name:`public-qa-${name}`,namespace:QA_NAMESPACE},spec:{accessModes:['ReadWriteOnce'],resources:{requests:{storage:size}}}}));
 const stager={apiVersion:'v1',kind:'Pod',metadata:{name:'public-qa-stager',namespace:QA_NAMESPACE,labels:{app:'public-qa-stager'}},spec:podSpec({readOnly:false})};
 return {apiVersion:'v1',kind:'List',items:[ns,deny,...claims,stager]};
}
export function trainingJob(runId,{resumeProvenance}={}){
 if(!/^public-qa-[a-z0-9-]{1,35}$/.test(runId))throw Error('invalid_run_id');
 const inputs=publicQaInputs(),spec=podSpec({gpu:true}),container=spec.containers[0];
 spec.volumes.push({name:'runtime',configMap:{name:inputs.runtimeConfigMap}});container.volumeMounts.push({name:'runtime',mountPath:'/runtime',readOnly:true});
 container.command=['python','/runtime/train-public-qa.py'];
 const stageTwo=resumeProvenance?.value?.schemaVersion===2;
 container.args=['--data','/data/public-qa-stage1.jsonl','--manifest','/data/public-qa-stage1.manifest.json','--model-dir','/models/foundation-base','--base-revision',QA_BASE_REVISION,'--output',`/checkpoints/runs/${runId}`,'--max-steps',stageTwo?'40':'20'];
 container.env=Object.entries({PYTHONPATH:'/runtime',PYTORCH_CUDA_ALLOC_CONF:'garbage_collection_threshold:0.5,max_split_size_mb:128',EVIDSCOPE_MEMORY_HIGH_REQUIRED:'1',EVIDSCOPE_ISOLATED:'1',EVIDSCOPE_DATASET_SHA256:inputs.datasetSha256,EVIDSCOPE_BASE_REPOSITORY:'fdtn-ai/Foundation-Sec-8B-Reasoning',EVIDSCOPE_BASE_REVISION:QA_BASE_REVISION,EVIDSCOPE_BASE_ARTIFACT_LOCK_SHA256:inputs.artifactLockSha256,EVIDSCOPE_TRAINING_IMAGE:QA_IMAGE}).map(([name,value])=>({name,value}));
 if(resumeProvenance){
  const parent=resumeProvenance.value;
  const initial=parent.schemaVersion===1&&/^public-qa-[a-z0-9-]{1,35}$/.test(parent.sourceRunId)&&parent.sourceGlobalStep===5;
  const extension=parent.schemaVersion===2&&parent.sourceRunId==='public-qa-resume-20260928-r1'&&parent.sourceGlobalStep===20&&parent.targetRunId===runId&&/^public-qa-stage2-[a-z0-9-]{1,28}$/.test(runId);
  if((!initial&&!extension)||!/^[a-f0-9]{64}$/.test(resumeProvenance.sha256))throw Error('resume_provenance_manifest_invalid');
  const cm=`public-qa-resume-${resumeProvenance.sha256.slice(0,16)}`;
  spec.volumes.push({name:'resume-provenance',configMap:{name:cm}});
  container.volumeMounts.push({name:'resume-provenance',mountPath:'/resume',readOnly:true});
  container.args.push('--resume-from-checkpoint',`/checkpoints/runs/${parent.sourceRunId}/checkpoint-${parent.sourceGlobalStep}`,'--resume-provenance','/resume/provenance.json');
  container.env.push({name:'EVIDSCOPE_RESUME_PROVENANCE_SHA256',value:resumeProvenance.sha256});
 }
 return {apiVersion:'batch/v1',kind:'Job',metadata:{name:runId,namespace:QA_NAMESPACE,annotations:{'evidscope.io/run-kind':stageTwo?'explicit-public-human-qa-stage2':'explicit-public-human-qa-stage1','evidscope.io/dataset-sha256':inputs.datasetSha256,'evidscope.io/manifest-sha256':inputs.manifestSha256}},spec:{backoffLimit:0,activeDeadlineSeconds:3600,template:{metadata:{labels:{app:'public-qa-training'}},spec}}};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){mkdirSync('.local/training/public-qa-run',{recursive:true});writeFileSync('.local/training/public-qa-run/setup.json',JSON.stringify(setupManifest(),null,2));console.log('Prepared isolated namespace, PVCs, default-deny policy and non-model staging pod.');}
