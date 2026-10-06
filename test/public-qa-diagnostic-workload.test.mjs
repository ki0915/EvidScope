import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {DIAGNOSTIC_PINS,DIAGNOSTIC_SOURCE_RUN,STAGE2_DIAGNOSTIC_PINS,STAGE2_DIAGNOSTIC_SOURCE_RUN,diagnosticRuntimeConfigMap,diagnosticJob,assertDiagnosticMounts} from '../scripts/public-qa-diagnostic-workload.mjs';
import {QA_IMAGE,QA_NODE,QA_BASE_REVISION,podSpec,runtimeConfigMap} from '../scripts/public-qa-workload.mjs';
import {publicQaControllerOptions,runPublicQa} from '../scripts/run-public-qa-job.mjs';

const inputs=()=>({...DIAGNOSTIC_PINS,mode:'public_qa_diagnostic',diagnosticOnly:true,sourceRunId:DIAGNOSTIC_SOURCE_RUN,rows:64,trainingProvenanceVerified:false,promotionAllowed:false,qualityClaimAllowed:false,runtimeConfigMap:diagnosticRuntimeConfigMap().metadata.name});
const stageTwoInputs=()=>({...inputs(),...STAGE2_DIAGNOSTIC_PINS,sourceRunId:STAGE2_DIAGNOSTIC_SOURCE_RUN,trainingProvenanceVerified:true});
test('stage2 diagnostic pins verified source and immutable adapter while preserving resource isolation',()=>{
 const job=diagnosticJob('public-qa-diag-stage2-unit',stageTwoInputs()),spec=job.spec.template.spec,c=spec.containers[0],env=Object.fromEntries(c.env.map(item=>[item.name,item.value]));
 assert.deepEqual(c.resources,podSpec({gpu:true}).containers[0].resources);assert.equal(job.spec.activeDeadlineSeconds,3600);
 assert.deepEqual(c.args.slice(-2),['--source-stage','stage2']);
 assert.equal(c.volumeMounts.find(v=>v.name==='adapters').subPath,`runs/${STAGE2_DIAGNOSTIC_SOURCE_RUN}/candidate`);
 assertDiagnosticMounts({spec},STAGE2_DIAGNOSTIC_SOURCE_RUN);assert.throws(()=>assertDiagnosticMounts({spec}),/live_diagnostic_mount_scope_invalid/);
 for(const [name,key]of [['VERIFICATION','sourceVerificationSha256'],['CANDIDATE','candidateMarkerSha256'],['ADAPTER','adapterSha256']])assert.equal(env[`EVIDSCOPE_DIAGNOSTIC_${name}_SHA256`],STAGE2_DIAGNOSTIC_PINS[key]);
 for(const key of ['adapterSha256','sourceControllerSha256','sourceVerificationSha256','candidateMarkerSha256','sourceRuntimeConfigMapSha256'])assert.throws(()=>diagnosticJob('public-qa-unit',{...stageTwoInputs(),[key]:'f'.repeat(64)}),/binding_invalid/);
 assert.throws(()=>diagnosticJob('public-qa-unit',{...stageTwoInputs(),trainingProvenanceVerified:false}),/binding_invalid/);
});
test('stage2 controller mode cannot train, resume or silently use the stage1 source',async()=>{
 const args=publicQaControllerOptions(['--execute-diagnostic-stage2','public-qa-diag-stage2-unit','--allow-interactive-use']);
 assert.equal(args.diagnostic,true);assert.equal(args.diagnosticStageTwo,true);assert.equal(args.executeTraining,true);assert.equal(args.pilot,false);
 assert.equal(publicQaControllerOptions(['--execute-diagnostic']).diagnosticStageTwo,false);
 assert.throws(()=>publicQaControllerOptions(['--execute-diagnostic-stage2','public-qa-unit','--allow-interactive-use','--resume-provenance','parent.json']),/diagnostic_cannot/);
 await assert.rejects(runPublicQa({diagnosticStageTwo:true}),/stage2_requires_diagnostic_mode/);
});
test('diagnostic Job fixes the dataset, same base and immutable candidate while limiting writes to diagnostics',()=>{
 const job=diagnosticJob('public-qa-diagnostic-unit',inputs()),s=job.spec.template.spec,c=s.containers[0],env=Object.fromEntries(c.env.map(x=>[x.name,x.value]));
 assert.equal(c.image,QA_IMAGE);assert.equal(s.nodeSelector['kubernetes.io/hostname'],QA_NODE);assert.equal(s.runtimeClassName,'nvidia');assert.deepEqual(c.resources,podSpec({gpu:true}).containers[0].resources);assert.equal(c.securityContext.readOnlyRootFilesystem,true);assert.equal(s.automountServiceAccountToken,false);
 assert.deepEqual(c.command,['python','/runtime/evaluate-public-qa-diagnostic.py']);
 assert.deepEqual(c.args,['--data','/data/diagnostic/data.jsonl','--manifest','/data/diagnostic/manifest.json','--model-dir','/models/foundation-base','--adapter-dir','/adapters/candidate','--output','/checkpoints/diagnostics/public-qa-diagnostic-unit']);
 assert.equal(env.EVIDSCOPE_DIAGNOSTIC_DATA_SHA256,DIAGNOSTIC_PINS.datasetSha256);assert.equal(env.EVIDSCOPE_DIAGNOSTIC_MANIFEST_SHA256,DIAGNOSTIC_PINS.manifestSha256);assert.equal(env.EVIDSCOPE_DIAGNOSTIC_CONTROLLER_SHA256,DIAGNOSTIC_PINS.sourceControllerSha256);assert.equal(env.EVIDSCOPE_BASE_REVISION,QA_BASE_REVISION);assert.equal(env.EVIDSCOPE_MEMORY_HIGH_REQUIRED,'1');
 assert.equal(job.metadata.annotations['evidscope.io/run-kind'],'explicit-public-qa-diagnostic');assert.equal(job.metadata.annotations['evidscope.io/source-verification-sha256'],DIAGNOSTIC_PINS.sourceVerificationSha256);
 const mounts=Object.fromEntries(c.volumeMounts.map(m=>[m.name,m]));assert.equal(mounts.adapters.readOnly,true);assert.equal(mounts.adapters.subPath,`runs/${DIAGNOSTIC_SOURCE_RUN}/candidate`);assert.deepEqual(mounts['diagnostic-output'],{name:'diagnostic-output',mountPath:'/checkpoints/diagnostics',subPath:'diagnostics',readOnly:false});assert.equal(mounts.checkpoints,undefined);assert.ok(['base','data'].every(name=>mounts[name].readOnly));
 assertDiagnosticMounts({spec:s});
});

test('live mount admission rejects writable candidates, root checkpoint mounts and foreign PVC aliases',()=>{
 for(const tamper of [s=>{s.containers[0].volumeMounts.find(m=>m.name==='adapters').readOnly=false;},s=>{s.containers[0].volumeMounts.find(m=>m.name==='diagnostic-output').subPath='runs';},s=>{s.containers[0].volumeMounts.find(m=>m.name==='diagnostic-output').mountPath='/checkpoints';},s=>{s.volumes.find(v=>v.name==='adapters').persistentVolumeClaim.readOnly=false;},s=>{s.containers[0].volumeMounts.push({name:'escape',mountPath:'/other'});s.volumes.push({name:'escape',persistentVolumeClaim:{claimName:'public-qa-checkpoints'}});}]){
  const s=diagnosticJob('public-qa-diagnostic-unit',inputs()).spec.template.spec;tamper(s);assert.throws(()=>assertDiagnosticMounts({spec:s}),/live_diagnostic/);
 }
});

test('diagnostic runtime is immutable, content-addressed and contains only curated inference helpers',()=>{
 const code=diagnosticRuntimeConfigMap(),hash=createHash('sha256').update(JSON.stringify(code.data)).digest('hex');
 assert.equal(code.immutable,true);assert.equal(code.metadata.annotations['evidscope.io/code-sha256'],hash);assert.equal(code.metadata.name,'public-qa-diagnostic-'+hash.slice(0,16));
 assert.deepEqual(Object.keys(code.data).sort(),['evaluate-public-qa-diagnostic.py','public_qa_cuda_runtime.py','public_qa_memory_gate.py','public_qa_thermal.py','training_artifacts.py'].sort());
 const original=runtimeConfigMap();assert.equal(original.data['evaluate-public-qa-diagnostic.py'],undefined);assert.ok(original.data['train-public-qa.py']);assert.ok(original.data['train-foundation-lora.py']);assert.ok(original.data['public_qa_resume.py']);
 assert.equal(podSpec({gpu:true}).containers[0].volumeMounts.find(m=>m.name==='checkpoints').mountPath,'/checkpoints');
});

test('diagnostic Job rejects changed provenance, data, promotion flags and arbitrary paths',()=>{
 for(const field of Object.keys(DIAGNOSTIC_PINS))assert.throws(()=>diagnosticJob('public-qa-unit',{...inputs(),[field]:'0'.repeat(64)}),/binding_invalid/);
 for(const patch of [{rows:65},{sourceRunId:'public-qa-other'},{promotionAllowed:true},{qualityClaimAllowed:true},{trainingProvenanceVerified:true},{mode:'training'}])assert.throws(()=>diagnosticJob('public-qa-unit',{...inputs(),...patch}),/binding_invalid/);
 for(const name of ['../other','other','public-qa-'+ 'a'.repeat(36),'public-qa-unit/escape'])assert.throws(()=>diagnosticJob(name,inputs()),/invalid_run_id/);
});

test('controller diagnostic mode is explicit and cannot combine with resume or pilot',async()=>{
 const d=publicQaControllerOptions(['--execute-diagnostic','public-qa-unit','--allow-interactive-use']);assert.equal(d.diagnostic,true);assert.equal(d.pilot,false);assert.equal(d.executeTraining,true);assert.equal(d.resumeProvenancePath,undefined);
 assert.throws(()=>publicQaControllerOptions(['--execute-diagnostic','public-qa-unit','--allow-interactive-use','--resume-provenance','source.json']),/diagnostic_cannot/);
 await assert.rejects(runPublicQa({diagnostic:true,pilot:true}),/diagnostic_cannot/);await assert.rejects(runPublicQa({diagnostic:true,resumeProvenancePath:'source.json'}),/diagnostic_cannot/);await assert.rejects(runPublicQa({diagnostic:true,runId:'../escape'}),/invalid_run_id/);
 const training=publicQaControllerOptions(['--execute-explicit-request','public-qa-resume-unit','--allow-interactive-use','--resume-provenance','source.json']);assert.equal(training.diagnostic,false);assert.equal(training.resumeProvenancePath,'source.json');assert.equal(publicQaControllerOptions(['--execute-resource-pilot']).pilot,true);assert.equal(publicQaControllerOptions(['--check-only']).executeTraining,false);
});
