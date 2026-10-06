import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtempSync,mkdirSync,copyFileSync,readFileSync,rmSync} from 'node:fs';
import {resolve,join,sep} from 'node:path';
import {selectGroundingRows} from '../scripts/prepare-public-qa-grounding.mjs';
import {publicQaGroundingInputs,groundingJob,assertGroundingMounts,GROUNDING_RUN_ID} from '../scripts/public-qa-grounding-workload.mjs';

const sha=text=>createHash('sha256').update(text).digest('hex');
function row(id,split,impossible=false){const context='원문 '+id,answers=impossible?[]:[{text:'원문',answer_start:0}];return {id,split,familyId:'family-'+id,context,contextSha256:sha(context),question:'무엇인가요?',answers,isImpossible:impossible,upstreamSplit:'train',upstreamRevision:'3efd98708a40ff49251fddde35453f8fbb11f536',sourceLicense:'CC-BY-SA-4.0',upstreamAnnotation:{kind:'human_authored_question_answer_spans'},originalQa:{question:'무엇인가요?',answers,is_impossible:impossible}};}
test('balanced selection preserves authentic originals and excludes all previously exposed families',()=>{
 const train=[row('a','train'),row('b','train',true),row('c','train'),row('d','train',true)],validation=[row('e','validation'),row('f','validation',true)];
 const {rows,counts}=selectGroundingRows({train,validation},[{id:'prior',familyId:'family-a',contextSha256:'prior'}],{trainPerLabel:1,validationPerLabel:1});
 assert.deepEqual(counts,{train:2,validation:2});assert.deepEqual(rows.map(r=>r.id),['c','b','e','f']);assert.equal(rows[1].context,train[1].context);assert.deepEqual(rows[1].originalQa,train[1].originalQa);assert.equal(rows[1].localHumanReviewPerformed,false);
});
test('selection rejects altered human labels and cross-split families',()=>{
 const sources={train:[row('a','train'),row('b','train',true)],validation:[row('c','validation'),row('d','validation',true)]};
 sources.train[0].question='가짜';assert.throws(()=>selectGroundingRows(sources,[],{trainPerLabel:1,validationPerLabel:1}),/original_changed/);sources.train[0].question='무엇인가요?';sources.validation[0].familyId=sources.train[0].familyId;assert.throws(()=>selectGroundingRows(sources,[],{trainPerLabel:1,validationPerLabel:1}),/split_leakage/);
});
test('real grounding workload resets training state, isolates warmstart and binds new data rather than diagnostic data',t=>{
 const parent=resolve('.test-runs');mkdirSync(parent,{recursive:true});const directory=mkdtempSync(join(parent,'grounding-input-'));assert(directory.startsWith(parent+sep));t.after(()=>rmSync(directory,{recursive:true,force:true}));
 const source='.local/public-training/grounding/20261005/'+GROUNDING_RUN_ID,metadata=JSON.parse(readFileSync(join(source,'manifest.json')));for(const name of ['data.jsonl','manifest.json',...Object.values(metadata.sourceFiles)])copyFileSync(join(source,name),join(directory,name));
 const runId='public-qa-grounding-test-new',inputs=publicQaGroundingInputs({runId,directory}),job=groundingJob(runId,inputs),pod=job.spec.template,c=pod.spec.containers[0];
 assert.equal(inputs.diagnosticOnly,false);assert.equal(inputs.rows,704);assert.equal(inputs.groundingProvenance.optimizerReset,true);assert.equal(inputs.groundingProvenance.schedulerReset,true);
 assert.equal(inputs.targetIdentity.precision,'bf16');assert.equal(inputs.targetIdentity.modelDtype,'bfloat16');assert.equal(inputs.targetIdentity.quantComputeDtype,'bfloat16');
 assert.deepEqual(c.args.slice(c.args.indexOf('--max-steps'),c.args.indexOf('--max-steps')+2),['--max-steps','20']);assert.equal(c.args.includes('--resume-from-checkpoint'),false);
 assert.equal(c.volumeMounts.find(m=>m.name==='warmstart').readOnly,true);assert.equal(c.volumeMounts.find(m=>m.name==='grounding-output').subPath,'grounding-runs');assert.equal(c.volumeMounts.some(m=>m.mountPath==='/checkpoints'),false);assert.doesNotThrow(()=>assertGroundingMounts(pod,inputs));
 pod.spec.volumes.find(v=>v.name==='runtime').configMap.defaultMode=420;assert.doesNotThrow(()=>assertGroundingMounts(pod,inputs));
 assert.equal(c.volumeMounts.find(m=>m.name==='data').subPath,`grounding/${runId}`);
 pod.spec.containers[0].volumeMounts.find(m=>m.name==='warmstart').readOnly=false;assert.throws(()=>assertGroundingMounts(pod,inputs),/mount_scope_invalid/);
 assert.throws(()=>groundingJob(runId,{...inputs,adapterSha256:'a'.repeat(64)}),/job_binding_invalid/);
 const token=groundingJob(runId,inputs,{tokenCheck:true});assert.equal(token.spec.template.spec.containers[0].args.includes('--token-check'),true);assert.equal(token.spec.template.spec.containers[0].resources.limits['nvidia.com/gpu'],undefined);
});
