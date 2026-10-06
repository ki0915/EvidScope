import test from 'node:test';
import assert from 'node:assert/strict';
import {trainingJob} from '../scripts/public-qa-workload.mjs';

const digest='a'.repeat(64);
const provenance=(targetRunId='public-qa-stage2-20260929-r1')=>({sha256:digest,value:{schemaVersion:2,sourceRunId:'public-qa-resume-20260928-r1',targetRunId,sourceGlobalStep:20}});

test('stage two job binds the exact completed step-20 parent and a new 40-step target',()=>{
 const runId='public-qa-stage2-20260929-r1',job=trainingJob(runId,{resumeProvenance:provenance(runId)}),container=job.spec.template.spec.containers[0];
 assert.equal(job.metadata.annotations['evidscope.io/run-kind'],'explicit-public-human-qa-stage2');
 assert.deepEqual(container.args.slice(container.args.indexOf('--max-steps'),container.args.indexOf('--max-steps')+2),['--max-steps','40']);
 assert.deepEqual(container.args.slice(-4),['--resume-from-checkpoint','/checkpoints/runs/public-qa-resume-20260928-r1/checkpoint-20','--resume-provenance','/resume/provenance.json']);
 assert.equal(container.volumeMounts.find(v=>v.name==='resume-provenance').readOnly,true);
 assert.equal(container.env.find(v=>v.name==='EVIDSCOPE_RESUME_PROVENANCE_SHA256').value,digest);
});

test('stage two manifest rejects target substitution and arbitrary parent steps',()=>{
 assert.throws(()=>trainingJob('public-qa-stage2-other',{resumeProvenance:provenance('public-qa-stage2-20260929-r1')}),/resume_provenance_manifest_invalid/);
 const wrong=provenance('public-qa-stage2-20260929-r1');wrong.value.sourceGlobalStep=10;
 assert.throws(()=>trainingJob('public-qa-stage2-20260929-r1',{resumeProvenance:wrong}),/resume_provenance_manifest_invalid/);
});
