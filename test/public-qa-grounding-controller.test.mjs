import test from 'node:test';
import assert from 'node:assert/strict';
import {publicQaControllerOptions,runPublicQa,retryPublicQaRead} from '../scripts/run-public-qa-job.mjs';

test('grounding is an explicit training mode with the approved interactive override',()=>{
 const options=publicQaControllerOptions(['--execute-grounding','public-qa-grounding-20261005-r1','--allow-interactive-use']);
 assert.equal(options.executeTraining,true);assert.equal(options.grounding,true);
 assert.equal(options.interactiveUseApproved,true);assert.equal(options.diagnostic,false);
 assert.equal(options.pilot,false);assert.equal(options.resumeProvenancePath,undefined);
});

test('transient Windows socket read failure has a bounded retry and preserves fresh result',async()=>{
 let calls=0;const delays=[],fresh={podUid:'fresh'};
 const result=await retryPublicQaRead(async()=>{if(++calls<3)throw Object.assign(Error('command failed'),{stderr:'dial tcp: bind: The system detected an invalid pointer address'});return fresh;},{pause:async ms=>delays.push(ms)});
 assert.equal(result,fresh);assert.equal(calls,3);assert.deepEqual(delays,[500,1000]);
});

test('persistent socket errors stop after three reads and non-socket errors never retry',async()=>{
 for(const [message,expected] of [['listen EFAULT',3],['Forbidden',1],['job_uid_changed',1],['OOMKilled',1]]){
  let calls=0;const error=Error(message);
  await assert.rejects(retryPublicQaRead(async()=>{calls++;throw error;},{pause:async()=>{}}),e=>e===error);
  assert.equal(calls,expected);
 }
});

test('persistent Windows bind failure may use one fresh alternate read; unrelated errors cannot',async()=>{
 let reads=0,fallbacks=0;
 const result=await retryPublicQaRead(async()=>{reads++;throw Error('bind: invalid pointer address');},{pause:async()=>{},fallback:async()=>{fallbacks++;return 'fresh alternate';}});
 assert.equal(result,'fresh alternate');assert.equal(reads,3);assert.equal(fallbacks,1);
 await assert.rejects(retryPublicQaRead(async()=>{throw Error('Forbidden');},{fallback:async()=>{fallbacks++;}}),/Forbidden/);
 assert.equal(fallbacks,1);
 await assert.rejects(retryPublicQaRead(async()=>{throw Error('EFAULT');},{pause:async()=>{},fallback:async()=>{throw Error('read_fallback_node_identity_changed');}}),/read_fallback_node_identity_changed/);
});

test('grounding generation diagnosis cannot train or restore optimizer state',async()=>{
 const options=publicQaControllerOptions(['--execute-grounding-diagnostic','public-qa-ground-diag-x','--allow-interactive-use']);
 assert.equal(options.groundingDiagnostic,true);assert.equal(options.grounding,false);assert.equal(options.diagnostic,false);
 assert.throws(()=>publicQaControllerOptions(['--execute-grounding-diagnostic','public-qa-ground-diag-x','--allow-interactive-use','--resume-provenance','source.json']),/grounding_diagnostic_cannot_use_other_execution_modes/);
 for(const extra of [{diagnostic:true},{pilot:true},{grounding:true},{resumeProvenancePath:'source.json'}]){
  await assert.rejects(runPublicQa({groundingDiagnostic:true,...extra}),/grounding_diagnostic_cannot_use_other_execution_modes/);
 }
});

test('grounding cannot silently mix warmstart with optimizer resume or diagnostic execution',async()=>{
 assert.throws(()=>publicQaControllerOptions(['--execute-grounding','public-qa-grounding-x','--allow-interactive-use','--resume-provenance','source.json']),/grounding_cannot_use_other_execution_modes/);
 for(const extra of [{diagnostic:true},{pilot:true},{resumeProvenancePath:'source.json'}]){
  await assert.rejects(runPublicQa({grounding:true,...extra}),/grounding_cannot_use_other_execution_modes/);
 }
});
