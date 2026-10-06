import test from 'node:test';
import assert from 'node:assert/strict';
import {adaptAgtApproval,AGT_APPROVAL_COMMIT} from '../src/agt-approval-adapter.mjs';
import {evaluate,validateEvent} from '../src/model.mjs';

const sha=char=>'sha256:'+char.repeat(64);
function fixture(){
 const context={systemId:'credit-ai',requestId:'request-1',attemptId:'attempt-1',modelId:'credit-model',modelVersion:'v1',actionId:'action-1',traceId:'trace-1'};
 const collector={id:'bank-authority',tenant:'alpha',kind:'authority',context:{...context},
  scope:{actor:'agent-1',tool:'credit-service',action:'tool.invoke',resource:'application-42'},actionDigest:sha('a'),clockUncertaintyMs:0};
 const receipt={context:{...context},request:{approval_request_id:'ar-1',policy_decision_id:'pd-1',agent_id:'agent-1',
  operation:'tool.invoke',target_resource:'application-42',action_digest:sha('a'),policy_version:'p1',
  approval_chain_id:'credit-review',approval_chain_version:'1',status:'allowed',fail_closed_on_timeout:true,
  requested_at:'2026-09-08T00:00:00Z',expires_at:'2026-09-08T01:00:00Z'},
  resolution:{approval_resolution_id:'apr-1',approval_request_id:'ar-1',action_digest:sha('a'),policy_version:'p1',
   approval_chain_version:'1',outcome:'allow',resolved_at:'2026-09-08T00:02:00Z',final_entry_digest:sha('c')},
  entries:[{approval_request_id:'ar-1',chain_entry_id:'ace-1',stage_index:0,approver_kind:'human',approver_identity:'reviewer-1',
   identity_assurance:'oidc',decision:'allow',input_digest:sha('b'),previous_entry_digest:null,entry_digest:sha('c'),decided_at:'2026-09-08T00:01:00Z'}]};
 return {receipt,collector};
}
const adapt=({receipt,collector})=>adaptAgtApproval(receipt,collector);

test('pinned AGT request, resolution and human entry become minimized authority records',()=>{
 const f=fixture(),before=structuredClone(f),{events,assurance}=adapt(f);
 assert.deepEqual(events.map(e=>e.kind),['grant','human_approval']);
 assert.equal(events[1].reviewer,'reviewer-1');assert.equal(events[0].validFrom,'2026-09-08T00:02:00.000Z');
 assert.equal(events[0].validUntil,'2026-09-08T01:00:00.000Z');assert.deepEqual(events[0].scope,f.collector.scope);
 for(const e of events){assert.equal(validateEvent(e,f.collector).source,'bank-authority');assert.ok(!('tenant' in e));}
 assert.equal(assurance.upstreamCommit,AGT_APPROVAL_COMMIT);
 assert.equal(assurance.signatureVerified,false);assert.equal(assurance.chainHashesVerified,false);
 assert.equal(assurance.approverIdentityVerified,false);assert.equal(assurance.executionVerified,false);
 assert.equal(JSON.parse(events[0].note).signatureVerified,false);assert.deepEqual(f,before);
 assert.deepEqual(adapt(f).events,events,'stable identifiers support ordinary ingestion deduplication');
});

test('context and trusted collector scope cannot be widened or borrowed across attempts and models',()=>{
 for(const key of Object.keys(fixture().receipt.context)){
  const f=fixture();f.receipt.context[key]='other';assert.throws(()=>adapt(f),/mismatch/,key);
  const missing=fixture();delete missing.receipt.context[key];assert.throws(()=>adapt(missing),/mismatch/,key);
 }
 for(const key of ['agent_id','operation','target_resource','action_digest']){
  const f=fixture();f.receipt.request[key]=key==='action_digest'?sha('f'):'other';assert.throws(()=>adapt(f),/mismatch/,key);
 }
 const f=fixture();delete f.collector.context.modelVersion;assert.throws(()=>adapt(f),/required/);
 const g=fixture();g.collector.kind='agent';assert.throws(()=>adapt(g),/authority/);
 const h=fixture();delete h.collector.clockUncertaintyMs;assert.throws(()=>adapt(h),/clock/);
});

test('unresolved, denied, malformed and incorrectly linked approval records produce no authority',()=>{
 const mutations=[
  f=>{delete f.receipt.resolution;},f=>{f.receipt.request.status='pending';},
  f=>{f.receipt.resolution.outcome='deny';},f=>{f.receipt.resolution.approval_request_id='other';},
  f=>{f.receipt.resolution.policy_version='other';},f=>{f.receipt.resolution.approval_chain_version='other';},
  f=>{f.receipt.request.fail_closed_on_timeout=false;},f=>{f.receipt.entries[0].decision='deny';},
  f=>{delete f.receipt.entries[0].approver_identity;},f=>{f.receipt.entries[0].identity_assurance='unverified';},
  f=>{f.receipt.entries[0].approval_request_id='other';},f=>{f.receipt.entries[0].previous_entry_digest=sha('d');},
  f=>{f.receipt.resolution.final_entry_digest=sha('d');},f=>{f.receipt.entries.push({...f.receipt.entries[0]});},
  f=>{f.receipt.request.expires_at=f.receipt.resolution.resolved_at;},f=>{f.receipt.entries[0].decided_at='2026-09-08T02:00:00Z';}
 ];
 for(const mutate of mutations){const f=fixture();mutate(f);assert.throws(()=>adapt(f));}
});

test('service approval and LLM advice never become human review or let advisory votes authorize alone',()=>{
 const service=fixture();service.receipt.entries[0].approver_kind='service';
 assert.deepEqual(adapt(service).events.map(e=>e.kind),['grant','automated_review']);
 assert.ok(!('reviewer' in adapt(service).events[1]));
 const advisory=fixture();advisory.receipt.entries[0].approver_kind='llm_advisory';
 assert.throws(()=>adapt(advisory),/advisory entries/);
 const mixed=fixture();mixed.receipt.entries.push({...mixed.receipt.entries[0],chain_entry_id:'ace-2',approver_kind:'llm_advisory',
  approver_identity:'model-judge',identity_assurance:'unverified',decision:'deny',previous_entry_digest:sha('c'),entry_digest:sha('d')});
 mixed.receipt.resolution.final_entry_digest=sha('d');
 const {events}=adapt(mixed);assert.equal(events[2].kind,'automated_review');assert.equal(events[2].status,'advisory_deny');
 assert.equal(events.filter(e=>e.kind==='human_approval').length,1);
});

test('explicit cancellation/revocation invalidates both prior grant and human approval during evaluation',()=>{
 for(const kind of ['cancelled','revoked']){
  const f=fixture(),original=adapt(f).events;
  f.receipt.request.status='cancelled';f.receipt.lifecycle={kind,occurredAt:'2026-09-08T00:03:00Z'};
  const revoked=adapt(f).events;assert.ok(revoked.every(e=>e.kind==='revoke'));
  assert.deepEqual(revoked.map(e=>e.authorityId),original.map(e=>e.id));
  const execution=validateEvent({...f.receipt.context,...f.collector.scope,id:'execution-1',kind:'execution',policyVersion:'p1',
   occurredAt:'2026-09-08T00:04:00Z',clockUncertaintyMs:0},{id:'bank-tool',tenant:'alpha',kind:'tool'});
  const records=[...original,...revoked].map(e=>validateEvent(e,f.collector));
  const assets=[{actor:'agent-1',tool:'credit-service',policyVersion:'p1',validFrom:'2026-09-08T00:00:00Z',approvalRequired:true}];
  const codes=evaluate([...records,execution],assets,[],[]).findings.map(f=>f.code);
  assert.ok(codes.includes('AUTHORITY_MISMATCH'));assert.ok(codes.includes('APPROVAL_MISMATCH'));
 }
 const missing=fixture();missing.receipt.request.status='cancelled';assert.throws(()=>adapt(missing),/timestamp/);
 const early=fixture();early.receipt.lifecycle={kind:'revoked',occurredAt:'2026-09-08T00:00:00Z'};assert.throws(()=>adapt(early),/precedes/);
});
