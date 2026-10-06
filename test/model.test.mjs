import test from 'node:test';
import assert from 'node:assert/strict';
import {evaluate,validateEvent} from '../src/model.mjs';

const common={tenant:'alpha',traceId:'trace-a',actionId:'action-a',actor:'agent-a',tool:'payments',action:'write',resource:'invoice-a',destination:'internal',policyVersion:'auth-v1'};
const at='2026-09-08T01:00:00.000Z';
const execution=(overrides={})=>({...common,id:'execution',source:'alpha-tool',sourceKind:'tool',kind:'execution',occurredAt:at,...overrides});
const grant=(overrides={})=>({...common,id:'grant',source:'alpha-authority',sourceKind:'authority',kind:'grant',occurredAt:'2026-09-08T00:30:00.000Z',validFrom:'2026-09-08T00:00:00.000Z',validUntil:'2026-09-08T02:00:00.000Z',scope:{actor:common.actor,tool:common.tool,action:common.action,resource:common.resource,destination:common.destination},...overrides});
const assess=(events)=>evaluate(events,[{actor:common.actor,tool:common.tool,destinations:['internal'],policyVersion:common.policyVersion,validFrom:'2026-09-08T00:00:00.000Z',approvalRequired:true}],[],[],Date.parse(at));
const codes=(result)=>result.findings.map(f=>f.code);

test('historical policy determines whether a per-action human approval is required',()=>{
 const policy={actor:common.actor,tool:common.tool,policyVersion:common.policyVersion,validFrom:'2026-09-08T00:00:00.000Z',approvalRequired:false};
 const run=assets=>codes(evaluate([execution(),grant()],assets,[],[]));
 assert.ok(!run([policy]).some(c=>/APPROVAL/.test(c)));
 assert.ok(run([{...policy,approvalRequired:true}]).includes('HUMAN_APPROVAL_MISSING'));
 for(const assets of [[],[{...policy,approvalRequired:undefined}],[{...policy,policyVersion:'other'}],[policy,{...policy,approvalRequired:true}]]){
  const result=run(assets);assert.ok(result.includes('APPROVAL_REQUIREMENT_UNKNOWN'));assert.ok(!result.includes('HUMAN_APPROVAL_MISSING'));
 }
});

test('approvals bind the model and attempt and preserve uncertainty instead of inventing ordering',()=>{
 const context={systemId:'credit',requestId:'r1',attemptId:'a1',modelId:'credit-model',modelVersion:'1'};
 const e=execution(context),g=grant(context),approval={...grant(context),id:'approval',kind:'human_approval',reviewer:'reviewer-a',receivedAt:'2026-09-08T03:00:00.000Z'};
 assert.ok(!codes(assess([e,g,approval])).some(c=>/^APPROVAL/.test(c)));
 for(const field of ['systemId','requestId','attemptId','modelId','modelVersion','actionId','traceId']){
  assert.ok(codes(assess([e,g,{...approval,[field]:'other'}])).includes('APPROVAL_MISMATCH'),field);
  assert.ok(codes(assess([e,g,{...approval,[field]:undefined}])).includes('APPROVAL_MISMATCH'),`${field} absent`);
 }
 const close={...approval,occurredAt:'2026-09-08T00:59:59.000Z',clockUncertaintyMs:2000};
 const uncertain=codes(assess([e,g,close]));assert.ok(uncertain.includes('APPROVAL_TIME_UNCERTAIN'));assert.ok(!uncertain.includes('APPROVAL_MISMATCH'));
 const revoked={...common,id:'revocation',source:approval.source,sourceKind:'authority',kind:'revoke',authorityId:approval.id,occurredAt:'2026-09-08T00:59:00.000Z'};
 assert.ok(codes(assess([e,g,approval,revoked])).includes('APPROVAL_MISMATCH'));
 const ambiguousRevoke={...revoked,occurredAt:'2026-09-08T00:59:59.000Z',clockUncertaintyMs:2000};
 assert.ok(codes(assess([e,g,approval,ambiguousRevoke])).includes('APPROVAL_TIME_UNCERTAIN'));
 assert.ok(codes(assess([e,{...g,clockUncertaintyMs:'unknown'},approval])).includes('AUTHORITY_TIME_UNCERTAIN'));
});

test('block and success evidence only conflict for the same attempt with determinable order',()=>{
 const context={requestId:'r1',attemptId:'a1',modelId:'credit',modelVersion:'1'};
 const block={...common,...context,id:'block',source:'safety',sourceKind:'safety',kind:'block_registered',occurredAt:at};
 const result=execution({...context,kind:'result',status:'success',occurredAt:'2026-09-08T01:00:01.000Z'});
 assert.ok(codes(assess([block,result])).includes('BLOCK_SUCCESS_CONFLICT'));
 assert.ok(!codes(assess([block,{...result,attemptId:'a2'}])).includes('BLOCK_SUCCESS_CONFLICT'));
 const uncertain=codes(assess([{...block,clockUncertaintyMs:2000},result]));
 assert.ok(uncertain.includes('CLOCK_ORDER_UNCERTAIN'));assert.ok(!uncertain.includes('BLOCK_SUCCESS_CONFLICT'));
 assert.equal(assess([block]).effect,'unconfirmed');
});

test('event metadata validates context identifiers and bounded or explicitly unknown clock error',()=>{
 const raw={id:'event',kind:'execution',actionId:'action',traceId:'trace',systemId:'credit',attemptId:'1',requestId:'req',modelId:'model',modelVersion:'v1',occurredAt:new Date().toISOString(),clockUncertaintyMs:25};
 const principal={id:'tool',tenant:'alpha',kind:'tool'};
 assert.equal(validateEvent(raw,principal).clockUncertaintyMs,25);
 assert.equal(validateEvent({...raw,clockUncertaintyMs:'unknown'},principal).clockUncertaintyMs,'unknown');
 for(const value of [-1,300001,1.5,'25',null])assert.throws(()=>validateEvent({...raw,clockUncertaintyMs:value},principal));
 assert.throws(()=>validateEvent({...raw,systemId:'invalid id'},principal));
});

test('authority uses issuance time and policy known at execution, including late-arriving evidence',()=>{
 assert.equal(assess([execution(),grant({receivedAt:'2026-09-08T03:00:00.000Z'})]).authority,'matched_at_event_time');
 for(const override of [{occurredAt:'2026-09-08T01:00:00.001Z'},{policyVersion:'auth-v2'},{validUntil:at},{validFrom:'2026-09-08T01:00:00.001Z'}]){
  assert.equal(assess([execution(),grant(override)]).authority,'unverified_or_mismatch',JSON.stringify(override));
 }
 assert.equal(assess([execution({policyVersion:undefined}),grant()]).authority,'unverified_or_mismatch');
 const revoked={...common,id:'revoked',source:'alpha-authority',sourceKind:'authority',kind:'revoke',authorityId:'grant',occurredAt:at};
 assert.equal(assess([execution(),grant(),revoked]).authority,'unverified_or_mismatch');
 assert.equal(assess([execution(),grant(),{...revoked,occurredAt:'2026-09-08T01:00:00.001Z'}]).authority,'matched_at_event_time');
});

test('human approval issued after execution or under another policy never satisfies prior review',()=>{
 const approval={...grant(),id:'approval',kind:'human_approval',reviewer:'reviewer-a'};
 assert.ok(!codes(assess([execution(),grant(),approval])).includes('APPROVAL_MISMATCH'));
 for(const override of [{occurredAt:'2026-09-08T02:00:00.000Z'},{policyVersion:'old'}]){
  assert.ok(codes(assess([execution(),grant(),{...approval,...override}])).includes('APPROVAL_MISMATCH'));
 }
 assert.ok(codes(assess([execution(),grant(),{...approval,kind:'automated_review'}])).includes('HUMAN_APPROVAL_MISSING'));
 const oversight={...common,id:'oversight',source:'alpha-authority',sourceKind:'authority',kind:'human_oversight_review',reviewer:'reviewer-a',systemId:'credit',modelId:'credit-model',modelVersion:'1',occurredAt:'2026-09-08T00:30:00.000Z'};
 assert.ok(codes(assess([execution(),grant(),oversight])).includes('HUMAN_APPROVAL_MISSING'),'oversight evidence is not per-action approval');
});

test('human oversight review requires authority provenance and system, model and policy binding',()=>{
 const raw={id:'oversight',kind:'human_oversight_review',actionId:'oversight-action',traceId:'oversight-trace',occurredAt:new Date().toISOString(),reviewer:'human-reviewer',systemId:'credit',modelId:'credit-model',modelVersion:'v2',policyVersion:'policy-v3'};
 const authority={id:'authority',tenant:'alpha',kind:'authority'};
 assert.equal(validateEvent(raw,authority).kind,'human_oversight_review');
 for(const field of ['reviewer','systemId','modelId','modelVersion','policyVersion'])assert.throws(()=>validateEvent({...raw,[field]:undefined},authority));
 assert.throws(()=>validateEvent(raw,{id:'agent',tenant:'alpha',kind:'agent'}));
});

test('self-reported delegation cannot substitute for independent parent-scoped authority',()=>{
 const child=execution({parentActionId:'parent-a'});
 const reported={...common,id:'delegation',source:'alpha-agent',sourceKind:'agent',kind:'delegation',occurredAt:at,parentActionId:'parent-a',scope:{resource:common.resource,action:common.action}};
 assert.ok(codes(assess([child,reported,grant()])).includes('DELEGATION_UNVERIFIED'));
 const scoped=grant({scope:{...grant().scope,parentActionId:'parent-a'}});
 const verified=assess([child,reported,scoped]);
 assert.equal(verified.authority,'matched_at_event_time');
 assert.ok(!codes(verified).includes('DELEGATION_UNVERIFIED'));
 for(const badScope of [{...scoped.scope,parentActionId:'parent-b'},{...scoped.scope,actor:'agent-b'},{...scoped.scope,tool:'other-tool'}]){
  const result=assess([child,reported,{...scoped,scope:badScope}]);
  assert.equal(result.authority,'unverified_or_mismatch');
  assert.ok(codes(result).includes('DELEGATION_UNVERIFIED'));
 }
 assert.equal(assess([execution(),scoped]).authority,'unverified_or_mismatch','parent-scoped grant is not a root-action grant');
});

test('stop confirmation matches the requested target and follows the request',()=>{
 const request={...common,id:'stop',source:'alpha-safety',sourceKind:'safety',kind:'stop_requested',occurredAt:at};
 const confirmation={...request,id:'confirmed',kind:'stop_confirmed',occurredAt:'2026-09-08T01:00:01.000Z'};
 assert.ok(!codes(assess([request,confirmation])).includes('STOP_UNCONFIRMED'));
 for(const override of [{actor:'another'},{tool:'another'},{action:'another'},{resource:'another'},{destination:'external'},{actionId:'other-action'},{occurredAt:'2026-09-08T00:59:59.000Z'},{sourceKind:'agent'}]){
  assert.ok(codes(assess([request,{...confirmation,...override}])).includes('STOP_UNCONFIRMED'),JSON.stringify(override));
 }
 const secondRequest={...request,id:'second-request',resource:'invoice-b'};
 const result=assess([request,confirmation,secondRequest]);
 assert.deepEqual(result.findings.filter(f=>f.code==='STOP_UNCONFIRMED').map(f=>f.evidence),[['alpha-safety/second-request']]);
 assert.ok(codes(assess([{...request,actor:undefined},{...confirmation,actor:undefined}])).includes('STOP_UNCONFIRMED'),'missing target identity stays unconfirmed');
});
