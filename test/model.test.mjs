import test from 'node:test';
import assert from 'node:assert/strict';
import {evaluate} from '../src/model.mjs';

const common={tenant:'alpha',traceId:'trace-a',actionId:'action-a',actor:'agent-a',tool:'payments',action:'write',resource:'invoice-a',destination:'internal',policyVersion:'auth-v1'};
const at='2026-09-08T01:00:00.000Z';
const execution=(overrides={})=>({...common,id:'execution',source:'alpha-tool',sourceKind:'tool',kind:'execution',occurredAt:at,...overrides});
const grant=(overrides={})=>({...common,id:'grant',source:'alpha-authority',sourceKind:'authority',kind:'grant',occurredAt:'2026-09-08T00:30:00.000Z',validFrom:'2026-09-08T00:00:00.000Z',validUntil:'2026-09-08T02:00:00.000Z',scope:{actor:common.actor,tool:common.tool,action:common.action,resource:common.resource,destination:common.destination},...overrides});
const assess=(events)=>evaluate(events,[{actor:common.actor,tool:common.tool,destinations:['internal']}],[],[],Date.parse(at));
const codes=(result)=>result.findings.map(f=>f.code);

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
