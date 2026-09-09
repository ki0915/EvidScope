import test from 'node:test';
import assert from 'node:assert/strict';
import {harness} from './harness.mjs';
import {submit} from '../src/client.mjs';
import {evaluate} from '../src/model.mjs';
import {demo} from '../scripts/demo.mjs';

test('서비스 결과의 성공·실패 혼재를 성공 하나로 축약하지 않는다',()=>{
 const base={tenant:'alpha',id:'r1',source:'tool',sourceKind:'tool',kind:'result',actionId:'a',occurredAt:new Date().toISOString(),actor:'agent',tool:'crm',action:'update',resource:'record'};
 assert.equal(evaluate([{...base,status:'failure'},{...base,id:'r2',status:'success'}],[],[],[]).effect,'mixed_results');
 assert.equal(evaluate([{...base,sourceKind:'agent',kind:'self_report',status:'success'}],[],[],[]).effect,'unconfirmed');
});

test('참고 데이터 자기보고·서비스 참조·누락·비밀 비수집을 실제 HTTP에서 구분',async t=>{
 const h=await harness();t.after(()=>h.close());const now=new Date().toISOString();
 const e={id:'ref-1',kind:'self_report',actionId:'ref-action',traceId:'ref-trace',occurredAt:now,actor:'a',tool:'search',action:'read',resource:'knowledge',dataRefs:[{id:'doc-1',kind:'document',version:'2',hash:'a'.repeat(64),role:'retrieved',locator:'https://example.invalid/no-automatic-fetch'}]};
 assert.equal((await submit(h.ingress.url,h.principal('agent'),{...e,dataRefs:[{...e.dataRefs[0],contents:'raw secret content'}]})).status,400);
 assert.equal((await submit(h.ingress.url,h.principal('agent'),{...e,dataRefs:[{...e.dataRefs[0],verification:'independently_verified'}]})).status,400);
 assert.equal((await submit(h.ingress.url,h.principal('agent'),e)).status,202);
 assert.equal((await submit(h.ingress.url,h.principal('tool'),{...e,id:'ref-tool',kind:'execution',dataRefs:[{...e.dataRefs[0],version:'1',hash:'b'.repeat(64)}]})).status,202);
 await h.analyze();const action=(await h.api('/api/actions/ref-action')).body;
 assert.equal(action.references.length,2);assert.equal(action.references[0].verification,'self_reported_reference');assert.equal(action.references[1].verification,'service_reported_reference');assert.equal(action.referenceCoverage.eventsWithReferences,2);assert.ok(action.evaluations[0].findings.some(f=>f.code==='REFERENCE_METADATA_CONFLICT'));
 const beta=(await h.api('/api/actions/ref-action',{tenant:'beta'})).body;assert.equal(beta.references.length,0);assert.match(beta.limitations.join(' '),/미수집/);
 assert.equal((await h.api('/api/actions/ref-action',{role:'agent'})).status,403);
 const bundle=(await h.api('/api/export')).body;assert.equal(bundle.disclosures[0].event.dataRefs[0].locator,e.dataRefs[0].locator);assert.ok(!JSON.stringify(bundle).includes('raw secret content'));
 const result=await demo({config:h.config,ingress:h.ingress.url,audit:h.audit.url});await h.analyze();const seeded=(await h.api('/api/actions/'+result.actionId)).body;assert.equal(seeded.references.length,2);assert.notEqual(seeded.references[0].hash,seeded.references[1].hash);
});

test('현재 목적지 정책을 과거 행동에 소급하지 않고 시점별 정책과 불확실성을 표시',()=>{
 const e={tenant:'alpha',id:'e',source:'tool-source',sourceKind:'tool',kind:'execution',actionId:'action',occurredAt:'2026-09-01T00:00:00.000Z',actor:'a',tool:'t',destination:'old.example',policyVersion:'old'};
 const old={id:'asset',actor:'a',tool:'t',policyVersion:'old',validFrom:'2026-08-01T00:00:00.000Z',validUntil:'2026-09-02T00:00:00.000Z',destinations:['old.example']};
 const current={...old,policyVersion:'new',validFrom:'2026-09-02T00:00:00.000Z',validUntil:undefined,destinations:['new.example']};
 let result=evaluate([e],[old,current],[],[]);assert.ok(!result.findings.some(f=>['DESTINATION_OUTSIDE_POLICY','POLICY_CONTEXT_UNVERIFIED'].includes(f.code)));
 result=evaluate([e],[current],[],[]);assert.ok(result.findings.some(f=>f.code==='POLICY_CONTEXT_UNVERIFIED'));assert.ok(!result.findings.some(f=>f.code==='DESTINATION_OUTSIDE_POLICY'));
 result=evaluate([e],[old,{...old,destinations:['conflicting.example']}],[],[]);assert.ok(result.findings.some(f=>f.code==='POLICY_CONTEXT_UNVERIFIED'));
 result=evaluate([{...e,destination:'outside.example'}],[old,current],[],[]);assert.ok(result.findings.some(f=>f.code==='DESTINATION_OUTSIDE_POLICY'));
});
