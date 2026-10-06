import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,verify} from 'node:crypto';
import {harness} from './harness.mjs';
import {submit} from '../src/client.mjs';
import {canonical} from '../src/crypto.mjs';

test('finance HTTP gateway: bounded verified import, source separation, model change and signed frozen report',async t=>{
 const h=await harness();t.after(()=>h.close());
 const system={id:'credit-http',name:'합성 금융 HTTP',owner:'감사팀',purpose:'대출 심사',role:'deployer',krRoles:['deployer'],markets:['KR'],domain:'credit',supplierId:'supplier-a',modelId:'credit-ai',modelVersion:'v1',substantialModification:false};
 assert.equal((await h.api('/api/governance/systems',{body:system,role:'reviewer'})).status,200);
 const bytes=Buffer.from('합성 문서'.repeat(1800)),bundle={id:'http-bundle',systemId:system.id,synthetic:true,supplierId:system.supplierId,modelId:system.modelId,modelVersion:'v1',purpose:system.purpose,testScope:'합성 HTTP 수신 검증',measures:['KR-34-RISK'],documents:[{id:'doc',name:'합성.txt',sha256:createHash('sha256').update(bytes).digest('hex'),contentBase64:bytes.toString('base64')}]};
 assert.ok(JSON.stringify(bundle).length>16384);
 assert.equal((await h.api('/api/governance/bundles',{body:bundle})).status,403);
 assert.equal((await h.api('/api/governance/bundles',{body:bundle,role:'reviewer'})).status,200);
 assert.equal((await h.api('/api/governance/bundles/http-bundle/export',{tenant:'beta'})).status,404);
 assert.equal((await h.api('/api/governance/bundles/http-bundle/export')).body.documents[0].contentBase64,bundle.documents[0].contentBase64);
 const occurredAt=new Date(Date.now()-1000).toISOString(),event={id:'result',kind:'result',status:'success',occurredAt,systemId:system.id,actionId:'credit-action',traceId:'credit-trace',requestId:'request-1',attemptId:'attempt-1',modelId:'credit-ai',modelVersion:'v1',policyVersion:'p1',actor:'credit-agent',tool:'credit-api',action:'score',resource:'synthetic-1'};
 assert.equal((await submit(h.ingress.url,h.principal('agent'),event)).status,403);
 assert.equal((await submit(h.ingress.url,h.principal('tool'),event)).status,202);await h.analyze();
 const view=(await h.api('/api/governance/finance?systemId=credit-http')).body;assert.equal(view.operations.length,1);assert.equal(view.operationalStatus,'observed_partial_evidence');assert.equal(view.operations[0].events[0].source,'alpha-tool');
 const response=await h.api('/api/governance/finance/report',{body:{systemId:system.id}});assert.equal(response.status,200);const report=response.body;assert.ok(verify(null,Buffer.from(canonical(report.snapshot)),h.publicKey,Buffer.from(report.signature,'base64')));
 await h.api('/api/governance/systems',{body:{...system,modelVersion:'v2'},role:'reviewer'});
 assert.ok((await h.api('/api/governance/finance?systemId=credit-http')).body.bundles[0].verification.issues.includes('MODEL_VERSION_MISMATCH'));
 assert.deepEqual((await h.api('/api/governance/finance/reports/'+report.id)).body,report);
 const old=h.vault.url;await h.restart();assert.equal(h.vault.url,old);
 assert.equal((await h.api('/api/governance/bundles/http-bundle/export')).body.documents[0].contentBase64,bundle.documents[0].contentBase64);
});
