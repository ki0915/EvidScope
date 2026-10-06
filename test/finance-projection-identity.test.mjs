import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {createService} from '../src/service.mjs';

const requirements=JSON.parse(readFileSync('data/requirements.json','utf8'));
function system(id){return {id,name:id,owner:'reviewer',purpose:'대출 심사 보조',role:'deployer',krRoles:['deployer'],markets:['KR'],domain:'credit',generative:false,highImpact:'candidate',supplierId:'supplier-'+id,modelId:'model-'+id,modelVersion:'v1',suppliedModelVersion:'v1',suppliedPurpose:'대출 심사 보조',substantialModification:false};}
function bundle(id,systemId){const bytes=Buffer.from('합성 원본 '+id),s=system(systemId);return {id,systemId,synthetic:true,supplierId:s.supplierId,modelId:s.modelId,modelVersion:s.modelVersion,purpose:s.purpose,testScope:'합성 시험',measures:['KR-34-RISK'],documents:[{id:'doc',name:id+'.txt',contentBase64:bytes.toString('base64'),sha256:createHash('sha256').update(bytes).digest('hex')}]};}
async function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-finance-identity-')),principals=['alpha','beta'].map(tenant=>({id:tenant+'-reviewer',role:'reviewer',tenant,token:tenant.repeat(40)})),service=createService({dataDir:dir,key:generateKeyPairSync('ed25519').privateKey,config:{principals},requirements}),store=service.store;
 t.after(()=>{store.close();assert.ok(resolve(dir).startsWith(resolve(tmpdir())+sep));rmSync(dir,{recursive:true,force:true});});
 const call=(path,body,tenant='alpha')=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),{authorization:'Bearer '+principals.find(p=>p.tenant===tenant).token},body===undefined?'':JSON.stringify(body));
 for(const tenant of ['alpha','beta'])for(const suffix of ['a','b']){await call('/api/governance/systems',system('credit-'+suffix),tenant);await call('/api/governance/bundles',bundle('bundle-'+suffix,'credit-'+suffix),tenant);}
 const rename=(type,from,to)=>store.db.prepare('UPDATE objects SET id=? WHERE tenant=? AND type=? AND id=?').run(to,'alpha',type,from);
 return {store,call,rename};
}

for(const type of ['system','supplier_bundle'])for(const change of ['rename','swap'])test(`finance rejects ${change==='rename'?'renamed':'swapped'} ${type} SQL identities before exporting or signing another target`,async t=>{
 const h=await fixture(t),prefix=type==='system'?'credit':'bundle',a=prefix+'-a',b=prefix+'-b';
 if(change==='rename')h.rename(type,a,'unsigned-alias');else{h.rename(type,a,'swap-temporary');h.rename(type,b,a);h.rename(type,'swap-temporary',b);}
 const id=change==='rename'?'unsigned-alias':a,before=h.store.ledgerObjects('alpha','finance_report');
 if(type==='system')await assert.rejects(h.call('/api/governance/finance/report',{systemId:id}),e=>e.status===409&&/서명 원장/.test(e.message));
 else await assert.rejects(h.call(`/api/governance/bundles/${id}/export`),e=>e.status===409&&/서명 원장/.test(e.message));
 assert.deepEqual(h.store.ledgerObjects('alpha','finance_report'),before,'a rejected request must not sign the mismatched context');
 const healthy=await h.call('/api/governance/bundles/bundle-a/export',undefined,'beta');assert.equal(healthy.systemId,'credit-a');assert.equal(Buffer.from(healthy.documents[0].contentBase64,'base64').toString(),'합성 원본 bundle-a');
 const report=await h.call('/api/governance/finance/report',{systemId:'credit-a'},'beta');assert.equal(report.snapshot.tenant,'beta');assert.equal(report.snapshot.system.id,'credit-a');
 if(change==='rename')h.rename(type,'unsigned-alias',a);else{h.rename(type,a,'swap-temporary');h.rename(type,b,a);h.rename(type,'swap-temporary',b);}
 const restored=await h.call('/api/governance/bundles/bundle-a/export');assert.equal(restored.id,'bundle-a');assert.equal(restored.systemId,'credit-a');assert.equal(Buffer.from(restored.documents[0].contentBase64,'base64').toString(),'합성 원본 bundle-a');
 const restoredReport=await h.call('/api/governance/finance/report',{systemId:'credit-a'});assert.equal(restoredReport.snapshot.system.id,'credit-a');assert.equal(restoredReport.snapshot.bundles[0].id,'bundle-a');
});

test('same-tenant object contents cannot be read through a foreign-tenant bundle ID',async t=>{
 const h=await fixture(t);await h.call('/api/governance/bundles',bundle('alpha-private','credit-a'));
 await assert.rejects(h.call('/api/governance/bundles/alpha-private/export',undefined,'beta'),e=>e.status===404);
 const report=await h.call('/api/governance/finance/report',{systemId:'credit-a'},'beta');assert.ok(report.snapshot.bundles.every(b=>b.id!=='alpha-private'));
});
