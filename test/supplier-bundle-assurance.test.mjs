// Regression tests for round-2 re-audit finding S11 (from the reviewer's PoC r2-poc-assurance-label): a supplier bundle the
// assessment author uploaded themselves (synthetic, no provenance, no supplier signature anywhere) was labelled
// 'supplier_signed_bundle' and lifted the item to 'source_bound'. The vault verifies no supplier signature: a bundle is
// 'vault_retained_supplier_bundle' and source-bound only when it was declared real and someone other than the assessment
// author confirmed its provenance; otherwise it is the author's own claim.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createService} from '../src/service.mjs';

const requirements=JSON.parse(readFileSync(new URL('../data/requirements.json',import.meta.url),'utf8'));
const sha=b=>createHash('sha256').update(b).digest('hex');
const system={id:'credit',name:'Synthetic credit',owner:'reviewer',purpose:'Loan assistance',markets:['KR'],krRoles:['deployer'],generative:false,
 highImpact:'confirmed',supplierId:'supplier-a',modelId:'credit-score',modelVersion:'v1',suppliedModelVersion:'v1',suppliedPurpose:'Loan assistance',
 substantialModification:false};
const principals=[{id:'author',role:'reviewer',tenant:'alpha',token:'a'.repeat(40)},{id:'checker',role:'reviewer',tenant:'alpha',token:'c'.repeat(40)}];
const checks={supplierIdentityChecked:true,deliveryReferenceChecked:true,modelPurposeScopeChecked:true};
function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-r2-assurance-'));
 const service=createService({dataDir:dir,key:generateKeyPairSync('ed25519').privateKey,config:{principals},requirements});
 t.after(()=>{service.store.close();rmSync(dir,{recursive:true,force:true});});
 const call=(path,body,who='author')=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),
  {authorization:'Bearer '+principals.find(p=>p.id===who).token},body===undefined?'':JSON.stringify(body));
 const bundle=(id,text,extra)=>{const bytes=Buffer.from(text);return call('/api/governance/bundles',{id,systemId:'credit',supplierId:'supplier-a',
  modelId:'credit-score',modelVersion:'v1',purpose:system.purpose,testScope:'none',measures:['KR-34-RISK'],reviewerNotes:'uploaded by the author',
  documents:[{id:'d',name:'claim.txt',sha256:sha(bytes),contentBase64:bytes.toString('base64')}],...extra});};
 const assess=(id,who='author')=>call('/api/governance/assessments',{systemId:'credit',requirementId:'KR-34-RISK',applicability:'applicable',
  assessment:'sufficient',legalReview:'pending',evidence:[{type:'document',ref:'supplier-bundle:'+id}],control:'c',owner:'o',reason:'r',
  nextReviewAt:'2099-01-01T00:00:00.000Z'},who);
 const item=async()=>(await call('/api/governance/report?systemId=credit')).items.find(i=>i.requirement.id==='KR-34-RISK');
 return {call,bundle,assess,item};
}

test('R2 S11: an author-uploaded synthetic bundle is self_asserted, never a signed or source-bound supplier record',async t=>{
 const h=fixture(t);await h.call('/api/governance/systems',system);
 await h.bundle('self','I, the assessment author, state that the supplier manages risk.',{synthetic:true});
 await h.assess('self');
 const item=await h.item();
 assert.deepEqual(item.evidenceAssurance.items.map(i=>i.assurance),['self_asserted']);
 assert.equal(item.evidenceAssurance.level,'self_asserted','author-only evidence is reported as self_asserted');
 assert.equal(item.evidenceAssurance.selfAssertedItems,1);
 assert.ok(!JSON.stringify(item).includes('supplier_signed_bundle'),'the old label is gone');
});

test('R2 S11: a real bundle is source-bound only after someone other than the author confirmed its provenance',async t=>{
 const h=fixture(t);await h.call('/api/governance/systems',system);
 const real=await h.bundle('real','Supplier risk statement delivered through the portal.',
  {synthetic:false,provenance:{channel:'supplier_portal',reference:'delivery-42',suppliedAt:'2026-10-01T00:00:00.000Z'}});
 const review=who=>h.call('/api/governance/bundles/real/provenance-reviews',
  {bundleHash:real.contentHash,decision:'verified',reason:'origin checked',checks},who);
 // The author vouches for their own upload: still the author's claim.
 await review('author');await h.assess('real');
 let item=await h.item();
 assert.deepEqual(item.evidenceAssurance.items.map(i=>i.assurance),['self_asserted']);assert.equal(item.evidenceAssurance.level,'self_asserted');
 // A second reviewer confirms the provenance; an assessment relying on that review binds the vault-retained bundle.
 await review('checker');assert.equal((await h.item()).status,'review_required','the earlier assessment relied on the earlier review');
 await h.assess('real');item=await h.item();
 assert.deepEqual(item.evidenceAssurance.items.map(i=>i.assurance),['vault_retained_supplier_bundle']);
 assert.equal(item.evidenceAssurance.level,'source_bound');assert.equal(item.evidenceAssurance.selfAssertedItems,0);
 // The checker's own assessment over the checker's review is self-vouched again.
 await h.assess('real','checker');assert.equal((await h.item()).evidenceAssurance.level,'self_asserted');
});
