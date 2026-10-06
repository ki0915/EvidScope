import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,createPublicKey} from 'node:crypto';
import {mkdirSync,mkdtempSync,readFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {createService} from '../src/service.mjs';
import {digest} from '../src/crypto.mjs';
import {normalizeSupplierProvenance,normalizeSupplierProvenanceReview} from '../src/supplier-provenance.mjs';
import {checkObjectProjection} from '../src/object-integrity.mjs';
import {createVaultBackup,createVaultRecoveryFrontier,restoreVaultBackup} from '../src/vault-recovery.mjs';

const system={id:'credit',name:'공급사 입력 계약 시험',owner:'reviewer',purpose:'대출 심사 보조',krRoles:['deployer'],markets:['KR'],domain:'credit',generative:false,highImpact:'candidate',supplierId:'supplier-a',modelId:'credit-model',modelVersion:'v1',suppliedModelVersion:'v1',suppliedPurpose:'대출 심사 보조',substantialModification:false};
const checks={supplierIdentityChecked:true,deliveryReferenceChecked:true,modelPurposeScopeChecked:true};
function input(){const bytes=Buffer.from('Generated contract-test fixture; no customer or supplier data.');return {id:'bundle',systemId:system.id,synthetic:false,provenance:{channel:'supplier_portal',reference:'delivery-fixture-42',suppliedAt:'2026-01-01T00:00:00.000Z'},supplierId:system.supplierId,modelId:system.modelId,modelVersion:system.modelVersion,purpose:system.purpose,testScope:'입력 계약 시험',measures:['KR-34-RISK'],documents:[{id:'doc',name:'fixture.txt',sha256:createHash('sha256').update(bytes).digest('hex'),contentBase64:bytes.toString('base64')}]};}
async function fixture(t){mkdirSync('.test-runs',{recursive:true});const root=mkdtempSync(resolve('.test-runs','supplier-origin-')),dir=join(root,'data'),key=generateKeyPairSync('ed25519').privateKey,principals=[{id:'reviewer',tenant:'alpha',role:'reviewer',token:'r'.repeat(40)}],config={principals},service=createService({dataDir:dir,key,config,requirements:JSON.parse(readFileSync('data/requirements.json'))});t.after(()=>service.store.close());const call=(path,body)=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),{authorization:'Bearer '+principals[0].token},body===undefined?'':JSON.stringify(body));await call('/api/governance/systems',system);return {service,call,root,dir,key,config};}

test('real intake requires explicit provenance and rejects attempts to import verification or reviewer authority',()=>{
 const p={channel:'email',reference:'delivery-id'};assert.deepEqual(normalizeSupplierProvenance(false,p),p);assert.equal(normalizeSupplierProvenance(true,undefined),undefined);
 for(const [synthetic,value]of [[undefined,p],[false,undefined],[false,{...p,reviewed:true}],[false,{...p,reference:' '}],[false,{...p,suppliedAt:'not-a-time'}],[false,{...p,channel:'authenticated_supplier'}]])assert.throws(()=>normalizeSupplierProvenance(synthetic,value));
 const b={contentHash:'a'.repeat(64)},r={bundleHash:b.contentHash,decision:'verified',reason:'checked delivery fixture',checks};assert.deepEqual(normalizeSupplierProvenanceReview(r,b),{decision:r.decision,reason:r.reason,checks});
 for(const bad of [{...r,bundleHash:'b'.repeat(64)},{...r,reviewer:'forged'},{...r,checks:{...checks,supplierIdentityChecked:false}},{...r,checks:{...checks,role:'admin'}},{...r,reason:'   '}])assert.throws(()=>normalizeSupplierProvenanceReview(bad,b));
});

test('upload and export do not become source review, and sufficient assessment binds server review hash',async t=>{
 const f=await fixture(t),bundle=await f.call('/api/governance/bundles',input());assert.equal(bundle.synthetic,false);assert.equal(bundle.verification.provenance.status,'unreviewed');assert.equal(bundle.verification.provenance.sourceAuthentication,'not_independently_verified');assert.equal(bundle.verification.status,'review_required');
 const assessment={systemId:system.id,requirementId:'KR-34-RISK',applicability:'applicable',assessment:'sufficient',legalReview:'reviewed',evidence:[{type:'document',ref:'supplier-bundle:bundle',provenanceReviewHash:'f'.repeat(64)}],control:'source review',owner:'reviewer',reason:'fixture',nextReviewAt:'2099-01-01T00:00:00.000Z'};
 await assert.rejects(f.call('/api/governance/assessments',assessment),/충분 평가/);
 const review=await f.call('/api/governance/bundles/bundle/provenance-reviews',{bundleHash:bundle.contentHash,decision:'verified',reason:'independent origin checks recorded in fixture',checks});assert.equal(review.reviewer,'reviewer');
 const saved=await f.call('/api/governance/assessments',assessment);assert.equal(saved.evidence[0].provenanceReviewHash,digest(review));
 const exported=await f.call('/api/governance/bundles/bundle/export');assert.deepEqual(exported.provenance,input().provenance);assert.equal(exported.synthetic,false);
 const imported=await f.call('/api/governance/bundles',{...exported,provenanceReviewHash:digest(review),verification:{provenance:{status:'reviewed'}}});assert.equal(imported.revision,2);assert.equal(imported.verification.provenance.status,'stale');assert.equal(imported.verification.status,'review_required');
 assert.equal((await f.call('/api/governance/bundles/bundle/provenance-reviews')).reviews.length,1);assert.deepEqual(f.service.store.get('alpha','assessment',saved.id),saved);
});

test('latest rejected source review reopens linked assessment without rewriting signed report history',async t=>{
 const f=await fixture(t),bundle=await f.call('/api/governance/bundles',input()),path='/api/governance/bundles/bundle/provenance-reviews';
 const first=await f.call(path,{bundleHash:bundle.contentHash,decision:'verified',reason:'fixture origin checked',checks}),assessment=await f.call('/api/governance/assessments',{systemId:system.id,requirementId:'KR-34-RISK',applicability:'applicable',assessment:'sufficient',legalReview:'reviewed',evidence:[{type:'document',ref:'supplier-bundle:bundle'}],control:'recorded review',owner:'reviewer',reason:'fixture',nextReviewAt:'2099-01-01T00:00:00.000Z'}),report=await f.call('/api/governance/finance/report',{systemId:system.id});
 await f.call(path,{bundleHash:bundle.contentHash,decision:'rejected',reason:'later origin conflict',checks:{...checks,deliveryReferenceChecked:false}});
 const current=await f.call('/api/governance/finance?systemId=credit');assert.equal(current.bundles[0].verification.provenance.status,'rejected');const reviewTasks=current.tasks.filter(task=>task.currentReviewHash);assert.equal(reviewTasks.length,1);assert.equal(reviewTasks[0].previousReviewHash,digest(first));
 const governance=await f.call('/api/governance/report?systemId=credit');assert.equal(governance.items.find(item=>item.requirement.id==='KR-34-RISK').status,'review_required');assert.deepEqual(await f.call('/api/governance/finance/reports/'+report.id),report);assert.deepEqual(f.service.store.get('alpha','assessment',assessment.id),assessment);
});

test('forged review projections and stale target hash are rejected before another review can be signed',async t=>{
 const f=await fixture(t),b=await f.call('/api/governance/bundles',input()),path='/api/governance/bundles/bundle/provenance-reviews',review=await f.call(path,{bundleHash:b.contentHash,decision:'unverified',reason:'origin not yet checked',checks:{supplierIdentityChecked:false,deliveryReferenceChecked:false,modelPurposeScopeChecked:false}});
 const cp=f.service.store.checkpoint('alpha');await assert.rejects(f.call(path,{bundleHash:'a'.repeat(64),decision:'verified',reason:'wrong revision',checks}),/현재.*해시/);assert.deepEqual(f.service.store.checkpoint('alpha'),cp);
 f.service.store.db.prepare('UPDATE objects SET body=? WHERE tenant=? AND type=? AND id=?').run(JSON.stringify({...review,decision:'verified'}),'alpha','supplier_provenance_review',review.id);
 await assert.rejects(f.call('/api/governance/finance?systemId=credit'),/서명 원장/);// The refused read appended nothing to the ledger; it is recorded in the access log instead.
 assert.deepEqual(f.service.store.rawBundle('alpha').records.slice(cp.count),[]);
 const attempt=f.service.accessLog.entries('alpha',{fromSeq:f.service.accessLog.status('alpha').entries}).at(-1).entry;
 assert.equal(attempt.target,'/api/governance/finance');assert.equal(attempt.principal,'reviewer');assert.match(attempt.queryHash,/^[a-f0-9]{64}$/);
 assert.equal(f.service.store.rawBundle('alpha').records.filter(row=>row.type==='supplier_provenance_review').length,1);
 assert.throws(()=>checkObjectProjection(f.service.store.db,'alpha',f.service.store.rawBundle('alpha').records),/Object projection/);
});

test('real-input origin reviews survive verified whole-vault recovery with their original signed projection',async t=>{
 const f=await fixture(t),bundle=await f.call('/api/governance/bundles',input()),review=await f.call('/api/governance/bundles/bundle/provenance-reviews',{bundleHash:bundle.contentHash,decision:'verified',reason:'fixture source checks',checks}),shared={privateKey:f.key,publicKey:createPublicKey(f.key)},backupDir=join(f.root,'backup');
 const anchor=await createVaultBackup({dataDir:f.dir,backupDir,...shared}),latest=await createVaultRecoveryFrontier({dataDir:f.dir,anchor,config:f.config,...shared}),restored=await restoreVaultBackup({backupDir,restoreDir:join(f.root,'restored'),anchor,frontier:latest.frontier,frontierAnchor:latest.anchor,config:f.config,...shared});assert.equal(restored.activationAccepted,true);
 const service=createService({dataDir:restored.restoredDirectory,key:f.key,config:f.config,requirements:JSON.parse(readFileSync('data/requirements.json'))});try{assert.deepEqual(service.store.get('alpha','supplier_provenance_review',review.id),review);checkObjectProjection(service.store.db,'alpha',service.store.rawBundle('alpha').records);const view=await service.handle('GET',new URL('/api/governance/finance?systemId=credit','http://local'),{authorization:'Bearer '+f.config.principals[0].token});assert.equal(view.bundles[0].verification.provenance.reviewHash,digest(review));assert.equal(view.bundles[0].verification.provenance.sourceAuthentication,'not_independently_verified');}finally{service.store.close();}
});
