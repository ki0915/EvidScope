import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {createHash,generateKeyPairSync,verify} from 'node:crypto';
import {mkdtempSync,readFileSync,readdirSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createService} from '../src/service.mjs';
import {canonical} from '../src/crypto.mjs';
import {createDocumentAdapter} from '../src/finance-evidence.mjs';

const reqs=JSON.parse(readFileSync('data/requirements.json','utf8'));
const system={id:'credit',name:'합성 대출 심사',owner:'감사팀',purpose:'대출 심사 보조',role:'deployer',krRoles:['deployer'],markets:['KR'],domain:'credit',generative:false,highImpact:'candidate',supplierId:'supplier-a',modelId:'credit-score',modelVersion:'v1',suppliedModelVersion:'v1',suppliedPurpose:'대출 심사 보조',substantialModification:false};
export function supplierBundle(){const bytes=Buffer.from('합성 공급사 시험 근거. 실제 금융 고객 자료가 아닙니다.');return {id:'supplier-v1',systemId:'credit',synthetic:true,supplierId:'supplier-a',modelId:'credit-score',modelVersion:'v1',purpose:system.purpose,testScope:'합성 대출 심사 사례',measures:['KR-34-RISK','KR-34-EXPLAIN'],documents:[{id:'doc-1',name:'합성 시험.txt',contentBase64:bytes.toString('base64'),sha256:createHash('sha256').update(bytes).digest('hex')}],reviewerNotes:'법적 인정 별도 검토'};}
function fixture(t){const dir=mkdtempSync(join(tmpdir(),'evidscope-finance-')),key=generateKeyPairSync('ed25519').privateKey;const principals=[['reviewer','alpha','r'],['auditor','alpha','a'],['reviewer','beta','b']].map(([role,tenant,prefix])=>({id:prefix,role,tenant,token:prefix.repeat(40)}));const service=createService({dataDir:dir,key,config:{principals},requirements:reqs});t.after(()=>service.store.db.close());const call=(path,body,who=0)=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),{authorization:'Bearer '+principals[who].token},body===undefined?'':JSON.stringify(body));return {dir,service,call};}
const assess={systemId:'credit',requirementId:'KR-34-RISK',applicability:'applicable',assessment:'sufficient',legalReview:'reviewed',evidence:[{type:'document',ref:'supplier-bundle:supplier-v1'}],control:'공급사 증빙 대조',owner:'감사팀',reason:'합성 검토',nextReviewAt:'2099-01-01T00:00:00Z'};

test('verified supplier bytes, role isolation, immutable signed review and changed model invalidation',async t=>{
 const f=fixture(t);await f.call('/api/governance/systems',system);const saved=await f.call('/api/governance/bundles',supplierBundle());
 assert.equal(saved.verification.status,'technical_match_human_review_required');assert.equal(saved.documents[0].contentBase64,undefined);
 assert.deepEqual(saved.verification.eligibleMeasureCandidates,['KR-34-RISK','KR-34-EXPLAIN']);
 await assert.rejects(f.call('/api/governance/bundles',supplierBundle(),1),/검토자/);
 await assert.rejects(f.call('/api/governance/bundles/supplier-v1/export',undefined,2),/테넌트/);
 const exported=await f.call('/api/governance/bundles/supplier-v1/export');assert.equal(exported.documents[0].contentBase64,supplierBundle().documents[0].contentBase64);
 await f.call('/api/governance/assessments',assess);
 await assert.rejects(f.call('/api/governance/assessments',{...assess,requirementId:'KR-34-OVERSIGHT'}),/조치 범위 밖/);
 const report=await f.call('/api/governance/finance/report',{systemId:'credit'});assert.equal(report.snapshot.operationalStatus,'execution_evidence_missing');
 assert.ok(verify(null,Buffer.from(canonical(report.snapshot)),report.publicKey,Buffer.from(report.signature,'base64')));
 await f.call('/api/governance/systems',{...system,modelVersion:'v2'});
 const current=await f.call('/api/governance/finance?systemId=credit');assert.ok(current.bundles[0].verification.issues.includes('MODEL_VERSION_MISMATCH'));
 const governance=await f.call('/api/governance/report?systemId=credit');assert.equal(governance.items.find(x=>x.requirement.id==='KR-34-RISK').status,'review_required');
 assert.deepEqual(await f.call('/api/governance/finance/reports/'+report.id),report);
 await assert.rejects(f.call('/api/governance/assessments',assess),/충분 평가/);
});

test('same private key representation can restore encrypted document bytes',()=>{
 const dir=mkdtempSync(join(tmpdir(),'evidscope-finance-key-')),key=generateKeyPairSync('ed25519').privateKey,bytes=Buffer.from('synthetic');
 const first=createDocumentAdapter(dir,key),hash=first.put('tenant-a',bytes);
 const restored=createDocumentAdapter(dir,key.export({type:'pkcs8',format:'pem'}));assert.deepEqual(restored.read('tenant-a',hash),bytes);assert.throws(()=>restored.read('tenant-b',hash));
});

test('unknown or changed supplied model and purpose require review even when current bundle matches',async t=>{
 for(const [field,value,issue] of [
  ['suppliedModelVersion',undefined,'SUPPLIED_MODEL_VERSION_UNKNOWN'],
  ['suppliedPurpose',undefined,'SUPPLIED_PURPOSE_UNKNOWN'],
  ['suppliedModelVersion','v0','SUPPLIED_MODEL_VERSION_MISMATCH'],
  ['suppliedPurpose','마케팅 고객 분류','SUPPLIED_PURPOSE_MISMATCH'],
 ])await t.test(issue,async t=>{
  const f=fixture(t);await f.call('/api/governance/systems',{...system,[field]:value});
  const saved=await f.call('/api/governance/bundles',supplierBundle());
  assert.equal(saved.verification.status,'review_required');assert.ok(saved.verification.issues.includes(issue));
  assert.equal(saved.verification.legalDecision,'human_review_required');
  assert.equal((await f.call('/api/governance/finance?systemId=credit')).system.substantialModification,false,'A mismatch must not determine substantial modification');
  await assert.rejects(f.call('/api/governance/assessments',assess),/충분 평가/);
 });
});

test('newly discovered supplied scope mismatch invalidates current assessment and preserves its signed history',async t=>{
 const f=fixture(t);await f.call('/api/governance/systems',system);await f.call('/api/governance/bundles',supplierBundle());
 const assessment=await f.call('/api/governance/assessments',assess);
 const report=await f.call('/api/governance/finance/report',{systemId:'credit'});
 await f.call('/api/governance/systems',{...system,suppliedPurpose:'마케팅 고객 분류'});
 const view=await f.call('/api/governance/finance?systemId=credit');
 assert.ok(view.bundles[0].verification.issues.includes('SUPPLIED_PURPOSE_MISMATCH'));
 const current=(await f.call('/api/governance/report?systemId=credit')).items.find(x=>x.requirement.id==='KR-34-RISK');
 assert.equal(current.status,'review_required');assert.equal(current.legalStatus,'review_required');
 assert.deepEqual(current.assessment,assessment);
 assert.deepEqual(await f.call('/api/governance/finance/reports/'+report.id),report);
 await assert.rejects(f.call('/api/governance/assessments',assess),/충분 평가/);
});

test('corrupt or missing document never remains verified; hashes and measure bounds are enforced',async t=>{
 const f=fixture(t);await f.call('/api/governance/systems',system);
 const bad=supplierBundle();bad.documents[0].sha256='0'.repeat(64);await assert.rejects(f.call('/api/governance/bundles',bad),/해시/);
 await assert.rejects(f.call('/api/governance/bundles',{...supplierBundle(),measures:['KR-34-OVERSIGHT']}),/제34조/);
 await f.call('/api/governance/bundles',supplierBundle());await f.call('/api/governance/assessments',assess);
 const root=join(f.dir,'finance-documents'),tenant=readdirSync(root)[0],file=join(root,tenant,readdirSync(join(root,tenant))[0]);
 assert.ok(!readFileSync(file,'utf8').includes('합성 공급사'));
 writeFileSync(file,'corrupt');
 const current=await f.call('/api/governance/finance?systemId=credit');assert.equal(current.bundles[0].verification.documents[0].status,'unavailable_or_corrupt');
 assert.equal((await f.call('/api/governance/report?systemId=credit')).items.find(x=>x.requirement.id==='KR-34-RISK').status,'review_required');
 await assert.rejects(f.call('/api/governance/bundles/supplier-v1/export'),/복구/);
});

test('bundle replacement invalidates only linked snapshots and cannot move between systems',async t=>{
 const f=fixture(t);await f.call('/api/governance/systems',system);await f.call('/api/governance/systems',{...system,id:'other'});
 await f.call('/api/governance/bundles',supplierBundle());await f.call('/api/governance/assessments',assess);
 await assert.rejects(f.call('/api/governance/assessments',{...assess,systemId:'other'}),/다른 시스템/);
 await assert.rejects(f.call('/api/governance/bundles',{...supplierBundle(),systemId:'other'}),/시스템을 변경/);
 await f.call('/api/governance/bundles',{...supplierBundle(),testScope:'수정 시험 범위'});
 assert.equal((await f.call('/api/governance/report?systemId=credit')).items.find(x=>x.requirement.id==='KR-34-RISK').status,'review_required');
 assert.equal((await f.call('/api/governance/finance?systemId=credit')).bundles[0].revision,2);
});

test('altered system or supplier projection cannot be legitimized by a new signed report',async t=>{
 const f=fixture(t);await f.call('/api/governance/systems',system);await f.call('/api/governance/bundles',supplierBundle());
 const prior=f.service.store.get('alpha','supplier_bundle','supplier-v1');
 f.service.store.db.prepare("UPDATE objects SET body=? WHERE tenant='alpha' AND type='supplier_bundle' AND id='supplier-v1'").run(JSON.stringify({...prior,modelVersion:'forged'}));
 await assert.rejects(f.call('/api/governance/finance/report',{systemId:'credit'}),/서명 원장/);
 await assert.rejects(f.call('/api/governance/assessments',assess),/서명 원장/);
 assert.equal(f.service.store.list('alpha','finance_report').length,0);
});

test('legacy system facts migrate once to unknown without rewriting historical assessments',()=>{
 const dir=mkdtempSync(join(tmpdir(),'evidscope-finance-migration-')),key=generateKeyPairSync('ed25519').privateKey,p={id:'reviewer',tenant:'alpha',role:'reviewer',token:'x'.repeat(40)},options={dataDir:dir,key,config:{principals:[p]},requirements:reqs};
 let service=createService(options);const old={...system,schemaVersion:2,updatedAt:'2026-09-01T00:00:00Z'};for(const field of ['krRoles','supplierId','modelId','substantialModification'])delete old[field];
 const historicalAssessment={id:'prior-human',systemId:old.id,requirementId:'KR-34-RISK',applicability:'applicable',assessment:'insufficient',legalReview:'pending',reason:'Prior human review',owner:'reviewer',evidence:[]};
 service.store.transaction(()=>{service.store.put(p,'system',old.id,old);service.store.put(p,'assessment',historicalAssessment.id,historicalAssessment);});service.store.db.close();
 service=createService(options);const updated=service.store.get('alpha','system','credit');assert.equal(updated.schemaVersion,4);assert.deepEqual(updated.krRoles,[]);assert.equal(updated.modelId,'unknown');assert.equal(updated.domesticImpact,'unknown');assert.equal(updated.aiBusinessOperator,'unknown');assert.equal(updated.providedAt,'unknown');assert.deepEqual(updated.highImpactDomains,[]);assert.equal(updated.updatedAt,old.updatedAt);const tasks=service.store.list('alpha','governance_task').length;assert.equal(tasks,1);service.store.db.close();
 service=createService(options);try{assert.equal(service.store.list('alpha','governance_task').length,tasks);assert.deepEqual(service.store.ledgerObjects('alpha','system')[0],updated);assert.deepEqual(service.store.ledgerObjects('alpha','assessment'),[historicalAssessment]);assert.deepEqual(service.store.get('alpha','assessment',historicalAssessment.id),historicalAssessment);}finally{service.store.db.close();}
});

test('startup refuses a downgraded and altered system projection without re-signing it',()=>{
 const dir=mkdtempSync(join(tmpdir(),'evidscope-finance-migration-tamper-')),key=generateKeyPairSync('ed25519').privateKey,p={id:'reviewer',tenant:'alpha',role:'reviewer',token:'x'.repeat(40)},options={dataDir:dir,key,config:{principals:[p]},requirements:reqs};
 let service=createService(options);service.store.transaction(()=>service.store.put(p,'system',system.id,{...system,schemaVersion:3}));
 const checkpoint=service.store.db.prepare("SELECT body FROM checkpoints WHERE tenant='alpha'").get().body,ledgerCount=service.store.db.prepare("SELECT COUNT(*) n FROM ledger WHERE tenant='alpha'").get().n,original=service.store.get('alpha','system','credit');
 service.store.db.prepare("UPDATE objects SET body=? WHERE tenant='alpha' AND type='system' AND id='credit'").run(JSON.stringify({...original,schemaVersion:2,owner:'attacker-owner',purpose:'attacker-purpose'}));service.store.close();
 assert.throws(()=>createService(options),/서명 원장/);
 const db=new DatabaseSync(join(dir,'evidence.db'),{readOnly:true});try{assert.equal(db.prepare("SELECT COUNT(*) n FROM ledger WHERE tenant='alpha'").get().n,ledgerCount);assert.equal(db.prepare("SELECT body FROM checkpoints WHERE tenant='alpha'").get().body,checkpoint);const latest=JSON.parse(db.prepare("SELECT body FROM ledger WHERE tenant='alpha' AND json_extract(body,'$.type')='system' ORDER BY seq DESC LIMIT 1").get().body).payload;assert.equal(latest.owner,system.owner);assert.equal(latest.purpose,system.purpose);assert.equal(latest.schemaVersion,3);}finally{db.close();}
});

for(const attack of ['insert','delete','sql-id'])test(`startup refuses ${attack} system projection drift`,()=>{
 const dir=mkdtempSync(join(tmpdir(),`evidscope-finance-migration-${attack}-`)),key=generateKeyPairSync('ed25519').privateKey,p={id:'reviewer',tenant:'alpha',role:'reviewer',token:'x'.repeat(40)},options={dataDir:dir,key,config:{principals:[p]},requirements:reqs};
 let service=createService(options);service.store.transaction(()=>service.store.put(p,'system',system.id,{...system,schemaVersion:3}));const before=service.store.db.prepare("SELECT COUNT(*) n FROM ledger WHERE tenant='alpha'").get().n;
 if(attack==='insert')service.store.db.prepare("INSERT INTO objects VALUES('alpha','system','injected',?)").run(JSON.stringify({...system,id:'injected',schemaVersion:2}));
 if(attack==='delete')service.store.db.prepare("DELETE FROM objects WHERE tenant='alpha' AND type='system' AND id='credit'").run();
 if(attack==='sql-id')service.store.db.prepare("UPDATE objects SET id='renamed' WHERE tenant='alpha' AND type='system' AND id='credit'").run();
 service.store.close();assert.throws(()=>createService(options),/서명 원장/);
 const db=new DatabaseSync(join(dir,'evidence.db'),{readOnly:true});try{assert.equal(db.prepare("SELECT COUNT(*) n FROM ledger WHERE tenant='alpha'").get().n,before);}finally{db.close();}
});

test('startup verifies every tenant before leaving any partial migration',()=>{
 const dir=mkdtempSync(join(tmpdir(),'evidscope-finance-migration-tenants-')),key=generateKeyPairSync('ed25519').privateKey,alpha={id:'alpha-reviewer',tenant:'alpha',role:'reviewer',token:'a'.repeat(40)},beta={id:'beta-reviewer',tenant:'beta',role:'reviewer',token:'b'.repeat(40)},options={dataDir:dir,key,config:{principals:[alpha,beta]},requirements:reqs};
 let service=createService(options);const legacy={...system,schemaVersion:2};for(const field of ['krRoles','supplierId','modelId','substantialModification'])delete legacy[field];service.store.transaction(()=>{service.store.put(alpha,'system',legacy.id,legacy);service.store.put(beta,'system',system.id,{...system,schemaVersion:3});});const alphaSystems=service.store.db.prepare("SELECT COUNT(*) n FROM ledger WHERE tenant='alpha' AND json_extract(body,'$.type')='system'").get().n;
 const betaSystem=service.store.get('beta','system','credit');service.store.db.prepare("UPDATE objects SET body=? WHERE tenant='beta' AND type='system' AND id='credit'").run(JSON.stringify({...betaSystem,owner:'attacker-owner'}));service.store.close();
 assert.throws(()=>createService(options),/서명 원장/);
 const db=new DatabaseSync(join(dir,'evidence.db'),{readOnly:true});try{assert.equal(db.prepare("SELECT COUNT(*) n FROM ledger WHERE tenant='alpha' AND json_extract(body,'$.type')='system'").get().n,alphaSystems);assert.equal(JSON.parse(db.prepare("SELECT body FROM objects WHERE tenant='alpha' AND type='system' AND id='credit'").get().body).schemaVersion,2);}finally{db.close();}
});

for(const attack of ['catalog','assessment'])test(`catalog change refuses altered ${attack} projection before signing review tasks`,()=>{
 const dir=mkdtempSync(join(tmpdir(),`evidscope-catalog-migration-${attack}-`)),key=generateKeyPairSync('ed25519').privateKey,p={id:'reviewer',tenant:'alpha',role:'reviewer',token:'x'.repeat(40)},options={dataDir:dir,key,config:{principals:[p]},requirements:reqs};
 let service=createService(options);service.store.transaction(()=>service.store.put(p,'assessment','assessment-one',{id:'assessment-one',systemId:'credit',requirementId:'KR-34-RISK',owner:'original-owner'}));const before=service.store.db.prepare("SELECT COUNT(*) n FROM ledger WHERE tenant='alpha'").get().n;
 const type=attack,id=attack==='catalog'?'current':'assessment-one',value=service.store.get('alpha',type,id);service.store.db.prepare('UPDATE objects SET body=? WHERE tenant=? AND type=? AND id=?').run(JSON.stringify(attack==='catalog'?{...value,hash:'f'.repeat(64)}:{...value,owner:'attacker-owner'}),'alpha',type,id);service.store.close();
 const changed={...options,requirements:[...reqs,{id:'TEST-CHANGE',title:'Synthetic catalog change'}]};assert.throws(()=>createService(changed),/서명 원장/);
 const db=new DatabaseSync(join(dir,'evidence.db'),{readOnly:true});try{assert.equal(db.prepare("SELECT COUNT(*) n FROM ledger WHERE tenant='alpha'").get().n,before);assert.equal(db.prepare("SELECT COUNT(*) n FROM ledger WHERE tenant='alpha' AND json_extract(body,'$.type')='governance_task'").get().n,0);}finally{db.close();}
});
