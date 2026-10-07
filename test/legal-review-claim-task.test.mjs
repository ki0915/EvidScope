// Regression tests for round-2 re-audit finding S11 (from the reviewer's PoC r2-poc-legal-claim-task): the author's own
// legalReview field is only a claim, but claiming 'reviewed' used to suppress the legal-review governance task, so the work
// queue showed nothing outstanding while the report's legalStatus stayed 'pending'.
import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createService} from '../src/service.mjs';

const requirements=JSON.parse(readFileSync(new URL('../data/requirements.json',import.meta.url),'utf8'));
const system={id:'sys1',name:'S',owner:'o',purpose:'p',markets:['EU','KR'],euRoles:['provider'],krRoles:['developer'],domesticImpact:true,
 aiBusinessOperator:true,defenceOrNationalSecurityOnly:false,highImpact:'confirmed',providedAt:new Date().toISOString()};
const principals=[{id:'author',role:'reviewer',tenant:'alpha',token:'a'.repeat(40)},{id:'legal',role:'reviewer',tenant:'alpha',token:'l'.repeat(40)}];
function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-r2-legal-')),key=generateKeyPairSync('ed25519').privateKey;
 const h={start:()=>{h.service=createService({dataDir:dir,key,config:{principals},requirements});}};
 h.start();t.after(()=>{h.service.store.close();rmSync(dir,{recursive:true,force:true});});
 h.restart=()=>{h.service.store.close();h.start();};
 h.call=(path,body,who='author')=>h.service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),
  {authorization:'Bearer '+principals.find(p=>p.id===who).token},body===undefined?'':JSON.stringify(body));
 h.assess=(requirementId,legalReview)=>h.call('/api/governance/assessments',{systemId:system.id,requirementId,applicability:'applicable',
  assessment:'sufficient',legalReview,evidence:[{type:'attestation',ref:'we promise it is fine'}],control:'c',owner:'o',reason:'because',
  nextReviewAt:'2099-01-01T00:00:00.000Z'});
 h.report=()=>h.call('/api/governance/report?systemId='+system.id);
 return h;
}

test('R2 S11: an author-claimed legal review opens the same legal-review task as an honest pending one',async t=>{
 const h=fixture(t);await h.call('/api/governance/systems',system);
 const honest=await h.assess('EU-50-1','pending'),claimed=await h.assess('EU-50-2','reviewed');
 const report=await h.report(),item=id=>report.items.find(i=>i.requirement.id===id),taskFor=a=>report.tasks.find(x=>x.id===a.id);
 // Both items are equally unconfirmed in the report ...
 assert.equal(item('EU-50-1').legalStatus,'pending');assert.equal(item('EU-50-2').legalStatus,'pending');
 assert.equal(item('EU-50-2').legalReview.authorClaim,'reviewed');
 // ... and both are outstanding work with the same legal-review task.
 assert.equal(taskFor(honest)?.status,'open');
 assert.equal(taskFor(claimed)?.status,'open','a self-claimed legal review still opens the legal-review task');
 assert.equal(taskFor(claimed).title,taskFor(honest).title);
 // The task stays open until someone other than the author confirms the review.
 const close=who=>h.call(`/api/governance/tasks/${claimed.id}`,{status:'closed',reason:'done'},who);
 await assert.rejects(close('legal'),error=>error.status===409,'no independent confirmation yet');
 await h.call(`/api/governance/assessments/${claimed.id}/legal-review`,{reason:'independent legal review'},'legal');
 await assert.rejects(close('author'),error=>error.status===403,'the author cannot close it');
 assert.equal((await close('legal')).status,'closed');
});

test('R2 S11: a self-claimed assessment recorded before the fix gets its legal-review task once at the next start',async t=>{
 const h=fixture(t);await h.call('/api/governance/systems',system);
 // What the earlier code stored for a self-claimed review: the assessment, and no task with its id.
 const store=()=>h.service.store,author={id:'author',tenant:'alpha'};
 const legacy={...await h.assess('EU-50-3','reviewed'),id:'legacy-claim'},confirmed={...await h.assess('EU-50-5','reviewed'),id:'confirmed-claim'};
 store().transaction(()=>{store().put(author,'assessment',legacy.id,legacy);store().put(author,'assessment',confirmed.id,confirmed);});
 // An earlier independent confirmation already covers confirmed-claim, so it needs no backfilled task.
 await h.call(`/api/governance/assessments/${confirmed.id}/legal-review`,{reason:'confirmed before the upgrade'},'legal');
 assert.equal((await h.report()).tasks.some(x=>['legacy-claim','confirmed-claim'].includes(x.id)),false);
 h.restart();
 const tasks=(await h.report()).tasks,task=tasks.find(x=>x.id==='legacy-claim');
 assert.equal(task?.status,'open','the self-claimed legal review is outstanding after the upgrade');
 assert.equal(task.requirementId,'EU-50-3');assert.match(task.title,/자기 확인/);
 assert.equal(tasks.some(x=>x.id==='confirmed-claim'),false);
 const signer=store().db.prepare(`SELECT json_extract(body,'$.principal') p FROM ledger WHERE tenant='alpha' AND json_extract(body,'$.type')='governance_task'
  AND json_extract(body,'$.payload.id')=?`).all('legacy-claim').map(row=>row.p);
 assert.deepEqual(signer,['legal-review-task-migration-v1']);
 const count=()=>store().db.prepare(`SELECT COUNT(*) n FROM ledger WHERE tenant='alpha' AND json_extract(body,'$.type')='governance_task'`).get().n;
 const before=count();
 h.restart();assert.equal(count(),before,'the backfill runs once');
 await h.call('/api/governance/assessments/legacy-claim/legal-review',{reason:'independent legal review'},'legal');
 assert.equal((await h.call('/api/governance/tasks/legacy-claim',{status:'closed',reason:'confirmed'},'legal')).status,'closed');
});
