import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {createHash,generateKeyPairSync,randomBytes,randomUUID} from 'node:crypto';
import {existsSync,mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createService} from '../src/service.mjs';
import {digest} from '../src/crypto.mjs';
import {harness} from './harness.mjs';

// Regression tests for adversarial-audit finding S12: (a) authenticate before buffering large bodies, (b) compare
// run-scoped tokens before verified replay, (c) malformed percent-encoding is a 400, (d) no orphaned document files.
const requirements=JSON.parse(readFileSync(new URL('../data/requirements.json',import.meta.url),'utf8'));
const system={id:'credit',name:'Synthetic credit',owner:'reviewer',purpose:'Loan assistance',markets:['KR'],krRoles:['deployer'],
 generative:false,highImpact:'confirmed',modelId:'credit-model',modelVersion:'v1',policyVersion:'credit-policy-v1'};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const input=(id,bytes)=>({id,systemId:system.id,name:'evidence.txt',mediaType:'text/plain',sha256:sha(bytes),contentBase64:bytes.toString('base64')});
const documentFile=(dir,tenant,hash)=>join(dir,'governance-documents',sha(Buffer.from(tenant)),hash+'.json');

let shared;
test.before(async()=>{shared=await harness();});
test.after(async()=>{await shared?.close();});

function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-request-hardening-'));
 const principals=[{id:'reviewer',role:'reviewer',tenant:'alpha',token:'r'.repeat(40)},{id:'auditor',role:'auditor',tenant:'alpha',token:'a'.repeat(40)}];
 const {privateKey}=generateKeyPairSync('ed25519'),service=createService({dataDir:dir,key:privateKey,config:{principals},requirements});
 t.after(()=>{service.store.close();rmSync(dir,{recursive:true,force:true});});
 const call=(path,body,who=0)=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),
  {authorization:'Bearer '+principals[who].token},body===undefined?'':JSON.stringify(body));
 return {dir,service,call};
}

// Declares a 6 MiB body but sends only 64 KiB: a server that buffers before authenticating never answers.
function partialUpload(base,path,headers={}){
 return new Promise((resolvePromise,reject)=>{
  const request=http.request(new URL(path,base),{method:'POST',headers:{'content-type':'application/json','content-length':String(6*1024*1024-1),...headers}});
  const timer=setTimeout(()=>{request.destroy();resolvePromise({status:'no_response_before_body_complete'});},3000);
  request.on('response',response=>{
   clearTimeout(timer);const chunks=[];response.on('data',chunk=>chunks.push(chunk));
   response.on('end',()=>{request.destroy();resolvePromise({status:response.statusCode,body:Buffer.concat(chunks).toString('utf8')});});
  });
  request.on('error',error=>{clearTimeout(timer);reject(error);});
  request.write('{"contentBase64":"'+'A'.repeat(64*1024));
 });
}

test('S12a: large-body routes reject anonymous and wrong-role clients before the body is buffered',async()=>{
 const h=shared,bearer=role=>({authorization:'Bearer '+h.principal(role).token});
 const cases=[
  [h.audit.url,'/api/governance/documents',{},401],[h.audit.url,'/api/governance/documents',bearer('auditor'),403],
  [h.audit.url,'/api/governance/bundles',{},401],[h.vault.url,'/api/governance/documents',{},401],
  [h.vault.url,'/api/governance/documents',bearer('auditor'),403],[h.vault.url,'/api/ingest/otlp',bearer('auditor'),403],
  [h.vault.url,'/internal/complete',bearer('agent'),403],[h.vault.url,`/internal/assistance/runs/${randomUUID()}/result`,{},401],
 ];
 for(const [base,path,headers,status] of cases){
  const response=await partialUpload(base,path,headers);
  assert.equal(response.status,status,`${base===h.audit.url?'audit':'vault'} ${path}`);
 }
 // An authorized upload through the gateway still works (the gateway asks the vault before buffering).
 assert.equal((await h.api('/api/governance/systems',{role:'reviewer',body:system})).status,200);
 const bytes=randomBytes(3*1024*1024),saved=await h.api('/api/governance/documents',{role:'reviewer',body:input('large-upload',bytes)});
 assert.equal(saved.status,200,JSON.stringify(saved.body));assert.equal(saved.body.sha256,sha(bytes));
});

test('S12b: run-scoped assistance tokens are compared before verified replay and before body parsing',async t=>{
 const h=fixture(t),store=h.service.store,id=randomUUID(),token=()=>`esr_${id}.${randomBytes(32).toString('base64url')}`,good=token(),bad=token();
 const run={id,packageId:'missing-package',state:'queued',credentialHash:digest(good)};
 store.transaction(()=>store.put({id:'synthetic-run',tenant:'alpha'},'assistance_run',id,run));
 let replays=0;const verifiedRows=store.verifiedRows.bind(store);store.verifiedRows=(...args)=>{replays++;return verifiedRows(...args);};
 const internal=(credential,operation,body)=>h.service.handle(body===undefined?'GET':'POST',new URL(`http://local/internal/assistance/runs/${id}/${operation}`),
  {authorization:'Bearer '+credential},body??'');
 await assert.rejects(internal(bad,'package'),error=>error.status===401);
 await assert.rejects(internal(bad,'result','{not json'),error=>error.status===401,'authentication precedes JSON parsing');
 const resultUrl=new URL(`http://local/internal/assistance/runs/${id}/result`);
 assert.throws(()=>h.service.preauthorize('POST',resultUrl,{authorization:'Bearer '+bad}),error=>error.status===401);
 assert.equal(replays,0,'a wrong token costs no signed-history replay');
 await assert.rejects(internal(good,'package'),error=>error.status===404,'the authentic token proceeds to the verified run');
 assert.ok(replays>0);
 // A forged projection cannot authenticate a token that the signed run does not bind.
 const forged={...run,credentialHash:digest(bad)};
 store.db.prepare("UPDATE objects SET body=? WHERE type='assistance_run' AND id=?").run(JSON.stringify(forged),id);
 await assert.rejects(internal(bad,'package'),error=>error.status===409);
});

test('S12c: malformed percent-encoding in a path is a 400 client error, not a storage failure',async t=>{
 const h=fixture(t),paths=['/api/actions/%E0%A4%A','/api/cases/%ZZ/review-context','/api/assistance/runs/%E0'];
 for(const path of paths)await assert.rejects(h.call(path,undefined,1),error=>error.status===400&&/퍼센트 인코딩/.test(error.message),path);
 for(const base of [shared.vault.url,shared.audit.url])for(const path of paths){
  const response=await fetch(base+path,{headers:{authorization:'Bearer '+shared.principal('auditor').token}});
  assert.equal(response.status,400,`${base} ${path}`);assert.doesNotMatch((await response.json()).error,/저장소/);
 }
});

test('S12d: document files written by a rolled-back transaction are removed; committed files stay',async t=>{
 const h=fixture(t),orphan=Buffer.from('bytes of a rolled-back intake'),committed=Buffer.from('bytes of a committed intake');
 await h.call('/api/governance/systems',system);await h.call('/api/governance/documents',input('kept',committed));
 h.service.store.db.exec(`CREATE TRIGGER fail_intake BEFORE INSERT ON governance_documents WHEN NEW.id='failing'
  BEGIN SELECT RAISE(ABORT,'synthetic failure'); END`);
 await assert.rejects(h.call('/api/governance/documents',input('failing',orphan)),/synthetic failure/);
 assert.equal(existsSync(documentFile(h.dir,'alpha',sha(orphan))),false,'the rolled-back intake leaves no encrypted file');
 await assert.rejects(h.call('/api/governance/documents',input('failing',committed)),/synthetic failure/);
 assert.equal(existsSync(documentFile(h.dir,'alpha',sha(committed))),true,'a rollback never removes a file that existed before');
 const detail=await h.call('/api/governance/documents/kept');assert.equal(detail.verification.status,'hash_verified_and_retrievable');
});

test('S12d: Store rollback actions run only for the level that rolls back and are dropped on commit',t=>{
 const h=fixture(t),store=h.service.store,log=[];
 store.transaction(()=>store.onRollback(()=>log.push('committed')));
 assert.throws(()=>store.transaction(()=>{
  store.onRollback(()=>log.push('outer'));store.transaction(()=>store.onRollback(()=>log.push('inner-released')));
  assert.throws(()=>store.transaction(()=>{store.onRollback(()=>log.push('inner-rolled-back'));throw Error('inner');}),/inner/);
  assert.deepEqual(log,['inner-rolled-back']);throw Error('outer');
 }),/outer/);
 assert.deepEqual(log,['inner-rolled-back','inner-released','outer']);
 assert.throws(()=>store.onRollback(()=>{}),/active transaction/);
});
