// In-process vault helpers for the event-key tests (round 2, audit S3). createService has the same signature on the base commit.
import assert from 'node:assert/strict';
import {createPrivateKey,generateKeyPairSync,randomUUID} from 'node:crypto';
import {mkdirSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {gunzipSync} from 'node:zlib';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createService} from '../src/service.mjs';
import {mac} from '../src/crypto.mjs';

const token=s=>s.repeat(40).slice(0,40);
// One agent source, a reviewer and an admin (two people for retention plans). cleanup=false leaves dir for a later reopen.
export function vault(t,{dir=mkdtempSync(join(tmpdir(),'evidscope-s3-')),key=generateKeyPairSync('ed25519').privateKey,options={},cleanup=true}={}){
 const principals=[{id:'alpha-agent',tenant:'alpha',role:'source',kind:'agent',token:token('a1'),hmacSecret:token('h1')},
  {id:'alpha-reviewer',tenant:'alpha',role:'reviewer',token:token('r1')},{id:'alpha-admin',tenant:'alpha',role:'admin',token:token('m1')}];
 const service=createService({dataDir:dir,key,config:{principals},...options});
 t.after(()=>{try{service.store.close();}catch{}if(cleanup)rmSync(dir,{recursive:true,force:true});});
 const principal=id=>principals.find(p=>p.id===id);
 const call=async(path,id,body)=>{
  try{return {status:200,body:await service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),{authorization:'Bearer '+principal(id).token},
   body===undefined?'':JSON.stringify(body))};}
  catch(error){if(!error.status)throw error;return {status:error.status,body:{error:error.message}};}
 };
 const ingest=async event=>{
  const body=JSON.stringify(event),stamp=String(Date.now()),nonce=randomUUID(),agent=principal('alpha-agent');
  try{return {status:202,body:await service.handle('POST',new URL('/api/ingest','http://local'),{authorization:'Bearer '+agent.token,
   'x-evid-timestamp':stamp,'x-evid-nonce':nonce,'x-evid-signature':mac(agent.hmacSecret,stamp,nonce,body)},body)};}
  catch(error){if(!error.status)throw error;return {status:error.status,body:{error:error.message}};}
 };
 // Two-person retention plan over every eligible event (holds keep the others).
 const erase=async reason=>{
  const plan=(await call('/api/retention/plans','alpha-reviewer',{reason})).body;
  assert.equal((await call(`/api/retention/plans/${plan.id}/approve`,'alpha-admin',{reason:'second person'})).status,200);
  assert.equal((await call(`/api/retention/plans/${plan.id}/execute`,'alpha-admin',{})).status,200);
  return plan;
 };
 return {dir,key,service,store:service.store,principal,call,ingest,erase};
}

// The base-commit vault in test/fixtures/event-keys-base-9177cee.json (see make-event-keys-base-fixture.mjs), restored to a new directory.
export function restoreBaseFixture(t,{dir=mkdtempSync(join(tmpdir(),'evidscope-s3-base-'))}={}){
 const fixture=JSON.parse(readFileSync(new URL('./fixtures/event-keys-base-9177cee.json',import.meta.url),'utf8'));
 mkdirSync(dir,{recursive:true,mode:0o700});writeFileSync(join(dir,'evidence.db'),gunzipSync(Buffer.from(fixture.evidenceDbGzipBase64,'base64')),{mode:0o600});
 t.after(()=>rmSync(dir,{recursive:true,force:true}));
 return {fixture,dir,key:createPrivateKey({key:Buffer.from(fixture.signingKeyPkcs8Base64,'base64'),format:'der',type:'pkcs8'})};
}
