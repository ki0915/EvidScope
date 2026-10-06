import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,randomUUID} from 'node:crypto';
import {existsSync,mkdtempSync,readFileSync,rmSync,statSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createService} from '../src/service.mjs';
import {mac} from '../src/crypto.mjs';

// S4: a retention erasure must not leave the destroyed event key (or the plaintext projection)
// in SQLite free space or in older WAL frames while the vault keeps running.
test('retention erasure leaves no event key bytes or plaintext in evidence.db or its WAL',async t=>{
 const dir=mkdtempSync(join(tmpdir(),'evidscope-erasure-')),token=s=>s.repeat(40).slice(0,40);
 const principals=[{id:'alpha-tool',tenant:'alpha',role:'source',kind:'tool',token:token('t1'),hmacSecret:token('h1')},{id:'alpha-reviewer',tenant:'alpha',role:'reviewer',token:token('r1')},{id:'alpha-admin',tenant:'alpha',role:'admin',token:token('m1')}];
 const service=createService({dataDir:dir,key:generateKeyPairSync('ed25519').privateKey,config:{principals}});
 t.after(()=>{try{service.store.close();}catch{}rmSync(dir,{recursive:true,force:true});});
 const principal=id=>principals.find(p=>p.id===id);
 const call=(path,id,body)=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),{authorization:'Bearer '+principal(id).token},body===undefined?'':JSON.stringify(body));
 await call('/api/retention/policy','alpha-reviewer',{retentionSeconds:1,purpose:'synthetic erasure test',reason:'S4 regression'});
 const marker='ERASURE-MARKER-900101-1234567',body=JSON.stringify({id:'e1',kind:'execution',occurredAt:new Date().toISOString(),traceId:'t',actionId:'a1',status:'success',note:marker});
 const stamp=String(Date.now()),nonce=randomUUID(),tool=principal('alpha-tool');
 const accepted=await service.handle('POST',new URL('/api/ingest','http://local'),{authorization:'Bearer '+tool.token,'x-evid-timestamp':stamp,'x-evid-nonce':nonce,'x-evid-signature':mac(tool.hmacSecret,stamp,nonce,body)},body);
 assert.equal(accepted.accepted,true);
 const db=service.store.db,eventKey=Buffer.from(db.prepare('SELECT key FROM event_keys WHERE tenant=?').get('alpha').key);assert.equal(eventKey.length,32);
 // Move the key page into the main file while older frames stay in the WAL (as a running vault would).
 db.prepare('PRAGMA wal_checkpoint(PASSIVE)').get();
 const files=[join(dir,'evidence.db'),join(dir,'evidence.db-wal')];
 const present=needle=>files.map(file=>existsSync(file)&&readFileSync(file).includes(needle));
 assert.ok(present(eventKey).some(Boolean),'precondition: the live event key is on disk');
 assert.ok(present(Buffer.from(marker)).some(Boolean),'precondition: the live plaintext projection is on disk');
 await new Promise(done=>setTimeout(done,1100));
 const plan=await call('/api/retention/plans','alpha-reviewer',{reason:'expired synthetic event'});
 await call(`/api/retention/plans/${plan.id}/approve`,'alpha-admin',{reason:'second person'});
 const disposition=await call(`/api/retention/plans/${plan.id}/execute`,'alpha-admin',{});
 assert.deepEqual(disposition.keyIds,[plan.items[0].keyId]);assert.equal(disposition.physicalMediaErasure,'not_verified');
 assert.equal(db.prepare('SELECT COUNT(*) n FROM event_keys').get().n,0);
 // The vault is still open: no close-time checkpoint helps here.
 assert.deepEqual(present(eventKey),[false,false],'erased event key bytes remain in evidence.db / WAL');
 assert.deepEqual(present(Buffer.from(marker)),[false,false],'erased plaintext projection remains in evidence.db / WAL');
 if(existsSync(files[1]))assert.equal(statSync(files[1]).size,0,'WAL is truncated after erasure');
 const integrity=await call('/api/integrity','alpha-reviewer');assert.equal(integrity.valid,true,integrity.error);
});
