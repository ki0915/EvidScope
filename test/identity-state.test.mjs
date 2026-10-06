import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Store} from '../src/store.mjs';
import {digest,canonical,makeCheckpoint} from '../src/crypto.mjs';
import {createIdentityState} from '../src/identity-state.mjs';

function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-identity-state-')),key=generateKeyPairSync('ed25519').privateKey,store=new Store(dir,key);
 t.after(()=>{store.close();rmSync(dir,{recursive:true,force:true});});
 const work={rows:0,anchors:0,chunks:0,maxChunk:0};
 const observed={publicKey:store.publicKey,db:{exec:sql=>store.db.exec(sql),prepare(sql){
  const statement=store.db.prepare(sql);
  return {
   get(...args){const result=statement.get(...args);if(sql.includes('AND seq=?')&&!sql.includes('substr'))work.anchors++;if(sql.includes('substr')){work.chunks++;work.maxChunk=Math.max(work.maxChunk,result?.chunk?.length||0);}return result;},
   *iterate(...args){for(const row of statement.iterate(...args)){work.rows++;yield row;}},
  };
 }}};
 const binding=(id='alice',tenant='alpha')=>({id,tenant});
 const put=(epoch,disabled,id='alice',tenant='alpha')=>store.transaction(()=>store.put({id:'admin',tenant},'identity_access',id,{id,epoch,disabled}));
 const append=(payload={},tenant='alpha')=>store.transaction(()=>store.append(tenant,'audit_access',payload,'tester'));
 const checkpoint=(tenant='alpha')=>store.db.prepare('SELECT body FROM checkpoints WHERE tenant=?').get(tenant)?.body;
 const replace=(seq,transform,tenant='alpha')=>{const row=JSON.parse(store.db.prepare('SELECT body FROM ledger WHERE tenant=? AND seq=?').get(tenant,seq).body);store.db.prepare('UPDATE ledger SET body=? WHERE tenant=? AND seq=?').run(canonical(transform(row)),tenant,seq);};
 return {store,key,observed,work,binding,put,append,checkpoint,replace,state:createIdentityState(observed)};
}

test('signed access state is tenant scoped, ignores unsigned projections and cannot be mutated by its caller',t=>{
 const h=fixture(t),a=h.binding();assert.deepEqual(h.state(a),{id:'alice',epoch:0,disabled:false});
 h.put(1,true);h.put(2,false,'alice','beta');
 h.store.db.prepare('UPDATE objects SET body=? WHERE tenant=?').run(JSON.stringify({id:'alice',epoch:99,disabled:false}),'alpha');
 const value=h.state(a);assert.deepEqual(value,{id:'alice',epoch:1,disabled:true});value.disabled=false;
 assert.equal(h.state(a).disabled,true);assert.deepEqual(h.state(h.binding('alice','beta')),{id:'alice',epoch:2,disabled:false});
 assert.deepEqual(h.state(h.binding('unknown')),{id:'unknown',epoch:0,disabled:false});
});

test('initial verification streams bounded chunks; unchanged state and deltas do not rescan historical rows',t=>{
 const h=fixture(t);
 h.store.transaction(()=>{h.store.append('alpha','audit_access',{large:'x'.repeat(300000)},'tester');for(let n=0;n<1000;n++)h.store.append('alpha','audit_access',{n},'tester');});
 h.put(1,false);assert.equal(h.state(h.binding()).epoch,1);assert.equal(h.work.rows,1002);assert.ok(h.work.chunks>=5);assert.ok(h.work.maxChunk<=65536);
 Object.assign(h.work,{rows:0,anchors:0,chunks:0});h.state(h.binding());h.state(h.binding('other'));assert.equal(h.work.rows,0);assert.equal(h.work.anchors,2);assert.equal(h.work.chunks,0);
 h.append({new:1});h.append({new:2});h.put(2,true);assert.equal(h.state(h.binding()).disabled,true);assert.equal(h.work.rows,3);
 h.work.rows=0;const restarted=createIdentityState(h.observed);assert.equal(restarted(h.binding()).disabled,true);assert.equal(h.work.rows,1005);
});

test('tampered suffix fails before any tentative identity state is published',t=>{
 const h=fixture(t);h.put(1,false);assert.equal(h.state(h.binding()).epoch,1);h.put(2,true);h.append({marker:'original'});
 const good=h.store.db.prepare('SELECT body FROM ledger WHERE tenant=? AND seq=?').get('alpha',3).body;
 h.store.db.exec('DROP TRIGGER immutable_update');h.replace(3,row=>({...row,payload:{marker:'tampered'}}));
 assert.throws(()=>h.state(h.binding()),/digest/);
 h.store.db.prepare('UPDATE ledger SET body=? WHERE tenant=? AND seq=?').run(good,'alpha',3);
 h.work.rows=0;assert.equal(h.state(h.binding()).epoch,2);assert.equal(h.work.rows,2,'failed extension must not advance the trusted cache');
});

test('same-checkpoint anchor tampering is detected',t=>{
 const h=fixture(t);h.put(1,true);h.state(h.binding());h.store.db.exec('DROP TRIGGER immutable_update');h.replace(1,row=>({...row,payload:{...row.payload,disabled:false}}));
 assert.throws(()=>h.state(h.binding()),/digest/);
});

test('a valid older signed checkpoint cannot roll back an established cache',t=>{
 const h=fixture(t);h.put(1,false);const earlier=h.checkpoint();h.state(h.binding());h.put(2,true);h.state(h.binding());
 h.store.db.exec('DROP TRIGGER immutable_delete');h.store.db.prepare('DELETE FROM ledger WHERE tenant=? AND seq>?').run('alpha',1);h.store.db.prepare('UPDATE checkpoints SET body=? WHERE tenant=?').run(earlier,'alpha');
 assert.throws(()=>h.state(h.binding()),/rollback/);
});

test('a differently signed head at the same count cannot replace an established cache',t=>{
 const h=fixture(t);h.put(1,true);h.state(h.binding());h.store.db.exec('DROP TRIGGER immutable_update');
 const row=JSON.parse(h.store.db.prepare('SELECT body FROM ledger WHERE tenant=?').get('alpha').body);row.payload.disabled=false;const hash=digest(row);
 h.store.db.prepare('UPDATE ledger SET body=?,hash=? WHERE tenant=?').run(canonical(row),hash,'alpha');h.store.db.prepare('UPDATE checkpoints SET body=? WHERE tenant=?').run(JSON.stringify(makeCheckpoint('alpha',1,hash,h.key)),'alpha');
 assert.throws(()=>h.state(h.binding()),/replacement/);
});

test('checkpoint tenant changes and missing checkpoints are rejected',t=>{
 const h=fixture(t);h.put(1,true);h.put(1,false,'alice','beta');h.state(h.binding());const original=h.checkpoint();
 h.store.db.prepare('UPDATE checkpoints SET body=? WHERE tenant=?').run(h.checkpoint('beta'),'alpha');assert.throws(()=>h.state(h.binding()),/tenant/);
 h.store.db.prepare('UPDATE checkpoints SET body=? WHERE tenant=?').run(original,'alpha');h.store.db.prepare('DELETE FROM checkpoints WHERE tenant=?').run('alpha');assert.throws(()=>h.state(h.binding()),/checkpoint/);
});

test('SQL tenant relocation and sequence gaps cannot authenticate signed records under another scope',t=>{
 const h=fixture(t);h.put(1,true);h.store.db.exec('DROP TRIGGER immutable_update');
 h.store.db.prepare('UPDATE ledger SET tenant=? WHERE tenant=?').run('other','alpha');h.store.db.prepare('UPDATE checkpoints SET tenant=? WHERE tenant=?').run('other','alpha');
 assert.throws(()=>h.state(h.binding('alice','other')),/tenant/);
 h.store.db.prepare('UPDATE ledger SET tenant=? WHERE tenant=?').run('alpha','other');h.store.db.prepare('UPDATE checkpoints SET tenant=? WHERE tenant=?').run('alpha','other');h.state(h.binding());h.append();h.append();
 h.store.db.prepare('UPDATE ledger SET seq=? WHERE tenant=? AND seq=?').run(0,'alpha',2);assert.throws(()=>h.state(h.binding()),/sequence/);
});

test('cached anchor SQL sequence binding and missing anchors are rejected',t=>{
 const h=fixture(t);h.put(1,true);h.state(h.binding());h.append();h.store.db.exec('DROP TRIGGER immutable_update');h.replace(1,row=>({...row,seq:9}));
 assert.throws(()=>h.state(h.binding()),/sequence/);h.store.db.exec('DROP TRIGGER immutable_delete');h.store.db.prepare('DELETE FROM ledger WHERE tenant=? AND seq=?').run('alpha',1);assert.throws(()=>h.state(h.binding()),/anchor/);
});

test('restart re-verifies historical bytes while an established cache retains its authenticated state',t=>{
 const h=fixture(t);h.put(1,true);h.append();h.state(h.binding());h.store.db.exec('DROP TRIGGER immutable_update');h.replace(1,row=>({...row,payload:{...row.payload,disabled:false}}));
 assert.equal(h.state(h.binding()).disabled,true,'cached access state does not trust changed historical bytes');
 assert.throws(()=>createIdentityState(h.observed)(h.binding()),/digest/);
});

test('oversized or malformed signed access records fail closed',t=>{
 const h=fixture(t);h.store.transaction(()=>h.store.append('alpha','identity_access',{id:'alice',epoch:1,disabled:true,padding:'x'.repeat(70000)},'admin'));
 assert.throws(()=>h.state(h.binding()),/size limit/);assert.ok(h.work.maxChunk<=65536);
 h.store.transaction(()=>h.store.append('beta','identity_access',{id:'alice',epoch:1,disabled:'false'},'admin'));
 assert.throws(()=>h.state(h.binding('alice','beta')),/Invalid signed/);
});

test('checkpoint failure leaves no open read transaction and state reads can nest in the access-write transaction',t=>{
 const h=fixture(t);h.put(1,false);h.store.transaction(()=>{assert.equal(h.state(h.binding()).epoch,1);h.store.put({id:'admin',tenant:'alpha'},'identity_access','alice',{id:'alice',epoch:2,disabled:true});});assert.equal(h.state(h.binding()).epoch,2);
 const good=h.checkpoint();const bad=JSON.parse(good);bad.signature='invalid';h.store.db.prepare('UPDATE checkpoints SET body=? WHERE tenant=?').run(JSON.stringify(bad),'alpha');
 assert.throws(()=>h.state(h.binding()),/signature/);h.store.db.prepare('UPDATE checkpoints SET body=? WHERE tenant=?').run(good,'alpha');h.append();assert.equal(h.state(h.binding()).disabled,true);
});
