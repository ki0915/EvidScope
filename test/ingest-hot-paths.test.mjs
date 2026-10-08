// Round-5 ingest hot paths (docs/performance.md): the array-free canonical form, cached prepared statements, cached epoch-key
// derivation and the indexes behind the per-batch backlog count and nonce expiry.
import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,randomBytes} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {canonical,payloadCommitment,mac} from '../src/crypto.mjs';
import {Store} from '../src/store.mjs';
import {databaseEpochStore,sealFingerprint} from '../src/event-keys.mjs';
import {decryptEvent,encryptEvent} from '../src/encryption.mjs';
import {createHmac} from 'node:crypto';

// The pre-round-5 implementation, kept here as the reference output.
function reference(v){
 if(v===null||typeof v!=='object')return JSON.stringify(v);
 if(Array.isArray(v))return '['+v.map(reference).join(',')+']';
 return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+reference(v[k])).join(',')+'}';
}
function store(t){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-hot-paths-')),value=new Store(dir,generateKeyPairSync('ed25519').privateKey);
 t.after(()=>{value.close();rmSync(dir,{recursive:true,force:true});});return value;
}

test('canonical: same text as the reference form, including undefined members, sparse arrays, unicode and nesting',()=>{
 const sparse=[1,,3];sparse[6]=null;
 const values=[null,0,-0,1e21,'a"b\\c ',true,[],{},[undefined,()=>1,Symbol('s'),null],{a:undefined,b:[undefined],'é':1,'10':2,'9':3,'':{}},
  sparse,{z:{y:{x:[{w:'v'},[[]]]}}},new Date(0),{toJSON(){return 'x';}},'\ud800',Object.assign(Object.create(null),{k:1}),[[1,[2,[3]]],{}]];
 for(let i=0;i<200;i++){const o={};for(let k=0;k<8;k++)o[randomBytes(3).toString('base64')]=k%3?randomBytes(4).toString('hex'):[k,{n:k}];values.push(o);}
 for(const value of values)assert.equal(canonical(value),reference(value));
});

test('cached statements: reused per SQL text; projection writes are refused outside projectionMutation',t=>{
 const s=store(t);
 assert.equal(s.cachedStatement('SELECT 1 AS one'),s.cachedStatement('SELECT 1 AS one'));
 assert.throws(()=>s.projectionStatement("INSERT INTO actions(tenant,id,version) VALUES('alpha','a',1)"),/outside Store.projectionMutation/);
 s.transaction(()=>s.projectionMutation(()=>s.projectionStatement("INSERT INTO actions(tenant,id,version) VALUES(?,?,1)").run('alpha','a')));
 assert.equal(s.db.prepare("SELECT version FROM actions WHERE tenant='alpha' AND id='a'").get().version,1);
 // The mutation clock still sees writes that bypass projectionMutation (prepared, so the authorizer runs), cache or not.
 const before=s.projectionMutationSerial;s.db.prepare("UPDATE actions SET version=2 WHERE tenant='alpha'").run();
 assert.ok(s.projectionMutationSerial>before);
});

test('ingest indexes: the per-batch backlog count and nonce expiry are index searches',t=>{
 const s=store(t),plan=sql=>s.db.prepare('EXPLAIN QUERY PLAN '+sql).all(...(sql.includes('?')?['alpha']:[])).map(row=>row.detail);
 assert.deepEqual(plan('SELECT COUNT(*) n FROM actions WHERE tenant=? AND analyzed<version'),['SEARCH actions USING INDEX actions_pending (tenant=?)']);
 assert.deepEqual(plan('DELETE FROM nonces WHERE expires<?'),['SEARCH nonces USING INDEX nonces_expires (expires<?)']);
});

test('epoch-key cache: a replaced or destroyed epoch secret is never served from cached derived keys',()=>{
 const db=new DatabaseSync(':memory:');
 db.exec(`CREATE TABLE event_key_epochs(tenant TEXT NOT NULL,epoch TEXT NOT NULL,secret BLOB NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(tenant,epoch));
  CREATE TABLE event_key_epoch_tombstones(tenant TEXT NOT NULL,epoch TEXT NOT NULL,destroyed_at TEXT NOT NULL,storage TEXT NOT NULL,
   PRIMARY KEY(tenant,epoch));`);
 const epochs=databaseEpochStore(db),raw='ab'.repeat(32);
 const first=sealFingerprint(epochs,'alpha','2026-11',raw);assert.equal(sealFingerprint(epochs,'alpha','2026-11',raw),first);
 db.prepare("UPDATE event_key_epochs SET secret=? WHERE tenant='alpha'").run(randomBytes(32));
 const second=sealFingerprint(epochs,'alpha','2026-11',raw);assert.notEqual(second,first);
 assert.equal(second,sealFingerprint(databaseEpochStore(db),'alpha','2026-11',raw));
 epochs.destroy('alpha','2026-11');
 assert.throws(()=>epochs.mac('alpha','2026-11','x'),/was destroyed/);
 db.close();
});

test('KeyObject keys: HMACs, commitments and event envelopes are unchanged',()=>{
 assert.equal(mac('secret','1','n','body'),createHmac('sha256','secret').update('1.n.body').digest('hex'));
 const salt=randomBytes(32),value={b:[1,{c:2}],a:'x'};
 assert.equal(payloadCommitment(salt,value),createHmac('sha256',salt).update('evidscope/payload-commitment/v2\0').update(reference(value)).digest('hex'));
 const event={id:'e',actionId:'a',tenant:'alpha',note:'n'.repeat(100)};
 const sealed=encryptEvent(event,'alpha',7,{policy:{version:1},retainUntil:'2026-12-01T00:00:00.000Z',keyEpoch:'2026-12'});
 assert.deepEqual(decryptEvent(sealed.payload,sealed.material),event);
});
