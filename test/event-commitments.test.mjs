// Round 2, audit S3: hiding payload commitments and keyed receipt fingerprints.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHmac,generateKeyPairSync} from 'node:crypto';
import {canonical,digest,makeCheckpoint,verifyBundle} from '../src/crypto.mjs';
import {validateEvent} from '../src/model.mjs';
import {vault} from './event-key-vault.mjs';

const later=ms=>new Promise(done=>setTimeout(done,ms));

// Fails on the base commit (9177cee): its ledger keeps sha256(canonical(event)) and sha256(raw body) after erasure.
test('an erased low-entropy event cannot be confirmed from the signed ledger or an export; retained events still verify',async t=>{
 const v=vault(t),dictionary=Array.from({length:16},(_,n)=>`status-${n}`),occurredAt=new Date().toISOString();
 const secret={id:'s3-secret',actionId:'s3-erase',traceId:'s3-trace',kind:'intent',occurredAt,note:dictionary[11]};
 const kept={id:'s3-kept',actionId:'s3-keep',traceId:'s3-trace',kind:'intent',occurredAt,note:dictionary[4]};
 assert.equal((await v.call('/api/retention/policy','alpha-reviewer',{retentionSeconds:1,purpose:'S3 regression',reason:'synthetic only'})).status,200);
 for(const event of [secret,kept])assert.equal((await v.ingest(event)).status,202);
 assert.equal((await v.call('/api/retention/holds','alpha-reviewer',{scope:'s3-keep',reason:'keep one event retained'})).status,200);
 await later(1100);
 assert.equal((await v.erase('erase the low-entropy event')).items.length,1);
 const bundle=(await v.call('/api/export','alpha-reviewer')).body,result=verifyBundle(bundle,v.store.publicKey);
 assert.equal(result.erasedEvents,1);assert.equal(result.disclosedEvents,1);assert.equal(bundle.disclosures[0].event.note,kept.note);
 // The attacker holds the export (the same rows as the ledger table) and knows every field of the erased event except its note.
 const erasedKeys=new Set(bundle.records.filter(row=>row.type==='retention_disposition').flatMap(row=>row.payload.keyIds));
 const row=bundle.records.find(r=>r.type==='event'&&erasedKeys.has(r.payload.keyId));
 const receipt=bundle.records.find(r=>r.type==='event_receipt'&&r.payload.eventSeq===row.seq).payload,recordedAt=Date.parse(row.recordedAt),confirmed=[];
 for(const note of dictionary){
  const raw={...secret,note},shape=validateEvent(raw,v.principal('alpha-agent'));
  if(receipt.fingerprint===digest(raw))confirmed.push(['receipt fingerprint',note]);
  for(const fingerprint of new Set([digest(raw),receipt.fingerprint]))for(let ms=recordedAt;ms>=recordedAt-3000;ms--){
   if(row.payload.payloadHash===digest({...shape,receivedAt:new Date(ms).toISOString(),fingerprint}))confirmed.push(['payload commitment',note]);
  }
 }
 assert.deepEqual(confirmed,[]);
});

test('v2 envelopes: per-event salt, HMAC commitment recorded with its algorithm, salt disclosed only for retained events',async t=>{
 const v=vault(t),occurredAt=new Date().toISOString(),tag='evidscope/payload-commitment/v2\0';
 for(const id of ['twin-a','twin-b'])assert.equal((await v.ingest({id,actionId:'twins',traceId:'twins',kind:'intent',occurredAt,note:'same'})).status,202);
 const bundle=v.store.bundle('alpha'),rows=bundle.records.filter(row=>row.type==='event');
 for(const row of rows){
  assert.equal(row.payload.format,'evidscope-encrypted-event-v2');assert.equal(row.payload.commitmentAlg,'evidscope/payload-commitment/v2');
  assert.equal(row.payload.payloadHash,undefined);assert.match(row.payload.payloadCommitment,/^[a-f0-9]{64}$/);
  assert.equal(row.payload.keyEpoch,row.payload.retainUntil.slice(0,7));
  const disclosure=bundle.disclosures.find(item=>item.seq===row.seq);assert.match(disclosure.salt,/^[a-f0-9]{64}$/);
  const expected=createHmac('sha256',Buffer.from(disclosure.salt,'hex')).update(tag+canonical(disclosure.event)).digest('hex');
  assert.equal(row.payload.payloadCommitment,expected);
  const stored=v.store.db.prepare('SELECT key FROM event_keys WHERE tenant=? AND key_id=?').get('alpha',row.payload.keyId).key;
  assert.equal(Buffer.from(stored).length,64);assert.equal(Buffer.from(stored).subarray(32).toString('hex'),disclosure.salt);
 }
 // Identical bodies (apart from their ids) do not share a commitment: the salt hides equality too.
 assert.notEqual(rows[0].payload.payloadCommitment,rows[1].payload.payloadCommitment);
 assert.equal(verifyBundle(bundle,v.store.publicKey).disclosedEvents,2);
 const tampered=(mutate,pattern)=>{const copy=structuredClone(bundle);mutate(copy);assert.throws(()=>verifyBundle(copy,v.store.publicKey),pattern);};
 tampered(b=>{b.disclosures[0].salt=b.disclosures[1].salt;},/Missing or altered retained event disclosure/);
 tampered(b=>{delete b.disclosures[0].salt;},/Missing or altered retained event disclosure/);
 tampered(b=>{b.disclosures[0].salt=b.disclosures[0].salt.toUpperCase();},/Missing or altered retained event disclosure/);
 tampered(b=>{b.disclosures[0].event.note='other';},/Missing or altered retained event disclosure/);
 tampered(b=>{b.disclosures.push({...b.disclosures[0],seq:999});},/Unexpected event disclosure/);
 // A row signed with an unknown commitment algorithm is refused instead of being checked as v1.
 const {privateKey,publicKey}=generateKeyPairSync('ed25519'),record={...rows[0],seq:1,previous:'0'.repeat(64)};delete record.hash;
 record.payload={...record.payload,seq:1,commitmentAlg:'sha256'};
 const hash=digest(record),forged={records:[{...record,hash}],checkpoint:makeCheckpoint('alpha',1,hash,privateKey),disclosures:[]};
 assert.throws(()=>verifyBundle(forged,publicKey),/Unsupported payload commitment/);
});

test('an erased v2 event keeps verifying without its salt, and disclosing its plaintext or salt afterwards is refused',async t=>{
 const v=vault(t);
 assert.equal((await v.call('/api/retention/policy','alpha-reviewer',{retentionSeconds:1,purpose:'S3',reason:'synthetic only'})).status,200);
 assert.equal((await v.ingest({id:'gone',actionId:'gone',traceId:'gone',kind:'intent',occurredAt:new Date().toISOString(),note:'x'})).status,202);
 const before=v.store.bundle('alpha');await later(1100);await v.erase('expired');
 const after=v.store.bundle('alpha');assert.deepEqual(after.disclosures,[]);assert.equal(verifyBundle(after,v.store.publicKey).erasedEvents,1);
 const leaked=structuredClone(after);leaked.disclosures=[before.disclosures[0]];
 assert.throws(()=>verifyBundle(leaked,v.store.publicKey),/erased plaintext disclosed/);
 // The earlier export still verifies on its own: erasure cannot revoke copies that were already handed out.
 assert.equal(verifyBundle(before,v.store.publicKey).disclosedEvents,1);
});
