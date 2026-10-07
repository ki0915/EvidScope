import {createHash, createHmac, timingSafeEqual, sign, verify} from 'node:crypto';
import {recordLeaf, verifyBundleTransparency} from './tlog.mjs';
export function canonical(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  return '{' + Object.keys(v).sort().map(k => JSON.stringify(k)+':'+canonical(v[k])).join(',') + '}';
}
export const digest = v => createHash('sha256').update(typeof v === 'string' ? v : canonical(v)).digest('hex');
export const mac = (key, timestamp, nonce, body) => createHmac('sha256',key).update(`${timestamp}.${nonce}.${body}`).digest('hex');
// Event envelopes. v1 commits to sha256(canonical(event)), which anyone holding the ledger can test against guesses even after
// erasure. v2 (round 2, audit S3) commits with HMAC-SHA256 keyed by a random 32-byte salt kept only with the event key, so the
// commitment hides the event once the key and salt are erased. Exports disclose the salt of every retained v2 event.
export const ENCRYPTED_EVENT_V1 = 'evidscope-encrypted-event-v1', ENCRYPTED_EVENT_V2 = 'evidscope-encrypted-event-v2';
export const PAYLOAD_COMMITMENT_V2 = 'evidscope/payload-commitment/v2', COMMITMENT_SALT_BYTES = 32;
export const isEncryptedEvent = payload => payload?.format === ENCRYPTED_EVENT_V1 || payload?.format === ENCRYPTED_EVENT_V2;
// The salt is the HMAC key: always exactly 32 bytes (HMAC treats k and k||0x00 as the same key).
export function payloadCommitment(salt, event) {
  if (!Buffer.isBuffer(salt) || salt.length !== COMMITMENT_SALT_BYTES) throw Error('Payload commitment salt must be 32 bytes');
  return createHmac('sha256', salt).update(PAYLOAD_COMMITMENT_V2 + '\0').update(canonical(event)).digest('hex');
}
// Receipt fingerprints: v1 is sha256(canonical(raw body)); v2 is fp2:<key epoch>:<HMAC tag under that epoch's destroyable key>.
export const RECEIPT_FINGERPRINT = /^(?:[a-f0-9]{64}|fp2:\d{4}-(?:0[1-9]|1[0-2]):[a-f0-9]{64})$/;
export function equal(a,b) { const x=Buffer.from(String(a)),y=Buffer.from(String(b)); return x.length===y.length && timingSafeEqual(x,y); }
export function makeCheckpoint(tenant,count,head,key) {
 const statement={format:'evidscope-checkpoint-v1',tenant,count,head};
 return {...statement,signature:sign(null,Buffer.from(canonical(statement)),key).toString('base64')};
}
export function verifyCheckpoint(cp,publicKey){
 if(!cp||cp.format!=='evidscope-checkpoint-v1')throw Error('Missing checkpoint');
 const statement={format:cp.format,tenant:cp.tenant,count:cp.count,head:cp.head};
 if(!verify(null,Buffer.from(canonical(statement)),publicKey,Buffer.from(cp.signature,'base64')))throw Error('Checkpoint signature invalid');return true;
}
// transparency (opt-in): {require, witnesses, quorum, originBase, maxStalenessSeconds, minimumCheckpoint}; see tlog.mjs.
export function verifyBundle(bundle,publicKey,expectedCheckpoint,{chainOnly=false,transparency}={}) {
 const cp=bundle.checkpoint;
 if(!cp || cp.format!=='evidscope-checkpoint-v1') throw Error('Missing checkpoint');
 verifyCheckpoint(cp,publicKey);
 if(expectedCheckpoint && canonical(cp)!==canonical(expectedCheckpoint)) throw Error('External checkpoint mismatch: possible rollback');
 let previous='0'.repeat(64),sequence=0;const leaves=transparency?[]:null;
 for(const row of bundle.records) {
   if(row.seq!==++sequence || row.tenant!==cp.tenant || row.previous!==previous) throw Error('Sequence, tenant or previous hash mismatch');
   const {hash,...record}=row;
   if(digest(record)!==hash) throw Error('Record digest mismatch');
   previous=hash;if(leaves)leaves.push(recordLeaf(hash));
 }
 if(sequence!==cp.count || previous!==cp.head) throw Error('Truncated or inconsistent export');
 let disclosedEvents=0,erasedEvents=0;
 if(!chainOnly){
  const disclosures=new Map();for(const d of bundle.disclosures||[]){if(disclosures.has(d.seq))throw Error('Duplicate disclosure');disclosures.set(d.seq,d);}
  const erased=new Map();for(const row of bundle.records.filter(r=>r.type==='retention_disposition'))for(const id of row.payload.keyIds||[])erased.set(id,row.seq);
  for(const row of bundle.records.filter(r=>r.type==='event'&&isEncryptedEvent(r.payload))){
   if(row.payload.tenant!==row.tenant||row.payload.seq!==row.seq)throw Error('Encrypted event binding mismatch');
   const v2=row.payload.format===ENCRYPTED_EVENT_V2;
   if(v2&&(row.payload.commitmentAlg!==PAYLOAD_COMMITMENT_V2||!/^[a-f0-9]{64}$/.test(row.payload.payloadCommitment)))throw Error('Unsupported payload commitment');
   const disclosure=disclosures.get(row.seq),event=disclosure?.event;if(erased.has(row.payload.keyId)){
    if(erased.get(row.payload.keyId)<=row.seq||event)throw Error('Invalid erasure order or erased plaintext disclosed');erasedEvents++;
   }else{
    const salt=v2&&typeof disclosure?.salt==='string'&&/^[a-f0-9]{64}$/.test(disclosure.salt)?Buffer.from(disclosure.salt,'hex'):null;
    if(!event||(v2?!salt||payloadCommitment(salt,event)!==row.payload.payloadCommitment:digest(event)!==row.payload.payloadHash))throw Error('Missing or altered retained event disclosure');
    if(event.tenant!==row.tenant)throw Error('Disclosure tenant mismatch');disclosedEvents++;disclosures.delete(row.seq);
   }
  }
  if(disclosures.size)throw Error('Unexpected event disclosure');
 }
 const tlog=transparency?verifyBundleTransparency({bundle,leaves,publicKey,options:transparency}):null;
 const rollbackChecked=!!expectedCheckpoint||!!tlog?.rollbackChecked;
 return {valid:true,count:sequence,tenant:cp.tenant,rollbackChecked,disclosedEvents,erasedEvents,scope:'Minimized received records; source truth and external effects are separate. Authorized erased content cannot be re-examined.',...(tlog?{transparency:tlog}:{})};
}
