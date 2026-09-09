import {createHash, createHmac, timingSafeEqual, sign, verify} from 'node:crypto';
export function canonical(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  return '{' + Object.keys(v).sort().map(k => JSON.stringify(k)+':'+canonical(v[k])).join(',') + '}';
}
export const digest = v => createHash('sha256').update(typeof v === 'string' ? v : canonical(v)).digest('hex');
export const mac = (key, timestamp, nonce, body) => createHmac('sha256',key).update(`${timestamp}.${nonce}.${body}`).digest('hex');
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
export function verifyBundle(bundle,publicKey,expectedCheckpoint,{chainOnly=false}={}) {
 const cp=bundle.checkpoint;
 if(!cp || cp.format!=='evidscope-checkpoint-v1') throw Error('Missing checkpoint');
 verifyCheckpoint(cp,publicKey);
 if(expectedCheckpoint && canonical(cp)!==canonical(expectedCheckpoint)) throw Error('External checkpoint mismatch: possible rollback');
 let previous='0'.repeat(64),sequence=0;
 for(const row of bundle.records) {
   if(row.seq!==++sequence || row.tenant!==cp.tenant || row.previous!==previous) throw Error('Sequence, tenant or previous hash mismatch');
   const {hash,...record}=row;
   if(digest(record)!==hash) throw Error('Record digest mismatch');
   previous=hash;
 }
 if(sequence!==cp.count || previous!==cp.head) throw Error('Truncated or inconsistent export');
 let disclosedEvents=0,erasedEvents=0;
 if(!chainOnly){
  const disclosures=new Map();for(const d of bundle.disclosures||[]){if(disclosures.has(d.seq))throw Error('Duplicate disclosure');disclosures.set(d.seq,d.event);}
  const erased=new Map();for(const row of bundle.records.filter(r=>r.type==='retention_disposition'))for(const id of row.payload.keyIds||[])erased.set(id,row.seq);
  for(const row of bundle.records.filter(r=>r.type==='event'&&r.payload.format==='evidscope-encrypted-event-v1')){
   if(row.payload.tenant!==row.tenant||row.payload.seq!==row.seq)throw Error('Encrypted event binding mismatch');
   const event=disclosures.get(row.seq);if(erased.has(row.payload.keyId)){
    if(erased.get(row.payload.keyId)<=row.seq||event)throw Error('Invalid erasure order or erased plaintext disclosed');erasedEvents++;
   }else{
    if(!event||digest(event)!==row.payload.payloadHash)throw Error('Missing or altered retained event disclosure');
    if(event.tenant!==row.tenant)throw Error('Disclosure tenant mismatch');disclosedEvents++;disclosures.delete(row.seq);
   }
  }
  if(disclosures.size)throw Error('Unexpected event disclosure');
 }
 return {valid:true,count:sequence,tenant:cp.tenant,rollbackChecked:!!expectedCheckpoint,disclosedEvents,erasedEvents,scope:'Minimized received records; source truth and external effects are separate. Authorized erased content cannot be re-examined.'};
}
