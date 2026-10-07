// Event-key epochs (round 2, audit S3). Every v2 event belongs to a per-tenant key epoch: the UTC month of its retainUntil.
// An epoch has one random 32-byte secret. HKDF of that secret gives the key of the receipt fingerprint tags of the epoch's
// events. Destroying the secret, once every event of the epoch is disposed and the month has ended, means a guessed raw body
// can no longer be tested against those receipts.
// The epoch store holds the secrets:
// - database: a table in evidence.db, used when no keystore is configured; it adds hiding after destruction and nothing else.
import {createHmac,hkdfSync,randomBytes} from 'node:crypto';
import {equal,isEncryptedEvent,verifyBundle,ENCRYPTED_EVENT_V2} from './crypto.mjs';

export const EPOCH_PATTERN=/^\d{4}-(?:0[1-9]|1[0-2])$/;
export const EPOCH_DESTROYED='event_key_epoch_destroyed',EPOCH_DESTRUCTION_FORMAT='evidscope-event-key-epoch-destruction-v1';
export const EPOCH_SECRET_BYTES=32;
const FINGERPRINT_INFO='evidscope/event-key-epoch/v1/receipt-fingerprint',FINGERPRINT_TAG='evidscope/receipt-fingerprint/v2\0';
const RAW_FINGERPRINT=/^[a-f0-9]{64}$/,FINGERPRINT_V2=/^fp2:(\d{4}-(?:0[1-9]|1[0-2])):([a-f0-9]{64})$/;
const derive=(secret,info)=>Buffer.from(hkdfSync('sha256',secret,Buffer.alloc(0),Buffer.from(info,'utf8'),32));
const checkEpoch=epoch=>{if(typeof epoch!=='string'||!EPOCH_PATTERN.test(epoch))throw Error('Invalid event-key epoch');return epoch;};

export function epochOfRetainUntil(retainUntil){
 if(typeof retainUntil!=='string'||!Number.isFinite(Date.parse(retainUntil)))throw Error('Invalid retention date for an event-key epoch');
 return checkEpoch(new Date(retainUntil).toISOString().slice(0,7));
}
// v2 envelopes record their epoch; v1 envelopes are filed under the month of their retainUntil in the same way.
export const eventKeyEpoch=payload=>payload.format===ENCRYPTED_EVENT_V2?checkEpoch(payload.keyEpoch):epochOfRetainUntil(payload.retainUntil);
// First instant after the epoch month: from then on no new event can get a retainUntil inside it.
export const epochEnd=epoch=>{const [year,month]=checkEpoch(epoch).split('-').map(Number);return Date.UTC(year,month,1);};

// Operations over an epoch secret; stores differ only in where the secret lives (secret(tenant,epoch) => Buffer|undefined).
function epochOperations(secret){
 const need=(tenant,epoch)=>{const value=secret(tenant,checkEpoch(epoch));if(!value)throw Error(`Event-key epoch ${epoch} is not available`);return value;};
 return {
  available:(tenant,epoch)=>EPOCH_PATTERN.test(epoch)&&!!secret(tenant,epoch),
  mac:(tenant,epoch,text)=>createHmac('sha256',derive(need(tenant,epoch),FINGERPRINT_INFO)).update(text).digest('hex'),
 };
}

// Secrets in evidence.db. mutate wraps writes (Store.projectionMutation). Old read-only snapshots may lack the tables.
export function databaseEpochStore(db,{mutate=fn=>fn()}={}){
 let ready=false;
 const tables=()=>ready||(ready=!!db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='event_key_epochs'").get());
 const secret=(tenant,epoch)=>{
  if(!tables())return undefined;const row=db.prepare('SELECT secret FROM event_key_epochs WHERE tenant=? AND epoch=?').get(tenant,epoch);
  return row?Buffer.from(row.secret):undefined;
 };
 const destroyed=(tenant,epoch)=>tables()&&!!db.prepare('SELECT 1 FROM event_key_epoch_tombstones WHERE tenant=? AND epoch=?').get(tenant,epoch);
 return {kind:'database',...epochOperations(secret),destroyed,
  ensure(tenant,epoch){
   checkEpoch(epoch);if(secret(tenant,epoch))return;
   if(destroyed(tenant,epoch))throw Error(`Event-key epoch ${epoch} was destroyed; it cannot take new events`);
   mutate(()=>db.prepare('INSERT INTO event_key_epochs VALUES(?,?,?,?)').run(tenant,epoch,randomBytes(EPOCH_SECRET_BYTES),new Date().toISOString()));
  },
  destroy(tenant,epoch,{at=new Date().toISOString()}={}){
   mutate(()=>{
    const deleted=db.prepare('DELETE FROM event_key_epochs WHERE tenant=? AND epoch=?').run(tenant,checkEpoch(epoch)).changes;
    if(deleted!==1)throw Error('Event-key epoch is not stored');
    db.prepare('INSERT INTO event_key_epoch_tombstones VALUES(?,?,?,?)').run(tenant,epoch,at,'database');
   });
  },
  list:tenant=>tables()?db.prepare('SELECT tenant,epoch,created_at AS createdAt FROM event_key_epochs WHERE tenant=? ORDER BY epoch').all(tenant):[],
  tombstones:tenant=>tables()
   ?db.prepare('SELECT tenant,epoch,destroyed_at AS destroyedAt FROM event_key_epoch_tombstones WHERE tenant=? ORDER BY epoch').all(tenant):[],
 };
}

// Receipt fingerprint v2: fp2:<epoch>:HMAC(epoch fingerprint key, tag || sha256 of the canonical raw body). Deterministic while
// the epoch secret exists, so retries stay duplicates; the epoch in the value lets a retry in a later month compare correctly.
export function sealFingerprint(epochs,tenant,epoch,rawDigest){
 if(!RAW_FINGERPRINT.test(rawDigest||''))throw Error('Raw event fingerprint must be a SHA-256 hex digest');
 epochs.ensure(tenant,epoch);return `fp2:${epoch}:${epochs.mac(tenant,epoch,FINGERPRINT_TAG+rawDigest)}`;
}
// 'same' | 'different' | 'unverifiable' (the epoch secret was destroyed, so the stored tag can no longer be compared).
export function compareFingerprint(epochs,tenant,stored,rawDigest){
 const v2=FINGERPRINT_V2.exec(typeof stored==='string'?stored:'');
 if(!v2)return stored===rawDigest?'same':'different';
 if(!epochs.available(tenant,v2[1]))return 'unverifiable';
 return equal(epochs.mac(tenant,v2[1],FINGERPRINT_TAG+rawDigest),v2[2])?'same':'different';
}

// Per epoch of one tenant, from the chain-verified ledger and the epoch store. An epoch can be destroyed once its month has
// ended (no new event can join it) and every event in it, and every retained receipt keyed by it, belongs to a disposed event.
export function epochInventory(store,tenant,{now=Date.now()}={}){
 const bundle=store.rawBundle(tenant);verifyBundle(bundle,store.publicKey,undefined,{chainOnly:true});
 const disposed=new Set(bundle.records.filter(row=>row.type==='retention_disposition').flatMap(row=>row.payload.keyIds||[]));
 const epochs=new Map(),retained=new Set();
 const entry=epoch=>{
  if(!epochs.has(epoch))epochs.set(epoch,{tenant,epoch,retainedEvents:0,disposedEvents:0,retainedFingerprints:0,stored:false,destroyed:false});
  return epochs.get(epoch);
 };
 for(const row of bundle.records)if(row.type==='event'&&isEncryptedEvent(row.payload)){
  const item=entry(eventKeyEpoch(row.payload));if(disposed.has(row.payload.keyId))item.disposedEvents++;else{item.retainedEvents++;retained.add(row.seq);}
 }
 for(const row of bundle.records)if(row.type==='event_receipt'){
  const v2=FINGERPRINT_V2.exec(typeof row.payload?.fingerprint==='string'?row.payload.fingerprint:'');
  if(v2&&retained.has(row.payload.eventSeq))entry(v2[1]).retainedFingerprints++;
 }
 const epochStore=store.eventKeyEpochs();
 for(const {epoch,createdAt} of epochStore.list(tenant))Object.assign(entry(epoch),{stored:true,createdAt});
 for(const {epoch,destroyedAt} of epochStore.tombstones(tenant))Object.assign(entry(epoch),{destroyed:true,destroyedAt});
 for(const row of bundle.records)if(row.type===EPOCH_DESTROYED&&epochs.has(row.payload?.epoch))epochs.get(row.payload.epoch).destructionSeq=row.seq;
 return [...epochs.values()].sort((a,b)=>a.epoch.localeCompare(b.epoch)).map(item=>{
  const periodEnded=now>=epochEnd(item.epoch);
  return {...item,storage:epochStore.kind,periodEnded,destroyable:item.stored&&!item.destroyed&&periodEnded&&!item.retainedEvents&&!item.retainedFingerprints};
 });
}

// Irreversible. Run with the vault stopped: a running vault keeps what it already read in memory.
export function destroyEpoch(store,{tenant,epoch,reason,actor='event-keys-cli',now=Date.now()}){
 checkEpoch(epoch);if(typeof reason!=='string'||!reason.trim()||reason.length>1000)throw Error('A reason (1-1000 characters) is required');
 const destroyedAt=new Date(now).toISOString();
 const result=store.transaction(()=>{
  const item=epochInventory(store,tenant,{now}).find(value=>value.epoch===epoch);
  if(!item?.stored||item.destroyed)throw Error(`Event-key epoch ${tenant}/${epoch} is not stored or was already destroyed`);
  if(!item.periodEnded)throw Error(`Event-key epoch ${epoch} has not ended; new events can still join it`);
  if(item.retainedEvents||item.retainedFingerprints)throw Error(`Event-key epoch ${tenant}/${epoch} still has retained events`);
  const epochStore=store.eventKeyEpochs();
  // Signed first, destroyed second: a failed destruction rolls the record back, and only a failed commit could leave the
  // secret destroyed without its record.
  const record=store.append(tenant,EPOCH_DESTROYED,{format:EPOCH_DESTRUCTION_FORMAT,epoch,storage:epochStore.kind,basis:'all_events_disposed',
   disposedEvents:item.disposedEvents,reason:reason.trim(),destroyedAt},actor);
  epochStore.destroy(tenant,epoch,{at:destroyedAt});
  return {destroyed:true,tenant,epoch,storage:epochStore.kind,disposedEvents:item.disposedEvents,recordSeq:record.seq,destroyedAt};
 });
 store.checkpointAfterErasure?.();
 return result;
}

// Honest /api/integrity summary of commitments, receipt fingerprints and epoch secrets for one tenant's verified records.
export function eventKeyStatus(store,tenant,records){
 const commitments={saltedV2:0,unsaltedV1:0},fingerprints={keyed:0,unkeyed:0},epochs=store.eventKeyEpochs();
 for(const row of records){
  if(row.type==='event'&&isEncryptedEvent(row.payload))commitments[row.payload.format===ENCRYPTED_EVENT_V2?'saltedV2':'unsaltedV1']++;
  if(row.type==='event_receipt')fingerprints[FINGERPRINT_V2.test(row.payload?.fingerprint||'')?'keyed':'unkeyed']++;
 }
 const epochCounts={storage:epochs.kind,stored:epochs.list(tenant).length,destroyed:epochs.tombstones(tenant).length};
 return {commitments,receiptFingerprints:fingerprints,epochs:epochCounts};
}
