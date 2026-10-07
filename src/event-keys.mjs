// Event-key epochs (round 2, audit S3). Every event belongs to a per-tenant key epoch: the UTC month of its retainUntil.
// An epoch has one random 32-byte secret. HKDF of that secret gives the key of the receipt fingerprint tags of the epoch's
// events and, with a keystore, the key that wraps each event's key || salt. Destroying the secret, once every event of the
// epoch is disposed and the month has ended, means a guessed raw body can no longer be tested against those receipts and,
// with a keystore, that no copy of evidence.db or vault backup can open the epoch's event keys any more.
// The epoch store holds the secrets:
// - database: tables in evidence.db, used when no keystore is configured. Event keys stay unwrapped; older copies of the
//   database keep the secrets.
// - keystore (src/event-keystore.mjs): files outside DATA_DIR sealed by the data key; event keys are stored wrapped.
// Epoch store interface, also the hook for a KMS or the signer process to hold the secrets (calls are synchronous because
// Store.transaction is): kind, wrapsEventKeys, available, present, ensure, destroyed, destroy, list, tombstones, mac, wrap, unwrap.
import {createCipheriv,createDecipheriv,createHmac,hkdfSync,randomBytes} from 'node:crypto';
import {canonical,equal,isEncryptedEvent,verifyBundle,ENCRYPTED_EVENT_V2} from './crypto.mjs';
import {eventKeyMaterialBytes,openEvent} from './encryption.mjs';

export const EPOCH_PATTERN=/^\d{4}-(?:0[1-9]|1[0-2])$/;
export const EPOCH_DESTROYED='event_key_epoch_destroyed',EPOCH_DESTRUCTION_FORMAT='evidscope-event-key-epoch-destruction-v1';
export const EPOCH_SECRET_BYTES=32;
const FINGERPRINT_INFO='evidscope/event-key-epoch/v1/receipt-fingerprint',FINGERPRINT_TAG='evidscope/receipt-fingerprint/v2\0';
const RAW_FINGERPRINT=/^[a-f0-9]{64}$/,FINGERPRINT_V2=/^fp2:(\d{4}-(?:0[1-9]|1[0-2])):([a-f0-9]{64})$/;
const WRAP_INFO='evidscope/event-key-epoch/v1/event-key-wrap',WRAPPED_FORMAT='evidscope-wrapped-event-key-v1';
// Wrapped key: 'EKW1' || material length in 32-byte units || iv || ciphertext || tag. Lengths 65 and 97 never equal a raw
// key (32 for v1, 64 for v2 key || salt), so the stored length alone tells wrapped from raw keys.
const WRAP_MAGIC=Buffer.from('EKW1'),WRAP_OVERHEAD=WRAP_MAGIC.length+1+12+16;
const derive=(secret,info)=>Buffer.from(hkdfSync('sha256',secret,Buffer.alloc(0),Buffer.from(info,'utf8'),32));
export const checkEpoch=epoch=>{if(typeof epoch!=='string'||!EPOCH_PATTERN.test(epoch))throw Error('Invalid event-key epoch');return epoch;};

export function epochOfRetainUntil(retainUntil){
 if(typeof retainUntil!=='string'||!Number.isFinite(Date.parse(retainUntil)))throw Error('Invalid retention date for an event-key epoch');
 return checkEpoch(new Date(retainUntil).toISOString().slice(0,7));
}
// v2 envelopes record their epoch; v1 envelopes are filed under the month of their retainUntil in the same way.
export const eventKeyEpoch=payload=>payload.format===ENCRYPTED_EVENT_V2?checkEpoch(payload.keyEpoch):epochOfRetainUntil(payload.retainUntil);
// First instant after the epoch month: from then on no new event can get a retainUntil inside it.
export const epochEnd=epoch=>{const [year,month]=checkEpoch(epoch).split('-').map(Number);return Date.UTC(year,month,1);};

// Operations over an epoch secret; stores differ only in where the secret lives (secret(tenant,epoch) => Buffer|undefined).
export function epochOperations(secret,destroyed){
 const need=(tenant,epoch)=>{
  const value=secret(tenant,checkEpoch(epoch));if(value)return value;
  throw Error(destroyed(tenant,epoch)?`Event-key epoch ${epoch} was destroyed; its event keys and receipt tags can no longer be opened`
   :`Event-key epoch ${epoch} is not available`);
 };
 return {
  available:(tenant,epoch)=>EPOCH_PATTERN.test(epoch)&&!!secret(tenant,epoch),
  mac:(tenant,epoch,text)=>createHmac('sha256',derive(need(tenant,epoch),FINGERPRINT_INFO)).update(text).digest('hex'),
  wrap(tenant,epoch,aad,plaintext){
   if(!Buffer.isBuffer(plaintext)||!plaintext.length||plaintext.length%32||plaintext.length>255*32)throw Error('Invalid event key material');
   const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',derive(need(tenant,epoch),WRAP_INFO),iv);cipher.setAAD(Buffer.from(canonical(aad)));
   return Buffer.concat([WRAP_MAGIC,Buffer.from([plaintext.length/32]),iv,cipher.update(plaintext),cipher.final(),cipher.getAuthTag()]);
  },
  unwrap(tenant,epoch,aad,blob){
   const bytes=Buffer.from(blob);
   const valid=bytes.length>WRAP_OVERHEAD&&bytes.subarray(0,4).equals(WRAP_MAGIC)&&bytes.length===WRAP_OVERHEAD+bytes[4]*32;
   if(!valid)throw Error('Wrapped event key is malformed');
   const decipher=createDecipheriv('aes-256-gcm',derive(need(tenant,epoch),WRAP_INFO),bytes.subarray(5,17));
   decipher.setAAD(Buffer.from(canonical(aad)));decipher.setAuthTag(bytes.subarray(bytes.length-16));
   return Buffer.concat([decipher.update(bytes.subarray(17,bytes.length-16)),decipher.final()]);
  },
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
 return {kind:'database',wrapsEventKeys:false,...epochOperations(secret,destroyed),destroyed,present:(tenant,epoch)=>!!secret(tenant,epoch),
  ensure(tenant,epoch){
   checkEpoch(epoch);if(secret(tenant,epoch))return;
   if(destroyed(tenant,epoch))throw Error(`Event-key epoch ${epoch} was destroyed; it cannot take new events`);
   mutate(()=>db.prepare('INSERT INTO event_key_epochs VALUES(?,?,?,?)').run(tenant,epoch,randomBytes(EPOCH_SECRET_BYTES),new Date().toISOString()));
  },
  destroy(tenant,epoch,{at=new Date().toISOString()}={}){
   mutate(()=>{
    const deleted=db.prepare('DELETE FROM event_key_epochs WHERE tenant=? AND epoch=?').run(tenant,checkEpoch(epoch)).changes;
    if(deleted!==1)throw Error('Event-key epoch is not stored');
    db.prepare('INSERT OR IGNORE INTO event_key_epoch_tombstones VALUES(?,?,?,?)').run(tenant,epoch,at,'database');
   });
  },
  list:tenant=>tables()?db.prepare('SELECT tenant,epoch,created_at AS createdAt FROM event_key_epochs WHERE tenant=? ORDER BY epoch').all(tenant):[],
  tombstones:tenant=>tables()
   ?db.prepare('SELECT tenant,epoch,destroyed_at AS destroyedAt FROM event_key_epoch_tombstones WHERE tenant=? ORDER BY epoch').all(tenant):[],
  // For the move to a keystore (migrateEventKeys).
  exportAll:()=>tables()?db.prepare('SELECT tenant,epoch,secret,created_at AS createdAt FROM event_key_epochs ORDER BY tenant,epoch').all()
   .map(row=>({...row,secret:Buffer.from(row.secret)})):[],
  allTombstones:()=>tables()?db.prepare('SELECT tenant,epoch,destroyed_at AS destroyedAt FROM event_key_epoch_tombstones ORDER BY tenant,epoch').all():[],
  clear:()=>mutate(()=>{db.prepare('DELETE FROM event_key_epochs').run();db.prepare('DELETE FROM event_key_epoch_tombstones').run();}),
 };
}

// Event keys at rest: raw key material with a database epoch store, wrapped under the event's epoch with a keystore. The AAD
// binds the wrapped key to its tenant, key id, ledger sequence and epoch.
const wrapAad=(payload,epoch)=>({format:WRAPPED_FORMAT,tenant:payload.tenant,keyId:payload.keyId,seq:payload.seq,keyEpoch:epoch});
export const isWrappedEventKey=(payload,stored)=>Buffer.from(stored).length===eventKeyMaterialBytes(payload)+WRAP_OVERHEAD;
export function storedEventKey(epochs,payload,material){
 if(!epochs.wrapsEventKeys)return material;
 const epoch=eventKeyEpoch(payload);epochs.ensure(payload.tenant,epoch);return epochs.wrap(payload.tenant,epoch,wrapAad(payload,epoch),material);
}
export function eventKeyMaterial(epochs,payload,stored){
 const bytes=Buffer.from(stored);if(bytes.length===eventKeyMaterialBytes(payload))return bytes;
 if(!isWrappedEventKey(payload,bytes))throw Error('Event key material has the wrong length');
 if(!epochs.wrapsEventKeys)throw Error('Event key is wrapped by an event keystore that is not configured');
 const epoch=eventKeyEpoch(payload);return epochs.unwrap(payload.tenant,epoch,wrapAad(payload,epoch),bytes);
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
  const periodEnded=now>=epochEnd(item.epoch),presentAgain=!!item.destructionSeq&&epochStore.present(tenant,item.epoch);
  const destroyable=(item.stored&&!item.destroyed||presentAgain)&&periodEnded&&!item.retainedEvents&&!item.retainedFingerprints;
  return {...item,storage:epochStore.kind,periodEnded,presentAgain,destroyable};
 });
}

// Irreversible. Run with the vault stopped: a running vault keeps what it already read in memory.
export function destroyEpoch(store,{tenant,epoch,reason,actor='event-keys-cli',now=Date.now()}){
 checkEpoch(epoch);if(typeof reason!=='string'||!reason.trim()||reason.length>1000)throw Error('A reason (1-1000 characters) is required');
 const destroyedAt=new Date(now).toISOString();
 const result=store.transaction(()=>{
  const item=epochInventory(store,tenant,{now}).find(value=>value.epoch===epoch),epochStore=store.eventKeyEpochs();
  // A keystore destruction whose ledger commit failed (secret gone, no record) is completed by recording it. An epoch the ledger
  // records as destroyed that is present again (a restored keystore backup) is destroyed again under the same record.
  const unrecorded=item?.destroyed&&!item.destructionSeq,present=epochStore.present(tenant,epoch);
  if(!item?.stored&&!unrecorded&&!(item?.destructionSeq&&present))throw Error(`Event-key epoch ${tenant}/${epoch} is not stored or was already destroyed`);
  if(!item.periodEnded)throw Error(`Event-key epoch ${epoch} has not ended; new events can still join it`);
  if(item.retainedEvents||item.retainedFingerprints)throw Error(`Event-key epoch ${tenant}/${epoch} still has retained events`);
  // Signed first, destroyed second: a failed destruction rolls the record back, and only a failed commit could leave the
  // secret destroyed without its record.
  const record=item.destructionSeq?{seq:item.destructionSeq}:store.append(tenant,EPOCH_DESTROYED,{format:EPOCH_DESTRUCTION_FORMAT,epoch,
   storage:epochStore.kind,basis:'all_events_disposed',disposedEvents:item.disposedEvents,reason:reason.trim(),destroyedAt},actor);
  if(item.stored||present)epochStore.destroy(tenant,epoch,{at:destroyedAt});
  return {destroyed:true,tenant,epoch,storage:epochStore.kind,disposedEvents:item.disposedEvents,recordSeq:record.seq,destroyedAt};
 });
 store.checkpointAfterErasure?.();
 return result;
}

// Moves a vault to its configured keystore (startup or scripts/event-keys.mjs migrate). Epoch secrets and tombstones created in
// database mode are imported unchanged, so existing receipt tags keep comparing, and deleted from evidence.db; every raw
// event key that opens its own signed event is wrapped under its epoch. One transaction; the keystore files are written first.
// What a move to the keystore still has to do: raw keys to wrap, epoch secrets and tombstones to move. Tolerates older schemas.
export function pendingEventKeyMigration(db){
 const table=name=>!!db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?").get(name),count=sql=>db.prepare(sql).get().n;
 return {rawKeys:table('event_keys')?count('SELECT COUNT(*) n FROM event_keys WHERE length(key) IN (32,64)'):0,
  epochs:table('event_key_epochs')?count('SELECT COUNT(*) n FROM event_key_epochs')+count('SELECT COUNT(*) n FROM event_key_epoch_tombstones'):0};
}
// importEpochs is false once the first move has completed (moved() marks it in the same transaction).
export function migrateEventKeys(store,{importEpochs=true,moved=()=>{}}={}){
 const epochs=store.eventKeyEpochs(),db=store.db;
 if(!epochs.wrapsEventKeys||!epochs.importEpoch)throw Error('Event-key migration requires a configured event keystore');
 const raw='FROM event_keys WHERE length(key) IN (32,64)',counts={wrappedKeys:0,importedEpochs:0,importedTombstones:0};
 const pending=pendingEventKeyMigration(db),move=importEpochs&&pending.epochs>0;
 if(!pending.rawKeys&&!move){moved();return counts;}
 store.transaction(()=>{
  const database=databaseEpochStore(db,{mutate:fn=>store.projectionMutation(fn)});
  if(move){
   for(const {tenant,epoch,secret,createdAt} of database.exportAll()){epochs.importEpoch(tenant,epoch,secret,createdAt);counts.importedEpochs++;}
   for(const {tenant,epoch,destroyedAt} of database.allTombstones()){epochs.importTombstone(tenant,epoch,destroyedAt);counts.importedTombstones++;}
   database.clear();
  }
  for(const {tenant} of db.prepare(`SELECT DISTINCT tenant ${raw} ORDER BY tenant`).all()){
   const bundle=store.rawBundle(tenant);verifyBundle(bundle,store.publicKey,undefined,{chainOnly:true});
   const payloads=new Map(bundle.records.filter(row=>row.type==='event'&&isEncryptedEvent(row.payload)).map(row=>[row.payload.keyId,row.payload]));
   for(const row of db.prepare(`SELECT key_id,seq,key ${raw} AND tenant=?`).all(tenant)){
    const payload=payloads.get(row.key_id),material=Buffer.from(row.key);
    if(!payload||payload.seq!==row.seq||payload.tenant!==tenant)throw Error('Event key without its signed event');
    openEvent(payload,material);
    const wrapped=storedEventKey(epochs,payload,material);
    store.projectionMutation(()=>db.prepare('UPDATE event_keys SET key=? WHERE tenant=? AND key_id=?').run(wrapped,tenant,row.key_id));
    counts.wrappedKeys++;
   }
  }
  moved();
 });
 // The raw keys and secrets were overwritten in place (secure_delete); older page images leave the WAL here.
 store.checkpointAfterErasure();
 return counts;
}

// Honest /api/integrity summary of event-key storage, commitments, receipt fingerprints and epochs for one tenant.
export function eventKeyStatus(store,tenant,records){
 const commitments={saltedV2:0,unsaltedV1:0},fingerprints={keyed:0,unkeyed:0},keys={wrapped:0,unwrapped:0},epochs=store.eventKeyEpochs();
 // An epoch the ledger records as destroyed must stay gone; a restored keystore backup or database copy would bring it back.
 const back=[...new Set(records.filter(row=>row.type===EPOCH_DESTROYED).map(row=>row.payload?.epoch))]
  .filter(epoch=>EPOCH_PATTERN.test(epoch||'')&&epochs.present(tenant,epoch));
 if(back.length)throw Error(`Destroyed event-key epoch ${back.join(',')} is present again; destroy it again with scripts/event-keys.mjs destroy`);
 // With a keystore, epoch rows in evidence.db are never used and never imported after the first move: only tampering adds them.
 const stray=epochs.wrapsEventKeys?pendingEventKeyMigration(store.db).epochs:0;
 if(stray)throw Error(`evidence.db holds ${stray} event-key epoch row(s) beside its event keystore; they are never imported. Review and delete them`);
 const payloads=new Map();
 for(const row of records){
  if(row.type==='event'&&isEncryptedEvent(row.payload)){
   commitments[row.payload.format===ENCRYPTED_EVENT_V2?'saltedV2':'unsaltedV1']++;payloads.set(row.payload.keyId,row.payload);
  }
  if(row.type==='event_receipt')fingerprints[FINGERPRINT_V2.test(row.payload?.fingerprint||'')?'keyed':'unkeyed']++;
 }
 for(const row of store.db.prepare('SELECT key_id,key FROM event_keys WHERE tenant=?').all(tenant)){
  const payload=payloads.get(row.key_id);if(payload)keys[isWrappedEventKey(payload,row.key)?'wrapped':'unwrapped']++;
 }
 const storage=epochs.wrapsEventKeys?keys.unwrapped?'keystore_migration_pending':'keystore_wrapped':'same_database_unwrapped';
 const epochCounts={storage:epochs.kind,stored:epochs.list(tenant).length,destroyed:epochs.tombstones(tenant).length};
 return {storage,keys,commitments,receiptFingerprints:fingerprints,epochs:epochCounts};
}
