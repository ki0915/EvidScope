import {DatabaseSync,constants as sqlite} from 'node:sqlite';
import {mkdirSync} from 'node:fs';
import {join} from 'node:path';
import {createPublicKey,createHash} from 'node:crypto';
import {canonical,digest,makeCheckpoint,verifyBundle,verifyCheckpoint,isEncryptedEvent,RECEIPT_FINGERPRINT} from './crypto.mjs';
import {encryptEvent,openEvent} from './encryption.mjs';
import {compareFingerprint,databaseEpochStore,epochOfRetainUntil,eventKeyMaterial,sealFingerprint,storedEventKey} from './event-keys.mjs';
import {checkActionRows,createActionProjectionReducer} from './action-integrity.mjs';
import {checkEventProjection} from './event-integrity.mjs';
import {checkDevelopmentRunProjection} from './development-integrity.mjs';
import {checkReceiptProjection,expectedReceiptProjection} from './receipt-integrity.mjs';
import {checkObjectProjection,isSignedObjectType,signedObjectProjection} from './object-integrity.mjs';
import {checkEvaluationProjection} from './evaluation-integrity.mjs';
import {applyGovernanceDocumentRecord,checkGovernanceDocumentRows} from './governance-documents.mjs';
import {REGISTRY_INPUT_TYPES,REGISTRY_TYPES,registryAnalysisInput} from './agent-registry.mjs';
import {relatedDenyInput} from './decision-rules.mjs';
import {STOP_ORDER_TYPE,stopOrderAnalysisInput} from './stop-orders.mjs';
import {APPROVAL_TYPE,approvalAnalysisInput} from './approvals.mjs';
import {evaluationEngine} from './model.mjs';
import {types} from 'node:util';
import {EMPTY_ROOT,blobToPeaks,ed25519RawPublic,formatCheckpoint,frontierAppend,frontierRoot,logVkey,noteVerifier,openNote,parseCheckpoint,peaksToBlob,recordLeaf,rootsAtSizes,signNote,tenantOrigin,validateOriginBase} from './tlog.mjs';

let transactionSequence=0n;
// Policy, evaluation and review reads refuse to serve a signed row larger than this (413), as the full-scan readers did.
export const VERIFIED_READ_ROW_BYTES=2*1024*1024;
// Per-tenant RFC 6962 trees (tlog_state), the deployment heads log (tlog_heads) and witness cosignatures. All three are
// derivable caches plus proof material checked against signed notes; append-only triggers stay droppable like immutable_*.
// tlog_heads_entries holds, for heads rows whose entries column is '', only the entries that changed at that row.
// tlog_checkpoints keeps each tenant checkpoint a witness cosigned (witnessTenantLogs) with its frontier, so the next
// consistency proof needs only the leaves after it and exports can ship the cosigned note.
const tlogTables=['tlog_state','tlog_heads','tlog_heads_entries','tlog_cosignatures','tlog_checkpoints'];
const tlogSchema=`CREATE TABLE IF NOT EXISTS tlog_state(tenant TEXT NOT NULL CHECK(tenant<>''),origin TEXT NOT NULL,size INTEGER NOT NULL CHECK(size>=0),peaks BLOB NOT NULL,root BLOB NOT NULL,note TEXT NOT NULL,PRIMARY KEY(tenant,origin));
   CREATE TRIGGER IF NOT EXISTS tlog_state_monotonic BEFORE UPDATE ON tlog_state WHEN NEW.size<OLD.size OR NEW.tenant<>OLD.tenant OR NEW.origin<>OLD.origin BEGIN SELECT RAISE(ABORT,'tlog size regression'); END;
   CREATE TRIGGER IF NOT EXISTS tlog_state_immutable_delete BEFORE DELETE ON tlog_state BEGIN SELECT RAISE(ABORT,'append only'); END;
   CREATE TABLE IF NOT EXISTS tlog_heads(origin TEXT NOT NULL,idx INTEGER NOT NULL CHECK(idx>=0),leaf BLOB NOT NULL,peaks BLOB NOT NULL,entries TEXT NOT NULL,note TEXT NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(origin,idx));
   CREATE TRIGGER IF NOT EXISTS tlog_heads_immutable_update BEFORE UPDATE ON tlog_heads BEGIN SELECT RAISE(ABORT,'append only'); END;
   CREATE TRIGGER IF NOT EXISTS tlog_heads_immutable_delete BEFORE DELETE ON tlog_heads BEGIN SELECT RAISE(ABORT,'append only'); END;
   CREATE TABLE IF NOT EXISTS tlog_heads_entries(origin TEXT NOT NULL,log TEXT NOT NULL,idx INTEGER NOT NULL CHECK(idx>=0),size INTEGER NOT NULL CHECK(size>0),root TEXT NOT NULL,PRIMARY KEY(origin,log,idx));
   CREATE INDEX IF NOT EXISTS tlog_heads_entries_by_idx ON tlog_heads_entries(origin,idx);
   CREATE TRIGGER IF NOT EXISTS tlog_heads_entries_immutable_update BEFORE UPDATE ON tlog_heads_entries BEGIN SELECT RAISE(ABORT,'append only'); END;
   CREATE TRIGGER IF NOT EXISTS tlog_heads_entries_immutable_delete BEFORE DELETE ON tlog_heads_entries BEGIN SELECT RAISE(ABORT,'append only'); END;
   CREATE TABLE IF NOT EXISTS tlog_cosignatures(origin TEXT NOT NULL,size INTEGER NOT NULL,key_id TEXT NOT NULL,name TEXT NOT NULL,timestamp INTEGER NOT NULL,line TEXT NOT NULL,received_at TEXT NOT NULL,PRIMARY KEY(origin,size,key_id));
   CREATE TRIGGER IF NOT EXISTS tlog_cosignatures_refresh_only BEFORE UPDATE ON tlog_cosignatures WHEN NEW.timestamp<=OLD.timestamp OR NEW.origin<>OLD.origin OR NEW.size<>OLD.size OR NEW.key_id<>OLD.key_id BEGIN SELECT RAISE(ABORT,'append only'); END;
   CREATE TRIGGER IF NOT EXISTS tlog_cosignatures_immutable_delete BEFORE DELETE ON tlog_cosignatures BEGIN SELECT RAISE(ABORT,'append only'); END;
   CREATE TABLE IF NOT EXISTS tlog_checkpoints(origin TEXT NOT NULL,size INTEGER NOT NULL CHECK(size>0),root BLOB NOT NULL,peaks BLOB NOT NULL,note TEXT NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(origin,size));
   CREATE TRIGGER IF NOT EXISTS tlog_checkpoints_immutable_update BEFORE UPDATE ON tlog_checkpoints BEGIN SELECT RAISE(ABORT,'append only'); END;
   CREATE TRIGGER IF NOT EXISTS tlog_checkpoints_immutable_delete BEFORE DELETE ON tlog_checkpoints BEGIN SELECT RAISE(ABORT,'append only'); END;
`+tlogTables.flatMap(table=>['insert','update','delete'].map(op=>`   CREATE TRIGGER IF NOT EXISTS ${table}_mutation_${op} AFTER ${op.toUpperCase()} ON ${table} BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;`)).join('\n');
// Event-key epoch secrets kept in evidence.db when no keystore is configured, and the record of destroyed epochs (event-keys.mjs).
const epochTables=['event_key_epochs','event_key_epoch_tombstones'];
const epochSchema=`CREATE TABLE IF NOT EXISTS event_key_epochs(tenant TEXT NOT NULL,epoch TEXT NOT NULL,secret BLOB NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(tenant,epoch));
   CREATE TABLE IF NOT EXISTS event_key_epoch_tombstones(tenant TEXT NOT NULL,epoch TEXT NOT NULL,destroyed_at TEXT NOT NULL,storage TEXT NOT NULL,PRIMARY KEY(tenant,epoch));
`+epochTables.flatMap(table=>['insert','update','delete'].map(op=>
 `   CREATE TRIGGER IF NOT EXISTS ${table}_mutation_${op} AFTER ${op.toUpperCase()} ON ${table} BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;`)).join('\n');
// Projections of governance_document and development_run_event records, verified as facets of the incremental state.
const facetTables=['governance_documents','development_run_events'];
const facetSchema=`CREATE TABLE IF NOT EXISTS governance_documents(tenant TEXT NOT NULL,id TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(tenant,id));
   CREATE TABLE IF NOT EXISTS development_run_events(tenant TEXT NOT NULL,source TEXT NOT NULL,event_id TEXT NOT NULL,run_id TEXT NOT NULL,occurred TEXT NOT NULL,
    received TEXT NOT NULL,fingerprint TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(tenant,source,event_id));
   CREATE INDEX IF NOT EXISTS development_run_tenant_run ON development_run_events(tenant,run_id,occurred);
`+facetTables.flatMap(table=>['insert','update','delete'].map(op=>
 `   CREATE TRIGGER IF NOT EXISTS ${table}_mutation_${op} AFTER ${op.toUpperCase()} ON ${table} BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;`)).join('\n');
// Facets outside the action gate: checkActionProjection does not require them, so their projections keep their own blast radius.
const OPTIONAL_FACETS=new Set(['governance_documents','development_runs']);

export class Store {
 constructor(dir,key,options={}) {
  mkdirSync(dir,{recursive:true}); this.key=key; this.publicKey=createPublicKey(key);this.db=new DatabaseSync(join(dir,'evidence.db'));
  this.tlog=options.tlog?{base:validateOriginBase(options.tlog.base),quorum:options.tlog.quorum||0,pub:ed25519RawPublic(this.publicKey),verified:new Map(),verifiers:new Map()}:null;this.quarantine=null;
  this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA secure_delete=ON;
   CREATE TABLE IF NOT EXISTS ledger(tenant TEXT, seq INTEGER, body TEXT NOT NULL, hash TEXT NOT NULL, PRIMARY KEY(tenant,seq));
   CREATE TABLE IF NOT EXISTS checkpoints(tenant TEXT PRIMARY KEY, body TEXT NOT NULL);
   CREATE TABLE IF NOT EXISTS events(tenant TEXT, source TEXT, id TEXT, fingerprint TEXT, action_id TEXT, trace_id TEXT, kind TEXT, received TEXT, body TEXT, PRIMARY KEY(tenant,source,id));
   CREATE INDEX IF NOT EXISTS event_received ON events(tenant,received);
   CREATE INDEX IF NOT EXISTS event_action_received ON events(tenant,action_id,received);
   CREATE INDEX IF NOT EXISTS event_source_received ON events(tenant,source,received);
   DROP INDEX IF EXISTS event_action;
   CREATE TABLE IF NOT EXISTS nonces(source TEXT, nonce TEXT, expires INTEGER, PRIMARY KEY(source,nonce));
   CREATE TABLE IF NOT EXISTS actions(tenant TEXT, id TEXT, version INTEGER NOT NULL, analyzed INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(tenant,id));
   CREATE INDEX IF NOT EXISTS actions_pending ON actions(tenant) WHERE analyzed<version;
   CREATE INDEX IF NOT EXISTS nonces_expires ON nonces(expires);
   CREATE TABLE IF NOT EXISTS evaluations(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT, action_id TEXT, version INTEGER, body TEXT);
   CREATE TABLE IF NOT EXISTS objects(tenant TEXT, type TEXT, id TEXT, body TEXT, PRIMARY KEY(tenant,type,id));
   CREATE TABLE IF NOT EXISTS counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL);
   CREATE TABLE IF NOT EXISTS event_keys(tenant TEXT,key_id TEXT,seq INTEGER,key BLOB NOT NULL,PRIMARY KEY(tenant,key_id));
   CREATE TABLE IF NOT EXISTS receipts(tenant TEXT,source TEXT,id TEXT,fingerprint TEXT,PRIMARY KEY(tenant,source,id));
   INSERT OR IGNORE INTO receipts SELECT tenant,source,id,fingerprint FROM events;
   CREATE TRIGGER IF NOT EXISTS immutable_update BEFORE UPDATE ON ledger BEGIN SELECT RAISE(ABORT,'append only'); END;
   CREATE TRIGGER IF NOT EXISTS immutable_delete BEFORE DELETE ON ledger BEGIN SELECT RAISE(ABORT,'append only'); END;
   CREATE TABLE IF NOT EXISTS projection_mutation_clock(id INTEGER PRIMARY KEY CHECK(id=1),serial INTEGER NOT NULL);
   INSERT OR IGNORE INTO projection_mutation_clock VALUES(1,0);
   CREATE TRIGGER IF NOT EXISTS events_mutation_insert AFTER INSERT ON events BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS events_mutation_update AFTER UPDATE ON events BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS events_mutation_delete AFTER DELETE ON events BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS receipts_mutation_insert AFTER INSERT ON receipts BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS receipts_mutation_update AFTER UPDATE ON receipts BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS receipts_mutation_delete AFTER DELETE ON receipts BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS actions_mutation_insert AFTER INSERT ON actions BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS actions_mutation_update AFTER UPDATE ON actions BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS actions_mutation_delete AFTER DELETE ON actions BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS event_keys_mutation_insert AFTER INSERT ON event_keys BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS event_keys_mutation_update AFTER UPDATE ON event_keys BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS event_keys_mutation_delete AFTER DELETE ON event_keys BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS ledger_mutation_insert AFTER INSERT ON ledger BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS ledger_mutation_update AFTER UPDATE ON ledger BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS ledger_mutation_delete AFTER DELETE ON ledger BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS checkpoints_mutation_insert AFTER INSERT ON checkpoints BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS checkpoints_mutation_update AFTER UPDATE ON checkpoints BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
    CREATE TRIGGER IF NOT EXISTS checkpoints_mutation_delete AFTER DELETE ON checkpoints BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
    CREATE TRIGGER IF NOT EXISTS objects_mutation_insert AFTER INSERT ON objects BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
    CREATE TRIGGER IF NOT EXISTS objects_mutation_update AFTER UPDATE ON objects BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
    CREATE TRIGGER IF NOT EXISTS objects_mutation_delete AFTER DELETE ON objects BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
    CREATE TRIGGER IF NOT EXISTS evaluations_mutation_insert AFTER INSERT ON evaluations BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
    CREATE TRIGGER IF NOT EXISTS evaluations_mutation_update AFTER UPDATE ON evaluations BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
    CREATE TRIGGER IF NOT EXISTS evaluations_mutation_delete AFTER DELETE ON evaluations BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   ${tlogSchema}
   ${facetSchema}
   ${epochSchema}`);
  this.eventKeyProvider=options.eventKeys||undefined;
  this.actionProjectionCache=new Map();this.rollbackActions=[];this.projectionMutationDepth=0;this.projectionMutationSerial=0;this.verifiedStateMaxAgeMs=options.verifiedStateMaxAgeMs??600000;
  this.observedProjectionMutationClock=this._mutationClock();
   const protectedTables=new Set(['events','receipts','actions','event_keys','ledger','checkpoints','objects','evaluations',...tlogTables,...facetTables,...epochTables]);
   const protectedTriggers=new Set(['events_mutation_insert','events_mutation_update','events_mutation_delete','receipts_mutation_insert','receipts_mutation_update','receipts_mutation_delete','actions_mutation_insert','actions_mutation_update','actions_mutation_delete','event_keys_mutation_insert','event_keys_mutation_update','event_keys_mutation_delete','ledger_mutation_insert','ledger_mutation_update','ledger_mutation_delete','checkpoints_mutation_insert','checkpoints_mutation_update','checkpoints_mutation_delete','objects_mutation_insert','objects_mutation_update','objects_mutation_delete','evaluations_mutation_insert','evaluations_mutation_update','evaluations_mutation_delete',...[...tlogTables,...facetTables,...epochTables].flatMap(table=>['insert','update','delete'].map(op=>`${table}_mutation_${op}`))]);
  this.db.setAuthorizer((action,table,_column,_database,source)=>{
   if(action===sqlite.SQLITE_DROP_TRIGGER&&protectedTriggers.has(table)||[sqlite.SQLITE_DROP_TABLE,sqlite.SQLITE_ALTER_TABLE].includes(action)&&([...protectedTables,'projection_mutation_clock'].includes(table)))return sqlite.SQLITE_DENY;
   if([sqlite.SQLITE_INSERT,sqlite.SQLITE_UPDATE,sqlite.SQLITE_DELETE].includes(action)&&table==='projection_mutation_clock'&&!protectedTriggers.has(source))return sqlite.SQLITE_DENY;
   if([sqlite.SQLITE_INSERT,sqlite.SQLITE_UPDATE,sqlite.SQLITE_DELETE].includes(action)&&protectedTables.has(table)&&source)return sqlite.SQLITE_DENY;
   if([sqlite.SQLITE_INSERT,sqlite.SQLITE_UPDATE,sqlite.SQLITE_DELETE].includes(action)&&protectedTables.has(table)&&this.projectionMutationDepth===0)this.projectionMutationSerial++;
   return sqlite.SQLITE_OK;
  });
 }
 // Prepared statements reused on hot paths (round 5, docs/performance.md). SQLite runs the authorizer above when a statement is
 // compiled, not when it runs, so only statements whose authorization cannot depend on the moment are cached: reads and writes
 // to unprotected tables (cachedStatement), and writes to protected tables that run inside projectionMutation (projectionStatement).
 cachedStatement(sql){const cache=this.statements??=new Map();let statement=cache.get(sql);if(!statement)cache.set(sql,statement=this.db.prepare(sql));return statement;}
 projectionStatement(sql){if(this.projectionMutationDepth===0)throw Error('Projection write outside Store.projectionMutation');return this.cachedStatement(sql);}
 _mutationClock(){return this.cachedStatement('SELECT serial FROM projection_mutation_clock WHERE id=1').get().serial;}
 projectionMutation(fn){if(this.projectionMutationDepth===0)this._syncProjectionMutationClock();this.projectionMutationDepth++;try{return fn();}finally{this.projectionMutationDepth--;if(this.projectionMutationDepth===0)this.observedProjectionMutationClock=this._mutationClock();}}
 _syncProjectionMutationClock(){const actual=this._mutationClock();if(actual!==this.observedProjectionMutationClock){this.projectionMutationSerial++;this.observedProjectionMutationClock=actual;}}
 // secure_delete zeroes freed cells and pages, but older page images survive in the WAL until it is reset.
 // Called after an erasure commits; never waits for readers (an online backup) and retries in the background.
 checkpointAfterErasure(attempt=0){
  if(!this.db.isOpen)return {busy:1,log:-1,checkpointed:-1};
  let result={busy:1,log:-1,checkpointed:-1};
  if(!this.db.isTransaction){this.db.exec('PRAGMA busy_timeout=0');try{result=this.db.prepare('PRAGMA wal_checkpoint(TRUNCATE)').get();}finally{this.db.exec('PRAGMA busy_timeout=5000');}}
  if(result.busy&&attempt<5)setTimeout(()=>{try{this.checkpointAfterErasure(attempt+1);}catch{}},1000*(attempt+1)).unref();
  return result;
 }
 transaction(fn) {
  if(typeof fn!=='function'||types.isAsyncFunction(fn))throw TypeError('Store.transaction requires a synchronous callback');
  // SQLite rolls a whole transaction back by itself on some errors (SQLITE_FULL, SQLITE_IOERR, ...). A caller that caught such an
  // error (a group-commit batch does, per event) must not go on writing in autocommit mode, or sign a checkpoint outside it.
  if(this.ledgerTransaction&&!this.ledgerTransaction.readOnly&&!this.db.isTransaction)throw Error('Store transaction ended early; refusing to write outside it');
  const nested=this.db.isTransaction,name=`evidscope_transaction_${++transactionSequence}`,ownsLedgerContext=!this.ledgerTransaction;
  const snapshot=!ownsLedgerContext?{heads:new Map([...this.ledgerTransaction.heads].map(([tenant,head])=>[tenant,{...head}])),dirty:new Set(this.ledgerTransaction.dirty),actionCandidates:new Map(this.ledgerTransaction.actionCandidates),appended:this.ledgerTransaction.appended.length}:null;
  const observedClock=this.observedProjectionMutationClock;this.db.exec(nested?`SAVEPOINT ${name}`:'BEGIN IMMEDIATE');const rollbackMark=this.rollbackActions.length;
  if(ownsLedgerContext)this.ledgerTransaction={heads:new Map(),dirty:new Set(),actionCandidates:new Map(),appended:[],advanced:new Set(),external:nested};
  try{
   const out=fn();
   if(out&&typeof out.then==='function'){if(types.isPromise(out))out.catch(()=>{});throw TypeError('Store.transaction requires a synchronous callback');}
   if(!this.db.isTransaction)throw Error('Store transaction ended early; refusing to write outside it');
   if(ownsLedgerContext&&!nested)this._advanceVerifiedStates();
   if(ownsLedgerContext)this.projectionMutation(()=>{for(const tenant of this.ledgerTransaction.dirty){const head=this.ledgerTransaction.heads.get(tenant);this.projectionStatement('INSERT INTO checkpoints VALUES(?,?) ON CONFLICT(tenant) DO UPDATE SET body=excluded.body').run(tenant,JSON.stringify(makeCheckpoint(tenant,head.seq,head.hash,this.key)));if(head.peaks)this._writeTlog(tenant,head.seq,head.peaks);}});
   this.db.exec(nested?`RELEASE ${name}`:'COMMIT');
   // Committed: undo actions registered at this level are dropped; a nested RELEASE keeps them for the outer level.
   if(ownsLedgerContext)this.rollbackActions.length=rollbackMark;
   if(ownsLedgerContext&&!this.ledgerTransaction.external)for(const [tenant,candidate] of this.ledgerTransaction.actionCandidates)this.actionProjectionCache.set(tenant,candidate);
   return out;
  }catch(error){
   // A verified state advanced over rows of this transaction describes rows that are gone now (see _advanceVerifiedStates).
   if(ownsLedgerContext)for(const tenant of this.ledgerTransaction.advanced)this.actionProjectionCache.delete(tenant);
   try{if(nested){this.db.exec(`ROLLBACK TO ${name}`);this.db.exec(`RELEASE ${name}`);}else if(this.db.isTransaction)this.db.exec('ROLLBACK');}
   catch(rollbackError){throw new AggregateError([error,rollbackError],'Store transaction rollback failed');}
   // The rollback also reverted the projection mutation clock: observe it as it was here, so the undone writes of this
   // transaction do not read as a write outside projectionMutation (which made the next check cold). A change this process
   // had not observed when the transaction began is still a mismatch.
   this.observedProjectionMutationClock=observedClock;
   // After a completed rollback, undo side effects outside SQLite (new document files) in reverse order (S12d).
   for(const action of this.rollbackActions.splice(rollbackMark).reverse())try{action();}catch{}
   if(snapshot){this.ledgerTransaction.heads=snapshot.heads;this.ledgerTransaction.dirty=snapshot.dirty;this.ledgerTransaction.actionCandidates=snapshot.actionCandidates;this.ledgerTransaction.appended.length=snapshot.appended;}
   throw error;
  }finally{if(ownsLedgerContext)this.ledgerTransaction=null;}
 }
 // Registers an undo action for a side effect outside SQLite; it runs only if the enclosing transaction rolls back.
 onRollback(action){if(!this.db.isTransaction||typeof action!=='function')throw Error('Store.onRollback requires an active transaction');this.rollbackActions.push(action);}
 checkpoint(tenant){
  const pending=this.ledgerTransaction?.dirty.has(tenant)&&this.ledgerTransaction.heads.get(tenant);
  if(pending)return makeCheckpoint(tenant,pending.seq,pending.hash,this.key);
  const saved=this.cachedStatement('SELECT body FROM checkpoints WHERE tenant=?').get(tenant);
  return saved?JSON.parse(saved.body):makeCheckpoint(tenant,0,'0'.repeat(64),this.key);
 }
 // retention: the event's Store.eventRetention when the caller already has it (it must be for payload.receivedAt).
 append(tenant,type,payload,principal,{retention}={}) {
  if(this.quarantine)throw Object.assign(Error('Transparency quarantine: '+this.quarantine.reason),{status:503});
  if(this.readOnlyRequest)throw Error('Read-only request cannot append to the ledger');
  // One transaction makes the ledger row, v1 checkpoint and tlog note atomic for direct callers too.
  if(!this.ledgerTransaction)return this.transaction(()=>this.append(tenant,type,payload,principal));
  let head=this.ledgerTransaction.heads.get(tenant);
  if(!head){
   head=this.cachedStatement('SELECT seq,hash FROM ledger WHERE tenant=? ORDER BY seq DESC LIMIT 1').get(tenant);
   const saved=this.cachedStatement('SELECT body FROM checkpoints WHERE tenant=?').get(tenant);
   if(head){const checkpoint=saved&&JSON.parse(saved.body);verifyCheckpoint(checkpoint,this.publicKey);if(checkpoint.tenant!==tenant||checkpoint.count!==head.seq||checkpoint.head!==head.hash)throw Error('Ledger head differs from previously signed checkpoint; refusing to re-seal');}
   else if(saved)throw Error('Ledger is missing beneath an existing checkpoint');
   head=head||{seq:0,hash:'0'.repeat(64)};if(this.tlog)head={...head,peaks:this._tlogHeadPeaks(tenant,head)};
   this.ledgerTransaction.heads.set(tenant,head);
  }
  const seq=(head?.seq||0)+1;let known=null;
  if(type==='event'){
   const encrypted=encryptEvent(payload,tenant,seq,retention||this.eventRetention(tenant,payload.receivedAt));
   if(!this.eventKeyEpochs().wrapsEventKeys)this._assertNoEventKeystore();
   const stored=storedEventKey(this.eventKeyEpochs(),encrypted.payload,encrypted.material);
   this.projectionMutation(()=>this.projectionStatement('INSERT INTO event_keys VALUES(?,?,?,?)').run(tenant,encrypted.keyId,seq,stored));payload=encrypted.payload;
   known={text:encrypted.text,stored};
  }
  const record={tenant,seq,previous:head?.hash||'0'.repeat(64),type,recordedAt:new Date().toISOString(),principal,payload};
  const body=canonical(record),hash=digest(body);this.projectionMutation(()=>this.projectionStatement('INSERT INTO ledger VALUES(?,?,?,?)').run(tenant,record.seq,body,hash));
  this.ledgerTransaction.heads.set(tenant,{seq:record.seq,hash,...(head.peaks?{peaks:frontierAppend(head.peaks,head.seq,recordLeaf(hash))}:{})});this.ledgerTransaction.dirty.add(tenant);
  this.ledgerTransaction.appended.push({tenant,seq,previous:record.previous,body,hash,known});
  return {...record,hash};
 }
 // Retention of a new event under the tenant's current policy; its key epoch is the UTC month of retainUntil.
 eventRetention(tenant,receivedAt){
  const policy=this.get(tenant,'retention_policy','current')||{version:0,retentionSeconds:30*86400,reason:'합성 파일럿 공학적 기본값; 법적 보존기간 아님'};
  const retainUntil=new Date(Date.parse(receivedAt)+policy.retentionSeconds*1000).toISOString();
  return {policy,retainUntil,keyEpoch:epochOfRetainUntil(retainUntil)};
 }
 // A database whose event keys moved to a keystore never takes another raw key, e.g. from a vault started before the move.
 // Checked once per write transaction: BEGIN IMMEDIATE keeps other connections from moving the keys meanwhile.
 _assertNoEventKeystore(){
  if(this.ledgerTransaction?.keystoreAbsent)return;
  if(this.cachedStatement("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='event_keystore_usage'").get()
   &&this.db.prepare('SELECT 1 FROM event_keystore_usage LIMIT 1').get())throw Error('This vault moved its event keys to an event keystore; restart it with EVENT_KEYSTORE_DIR and DATA_KEY_FILE');
  if(this.ledgerTransaction)this.ledgerTransaction.keystoreAbsent=true;
 }
 // Epoch secrets: the configured keystore, else the tables in this database (event-keys.mjs).
 eventKeyEpochs(){return this.eventKeyProvider??=databaseEpochStore(this.db,{mutate:fn=>this.projectionMutation(fn),read:sql=>this.cachedStatement(sql)});}
 // Attach the keystore before the first event is read or written (event-keystore.mjs attachEventKeystore).
 useEventKeys(epochs){
  if(this.eventKeyProvider&&this.eventKeyProvider!==epochs&&this.eventKeyProvider.kind!=='database')throw Error('Another event-key store is attached');
  this.eventKeyProvider=epochs;
 }
 // Source ingest replaces the raw-body digest by a tag keyed by the event's epoch (call inside the ingest transaction).
 sealEventFingerprint(tenant,event,retention=this.eventRetention(tenant,event.receivedAt)){return {...event,fingerprint:sealFingerprint(this.eventKeyEpochs(),tenant,retention.keyEpoch,event.fingerprint)};}
 compareEventFingerprint(tenant,stored,rawDigest){return compareFingerprint(this.eventKeyEpochs(),tenant,stored,rawDigest);}
 // {event, salt} of one encrypted ledger event from its stored key (raw, or wrapped under its epoch with a keystore).
 _openEvent(payload,stored){return openEvent(payload,eventKeyMaterial(this.eventKeyEpochs(),payload,stored));}
 // Read-only scope (GET requests): one deferred WAL read snapshot for the whole request under PRAGMA query_only, so every
 // write on this connection fails and Store.transaction inside it is a savepoint of that snapshot. What is verified is what
 // is served; other connections may commit meanwhile (the next read then fails closed). The scope owns the ledger context,
 // so verified-state candidates built in the snapshot are promoted when it ends.
 beginReadOnly(){
  if(this.db.isTransaction||this.ledgerTransaction)throw Error('Read-only scope must begin outside a transaction');
  this.db.exec('PRAGMA query_only=ON');
  try{this.db.exec('BEGIN DEFERRED');}catch(error){this.db.exec('PRAGMA query_only=OFF');throw error;}
  this.readOnlyRequest=true;this.ledgerTransaction={heads:new Map(),dirty:new Set(),actionCandidates:new Map(),appended:[],advanced:new Set(),external:false,readOnly:true};
 }
 endReadOnly(){
  if(!this.readOnlyRequest)return;
  const context=this.ledgerTransaction;this.readOnlyRequest=false;this.ledgerTransaction=null;
  if(!this.db.isOpen)return;
  try{if(this.db.isTransaction)this.db.exec('COMMIT');}finally{this.db.exec('PRAGMA query_only=OFF');}
  for(const [tenant,candidate] of context.actionCandidates)this.actionProjectionCache.set(tenant,candidate);
 }
 // One read snapshot outside a request scope (long verifications that must not hold the write lock).
 read(fn){if(this.readOnlyRequest||this.db.isTransaction)return this.transaction(fn);this.beginReadOnly();try{return this.transaction(fn);}finally{this.endReadOnly();}}
 audit(p,operation,target='') {return this.transaction(()=>this.append(p.tenant,'audit_access',{operation,target},p.id));}
 get(tenant,type,id) {const r=this.cachedStatement('SELECT body FROM objects WHERE tenant=? AND type=? AND id=?').get(tenant,type,id);return r?JSON.parse(r.body):null;}
 list(tenant,type) {return this.db.prepare('SELECT body FROM objects WHERE tenant=? AND type=? ORDER BY id').all(tenant,type).map(r=>JSON.parse(r.body));}
 put(p,type,id,body) {this.append(p.tenant,type,body,p.id);this.projectionMutation(()=>this.db.prepare('INSERT INTO objects VALUES(?,?,?,?) ON CONFLICT(tenant,type,id) DO UPDATE SET body=excluded.body').run(p.tenant,type,id,JSON.stringify(body)));return body;}
 events(tenant,actionId) {const sql=actionId?'SELECT body FROM events WHERE tenant=? AND action_id=? ORDER BY received,source,id':'SELECT body FROM events WHERE tenant=? ORDER BY received,source,id';return this.db.prepare(sql).all(...(actionId?[tenant,actionId]:[tenant])).map(r=>JSON.parse(r.body));}
 evaluations(tenant,actionId) {return this.db.prepare('SELECT body FROM evaluations WHERE tenant=? AND action_id=? ORDER BY id DESC').all(tenant,actionId).map(r=>JSON.parse(r.body));}
 rawBundle(tenant) {
  const records=this.db.prepare('SELECT seq,body,hash FROM ledger WHERE tenant=? ORDER BY seq').all(tenant).map(r=>{const record=JSON.parse(r.body);if(record.tenant!==tenant||record.seq!==r.seq)throw Error('Ledger SQL tenant or sequence differs from signed record');return {...record,hash:r.hash};});
  const checkpoint=this.checkpoint(tenant);
  if(checkpoint.tenant!==tenant)throw Error('Checkpoint tenant mismatch');
  return {format:'evidscope-export-v2',records,checkpoint,limitations:['Minimized receipt evidence; no original prompt or response','Signature authenticates local vault, not truth of source claims','Pin public key and checkpoint out of band to detect replacement and rollback','Erasure covers live event keys and query copies; prior exports/backups need separate disposition']};
 }
 decodeRecords(bundle){return this._decodeOpenings(bundle).map(item=>item.event);}
 // Retained events with their v2 commitment salts (null for v1 and plaintext legacy rows).
 _decodeOpenings(bundle){
  const erased=new Set(bundle.records.filter(r=>r.type==='retention_disposition').flatMap(r=>r.payload.keyIds||[]));
  return bundle.records.filter(r=>r.type==='event').flatMap(r=>{
   if(!isEncryptedEvent(r.payload))return [{event:{...r.payload,seq:r.seq,hash:r.hash},salt:null,encrypted:false}];
   const k=this.db.prepare('SELECT key FROM event_keys WHERE tenant=? AND key_id=?').get(r.tenant,r.payload.keyId);
   if(erased.has(r.payload.keyId)){if(k)throw Error('Erased event key unexpectedly retained');return [];}
   if(!k)throw Error('Event key missing without authorized disposition');
   const opened=this._openEvent(r.payload,k.key);return [{event:{...opened.event,seq:r.seq,hash:r.hash},salt:opened.salt,encrypted:true}];
  });
 }
 // Export disclosures: every retained encrypted event, with its salt when the envelope is v2.
 bundle(tenant){const b=this.rawBundle(tenant);verifyBundle(b,this.publicKey,undefined,{chainOnly:true});
  b.disclosures=this._decodeOpenings(b).filter(item=>item.encrypted).map(({event:{seq,hash,...event},salt})=>salt?{seq,event,salt:salt.toString('hex')}:{seq,event});return b;}
 // Export only: internal readers (rawBundle/bundle) never pay for transparency proofs.
 exportBundle(tenant){const b=this.bundle(tenant),transparency=this.tlog&&this.tlogEvidence?this.tlogEvidence(tenant,b.records):null;return transparency?{...b,transparency}:b;}
 ledgerEvents(tenant,actionId){const b=this.rawBundle(tenant);verifyBundle(b,this.publicKey,undefined,{chainOnly:true});return this.decodeRecords(b).filter(e=>!actionId||e.actionId===actionId).sort((a,b)=>a.receivedAt.localeCompare(b.receivedAt)||a.source.localeCompare(b.source)||a.id.localeCompare(b.id));}
 ledgerObjects(tenant,type){const b=this.rawBundle(tenant);verifyBundle(b,this.publicKey,undefined,{chainOnly:true});return [...new Map(b.records.filter(r=>r.type===type&&r.payload.id).map(r=>[r.payload.id,r.payload])).values()];}
 // Consume this iterator to exhaustion before using any rows: final signed checkpoint
 // verification runs after the last row. A single oversized row is hashed in chunks.
 *verifiedRows(tenant,maxRowBytes,{hashesOnly=false}={}){
  const cp=this.checkpoint(tenant);verifyCheckpoint(cp,this.publicKey);
  if(cp.tenant!==tenant)throw Error('Checkpoint tenant mismatch');
  let previous='0'.repeat(64),sequence=0;
  const query=this.db.prepare(`SELECT seq,hash,length(CAST(body AS BLOB)) AS bytes,
   json_extract(body,'$.tenant') AS record_tenant,json_extract(body,'$.seq') AS record_seq,
   json_extract(body,'$.previous') AS previous,
   CASE WHEN length(CAST(body AS BLOB))<=? THEN body ELSE NULL END AS body
   FROM ledger WHERE tenant=? ORDER BY seq`);
  for(const row of query.iterate(maxRowBytes,tenant)){
   if(row.seq!==++sequence||row.record_seq!==sequence||row.record_tenant!==tenant||row.previous!==previous)throw Error('Sequence, tenant or previous hash mismatch');
   let hash;
   if(row.body!==null)hash=digest(row.body);
   else {
    const hasher=createHash('sha256'),chunk=this.db.prepare('SELECT substr(CAST(body AS BLOB),?,65536) AS chunk FROM ledger WHERE tenant=? AND seq=?');
    for(let offset=1;offset<=row.bytes;offset+=65536)hasher.update(chunk.get(offset,tenant,row.seq).chunk);
    hash=hasher.digest('hex');
   }
   if(hash!==row.hash)throw Error('Record digest mismatch');previous=hash;
   yield row.body===null?{oversized:true,bytes:row.bytes,seq:row.seq,hash:row.hash}:hashesOnly?{seq:row.seq,hash:row.hash}:{...JSON.parse(row.body),hash:row.hash,recordBytes:row.bytes};
  }
  if(sequence!==cp.count||previous!==cp.head)throw Error('Truncated or inconsistent export');
 }
 // Cold streaming reader of the v1 inputs (tests). Analysis uses cachedAnalysisSnapshot, which also carries the registry inputs.
 verifiedAnalysisSnapshot(tenant,actionId,limits){
  const maxBytes=limits.snapshotBytes-4096,maxRows={assets:limits.assets,rules:limits.rules,exceptions:limits.exceptions};
  const events=[],maps={assets:new Map(),rules:new Map(),exceptions:new Map()},types={asset:'assets',rule:'rules',exception:'exceptions'};
  let usedBytes=100,observedEvents=0,observedEventsComplete=true;const reasons=new Set();
  const over=reason=>{reasons.add(reason);events.length=0;for(const map of Object.values(maps))map.clear();};
  const keyQuery=this.db.prepare('SELECT key FROM event_keys WHERE tenant=? AND key_id=?');
  const disposition=this.db.prepare(`SELECT 1 FROM ledger l,json_each(l.body,'$.payload.keyIds') k
   WHERE l.tenant=? AND json_extract(l.body,'$.type')='retention_disposition' AND k.value=? LIMIT 1`);
  for(const row of this.verifiedRows(tenant,maxBytes)){
   if(row.oversized){over('ledgerRowBytes');observedEventsComplete=false;continue;}
   if(row.type==='retention_disposition'){
    for(const id of row.payload.keyIds||[])if(keyQuery.get(tenant,id))throw Error('Erased event key unexpectedly retained');
    continue;
   }
   if(row.type==='event'){
    let event;
    if(isEncryptedEvent(row.payload)){
     if(row.payload.tenant!==tenant||row.payload.seq!==row.seq)throw Error('Encrypted event envelope mismatch');
     const k=keyQuery.get(tenant,row.payload.keyId);
     if(!k){if(!disposition.get(tenant,row.payload.keyId))throw Error('Event key missing without authorized disposition');continue;}
     if(actionId===null)continue;
     if(Object.hasOwn(row.payload,'actionId')&&row.payload.actionId!==actionId)continue;
     event=this._openEvent(row.payload,k.key).event;
    }else event=row.payload;
    if(actionId===null||event.actionId!==actionId)continue;observedEvents++;
    if(observedEvents>limits.events)over('events');
    if(reasons.size)continue;
    const value={...event,seq:row.seq,hash:row.hash};usedBytes+=Buffer.byteLength(JSON.stringify(value))+1;
    if(usedBytes>maxBytes)over('snapshotBytes');else events.push(value);
   }else if(types[row.type]&&!reasons.size&&row.payload.id){
    const name=types[row.type],map=maps[name],value=row.type==='rule'?{...row.payload,versions:row.payload.versions.filter(v=>v.status==='active')}:row.payload;
    // Asset versions are historical policy evidence. Preserve every authoritative
    // registration even when legacy entries reused version/updatedAt metadata.
    const mapKey=name==='assets'?`${value.id}:${row.seq}`:value.id;
    const old=map.get(mapKey);usedBytes-=old?Buffer.byteLength(JSON.stringify(old)):0;usedBytes+=Buffer.byteLength(JSON.stringify(value))+1;
    map.set(mapKey,value);
    const count=name==='rules'?[...map.values()].reduce((n,r)=>n+r.versions.length,0):map.size;
    if(count>maxRows[name])over(name);else if(usedBytes>maxBytes)over('snapshotBytes');
   }
  }
  if(reasons.size)return {resourceLimit:{reasons:[...reasons],observedEventsComplete,snapshotBytesAtLeast:usedBytes},observedEvents};
  return {events:events.sort((a,b)=>a.receivedAt.localeCompare(b.receivedAt)||a.source.localeCompare(b.source)||a.id.localeCompare(b.id)),assets:[...maps.assets.values()],rules:[...maps.rules.values()].flatMap(r=>r.versions),exceptions:[...maps.exceptions.values()]};
 }
 // Registry input (agent_registry / agent_registry_policy versions) and related deny decisions join the snapshot only when they
 // exist, so tenants without them keep the v1 snapshot; src/policy-replay.mjs builds the same input from the export.
 cachedAnalysisSnapshot(tenant,actionId,limits){
  this.checkActionProjection(tenant);const state=this.ledgerTransaction?.actionCandidates.get(tenant)||this.actionProjectionCache.get(tenant);if(!state)throw Error('Verified action state is unavailable');
  const events=actionId===null?[]:[...state.eventsBySequence.values()].filter(event=>event.actionId===actionId),assets=[...state.analysisAssets.values()],rules=[...state.analysisRules.values()].flatMap(rule=>(rule.versions||[]).filter(version=>version.status==='active')),exceptions=[...state.analysisExceptions.values()];
  const registry=registryAnalysisInput(state.registryRows.filter(row=>REGISTRY_INPUT_TYPES.includes(row.type))),relatedDecisions=relatedDenyInput(events,state.eventsBySequence.values());
  // Approval requests of this action (latest versions, in the order they were opened) join only when there are any.
  const approvals=actionId===null?undefined:approvalAnalysisInput(this._approvalValues(state,actionId).map(value=>value.payload));
  // Stop orders (docs/kill-switch.md) join only when the tenant has one; their activations come from every retained event.
  const stopOrders=stopOrderAnalysisInput(state.registryRows,state.eventsBySequence.values());
  const extra={...(registry?{registry}:{}),...(relatedDecisions?{relatedDecisions}:{}),...(approvals?{approvals}:{}),...(stopOrders?{stopOrders}:{})};
  const extraBytes=Object.keys(extra).length?Buffer.byteLength(JSON.stringify(extra))+1:0;
  const reasons=[],used=100+extraBytes+[...events,...assets,...rules,...exceptions].reduce((total,value)=>total+Buffer.byteLength(JSON.stringify(value))+1,0),counts={events:events.length,assets:assets.length,rules:rules.length,exceptions:exceptions.length};
  for(const [name,count] of Object.entries(counts))if(count>limits[name])reasons.push(name);if(used>limits.snapshotBytes-4096)reasons.push('snapshotBytes');
  if(reasons.length)return {resourceLimit:{reasons:[...new Set(reasons)],observedEventsComplete:true,snapshotBytesAtLeast:used,engine:evaluationEngine({events,...extra})},observedEvents:events.length};
  return {events:events.sort((a,b)=>a.receivedAt.localeCompare(b.receivedAt)||a.source.localeCompare(b.source)||a.id.localeCompare(b.id)),assets,rules,exceptions,...extra};
 }
 // Signed agent registry, transition, registry-policy and stop-order records in ledger order (deep copies) for history,
 // lifecycle and bundle-revision reads.
 cachedRegistryRows(tenant){
  const state=this._verifiedActionState(tenant),types=[...REGISTRY_TYPES,STOP_ORDER_TYPE];
  if(types.some(type=>state.oversizedTypes.has(type))||state.oversizedTypes.has('*'))return {oversized:true,rows:[]};
  this._assertFacets(state,types.map(type=>'objects:'+type));
  return {oversized:false,rows:state.registryRows.map(row=>structuredClone(row))};
 }
 // Approval requests of a tenant (one action, or all) as latest signed versions with their ledger seq and record hash, in the
 // order they were opened, or one request by id (history:true adds every signed version). Only the objects:approval_request facet must hold.
 cachedApprovals(tenant,{actionId,id,history=false}={}){
  const state=this._verifiedActionState(tenant);
  if(state.oversizedTypes.has(APPROVAL_TYPE)||state.oversizedTypes.has('*'))return {oversized:true,values:[]};
  this._assertFacets(state,['objects:'+APPROVAL_TYPE]);
  const values=id!==undefined?[state.objects.get(canonical([APPROVAL_TYPE,id]))].filter(Boolean):actionId!==undefined?this._approvalValues(state,actionId)
   :[...state.objects.values()].filter(value=>value.type===APPROVAL_TYPE).sort((a,b)=>a.firstSeq-b.firstSeq);
  return {oversized:false,values:values.map(value=>({id:value.id,seq:value.row.seq,hash:value.row.hash,body:structuredClone(value.payload),
   ...(history?{versions:structuredClone(state.approvalHistory.get(value.id)||[])}:{})}))};
 }
 _approvalValues(state,actionId){return (state.approvalActions.get(actionId)||[]).map(id=>state.objects.get(canonical([APPROVAL_TYPE,id]))).filter(Boolean);}
 cachedSignedObjects(tenant,types){
  if(!Array.isArray(types)||types.some(type=>!isSignedObjectType(type)))throw TypeError('Signed object types are required');
  const state=this.verifiedFacets(tenant),selected=new Set(types);
  return [...state.objects.values()].filter(value=>selected.has(value.type)).sort((a,b)=>a.row.seq-b.row.seq).map(value=>({seq:value.row.seq,type:value.type,id:value.id,body:structuredClone(value.payload)}));
 }
 // Policy reads: the latest signed value per id in first-signed order (what a full ledger scan into a Map returns), as deep
 // copies. Only the objects:<type> facet must hold. A row over the read limit of this (or an unknown) type is reported, not served.
 cachedPolicyObjects(tenant,type){
  if(!isSignedObjectType(type))throw TypeError('Signed object type is required');
  const state=this._verifiedActionState(tenant);
  if(state.oversizedTypes.has(type)||state.oversizedTypes.has('*'))return {oversized:true,values:[]};
  this._assertFacets(state,['objects:'+type]);
  const values=[...state.objects.values()].filter(value=>value.type===type).sort((a,b)=>a.firstSeq-b.firstSeq);
  return {oversized:false,values:values.map(value=>({id:value.id,seq:value.row.seq,body:structuredClone(value.payload)}))};
 }
 // Signed evaluations in ledger order (deep copies); latest keeps only the last evaluation per action.
 cachedEvaluations(tenant,{actionId,latest=false,values:copy=true}={}){
  const state=this._verifiedActionState(tenant);
  if(state.oversizedTypes.has('evaluation')||state.oversizedTypes.has('*'))return {oversized:true,values:[]};
  this._assertFacets(state,['evaluations']);
  let values=actionId===undefined?state.evaluations:state.evaluations.filter(value=>value.actionId===actionId);
  if(latest)values=[...new Map(values.map(value=>[value.actionId,value])).values()];
  return {oversized:false,values:copy?values.map(value=>structuredClone(value)):[]};
 }
 // Retained signed events, decrypted, sorted like ledgerEvents. The facets name which projections must also hold.
 cachedEvents(tenant,{facets=['keys','events'],actionId}={}){
  const state=this.verifiedFacets(tenant,facets);
  const events=[...state.eventsBySequence.values()].filter(event=>actionId===undefined||event.actionId===actionId);
  return events.sort((a,b)=>a.receivedAt.localeCompare(b.receivedAt)||a.source.localeCompare(b.source)||a.id.localeCompare(b.id)).map(event=>structuredClone(event));
 }
 // Signed review material of one case while every core facet holds: retained events and evaluations of the action in ledger
 // order, the case's decisions in signed order and the latest signed case, as deep copies. Counts over limits are reported first.
 cachedCaseMaterial(tenant,caseId,actionId,limits){
  const state=this.verifiedFacets(tenant),signedCase=state.objects.get(canonical(['case',caseId]));
  const events=[...state.eventsBySequence.values()].filter(event=>event.actionId===actionId),evaluations=state.evaluations.filter(value=>value.actionId===actionId);
  const decisions=[...state.objects.values()].filter(value=>value.type==='case_decision'&&value.payload.caseId===caseId).sort((a,b)=>a.firstSeq-b.firstSeq).map(value=>value.payload);
  const overLimit=events.length>limits.events||evaluations.length>limits.evaluations||decisions.length>limits.decisions,copy=values=>overLimit?[]:values.map(value=>structuredClone(value));
  return {oversized:state.oversizedTypes.size>0,overLimit,case:signedCase?structuredClone(signedCase.payload):null,events:copy(events),evaluations:copy(evaluations),decisions:copy(decisions)};
 }
 // Lookup of retained signed events by `${source}/${id}`; get returns a deep copy.
 cachedEventIndex(tenant,facets=['keys','events']){
  const state=this.verifiedFacets(tenant,facets),index=new Map();
  for(const event of state.eventsBySequence.values())index.set(`${event.source}/${event.id}`,event);
  return {has:ref=>index.has(ref),get:ref=>index.has(ref)?structuredClone(index.get(ref)):undefined};
 }
 checkProjection(tenant,original=this.ledgerEvents(tenant)){return checkEventProjection(this.db,tenant,original);}
 // Without facets every facet must hold (the action, analysis and ingest gate). Readers name the facets they serve from,
 // which keeps the per-projection blast radius of the former full-scan verifiers.
 verifiedFacets(tenant,facets){const state=this._verifiedActionState(tenant);this._assertFacets(state,facets);return state;}
 _assertFacets(state,facets){
  let first=null;
  for(const [facet,fault] of state.faults)if((facets?facets.includes(facet):!OPTIONAL_FACETS.has(facet))&&(!first||fault.order<first.order))first=fault;
  if(first)throw first.error;
 }
 verifiedStateStatus(tenant){
  const state=this.ledgerTransaction?.actionCandidates.get(tenant)||this.actionProjectionCache.get(tenant);
  if(!state)return {tenant,cached:false,maxAgeMs:this.verifiedStateMaxAgeMs};
  return {tenant,cached:true,count:state.count,head:state.head,verifiedAt:new Date(state.verifiedAt).toISOString(),updatedAt:new Date(state.updatedAt).toISOString(),
   coldVerifications:state.coldVerifications,maxAgeMs:this.verifiedStateMaxAgeMs,faults:[...state.faults.keys()].sort()};
 }
 _fault(state,facet,error){if(!state.faults.has(facet))state.faults.set(facet,{error,order:++state.faultSerial});}
 _facet(state,facet,check){try{check();}catch(error){this._fault(state,facet,error);}}
 _databaseVersions(){return {data:this.cachedStatement('PRAGMA data_version').get().data_version,schema:this.cachedStatement('PRAGMA schema_version').get().schema_version};}
 _keyDigest(value){return createHash('sha256').update(value).digest('hex');}
 _verifyEventKeys(tenant,expected){
  const rows=this.db.prepare('SELECT key_id,seq,key FROM event_keys WHERE tenant=? ORDER BY key_id').all(tenant);
  if(rows.length!==expected.size)throw Error('Event key projection differs from signed evidence');
  for(const row of rows){const value=expected.get(row.key_id);if(!value||value.seq!==row.seq||value.digest!==this._keyDigest(row.key))throw Error('Event key projection differs from signed evidence');}
 }
 // Cold check of every projection against the replayed signed state. A mismatch faults only its facet.
 _verifyActionState(tenant,state){
  const events=[...state.eventsBySequence.values()];
  this._facet(state,'events',()=>checkEventProjection(this.db,tenant,events));
  this._facet(state,'receipts',()=>checkReceiptProjection(this.db,tenant,state.receiptRecords,events));
  this._facet(state,'keys',()=>this._verifyEventKeys(tenant,state.keys));
  const signed=new Map(),projected=new Map();
  for(const value of state.objects.values()){if(!signed.has(value.type))signed.set(value.type,new Map());signed.get(value.type).set(value.id,canonical(value.payload));}
  for(const row of this.db.prepare('SELECT type,id,body FROM objects WHERE tenant=?').all(tenant)){if(!projected.has(row.type))projected.set(row.type,[]);projected.get(row.type).push(row);}
  for(const type of new Set([...signed.keys(),...projected.keys()]))this._facet(state,isSignedObjectType(type)?'objects:'+type:'objects:other',()=>{
   const expected=signed.get(type)||new Map(),rows=projected.get(type)||[];
   if(rows.length!==expected.size||rows.some(row=>expected.get(row.id)!==this._canonicalBody(row.body)))throw Error('Object projection differs from signed evidence');
  });
  this._facet(state,'evaluations',()=>checkEvaluationProjection(this.db,tenant,state.evaluations));
  if(!state.faults.has('actions'))this._facet(state,'actions',()=>checkActionRows(this.db,tenant,state.action.finish()));
  this._facet(state,'governance_documents',()=>checkGovernanceDocumentRows(this.db,tenant,state.governanceDocuments));
  this._facet(state,'development_runs',()=>checkDevelopmentRunProjection(this.db,tenant,[...state.developmentEvents.values()]));
 }
 _canonicalBody(body){try{return canonical(JSON.parse(body));}catch{return null;}}
 _applyReceiptEvidence(state,row,disclosed){
  const receiptIdentity=(source,id)=>canonical([source,id]),validDigest=/^[a-f0-9]{64}$/,validFingerprint=RECEIPT_FINGERPRINT;
  if(row.type==='event'){
   const keyId=row.payload?.keyId;state.receiptEvents.set(row.seq,{hash:row.hash,keyId});
   if(disclosed){const identity=receiptIdentity(disclosed.source,disclosed.id);if(state.receiptEntries.has(identity)||state.receiptCovered.has(row.seq)||typeof disclosed.fingerprint!=='string'||!disclosed.fingerprint)throw Error('Receipt retained event identity is invalid');state.receiptEntries.set(identity,{source:disclosed.source,id:disclosed.id,fingerprint:disclosed.fingerprint,eventSeq:row.seq,eventHash:row.hash,signed:false});state.receiptCovered.add(row.seq);}
   return;
  }
  if(row.type==='event_receipt'){
   const value=row.payload||{},event=state.receiptEvents.get(value.eventSeq),identity=receiptIdentity(value.source,value.id),existing=state.receiptEntries.get(identity),upgrading=existing&&!existing.signed&&existing.eventSeq===value.eventSeq;
   if(value.format!=='evidscope-event-receipt-v1'||typeof value.source!=='string'||!value.source||typeof value.id!=='string'||!value.id||!validFingerprint.test(value.fingerprint||'')||!Number.isSafeInteger(value.eventSeq)||value.eventSeq<1||!validDigest.test(value.eventHash||'')||!event||event.hash!==value.eventHash||row.seq<=value.eventSeq)throw Error('Receipt signed history is invalid');
   const disposition=state.receiptDispositions.get(event.keyId);if(disposition!==undefined&&row.seq>=disposition)throw Error('Receipt was not preserved before event disposition');
   if(value.basis!==undefined&&!['source_ingest','verified_before_retention'].includes(value.basis))throw Error('Receipt signed history has an invalid basis');
   if(value.basis==='source_ingest'&&row.principal!==value.source)throw Error('Receipt source attestation principal differs');
   if(value.basis==='verified_before_retention'&&value.attestedBy!==row.principal)throw Error('Receipt retention attestation principal differs');
   if(existing&&!upgrading||state.receiptCovered.has(value.eventSeq)&&!upgrading)throw Error('Receipt signed history is duplicated');
   const retained=state.eventsBySequence.get(value.eventSeq);if(retained&&(retained.source!==value.source||retained.id!==value.id||retained.fingerprint!==value.fingerprint))throw Error('Receipt signed history differs from retained event');
   state.receiptEntries.set(identity,{source:value.source,id:value.id,fingerprint:value.fingerprint,eventSeq:value.eventSeq,eventHash:value.eventHash,signed:true});state.receiptCovered.add(value.eventSeq);state.receiptSignedSequences.add(value.eventSeq);return;
  }
  if(row.type==='retention_disposition')for(const keyId of row.payload?.keyIds||[]){const sequence=state.eventKeys.get(keyId);if(sequence!==undefined&&!state.receiptSignedSequences.has(sequence))throw Error('Receipt history is missing for disposed legacy event');if(!state.receiptDispositions.has(keyId))state.receiptDispositions.set(keyId,row.seq);}
 }
 _captureActionTouches(state,row,disclosed,touched){
  if(!touched)return;
  const remember=id=>{if(typeof id==='string'&&id&&!touched.actions.has(id))touched.actions.set(id,state.action.get(id));};
  if(row.type==='event')remember(disclosed?.actionId??row.payload.actionId);
  else if(row.type===APPROVAL_TYPE)remember(row.payload.actionId);
  else if(['asset','rule','exception',...REGISTRY_INPUT_TYPES,STOP_ORDER_TYPE].includes(row.type)){if(!touched.allActions){for(const value of state.action.rows())remember(value.id);touched.allActions=true;}}
  else if(row.type==='evaluation')remember(row.payload.actionId);
  else if(row.type==='retention_disposition'){
   const sequences=Array.isArray(row.payload.sequences)?row.payload.sequences:(row.payload.keyIds||[]).map(keyId=>state.eventKeys.get(keyId));
   for(const sequence of sequences)remember(state.actionByEventSequence.get(sequence));
  }
 }
 // Replays one authenticated row. Signed-history problems that concern one projection fault that facet and the replay goes on,
 // so the remaining facets stay servable; chain and checkpoint failures are raised by the caller and fail everything.
 // known ({text, stored}): an event row this transaction wrote, with the plaintext and stored key bytes it sealed.
 _applyActionStateRow(tenant,state,row,touched,known){
  if(row.recordBytes>VERIFIED_READ_ROW_BYTES)state.oversizedTypes.add(typeof row.type==='string'?row.type:'*');
  this._facet(state,'objects:'+row.type,()=>{
   const objectValue=signedObjectProjection(row);if(!objectValue)return;
   touched?.objects.add(objectValue.key);state.objects.set(objectValue.key,{...objectValue,row,firstSeq:state.objects.get(objectValue.key)?.firstSeq??row.seq});
  });
  if(row.type==='evaluation')state.evaluations.push(row.payload);
  let disclosed;
  this._facet(state,'events',()=>{
   if(row.type==='event'){
    touched?.receiptEvents.add(row.seq);
    if(isEncryptedEvent(row.payload)){
     state.receiptRecords.push({tenant:row.tenant,seq:row.seq,type:row.type,payload:{keyId:row.payload.keyId},hash:row.hash,principal:row.principal});
     state.eventKeys.set(row.payload.keyId,row.seq);touched?.keys.add(row.payload.keyId);
     const stored=known?{key:known.stored}:this.cachedStatement('SELECT key FROM event_keys WHERE tenant=? AND key_id=?').get(tenant,row.payload.keyId);
     if(known){state.keys.set(row.payload.keyId,{seq:row.seq,digest:this._keyDigest(stored.key)});disclosed=JSON.parse(known.text);}
     else if(stored){state.keys.set(row.payload.keyId,{seq:row.seq,digest:this._keyDigest(stored.key)});try{disclosed=this._openEvent(row.payload,stored.key).event;}catch(error){this._fault(state,'keys',error);throw error;}}
    }else {
     disclosed=row.payload;
     state.receiptRecords.push({tenant:row.tenant,seq:row.seq,type:row.type,payload:{},hash:row.hash,principal:row.principal});
    }
   }else if(row.type==='event_receipt'||row.type==='retention_disposition')state.receiptRecords.push(row);
  });
  this._facet(state,'receipts',()=>this._applyReceiptEvidence(state,row,disclosed));
  if(!state.faults.has('actions'))this._facet(state,'actions',()=>{this._captureActionTouches(state,row,disclosed,touched);state.action.apply(row,disclosed);});
  this._facet(state,'events',()=>{
   if(row.type==='event')state.actionByEventSequence.set(row.seq,disclosed?.actionId??row.payload.actionId);
   if(disclosed){const event={...disclosed,seq:row.seq,hash:row.hash};state.eventsBySequence.set(row.seq,event);touched?.events.set(canonical([event.source,event.id]),event);touched?.receipts.set(canonical([event.source,event.id]),{source:event.source,id:event.id,fingerprint:event.fingerprint});}
   if(row.type==='event_receipt'){const value=row.payload;touched?.receipts.set(canonical([value.source,value.id]),{source:value.source,id:value.id,fingerprint:value.fingerprint});}
   if(row.type==='retention_disposition')for(const keyId of row.payload.keyIds||[]){const sequence=state.eventKeys.get(keyId),event=sequence===undefined?null:state.eventsBySequence.get(sequence);if(event)touched?.events.set(canonical([event.source,event.id]),null);state.disposed.add(keyId);state.keys.delete(keyId);if(sequence!==undefined)state.eventsBySequence.delete(sequence);touched?.keys.add(keyId);}
  });
  if(row.type==='governance_document')this._facet(state,'governance_documents',()=>{const value=applyGovernanceDocumentRecord(state.governanceDocuments,row.payload);touched?.governanceDocuments.add(value.id);});
  if(row.type==='development_run_event')this._facet(state,'development_runs',()=>{
   const event=row.payload;
   if(!event||typeof event!=='object'||Array.isArray(event)||event.tenant!==tenant||typeof event.source!=='string'||typeof event.eventId!=='string')throw Error('Development projection differs from signed evidence: invalid authenticated event');
   const identity=canonical([event.source,event.eventId]);if(state.developmentEvents.has(identity))throw Error('Development projection differs from signed evidence: duplicate authenticated event identity');
   state.developmentEvents.set(identity,event);touched?.developmentEvents.add(identity);
  });
  if(row.type==='asset'&&row.payload?.id)state.analysisAssets.set(`${row.payload.id}:${row.seq}`,row.payload);
  if(row.type==='rule'&&row.payload?.id)state.analysisRules.set(row.payload.id,row.payload);
  if(row.type==='exception'&&row.payload?.id)state.analysisExceptions.set(row.payload.id,row.payload);
  if(REGISTRY_TYPES.includes(row.type)||row.type===STOP_ORDER_TYPE)
   state.registryRows.push({seq:row.seq,type:row.type,principal:row.principal,recordedAt:row.recordedAt,hash:row.hash,payload:row.payload});
  if(row.type===APPROVAL_TYPE&&typeof row.payload?.id==='string'){
   const id=row.payload.id,ids=state.approvalActions.get(row.payload.actionId)||[];
   if(typeof row.payload.actionId==='string'&&!ids.includes(id))state.approvalActions.set(row.payload.actionId,[...ids,id]);
   state.approvalHistory.set(id,[...(state.approvalHistory.get(id)||[]),{seq:row.seq,hash:row.hash,recordedAt:row.recordedAt,principal:row.principal,payload:row.payload}]);
  }
 }
 _checkKeyCoverage(state,keyIds,sequences){
  for(const keyId of keyIds)if(state.eventKeys.has(keyId)&&!state.keys.has(keyId)&&!state.disposed.has(keyId))this._fault(state,'keys',Error('Event key missing without authorized disposition'));
  for(const sequence of sequences)if(!state.receiptCovered.has(sequence))this._fault(state,'receipts',Error('Receipt history is missing for disposed legacy event'));
 }
 _emptyActionState(tenant){return {tenant,count:0,head:'0'.repeat(64),action:createActionProjectionReducer(tenant),actionByEventSequence:new Map(),
  analysisAssets:new Map(),analysisRules:new Map(),analysisExceptions:new Map(),registryRows:[],approvalActions:new Map(),approvalHistory:new Map(),objects:new Map(),evaluations:[],
  receiptRecords:[],receiptEvents:new Map(),receiptEntries:new Map(),receiptCovered:new Set(),receiptSignedSequences:new Set(),receiptDispositions:new Map(),eventsBySequence:new Map(),eventKeys:new Map(),keys:new Map(),disposed:new Set(),
  faults:new Map(),faultSerial:0,oversizedTypes:new Set(),governanceDocuments:new Map(),developmentEvents:new Map(),verifiedAt:0,updatedAt:0,coldVerifications:0,versions:this._databaseVersions()};}
 _cloneActionState(state){return {...state,action:state.action.fork(),actionByEventSequence:new Map(state.actionByEventSequence),
  analysisAssets:new Map(state.analysisAssets),analysisRules:new Map(state.analysisRules),analysisExceptions:new Map(state.analysisExceptions),registryRows:state.registryRows.slice(),
  approvalActions:new Map(state.approvalActions),approvalHistory:new Map(state.approvalHistory),objects:new Map(state.objects),
  evaluations:state.evaluations.slice(),receiptRecords:state.receiptRecords.slice(),receiptEvents:new Map(state.receiptEvents),receiptEntries:new Map(state.receiptEntries),
  receiptCovered:new Set(state.receiptCovered),receiptSignedSequences:new Set(state.receiptSignedSequences),receiptDispositions:new Map(state.receiptDispositions),eventsBySequence:new Map(state.eventsBySequence),eventKeys:new Map(state.eventKeys),keys:new Map(state.keys),
  disposed:new Set(state.disposed),faults:new Map(state.faults),oversizedTypes:new Set(state.oversizedTypes),governanceDocuments:new Map(state.governanceDocuments),developmentEvents:new Map(state.developmentEvents)};}
 // A faulted state is cached only when it describes committed data: a write transaction can be between a ledger append
 // and its projection rows, and its candidate would be promoted at COMMIT.
 _stageActionState(tenant,state){
  state.versions=this._databaseVersions();state.mutationSerial=this.projectionMutationSerial;state.updatedAt=Date.now();
  if(state.faults.size&&this.ledgerTransaction&&!this.ledgerTransaction.readOnly){this.ledgerTransaction.actionCandidates.delete(tenant);if(this.actionProjectionCache.get(tenant)===state)this.actionProjectionCache.delete(tenant);return;}
  if(this.ledgerTransaction)this.ledgerTransaction.actionCandidates.set(tenant,state);else this.actionProjectionCache.set(tenant,state);
 }
 // Delta check of the rows a verified suffix touched; a mismatch faults only its facet.
 _verifyActionDelta(tenant,state,touched){
  if(!state.faults.has('actions'))this._facet(state,'actions',()=>{
   for(const [id,prior] of touched.actions){const expected=state.action.get(id);if(canonical(prior)===canonical(expected))continue;const row=this.cachedStatement('SELECT tenant,id,version,analyzed FROM actions WHERE tenant=? AND id=?').get(tenant,id);if(canonical(row)===canonical(expected))continue;throw Error('Action projection differs from signed evidence');}
  });
  this._facet(state,'events',()=>{
   for(const [identity,expected] of touched.events){
    const [source,id]=JSON.parse(identity),row=this.cachedStatement('SELECT tenant,source,id,fingerprint,action_id,trace_id,kind,received,body FROM events WHERE tenant=? AND source=? AND id=?').get(tenant,source,id);
    if(expected===null){if(row)throw Error('Event projection differs from signed evidence: retained disposed row');continue;}
    let body;try{body=JSON.parse(row?.body);}catch{throw Error('Event projection differs from signed evidence: invalid body JSON');}
    if(!row||canonical(body)!==canonical(expected)||canonical([row.tenant,row.source,row.id,row.fingerprint,row.action_id,row.trace_id,row.kind,row.received])!==canonical([expected.tenant,expected.source,expected.id,expected.fingerprint,expected.actionId,expected.traceId,expected.kind,expected.receivedAt]))throw Error('Event projection differs from signed evidence');
   }
  });
  this._facet(state,'receipts',()=>{
   for(const [identity,expected] of touched.receipts){const [source,id]=JSON.parse(identity),row=this.cachedStatement('SELECT source,id,fingerprint FROM receipts WHERE tenant=? AND source=? AND id=?').get(tenant,source,id);if(!row||canonical(row)!==canonical(expected))throw Error('Receipt projection differs from signed history');}
  });
  this._facet(state,'keys',()=>{
   for(const keyId of touched.keys){const expected=state.keys.get(keyId),row=this.cachedStatement('SELECT seq,key FROM event_keys WHERE tenant=? AND key_id=?').get(tenant,keyId);if(!expected){if(row)throw Error('Event key projection differs from signed evidence');continue;}if(!row||row.seq!==expected.seq||this._keyDigest(row.key)!==expected.digest)throw Error('Event key projection differs from signed evidence');}
  });
  for(const key of touched.objects){const expected=state.objects.get(key);if(!expected)continue;this._facet(state,'objects:'+expected.type,()=>{const row=this.cachedStatement('SELECT body FROM objects WHERE tenant=? AND type=? AND id=?').get(tenant,expected.type,expected.id);if(!row||this._canonicalBody(row.body)!==canonical(expected.payload))throw Error('Object projection differs from signed evidence');});}
  if(touched.governanceDocuments.size)this._facet(state,'governance_documents',()=>checkGovernanceDocumentRows(this.db,tenant,state.governanceDocuments,touched.governanceDocuments));
  if(touched.developmentEvents.size)this._facet(state,'development_runs',()=>{for(const identity of touched.developmentEvents)this._verifyDevelopmentRow(tenant,state.developmentEvents.get(identity));});
  this._facet(state,'evaluations',()=>{
   if(touched.evaluationsStart!==state.evaluations.length){const rows=this.db.prepare('SELECT action_id,version,body FROM evaluations WHERE tenant=? ORDER BY id LIMIT -1 OFFSET ?').all(tenant,touched.evaluationsStart);if(touched.evaluationsStart+rows.length!==state.evaluations.length)throw Error('Evaluation projection differs from signed evidence');for(let index=0;index<rows.length;index++){const expected=state.evaluations[touched.evaluationsStart+index],row=rows[index];if(row.action_id!==expected.actionId||row.version!==expected.version||canonical(JSON.parse(row.body))!==canonical(expected))throw Error('Evaluation projection differs from signed evidence');}}
  });
 }
 _assertCheckpointHead(tenant,checkpoint){
  const head=this.cachedStatement('SELECT seq,hash FROM ledger WHERE tenant=? ORDER BY seq DESC LIMIT 1').get(tenant);
  if(checkpoint.count===0){if(head||checkpoint.head!=='0'.repeat(64))throw Error('Truncated or inconsistent export');}
  else if(!head||head.seq!==checkpoint.count||head.hash!==checkpoint.head)throw Error('Truncated or inconsistent export');
 }
 _coldActionState(tenant,checkpoint){
  const state=this._emptyActionState(tenant);
  for(const row of this.verifiedRows(tenant,16*1024*1024)){
   if(row.oversized){const type=this.db.prepare("SELECT json_extract(body,'$.type') AS type FROM ledger WHERE tenant=? AND seq=?").get(tenant,row.seq)?.type;if(['event','event_receipt','asset','rule','exception','evaluation','retention_disposition'].includes(type)||isSignedObjectType(type))throw Error('Action history row exceeds replay limit');state.oversizedTypes.add(type||'*');continue;}
   this._applyActionStateRow(tenant,state,row);
  }
  this._checkKeyCoverage(state,state.eventKeys.keys(),state.receiptEvents.keys());
  state.count=checkpoint.count;state.head=checkpoint.head;return state;
 }
 _verifiedActionSuffix(tenant,state,checkpoint){
  const rows=[];let sequence=state.count,previous=state.head;
  const query=this.db.prepare(`SELECT seq,hash,length(CAST(body AS BLOB)) AS bytes,
   json_extract(body,'$.tenant') AS record_tenant,json_extract(body,'$.seq') AS record_seq,
   json_extract(body,'$.previous') AS previous,
   CASE WHEN length(CAST(body AS BLOB))<=? THEN body ELSE NULL END AS body
   FROM ledger WHERE tenant=? AND seq>? ORDER BY seq`);
  for(const row of query.iterate(16*1024*1024,tenant,state.count)){
   if(row.seq!==++sequence||row.record_seq!==sequence||row.record_tenant!==tenant||row.previous!==previous)throw Error('Sequence, tenant or previous hash mismatch');
   let hash;
   if(row.body!==null)hash=digest(row.body);
   else {const hasher=createHash('sha256'),chunk=this.db.prepare('SELECT substr(CAST(body AS BLOB),?,65536) AS chunk FROM ledger WHERE tenant=? AND seq=?');for(let offset=1;offset<=row.bytes;offset+=65536)hasher.update(chunk.get(offset,tenant,row.seq).chunk);hash=hasher.digest('hex');}
   if(hash!==row.hash)throw Error('Record digest mismatch');previous=hash;
    if(row.body===null){const type=this.db.prepare("SELECT json_extract(body,'$.type') AS type FROM ledger WHERE tenant=? AND seq=?").get(tenant,row.seq)?.type;if(['event','event_receipt','asset','rule','exception','evaluation','retention_disposition'].includes(type)||isSignedObjectType(type))throw Error('Action history row exceeds replay limit');state.oversizedTypes.add(type||'*');continue;}
   rows.push({...JSON.parse(row.body),hash:row.hash,recordBytes:row.bytes});
  }
  if(sequence!==checkpoint.count||previous!==checkpoint.head)throw Error('Truncated or inconsistent export');
  return rows;
 }
 // Round 6 (docs/performance.md): a write transaction that began on a current verified state carries it over the rows it
 // appended, before COMMIT and under its write lock, instead of the next transaction reading them back. The replay and the
 // projection delta check are the same as for a suffix read from SQL; only re-deriving what this transaction produced is
 // skipped: the record text and hash it inserted, and the plaintext and key bytes of each event it sealed (decryption).
 // Rows of another writer change data_version, writes of this connection outside projectionMutation change the mutation
 // serial, and either makes the next check cold, as before. Not carried (left to the next check): external or faulted states,
 // rows this transaction did not append, oversized rows. Any error drops the state; a rollback drops it from the cache.
 _advanceVerifiedStates(){
  const context=this.ledgerTransaction;if(!context.appended.length||context.external||context.readOnly)return;
  this._syncProjectionMutationClock();const versions=this._databaseVersions();
  for(const tenant of context.dirty){
   const state=context.actionCandidates.get(tenant)||this.actionProjectionCache.get(tenant),head=context.heads.get(tenant);
   const rows=context.appended.filter(row=>row.tenant===tenant);
   if(!state||!rows.length||state.faults.size||state.versions.data!==versions.data||state.versions.schema!==versions.schema
    ||state.mutationSerial!==this.projectionMutationSerial||state.count!==rows[0].seq-1||state.head!==rows[0].previous||head.seq!==rows.at(-1).seq||head.hash!==rows.at(-1).hash
    ||rows.some((row,index)=>row.seq!==state.count+index+1||index&&row.previous!==rows[index-1].hash||Buffer.byteLength(row.body)>16*1024*1024))continue;
   context.advanced.add(tenant);
   const touched={actions:new Map(),allActions:false,events:new Map(),receipts:new Map(),keys:new Set(),receiptEvents:new Set(),objects:new Set(),governanceDocuments:new Set(),developmentEvents:new Set(),evaluationsStart:state.evaluations.length};
   try{
    for(const row of rows)this._applyActionStateRow(tenant,state,{...JSON.parse(row.body),hash:row.hash,recordBytes:Buffer.byteLength(row.body)},touched,row.known);
    this._checkKeyCoverage(state,touched.keys,touched.receiptEvents);
    state.count=head.seq;state.head=head.hash;this._verifyActionDelta(tenant,state,touched);
   }catch{this.actionProjectionCache.delete(tenant);context.actionCandidates.delete(tenant);continue;}
   this._stageActionState(tenant,state);
  }
 }
 // Incremental verified state of a tenant's signed history and its projections (see _verifyActionState for the facets).
 // Cold: replay the whole signed ledger; warm: verify only the signed suffix and the projection rows it touched. A state
 // older than verifiedStateMaxAgeMs, or cold:true, is rebuilt cold so edits that bypass SQLite are found within that bound.
 _verifiedActionState(tenant,{cold=false}={}){
  this._syncProjectionMutationClock();
  const checkpoint=this.checkpoint(tenant);verifyCheckpoint(checkpoint,this.publicKey);if(checkpoint.tenant!==tenant)throw Error('Checkpoint tenant mismatch');this._assertCheckpointHead(tenant,checkpoint);
  const versions=this._databaseVersions(),cached=this.ledgerTransaction?.actionCandidates.get(tenant)||this.actionProjectionCache.get(tenant);
  const current=cached&&cached.versions.data===versions.data&&cached.versions.schema===versions.schema&&cached.mutationSerial===this.projectionMutationSerial;
  if(current){
   if(checkpoint.count<cached.count)throw Error('Ledger checkpoint moved behind previously verified state');
   if(checkpoint.count===cached.count&&checkpoint.head!==cached.head)throw Error('Ledger checkpoint conflicts with previously verified state');
  }
  if(!current||cold||Date.now()-cached.verifiedAt>=this.verifiedStateMaxAgeMs){
   const candidate=this._coldActionState(tenant,checkpoint);this._verifyActionState(tenant,candidate);
   candidate.verifiedAt=Date.now();candidate.coldVerifications=(cached?.coldVerifications||0)+1;this._stageActionState(tenant,candidate);return candidate;
  }
  if(checkpoint.count===cached.count)return cached;
  const touched={actions:new Map(),allActions:false,events:new Map(),receipts:new Map(),keys:new Set(),receiptEvents:new Set(),objects:new Set(),governanceDocuments:new Set(),developmentEvents:new Set(),evaluationsStart:cached.evaluations.length},pending=!!this.ledgerTransaction?.dirty.has(tenant),inPlace=!pending&&!this.ledgerTransaction?.external;
  const candidate=inPlace?cached:this._cloneActionState(cached);
  try{
   const suffix=this._verifiedActionSuffix(tenant,candidate,checkpoint);
   for(const row of suffix)this._applyActionStateRow(tenant,candidate,row,touched);
   this._checkKeyCoverage(candidate,touched.keys,touched.receiptEvents);
   candidate.count=checkpoint.count;candidate.head=checkpoint.head;this._verifyActionDelta(tenant,candidate,touched);
  }catch(error){if(inPlace){this.actionProjectionCache.delete(tenant);this.ledgerTransaction?.actionCandidates.delete(tenant);}throw error;}
  this._stageActionState(tenant,candidate);return candidate;
 }
 checkActionProjection(tenant,{cold=false}={}){const state=this._verifiedActionState(tenant,{cold});this._assertFacets(state);return {valid:true,actions:state.action.size};}
 checkDevelopmentRunProjection(tenant){
  const state=this._verifiedActionState(tenant);
  if(state.oversizedTypes.has('development_run_event')||state.oversizedTypes.has('*'))throw Error('Development history row exceeds replay limit');
  this._assertFacets(state,['development_runs']);return {valid:true,developmentEvents:state.developmentEvents.size};
 }
 _verifyDevelopmentRow(tenant,signed){
  const row=this.db.prepare('SELECT tenant,source,event_id,run_id,occurred,received,fingerprint,body FROM development_run_events WHERE tenant=? AND source=? AND event_id=?').get(tenant,signed.source,signed.eventId);
  if(!row||this._canonicalBody(row.body)!==canonical(signed))throw Error('Development projection differs from signed evidence: body');
  const index=[row.tenant,row.source,row.event_id,row.run_id,row.occurred,row.received,row.fingerprint];
  if(canonical(index)!==canonical([signed.tenant,signed.source,signed.eventId,signed.runId,signed.occurredAt,signed.receivedAt,signed.fingerprint]))throw Error('Development projection differs from signed evidence: index');
 }
 // Latest signed governance document metadata per id, in first-signed order, as deep copies.
 cachedGovernanceDocuments(tenant){
  const state=this._verifiedActionState(tenant);
  if(state.oversizedTypes.has('governance_document'))return {oversized:true,latest:new Map()};
  this._assertFacets(state,['governance_documents']);
  return {oversized:false,latest:new Map([...state.governanceDocuments].map(([id,value])=>[id,structuredClone(value)]))};
 }
 _tlogOrigin(tenant){return tenantOrigin(this.tlog.base,tenant);}
 _tlogRow(tenant){return this.tlog?this.db.prepare('SELECT size,peaks,root,note FROM tlog_state WHERE tenant=? AND origin=?').get(tenant,this._tlogOrigin(tenant))||null:null;}
 _tlogVerifier(origin){let v=this.tlog.verifiers.get(origin);if(!v){v=noteVerifier(logVkey(origin,this.publicKey));this.tlog.verifiers.set(origin,v);}return v;}
 // I2: the stored frontier folds to the signed root, and the signed note names this tenant origin and size.
 _tlogVerifiedPeaks(tenant,row){
  const origin=this._tlogOrigin(tenant),peaks=blobToPeaks(row.peaks,row.size),root=frontierRoot(peaks);
  if(!root.equals(Buffer.from(row.root)))throw Error('Ledger tlog frontier differs from its signed root; refusing to re-seal');
  if(this.tlog.verified.get(tenant)!==row.note){
   const c=parseCheckpoint(openNote(row.note,[this._tlogVerifier(origin)]).text);
   if(c.origin!==origin||c.size!==row.size||!c.root.equals(root))throw Error('Ledger tlog checkpoint differs from its signed note; refusing to re-seal');this.tlog.verified.set(tenant,row.note);}
  return peaks;
 }
 _tlogHeadPeaks(tenant,head){
  const row=this._tlogRow(tenant);
  // Only the startup syncTlog rebuilds lost state; at runtime a missing row or a head below its witnessed heads entry is a tamper.
  const floor=this.tlogHeadsFloor?.(this._tlogOrigin(tenant))||0;
  if(head.seq<floor)throw Error(`Ledger head (size ${head.seq}) is behind its heads log entry (size ${floor}) (rollback); refusing to re-seal`);
  if(!head.seq){if(row?.size)throw Error('Ledger is missing beneath an existing tlog checkpoint');return [];}
  if(!row)throw Error('Truncated or inconsistent tlog state: the tenant checkpoint is missing beneath existing history; refusing to re-seal');
  if(row.size!==head.seq)throw Error('Ledger head differs from previously signed tlog checkpoint; refusing to re-seal');
  const peaks=this._tlogVerifiedPeaks(tenant,row);
  if(row.size%2===1&&!peaks.at(-1).equals(recordLeaf(head.hash)))throw Error('Ledger head differs from previously signed tlog checkpoint; refusing to re-seal');
  return peaks;
 }
 // Legacy or lost cache: rebuild only from history that verifies against the signed v1 checkpoint (no re-sealing of unsigned rows).
 _tlogRebuild(tenant,sizes=[]){
  const leaves=function*(rows){for(const row of rows)yield recordLeaf(row.hash);};
  const {roots,size,peaks}=rootsAtSizes(leaves(this.verifiedRows(tenant,16*1024*1024,{hashesOnly:true})),sizes);
  return {roots,size,peaks};
 }
 _writeTlog(tenant,size,peaks){
  const origin=this._tlogOrigin(tenant),root=frontierRoot(peaks),note=signNote(formatCheckpoint({origin,size,root}),{name:origin,privateKey:this.key,pub:this.tlog.pub});
  this.db.prepare('INSERT INTO tlog_state VALUES(?,?,?,?,?,?) ON CONFLICT(tenant,origin) DO UPDATE SET size=excluded.size,peaks=excluded.peaks,root=excluded.root,note=excluded.note').run(tenant,origin,size,peaksToBlob(peaks),root,note);
  this.tlog.verified.set(tenant,note);
 }
 // Committed note, or the unsigned pending head inside a transaction: notes are signed only at commit.
 tlogCheckpoint(tenant){
  if(!this.tlog)return null;
  const origin=this._tlogOrigin(tenant),pending=this.ledgerTransaction?.dirty.has(tenant)&&this.ledgerTransaction.heads.get(tenant);
  if(pending?.peaks)return {origin,size:pending.seq,root:frontierRoot(pending.peaks),note:null,pending:true};
  const row=this._tlogRow(tenant);
  return row?{origin,size:row.size,root:Buffer.from(row.root),note:row.note,pending:false}:{origin,size:0,root:EMPTY_ROOT,note:null,pending:false};
 }
 // Startup migration: create or extend tlog state for every ledger tenant before any request can append.
 syncTlog(){
  if(!this.tlog)return {tenants:0,rebuilt:0};
  const tenants=this.db.prepare('SELECT DISTINCT tenant FROM ledger ORDER BY tenant').all().map(r=>r.tenant);let rebuilt=0;
  for(const tenant of tenants){
   const row=this._tlogRow(tenant),head=this.db.prepare('SELECT seq,hash FROM ledger WHERE tenant=? ORDER BY seq DESC LIMIT 1').get(tenant);
   if(row&&row.size===head.seq){this._tlogHeadPeaks(tenant,head);continue;}
   if(row&&row.size>head.seq)throw Error('Truncated or inconsistent ledger: tenant is behind its signed tlog checkpoint (rollback)');
   if(row)this._tlogVerifiedPeaks(tenant,row);
   const result=this._tlogRebuild(tenant,row?[row.size]:[]);
   if(row&&!result.roots.get(row.size)?.equals(Buffer.from(row.root)))throw Error('Ledger conflicts with its signed tlog checkpoint (fork)');
   this.projectionMutation(()=>this._writeTlog(tenant,result.size,result.peaks));rebuilt++;
  }
  const prefix=this.tlog.base+'/t/';
  for(const {tenant} of this.db.prepare('SELECT tenant FROM tlog_state WHERE substr(origin,1,?)=? AND size>0').all(prefix.length,prefix))if(!tenants.includes(tenant))throw Error('Ledger is missing beneath an existing tlog checkpoint (tenant removal)');
  return {tenants:tenants.length,rebuilt};
 }
 rebuild(p) {return this.transaction(()=>{const bundle=this.rawBundle(p.tenant);verifyBundle(bundle,this.publicKey,undefined,{chainOnly:true});const original=this.decodeRecords(bundle),development=bundle.records.filter(row=>row.type==='development_run_event').map(row=>row.payload),receipts=expectedReceiptProjection(p.tenant,bundle.records,original);this.db.prepare('DELETE FROM events WHERE tenant=?').run(p.tenant);this.db.prepare('DELETE FROM receipts WHERE tenant=?').run(p.tenant);for(const e of original)this.project(e);for(const value of receipts.entries.values())this.db.prepare('INSERT OR REPLACE INTO receipts VALUES(?,?,?,?)').run(p.tenant,value.source,value.id,value.fingerprint);this.db.prepare('DELETE FROM development_run_events WHERE tenant=?').run(p.tenant);for(const e of development)this.db.prepare('INSERT INTO development_run_events VALUES(?,?,?,?,?,?,?,?)').run(e.tenant,e.source,e.eventId,e.runId,e.occurredAt,e.receivedAt,e.fingerprint,JSON.stringify(e));this.append(p.tenant,'projection_rebuild',{projections:['events','receipts','development_run_events']},p.id);return {rebuilt:original.length,receipts:receipts.entries.size,developmentEvents:development.length};});}
 project(e) {this.projectionMutation(()=>{this.projectionStatement('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)').run(e.tenant,e.source,e.id,e.fingerprint,e.actionId,e.traceId,e.kind,e.receivedAt,JSON.stringify(e));this.projectionStatement('INSERT OR IGNORE INTO receipts VALUES(?,?,?,?)').run(e.tenant,e.source,e.id,e.fingerprint);});}
 count(name,n=1) {if(n)this.cachedStatement('INSERT INTO counters VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value').run(name,n);}
 close(){this.accessLog?.close();this.statements?.clear();this.db.close();}
}
