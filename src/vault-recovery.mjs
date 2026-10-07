import {DatabaseSync,backup} from 'node:sqlite';
import {createHash,createPrivateKey,createPublicKey,createCipheriv,createDecipheriv,randomBytes,sign,verify} from 'node:crypto';
import {mkdirSync,mkdtempSync,lstatSync,existsSync,readdirSync,readFileSync,writeFileSync,copyFileSync,unlinkSync,renameSync,chmodSync,createReadStream,createWriteStream,rmdirSync} from 'node:fs';
import {resolve,join,dirname,basename,relative,isAbsolute,sep} from 'node:path';
import {pipeline} from 'node:stream/promises';
import {Store} from './store.mjs';
import {canonical,digest,verifyCheckpoint} from './crypto.mjs';
import {checkDocumentFiles} from './document-integrity.mjs';
import {checkObjectProjection} from './object-integrity.mjs';
import {checkEvaluationProjection} from './evaluation-integrity.mjs';
import {checkActionProjection} from './action-integrity.mjs';
import {checkEventProjection} from './event-integrity.mjs';
import {checkDevelopmentRunProjection} from './development-integrity.mjs';
import {checkReceiptProjection} from './receipt-integrity.mjs';
import {signRecoveryFrontier,verifyRecoveryFrontier,applyRecoveryFrontier} from './recovery-frontier.mjs';
import {createKeyring,PURPOSES,LEGACY_KEY_ID,KEY_ID_PATTERN} from './data-keys.mjs';
import {sealRestorationState,pinRestorationState,recoveryPinPath} from './recovery-state.mjs';
import {frontierTransparency,planTlogEpoch,writeTlogEpochs} from './transparency-epoch.mjs';
import {signerKeysOf} from './transparency.mjs';
import {headsOrigin,validateOriginBase} from './tlog.mjs';
import {ACCESS_BATCH_TYPE,ACCESS_LOG_FILE,verifyAccessLogDatabase} from './access-log.mjs';

const FORMAT='evidscope-vault-backup-v1',FORMAT_V2='evidscope-vault-backup-v2';
const backupAad=(format,keyId)=>Buffer.from(format===FORMAT?FORMAT:canonical({format,keyId}));
const ACCESS_MEMBER='access-log.db.enc',accessAad=(format,keyId)=>Buffer.from(canonical({format,keyId,member:ACCESS_LOG_FILE}));
const PLAINTEXT_FILES=['evidence.db','evidence.db-wal','evidence.db-shm',ACCESS_LOG_FILE,ACCESS_LOG_FILE+'-wal',ACCESS_LOG_FILE+'-shm'];
// Every sealed access range named by the snapshot's signed audit_access_batch records must be present in the access-log
// snapshot (taken after the evidence snapshot, so it can only be longer). Returns the sealed/unsealed counts per tenant.
function checkAccessLogSnapshot(evidenceFile,accessFile,tenants){
 const evidence=new DatabaseSync(evidenceFile,{readOnly:true,timeout:5000}),access=accessFile?new DatabaseSync(accessFile,{readOnly:true,timeout:5000}):null,out={};
 try{
  for(const tenant of tenants){
   const records=evidence.prepare("SELECT seq,body FROM ledger WHERE tenant=? AND json_extract(body,'$.type')=? ORDER BY seq").all(tenant,ACCESS_BATCH_TYPE).map(row=>{const r=JSON.parse(row.body);return {seq:row.seq,type:r.type,payload:r.payload};});
   if(!access){if(records.length)throw Error('Access log is missing beneath sealed access batches');continue;}
   const checked=verifyAccessLogDatabase(access,tenant,records);out[tenant]={sealedEntries:checked.sealedEntries,batches:checked.batches};
  }
  return out;
 }finally{evidence.close();access?.close();}
}
const contained=(root,path)=>{const rel=relative(root,path);return !rel||!isAbsolute(rel)&&rel!=='..'&&!rel.startsWith('..'+sep);};
const hashBytes=bytes=>createHash('sha256').update(bytes).digest('hex');
const publicDer=key=>createPublicKey(key).export({format:'der',type:'spki'});
function keys(privateKey,publicKey,{dataKey,previousDataKeys=[]}={}){
 const key=typeof privateKey==='object'&&privateKey.type==='private'?privateKey:createPrivateKey(privateKey);
 const pub=typeof publicKey==='object'&&publicKey.type==='public'?publicKey:createPublicKey(publicKey);
 if(key.asymmetricKeyType!=='ed25519'||!publicDer(key).equals(pub.export({format:'der',type:'spki'})))throw Error('Independent trust key does not match vault key');
 return {key,pub,keyring:createKeyring({signingKey:key,dataKey,previousDataKeys})};
}
function noLinks(path){
 const absolute=resolve(path);let current=absolute;
 for(;;){if(existsSync(current)&&lstatSync(current).isSymbolicLink())throw Error('Symlink or junction is not allowed');const parent=dirname(current);if(parent===current)break;current=parent;}
 return absolute;
}
function member(root,path){
 if(typeof path!=='string'||path.includes('\\')||isAbsolute(path)||path.split('/').some(x=>!x||x==='.'||x==='..'))throw Error('Invalid backup member path');
 const file=resolve(root,...path.split('/')),rel=relative(root,file);
 if(!rel||rel.startsWith('..'+sep)||isAbsolute(rel))throw Error('Backup member escapes directory');
 noLinks(file);return file;
}
async function hashFile(file){const hash=createHash('sha256');for await(const chunk of createReadStream(file))hash.update(chunk);return hash.digest('hex');}
function files(root,prefix=''){
 return readdirSync(root,{withFileTypes:true}).flatMap(entry=>{
  const name=prefix+entry.name,path=join(root,entry.name);if(lstatSync(path).isSymbolicLink())throw Error('Symlink or junction is not allowed');
  if(entry.isDirectory())return files(path,name+'/');if(!entry.isFile())throw Error('Non-regular backup member');return [name];
 }).sort();
}
// A vault that recorded a data key must never be sealed or certified with the signing key alone: the legacy backup key is
// derived from the signing key, and the backup holds every retained event key. Retired key ids no longer bind.
function assertSeparationKept(file,keyring,config,operation){
 const db=new DatabaseSync(file,{readOnly:true,timeout:5000});
 try{
  const table=db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='data_key_usage'").get();
  const missing=(table?db.prepare('SELECT kid FROM data_key_usage WHERE retired_at IS NULL ORDER BY kid').all():[]).map(r=>r.kid).filter(kid=>!keyring.keyIds.includes(kid));
  if(missing.length)throw Error(`Vault key separation is active: data key(s) ${missing.join(',')} are not configured; refusing a ${operation} without DATA_KEY_FILE`);
  if(!keyring.separated&&config?.profile==='enterprise')throw Error(`Enterprise profile requires DATA_KEY_FILE for a ${operation}`);
 }finally{db.close();}
}
function readonlyStore(file,key){const store=Object.create(Store.prototype);store.key=key;store.publicKey=createPublicKey(key);store.db=new DatabaseSync(file,{readOnly:true,timeout:5000});return store;}

// Examine a fixed SQLite snapshot, never the source while it is still changing.
function inspectDatabase(file,dataDir,key,keyring,expectedCheckpoints){
 const store=readonlyStore(file,key),documents=new Map(),tenants=[];
 try{
  if(store.db.prepare('PRAGMA integrity_check').all().some(r=>r.integrity_check!=='ok'))throw Error('SQLite integrity check failed');
  const hasDevelopment=!!store.db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='development_run_events'").get(),hasGovernanceDocuments=!!store.db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='governance_documents'").get();
  const hasTlog=!!store.db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='tlog_state'").get();
  // Include every evidence projection, even when its tenant has no signed history.
  // Otherwise an orphan actions row can survive a falsely verified whole-vault restore.
  const core='SELECT tenant FROM ledger UNION SELECT tenant FROM checkpoints UNION SELECT tenant FROM objects UNION SELECT tenant FROM events UNION SELECT tenant FROM actions';
  const names=store.db.prepare(core+' UNION SELECT tenant FROM event_keys UNION SELECT tenant FROM receipts UNION SELECT tenant FROM evaluations'+(hasDevelopment?' UNION SELECT tenant FROM development_run_events':'')+(hasGovernanceDocuments?' UNION SELECT tenant FROM governance_documents':'')+(hasTlog?' UNION SELECT tenant FROM tlog_state':'')+' ORDER BY tenant').all().map(r=>r.tenant);
  if(expectedCheckpoints&&canonical(names)!==canonical(Object.keys(expectedCheckpoints).sort()))throw Error('Tenant set differs from independent checkpoints');
  for(const tenant of names){
   // Exhaust the iterator to authenticate the SQL tenant/sequence columns too.
   for(const row of store.verifiedRows(tenant,16*1024*1024))if(row.oversized)throw Error('Recovery verification row limit exceeded');
   const bundle=store.bundle(tenant);if(bundle.checkpoint.tenant!==tenant)throw Error('Checkpoint tenant mismatch');
   if(expectedCheckpoints&&canonical(bundle.checkpoint)!==canonical(expectedCheckpoints[tenant]))throw Error('External checkpoint mismatch: possible rollback');
   const evaluations=[],development=[];
   for(const row of bundle.records){
    if(row.type==='evaluation')evaluations.push(row.payload);
    if(row.type==='development_run_event')development.push(row.payload);
   }
   const objectProjection=checkObjectProjection(store.db,tenant,bundle.records);
   const checkedDocuments=checkDocumentFiles({db:store.db,tenant,records:bundle.records,dataDir,keyring});
   for(const document of checkedDocuments.files)documents.set(document.path,document);
   checkEvaluationProjection(store.db,tenant,evaluations);
   checkActionProjection(store.db,tenant,bundle.records,store.decodeRecords(bundle));
   const developmentProjection=checkDevelopmentRunProjection(store.db,tenant,development);
   const events=store.decodeRecords(bundle);checkEventProjection(store.db,tenant,events);
   const receiptProjection=checkReceiptProjection(store.db,tenant,bundle.records,events);
   tenants.push({tenant,checkpoint:bundle.checkpoint,retainedEvents:events.length,objects:objectProjection.objects,governanceDocuments:checkedDocuments.governanceDocumentProjection.documents,governanceDocumentRevisions:checkedDocuments.governanceDocumentProjection.revisions,documentFiles:checkedDocuments.summary.uniqueFiles,evaluations:evaluations.length,developmentEvents:developmentProjection.developmentEvents,receipts:receiptProjection.receipts,signedReceipts:receiptProjection.signedReceipts,legacyRetainedReceipts:receiptProjection.legacyRetainedReceipts});
  }
  for(const path of documents.keys())member(dataDir,path);
  return {tenants,documents:[...documents.keys()].sort()};
 }finally{store.close();}
}

export async function createVaultBackup({dataDir,backupDir,privateKey,publicKey,dataKey,previousDataKeys,config}){
 const {key,pub,keyring}=keys(privateKey,publicKey,{dataKey,previousDataKeys}),format=keyring.separated?FORMAT_V2:FORMAT,keyId=keyring.writeKeyId,encryption=keyring.key('vaultBackup',keyId),source=noLinks(dataDir),output=noLinks(backupDir);
 if(existsSync(output)||contained(source,output))throw Error('Backup requires a new directory outside the source');
 const sourceFile=member(source,'evidence.db');if(!lstatSync(sourceFile).isFile())throw Error('Missing vault database');
 mkdirSync(output,{mode:0o700});
 const temporary=join(output,'.snapshot.db');let sourceDb;
 try{
  sourceDb=new DatabaseSync(sourceFile,{readOnly:true,timeout:5000});
  await backup(sourceDb,temporary);sourceDb.close();sourceDb=null;chmodSync(temporary,0o600);
  assertSeparationKept(temporary,keyring,config,'backup');
  const snapshot=inspectDatabase(temporary,source,key,keyring);
  const accessSource=join(source,ACCESS_LOG_FILE),accessTemporary=join(output,'.access-log.db'),hasAccessLog=existsSync(accessSource);
  if(hasAccessLog){if(!member(source,ACCESS_LOG_FILE)||!lstatSync(accessSource).isFile())throw Error('Invalid access log file');
   const accessDb=new DatabaseSync(accessSource,{readOnly:true,timeout:5000});try{await backup(accessDb,accessTemporary);}finally{accessDb.close();}chmodSync(accessTemporary,0o600);}
  const accessTenants=checkAccessLogSnapshot(temporary,hasAccessLog?accessTemporary:null,snapshot.tenants.map(t=>t.tenant));
  const inventory=[];
  for(const path of snapshot.documents){const input=member(source,path),target=member(output,path);mkdirSync(dirname(target),{recursive:true,mode:0o700});copyFileSync(input,target);chmodSync(target,0o600);inventory.push({path,bytes:lstatSync(target).size,sha256:await hashFile(target)});}
  // Read copied ciphertext back, so concurrent loss or corruption cannot be sealed.
  inspectDatabase(temporary,output,key,keyring,Object.fromEntries(snapshot.tenants.map(t=>[t.tenant,t.checkpoint])));
  const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',encryption,iv);cipher.setAAD(backupAad(format,keyId));
  const encrypted=join(output,'evidence.db.enc');
  await pipeline(createReadStream(temporary),cipher,createWriteStream(encrypted,{flags:'wx',mode:0o600}));
  inventory.unshift({path:'evidence.db.enc',bytes:lstatSync(encrypted).size,sha256:await hashFile(encrypted)});
  let accessLog=null;
  if(hasAccessLog){
   const accessIv=randomBytes(12),accessCipher=createCipheriv('aes-256-gcm',encryption,accessIv);accessCipher.setAAD(accessAad(format,keyId));const accessEncrypted=join(output,ACCESS_MEMBER);
   await pipeline(createReadStream(accessTemporary),accessCipher,createWriteStream(accessEncrypted,{flags:'wx',mode:0o600}));
   inventory.splice(1,0,{path:ACCESS_MEMBER,bytes:lstatSync(accessEncrypted).size,sha256:await hashFile(accessEncrypted)});
   accessLog={algorithm:'aes-256-gcm',iv:accessIv.toString('base64'),tag:accessCipher.getAuthTag().toString('base64'),plaintextSha256:await hashFile(accessTemporary),tenants:accessTenants};
  }
  const statement={format,createdAt:new Date().toISOString(),keyFingerprint:hashBytes(pub.export({format:'der',type:'spki'})),database:{algorithm:'aes-256-gcm',...(format===FORMAT_V2?{kdf:'hkdf-sha256',info:PURPOSES.vaultBackup,keyId}:{}),iv:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64'),plaintextSha256:await hashFile(temporary)},...(accessLog?{accessLog}:{}),files:inventory,tenants:snapshot.tenants,scope:'Whole local vault; credentials, signing private key and data-encryption keys excluded. Historical supplier and first-party governance document ciphertext included. This snapshot does not prove elapsed five-year retention. External backups and later erasures require separate disposition.'};
  const manifest={...statement,signature:sign(null,Buffer.from(canonical(statement)),key).toString('base64')};
  unlinkSync(temporary);
  writeFileSync(join(output,'manifest.json'),JSON.stringify(manifest,null,2)+'\n',{flag:'wx',mode:0o600});
  return {format:'evidscope-recovery-anchor-v1',manifestSha256:digest(manifest),keyFingerprint:statement.keyFingerprint,checkpoints:Object.fromEntries(snapshot.tenants.map(t=>[t.tenant,t.checkpoint]))};
 }finally{sourceDb?.close();for(const name of ['.snapshot.db','.snapshot.db-wal','.snapshot.db-shm','.access-log.db','.access-log.db-wal','.access-log.db-shm']){const file=join(output,name);if(existsSync(file))unlinkSync(file);}}
}

async function verifyArchive(backupDir,pub,anchor){
 const root=noLinks(backupDir),path=member(root,'manifest.json');if(lstatSync(path).size>16*1024*1024)throw Error('Backup manifest too large');
 const manifest=JSON.parse(readFileSync(path,'utf8')),{signature,...statement}=manifest;
 if(![FORMAT,FORMAT_V2].includes(statement.format)||!verify(null,Buffer.from(canonical(statement)),pub,Buffer.from(signature||'','base64')))throw Error('Backup signature invalid');
 const fingerprint=hashBytes(pub.export({format:'der',type:'spki'}));
 if(!anchor||anchor.format!=='evidscope-recovery-anchor-v1'||anchor.manifestSha256!==digest(manifest)||anchor.keyFingerprint!==fingerprint||statement.keyFingerprint!==fingerprint)throw Error('Independent recovery anchor mismatch');
 if(!Array.isArray(statement.files)||!statement.files.length||!Array.isArray(statement.tenants)||!anchor.checkpoints)throw Error('Invalid recovery manifest');
 if(canonical(Object.fromEntries(statement.tenants.map(t=>[t.tenant,t.checkpoint])))!==canonical(anchor.checkpoints))throw Error('Independent checkpoint set mismatch');
 for(const cp of Object.values(anchor.checkpoints))verifyCheckpoint(cp,pub);
 const paths=statement.files.map(f=>f.path);
 if(new Set(paths).size!==paths.length||paths.filter(p=>p==='evidence.db.enc').length!==1||paths.includes(ACCESS_MEMBER)!==!!statement.accessLog||paths.some(p=>p!=='evidence.db.enc'&&p!==ACCESS_MEMBER&&!/^(?:finance-documents|governance-documents)\/[a-f0-9]{64}\/[a-f0-9]{64}\.json$/.test(p)))throw Error('Invalid backup inventory');
 if(canonical(files(root))!==canonical(['manifest.json',...paths].sort()))throw Error('Backup inventory is incomplete or has unlisted files');
 for(const f of statement.files){const file=member(root,f.path);if(lstatSync(file).size!==f.bytes||await hashFile(file)!==f.sha256)throw Error('Backup member digest mismatch');}
 return manifest;
}

// transparency (optional): the source's transparency config, naming the heads origin of the freshness companion.
export async function createVaultRecoveryFrontier({dataDir,privateKey,publicKey,dataKey,previousDataKeys,anchor,config,transparency}){
 const {key,pub,keyring}=keys(privateKey,publicKey,{dataKey,previousDataKeys}),source=noLinks(dataDir),sourceFile=member(source,'evidence.db');
 if(!config||typeof config!=='object')throw Error('Recovery frontier requires current credential/config binding');
 const stage=mkdtempSync(join(dirname(source),'.recovery-frontier-')),snapshotFile=join(stage,'snapshot.db');let db,store;
 try{
  db=new DatabaseSync(sourceFile,{readOnly:true,timeout:5000});await backup(db,snapshotFile);db.close();db=null;
  assertSeparationKept(snapshotFile,keyring,config,'recovery frontier');
  const checked=inspectDatabase(snapshotFile,source,key,keyring);store=readonlyStore(snapshotFile,key);
  const signed=signRecoveryFrontier({bundles:checked.tenants.map(t=>store.rawBundle(t.tenant)),archiveAnchor:anchor,privateKey:key,publicKey:pub,config});
  const companion=frontierTransparency({db:store.db,key,frontier:signed.frontier,headsOrigin:transparency?.origin?headsOrigin(validateOriginBase(transparency.origin)):null,
   headsKeys:signerKeysOf(transparency)});
  return companion?{...signed,transparency:companion}:signed;
 }finally{
  store?.close();db?.close();for(const name of ['snapshot.db','snapshot.db-wal','snapshot.db-shm']){const file=join(stage,name);if(existsSync(file))unlinkSync(file);}rmdirSync(stage);
 }
}

// transparency (optional): {config, previous, previousPin, frontierTransparency, acceptLoss, signerHead} for a restore epoch (transparency-epoch.mjs).
export async function restoreVaultBackup({backupDir,restoreDir,privateKey,publicKey,dataKey,previousDataKeys,anchor,frontier,frontierAnchor,config,transparency}){
 const {key,pub,keyring}=keys(privateKey,publicKey,{dataKey,previousDataKeys}),root=noLinks(backupDir),target=noLinks(restoreDir);
 if(existsSync(target)||contained(root,target))throw Error('Restore requires a new directory outside the backup');
 if(existsSync(recoveryPinPath(target)))throw Error('External restoration pin already exists; refusing overwrite');
 const manifest=await verifyArchive(root,pub,anchor);
 const activationAccepted=frontier!==undefined||frontierAnchor!==undefined||config!==undefined;
 let frontierStatement=null;
 if(activationAccepted){if(!frontier||!frontierAnchor||!config)throw Error('Activation requires frontier, independent frontier anchor and current config');frontierStatement=verifyRecoveryFrontier({frontier,anchor:frontierAnchor,archiveAnchor:anchor,publicKey:pub,config});}
 const stage=mkdtempSync(join(dirname(target),'.'+basename(target)+'-incomplete-'));chmodSync(stage,0o700);
 const database=join(stage,'evidence.db');
 try{
  const enc=manifest.database,v2=manifest.format===FORMAT_V2;
  if(enc.algorithm!=='aes-256-gcm'||v2&&(enc.kdf!=='hkdf-sha256'||enc.info!==PURPOSES.vaultBackup||!KEY_ID_PATTERN.test(enc.keyId||''))||!v2&&['kdf','info','keyId'].some(name=>Object.hasOwn(enc,name)))throw Error('Unsupported backup encryption');
  const keyId=v2?enc.keyId:LEGACY_KEY_ID;
  const decipher=createDecipheriv('aes-256-gcm',keyring.key('vaultBackup',keyId),Buffer.from(enc.iv,'base64'));decipher.setAAD(backupAad(manifest.format,keyId));decipher.setAuthTag(Buffer.from(manifest.database.tag,'base64'));
  await pipeline(createReadStream(member(root,'evidence.db.enc')),decipher,createWriteStream(database,{flags:'wx',mode:0o600}));
  if(await hashFile(database)!==manifest.database.plaintextSha256)throw Error('Restored database digest mismatch');
  const access=manifest.accessLog,accessFile=join(stage,ACCESS_LOG_FILE);
  if(access){
   if(access.algorithm!=='aes-256-gcm')throw Error('Unsupported backup encryption');
   const accessDecipher=createDecipheriv('aes-256-gcm',keyring.key('vaultBackup',keyId),Buffer.from(access.iv,'base64'));accessDecipher.setAAD(accessAad(manifest.format,keyId));accessDecipher.setAuthTag(Buffer.from(access.tag,'base64'));
   await pipeline(createReadStream(member(root,ACCESS_MEMBER)),accessDecipher,createWriteStream(accessFile,{flags:'wx',mode:0o600}));
   if(await hashFile(accessFile)!==access.plaintextSha256)throw Error('Restored access log digest mismatch');
  }
  const documentFiles=manifest.files.filter(f=>f.path!=='evidence.db.enc'&&f.path!==ACCESS_MEMBER);
  for(const f of documentFiles){const output=member(stage,f.path);mkdirSync(dirname(output),{recursive:true,mode:0o700});copyFileSync(member(root,f.path),output);chmodSync(output,0o600);if(await hashFile(output)!==f.sha256)throw Error('Document changed during restoration');}
  const restored=inspectDatabase(database,stage,key,keyring,anchor.checkpoints);
  if(canonical(restored.tenants)!==canonical(manifest.tenants)||canonical(restored.documents)!==canonical(documentFiles.map(f=>f.path).sort()))throw Error('Restored evidence differs from signed inventory');
  if(canonical(checkAccessLogSnapshot(database,access?accessFile:null,restored.tenants.map(t=>t.tenant)))!==canonical(access?access.tenants:{}))throw Error('Restored access log differs from signed inventory');
  // A restore forks the transparency log: plan the new origin epoch and the witness freshness check before writing anything.
  const epoch=await planTlogEpoch({database,key,archiveAnchor:anchor,transparency,frontier:frontierStatement,frontierSha256:frontier?digest(frontier):null,restoreDir:target});
  const store=new Store(stage,key);let activation,applied=null;
  try{
   if(activationAccepted)applied=applyRecoveryFrontier({store,frontier,anchor:frontierAnchor,archiveAnchor:anchor,config,freshness:epoch.freshness});
   writeTlogEpochs(store,epoch);
   activation=sealRestorationState({store,dataDir:stage,archiveAnchor:anchor,frontier,config,activationAccepted});
  }finally{store.close();}
  const freshnessEstablished=applied?.freshnessEstablished===true;
  const accepted=inspectDatabase(database,stage,key,keyring);
  const activationPin=pinRestorationState({dataDir:target,marker:activation,key});
  // Reserve the final path against accidental overwrite. Only this empty directory is removed.
  mkdirSync(target,{mode:0o700});
  try{rmdirSync(target);renameSync(stage,target);}catch(error){throw Error('Restore publication failed: '+error.message);}
  return {verified:true,restoredDirectory:target,activationPin,manifestSha256:digest(manifest),tenants:accepted.tenants,documents:accepted.documents.length,governanceDocuments:accepted.documents.filter(path=>path.startsWith('governance-documents/')).length,rollbackChecked:true,activationAccepted,activationStatus:activation.status,frontierSha256:activation.frontierSha256,freshnessEstablished,...(epoch.result?{transparency:epoch.result}:{}),servicesStarted:false,scope:'Snapshot integrity verified. Activation requires independently pinned latest access/erasure frontier; '+(freshnessEstablished?'its freshness was established against the witness quorum of the previous transparency origin.':'its freshness remains an operator responsibility.')+' External restoration pin must remain protected outside the data directory. Not elapsed five-year retention, HA, remote retention, source truth, or legal sufficiency certification.'};
 }catch(error){
  // Keep encrypted documents for diagnosis; remove known plaintext DB files only.
  for(const name of PLAINTEXT_FILES){const file=join(stage,name);if(existsSync(file))unlinkSync(file);}
  throw error;
 }
}
