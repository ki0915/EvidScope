import {DatabaseSync,backup} from 'node:sqlite';
import {createHash,createPrivateKey,createPublicKey,createCipheriv,createDecipheriv,randomBytes,sign,verify} from 'node:crypto';
import {mkdirSync,mkdtempSync,lstatSync,existsSync,readdirSync,readFileSync,writeFileSync,copyFileSync,unlinkSync,renameSync,chmodSync,createReadStream,createWriteStream} from 'node:fs';
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

const FORMAT='evidscope-vault-backup-v1';
const hashBytes=bytes=>createHash('sha256').update(bytes).digest('hex');
const publicDer=key=>createPublicKey(key).export({format:'der',type:'spki'});
function keys(privateKey,publicKey){
 const key=typeof privateKey==='object'&&privateKey.type==='private'?privateKey:createPrivateKey(privateKey);
 const pub=typeof publicKey==='object'&&publicKey.type==='public'?publicKey:createPublicKey(publicKey);
 if(key.asymmetricKeyType!=='ed25519'||!publicDer(key).equals(pub.export({format:'der',type:'spki'})))throw Error('Independent trust key does not match vault key');
 return {key,pub,encryption:createHash('sha256').update('evidscope-vault-backup-encryption-v1').update(key.export({format:'der',type:'pkcs8'})).digest()};
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
function readonlyStore(file,key){const store=Object.create(Store.prototype);store.key=key;store.publicKey=createPublicKey(key);store.db=new DatabaseSync(file,{readOnly:true,timeout:5000});return store;}

// Examine a fixed SQLite snapshot, never the source while it is still changing.
function inspectDatabase(file,dataDir,key,expectedCheckpoints){
 const store=readonlyStore(file,key),documents=new Map(),tenants=[];
 try{
  if(store.db.prepare('PRAGMA integrity_check').all().some(r=>r.integrity_check!=='ok'))throw Error('SQLite integrity check failed');
  const hasDevelopment=!!store.db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='development_run_events'").get(),hasGovernanceDocuments=!!store.db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='governance_documents'").get();
  // Include every evidence projection, even when its tenant has no signed history.
  // Otherwise an orphan actions row can survive a falsely verified whole-vault restore.
  const names=store.db.prepare('SELECT tenant FROM ledger UNION SELECT tenant FROM checkpoints UNION SELECT tenant FROM objects UNION SELECT tenant FROM events UNION SELECT tenant FROM actions UNION SELECT tenant FROM event_keys UNION SELECT tenant FROM receipts UNION SELECT tenant FROM evaluations'+(hasDevelopment?' UNION SELECT tenant FROM development_run_events':'')+(hasGovernanceDocuments?' UNION SELECT tenant FROM governance_documents':'')+' ORDER BY tenant').all().map(r=>r.tenant);
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
   const checkedDocuments=checkDocumentFiles({db:store.db,tenant,records:bundle.records,dataDir,key});
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

export async function createVaultBackup({dataDir,backupDir,privateKey,publicKey}){
 const {key,pub,encryption}=keys(privateKey,publicKey),source=noLinks(dataDir),output=noLinks(backupDir);
 if(existsSync(output)||output===source||output.startsWith(source+sep))throw Error('Backup requires a new directory outside the source');
 const sourceFile=member(source,'evidence.db');if(!lstatSync(sourceFile).isFile())throw Error('Missing vault database');
 mkdirSync(output,{mode:0o700});
 const temporary=join(output,'.snapshot.db');let sourceDb;
 try{
  sourceDb=new DatabaseSync(sourceFile,{readOnly:true,timeout:5000});
  await backup(sourceDb,temporary);sourceDb.close();sourceDb=null;chmodSync(temporary,0o600);
  const snapshot=inspectDatabase(temporary,source,key);
  const inventory=[];
  for(const path of snapshot.documents){const input=member(source,path),target=member(output,path);mkdirSync(dirname(target),{recursive:true,mode:0o700});copyFileSync(input,target);chmodSync(target,0o600);inventory.push({path,bytes:lstatSync(target).size,sha256:await hashFile(target)});}
  // Read copied ciphertext back, so concurrent loss or corruption cannot be sealed.
  inspectDatabase(temporary,output,key,Object.fromEntries(snapshot.tenants.map(t=>[t.tenant,t.checkpoint])));
  const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',encryption,iv);cipher.setAAD(Buffer.from(FORMAT));
  const encrypted=join(output,'evidence.db.enc');
  await pipeline(createReadStream(temporary),cipher,createWriteStream(encrypted,{flags:'wx',mode:0o600}));
  inventory.unshift({path:'evidence.db.enc',bytes:lstatSync(encrypted).size,sha256:await hashFile(encrypted)});
  const statement={format:FORMAT,createdAt:new Date().toISOString(),keyFingerprint:hashBytes(pub.export({format:'der',type:'spki'})),database:{algorithm:'aes-256-gcm',iv:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64'),plaintextSha256:await hashFile(temporary)},files:inventory,tenants:snapshot.tenants,scope:'Whole local vault; credentials and private key excluded. Historical supplier and first-party governance document ciphertext included. This snapshot does not prove elapsed five-year retention. External backups and later erasures require separate disposition.'};
  const manifest={...statement,signature:sign(null,Buffer.from(canonical(statement)),key).toString('base64')};
  unlinkSync(temporary);
  writeFileSync(join(output,'manifest.json'),JSON.stringify(manifest,null,2)+'\n',{flag:'wx',mode:0o600});
  return {format:'evidscope-recovery-anchor-v1',manifestSha256:digest(manifest),keyFingerprint:statement.keyFingerprint,checkpoints:Object.fromEntries(snapshot.tenants.map(t=>[t.tenant,t.checkpoint]))};
 }finally{sourceDb?.close();for(const name of ['.snapshot.db','.snapshot.db-wal','.snapshot.db-shm']){const file=join(output,name);if(existsSync(file))unlinkSync(file);}}
}

async function verifyArchive(backupDir,pub,anchor){
 const root=noLinks(backupDir),path=member(root,'manifest.json');if(lstatSync(path).size>16*1024*1024)throw Error('Backup manifest too large');
 const manifest=JSON.parse(readFileSync(path,'utf8')),{signature,...statement}=manifest;
 if(statement.format!==FORMAT||!verify(null,Buffer.from(canonical(statement)),pub,Buffer.from(signature||'','base64')))throw Error('Backup signature invalid');
 const fingerprint=hashBytes(pub.export({format:'der',type:'spki'}));
 if(!anchor||anchor.format!=='evidscope-recovery-anchor-v1'||anchor.manifestSha256!==digest(manifest)||anchor.keyFingerprint!==fingerprint||statement.keyFingerprint!==fingerprint)throw Error('Independent recovery anchor mismatch');
 if(!Array.isArray(statement.files)||!statement.files.length||!Array.isArray(statement.tenants)||!anchor.checkpoints)throw Error('Invalid recovery manifest');
 if(canonical(Object.fromEntries(statement.tenants.map(t=>[t.tenant,t.checkpoint])))!==canonical(anchor.checkpoints))throw Error('Independent checkpoint set mismatch');
 for(const cp of Object.values(anchor.checkpoints))verifyCheckpoint(cp,pub);
 const paths=statement.files.map(f=>f.path);
 if(new Set(paths).size!==paths.length||paths.filter(p=>p==='evidence.db.enc').length!==1||paths.some(p=>p!=='evidence.db.enc'&&!/^(?:finance-documents|governance-documents)\/[a-f0-9]{64}\/[a-f0-9]{64}\.json$/.test(p)))throw Error('Invalid backup inventory');
 if(canonical(files(root))!==canonical(['manifest.json',...paths].sort()))throw Error('Backup inventory is incomplete or has unlisted files');
 for(const f of statement.files){const file=member(root,f.path);if(lstatSync(file).size!==f.bytes||await hashFile(file)!==f.sha256)throw Error('Backup member digest mismatch');}
 return manifest;
}

export async function restoreVaultBackup({backupDir,restoreDir,privateKey,publicKey,anchor}){
 const {key,pub,encryption}=keys(privateKey,publicKey),root=noLinks(backupDir),target=noLinks(restoreDir);
 if(existsSync(target)||target===root||target.startsWith(root+sep))throw Error('Restore requires a new directory outside the backup');
 const manifest=await verifyArchive(root,pub,anchor);
 const stage=mkdtempSync(join(dirname(target),'.'+basename(target)+'-incomplete-'));chmodSync(stage,0o700);
 const database=join(stage,'evidence.db');
 try{
  if(manifest.database.algorithm!=='aes-256-gcm')throw Error('Unsupported backup encryption');
  const decipher=createDecipheriv('aes-256-gcm',encryption,Buffer.from(manifest.database.iv,'base64'));decipher.setAAD(Buffer.from(FORMAT));decipher.setAuthTag(Buffer.from(manifest.database.tag,'base64'));
  await pipeline(createReadStream(member(root,'evidence.db.enc')),decipher,createWriteStream(database,{flags:'wx',mode:0o600}));
  if(await hashFile(database)!==manifest.database.plaintextSha256)throw Error('Restored database digest mismatch');
  for(const f of manifest.files.filter(f=>f.path!=='evidence.db.enc')){const output=member(stage,f.path);mkdirSync(dirname(output),{recursive:true,mode:0o700});copyFileSync(member(root,f.path),output);chmodSync(output,0o600);if(await hashFile(output)!==f.sha256)throw Error('Document changed during restoration');}
  const restored=inspectDatabase(database,stage,key,anchor.checkpoints);
  if(canonical(restored.tenants)!==canonical(manifest.tenants)||canonical(restored.documents)!==canonical(manifest.files.filter(f=>f.path!=='evidence.db.enc').map(f=>f.path).sort()))throw Error('Restored evidence differs from signed inventory');
  // Reserve the final path against accidental overwrite. Only this empty directory is removed.
  mkdirSync(target,{mode:0o700});
  try{const {rmdirSync}=await import('node:fs');rmdirSync(target);renameSync(stage,target);}catch(error){throw Error('Restore publication failed: '+error.message);}
  return {verified:true,restoredDirectory:target,manifestSha256:digest(manifest),tenants:restored.tenants,documents:restored.documents.length,governanceDocuments:restored.documents.filter(path=>path.startsWith('governance-documents/')).length,rollbackChecked:true,servicesStarted:false,scope:'Snapshot recovery verified; not elapsed five-year retention, HA, remote retention, source truth, or legal sufficiency certification.'};
 }catch(error){
  // Keep encrypted documents for diagnosis; remove known plaintext DB files only.
  for(const name of ['evidence.db','evidence.db-wal','evidence.db-shm']){const file=join(stage,name);if(existsSync(file))unlinkSync(file);}
  throw error;
 }
}
