import {existsSync,lstatSync,readFileSync,writeFileSync} from 'node:fs';
import {join,resolve,dirname,basename} from 'node:path';
import {createPublicKey,sign,verify,randomUUID} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {canonical,digest,verifyCheckpoint} from './crypto.mjs';

const FORMAT='evidscope-restoration-state-v1',FILE='vault-restoration.json';
export const recoveryPinPath=dataDir=>join(dirname(resolve(dataDir)),'.'+basename(resolve(dataDir))+'-recovery-pin.json');
const fail=message=>{throw Error('Recovery activation rejected: '+message);};
function noLinks(path){for(let current=resolve(path);;){if(existsSync(current)&&lstatSync(current).isSymbolicLink())fail('symlink or junction');const parent=dirname(current);if(parent===current)return;current=parent;}}

export function pinRestorationState({dataDir,marker,key}){
 const file=recoveryPinPath(dataDir);noLinks(file);
 const statement={format:'evidscope-restoration-pin-v1',dataDir:resolve(dataDir),markerSha256:digest(marker)};
 const pin={...statement,signature:sign(null,Buffer.from(canonical(statement)),key).toString('base64')};
 writeFileSync(file,JSON.stringify(pin,null,2)+'\n',{flag:'wx',mode:0o600});return file;
}

// This receipt is written only after snapshot validation and, for activation,
// independently pinned post-backup access/erasure state has been replayed.
export function sealRestorationState({store,dataDir,archiveAnchor,frontier,config,activationAccepted}){
 const restoreId=randomUUID(),status=activationAccepted?'accepted':'quarantined';
 const binding={restoreId,status,archiveManifestSha256:archiveAnchor.manifestSha256,frontierSha256:frontier?digest(frontier):null,configHash:activationAccepted?digest(config):null};
 const names=store.db.prepare('SELECT tenant FROM checkpoints UNION SELECT tenant FROM ledger ORDER BY tenant').all().map(r=>r.tenant);
 if(!names.length)names.push('__evidscope_recovery__');
 store.transaction(()=>{for(const tenant of names)store.append(tenant,'recovery_restore',binding,'vault-recovery');});
 const statement={format:FORMAT,...binding,checkpoints:Object.fromEntries(names.map(tenant=>[tenant,store.checkpoint(tenant)]))};
 const marker={...statement,signature:sign(null,Buffer.from(canonical(statement)),store.key).toString('base64')};
 writeFileSync(join(dataDir,FILE),JSON.stringify(marker,null,2)+'\n',{flag:'wx',mode:0o600});
 return marker;
}

// Run before Store opens a write connection or startup adds any ledger rows.
export function assertRecoveryActivation({dataDir,key,config}){
 const markerFile=join(dataDir,FILE),database=join(dataDir,'evidence.db'),pinFile=recoveryPinPath(dataDir),pub=createPublicKey(key);
 noLinks(dataDir);noLinks(markerFile);noLinks(database);noLinks(pinFile);
 if(existsSync(pinFile)){
  if(!lstatSync(pinFile).isFile()||lstatSync(pinFile).size>16*1024*1024)fail('invalid external restoration pin');
  const pin=JSON.parse(readFileSync(pinFile,'utf8')),{signature,...statement}=pin;
  if(statement.format!=='evidscope-restoration-pin-v1'||statement.dataDir!==resolve(dataDir)||!verify(null,Buffer.from(canonical(statement)),pub,Buffer.from(signature||'','base64')))fail('external restoration pin invalid');
  if(!existsSync(markerFile))fail('externally pinned restoration marker missing');
  if(!existsSync(database))fail('externally pinned restoration database missing');
  if(!lstatSync(markerFile).isFile()||lstatSync(markerFile).size>16*1024*1024)fail('invalid marker file');
  if(digest(JSON.parse(readFileSync(markerFile,'utf8')))!==statement.markerSha256)fail('external restoration pin mismatch');
 }
 if(!existsSync(database)){if(existsSync(markerFile))fail('marker without database');return;}
 const db=new DatabaseSync(database,{readOnly:true,timeout:5000});
 try{
  const hasLedger=!!db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='ledger'").get();
  if(!existsSync(markerFile)){
   if(hasLedger&&db.prepare("SELECT 1 FROM ledger WHERE json_extract(body,'$.type')='recovery_restore' LIMIT 1").get())fail('restoration marker missing');
   return;
  }
  if(!lstatSync(markerFile).isFile()||lstatSync(markerFile).size>16*1024*1024)fail('invalid marker file');
  if(!existsSync(pinFile))fail('external restoration pin missing');
  const marker=JSON.parse(readFileSync(markerFile,'utf8')),{signature,...statement}=marker;
  if(statement.format!==FORMAT||!verify(null,Buffer.from(canonical(statement)),pub,Buffer.from(signature||'','base64')))fail('marker signature');
  if(statement.status!=='accepted')fail('snapshot quarantined; latest independently pinned frontier required');
  if(statement.configHash!==digest(config))fail('credential/config binding changed');
  if(!statement.restoreId||!statement.frontierSha256||!statement.checkpoints||!Object.keys(statement.checkpoints).length||!hasLedger)fail('incomplete accepted marker');
  const binding={restoreId:statement.restoreId,status:statement.status,archiveManifestSha256:statement.archiveManifestSha256,frontierSha256:statement.frontierSha256,configHash:statement.configHash};
  const tenants=db.prepare('SELECT tenant FROM checkpoints UNION SELECT tenant FROM ledger ORDER BY tenant').all().map(r=>r.tenant);
  for(const tenant of Object.keys(statement.checkpoints))if(!tenants.includes(tenant))fail('accepted tenant missing');
  for(const tenant of tenants){
   const cpRow=db.prepare('SELECT body FROM checkpoints WHERE tenant=?').get(tenant);if(!cpRow)fail('checkpoint missing');
   const cp=JSON.parse(cpRow.body),accepted=statement.checkpoints[tenant];verifyCheckpoint(cp,pub);
   if(cp.tenant!==tenant||!Number.isSafeInteger(cp.count)||cp.count<0)fail('checkpoint binding');
   if(accepted){verifyCheckpoint(accepted,pub);if(accepted.tenant!==tenant||cp.count<accepted.count)fail('accepted checkpoint rollback');}
   let previous='0'.repeat(64),sequence=0,lastRestore=null,prefixFound=!accepted;
   for(const sql of db.prepare('SELECT seq,body,hash FROM ledger WHERE tenant=? ORDER BY seq').iterate(tenant)){
    if(Buffer.byteLength(sql.body)>16*1024*1024)fail('ledger row limit');
    const row=JSON.parse(sql.body);
    if(sql.seq!==++sequence||row.seq!==sequence||row.tenant!==tenant||row.previous!==previous||digest(row)!==sql.hash)fail('ledger integrity');
    previous=sql.hash;if(accepted&&sequence===accepted.count){if(previous!==accepted.head)fail('accepted checkpoint lineage');prefixFound=true;}
    if(row.type==='recovery_restore')lastRestore=row.payload;
   }
   if(sequence!==cp.count||previous!==cp.head||!prefixFound)fail('truncated history');
   if(accepted&&canonical(lastRestore)!==canonical(binding)||!accepted&&lastRestore)fail('restoration binding changed');
  }
 }finally{db.close();}
}
