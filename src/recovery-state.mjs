import {existsSync,lstatSync,readFileSync,renameSync,rmSync,writeFileSync} from 'node:fs';
import {join,resolve,dirname,basename} from 'node:path';
import {createPublicKey,sign,verify,randomUUID} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {canonical,digest,verifyCheckpoint} from './crypto.mjs';

const FORMAT='evidscope-restoration-state-v1',FILE='vault-restoration.json';
export const recoveryPinPath=dataDir=>join(dirname(resolve(dataDir)),'.'+basename(resolve(dataDir))+'-recovery-pin.json');
// Signed config rebinding of an activated restoration (S8): the chain lives in the data directory, its head is pinned outside it.
const REBIND_FORMAT='evidscope-config-rebinding-v1',REBIND_CHAIN='evidscope-config-rebinding-chain-v1',REBIND_PIN='evidscope-config-rebinding-pin-v1';
const REBIND_FILE='vault-config-rebinding.json',REBIND_TYPE='recovery_config_rebinding';
export const configRebindingPath=dataDir=>join(resolve(dataDir),REBIND_FILE);
export const configRebindingPinPath=dataDir=>join(dirname(resolve(dataDir)),'.'+basename(resolve(dataDir))+'-config-rebinding-pin.json');
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

const signed=(statement,key)=>({...statement,signature:sign(null,Buffer.from(canonical(statement)),key).toString('base64')});
function signatureValid(value,pub){
 const {signature,...statement}=value||{};
 return typeof signature==='string'&&verify(null,Buffer.from(canonical(statement)),pub,Buffer.from(signature,'base64'));
}
function boundedJson(file,label){
 if(!lstatSync(file).isFile()||lstatSync(file).size>16*1024*1024)fail('invalid '+label);
 try{return JSON.parse(readFileSync(file,'utf8'));}catch{fail('invalid '+label);}
}
// Writes a new version next to the old one and renames it into place, so a reader sees the old or the new file, never a part.
function replaceJson(file,value){
 noLinks(file);const temporary=`${file}.${randomUUID()}.tmp`;
 writeFileSync(temporary,JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});
 try{renameSync(temporary,file);}catch(error){rmSync(temporary,{force:true});throw error;}
}
// Each entry is signed by the vault key and names its restoration (restoreId, marker hash), the configuration hash it
// replaces, the new configuration hash and the previous entry, so the chain starts at the hash the restoration bound.
function rebindingChain(dataDir,marker,pub){
 const file=configRebindingPath(dataDir);if(!existsSync(file))return [];
 const chain=boundedJson(file,'config rebinding record'),entries=chain?.entries,markerSha256=digest(marker);
 if(chain?.format!==REBIND_CHAIN||!Array.isArray(entries)||!entries.length||Object.keys(chain).length!==2)fail('invalid config rebinding record');
 entries.forEach((entry,index)=>{
  const previous=entries[index-1];
  if(entry?.format!==REBIND_FORMAT||!signatureValid(entry,pub))fail('config rebinding signature');
  if(entry.restoreId!==marker.restoreId||entry.markerSha256!==markerSha256)fail('config rebinding belongs to another restoration');
  if(entry.sequence!==index+1||entry.previousConfigHash!==(previous?previous.configHash:marker.configHash)
   ||entry.previousEntrySha256!==(previous?digest(previous):null)||!/^[a-f0-9]{64}$/.test(entry.configHash))fail('config rebinding chain');
 });
 return entries;
}
// How many chain entries the external pin covers (0 without a pin). A pin ahead of the record means the record was rolled back.
function pinnedRebindings(dataDir,marker,pub,entries){
 const file=configRebindingPinPath(dataDir);if(!existsSync(file))return 0;
 const pin=boundedJson(file,'external config rebinding pin');
 if(pin?.format!==REBIND_PIN||pin.dataDir!==resolve(dataDir)||!signatureValid(pin,pub)||!Number.isSafeInteger(pin.sequence)||pin.sequence<1)
  fail('external config rebinding pin invalid');
 if(pin.restoreId!==marker.restoreId)fail('external config rebinding pin belongs to another restoration');
 if(pin.sequence>entries.length)fail(entries.length?'config rebinding record rollback':'externally pinned config rebinding record missing');
 if(pin.headSha256!==digest(entries[pin.sequence-1]))fail('external config rebinding pin mismatch');
 return pin.sequence;
}
function pinRebinding(dataDir,marker,entry,key){
 const file=configRebindingPinPath(dataDir);
 replaceJson(file,signed({format:REBIND_PIN,dataDir:resolve(dataDir),restoreId:marker.restoreId,sequence:entry.sequence,headSha256:digest(entry)},key));
 return file;
}
const rebindingRecord=entry=>({format:REBIND_FORMAT,restoreId:entry.restoreId,sequence:entry.sequence,previousConfigHash:entry.previousConfigHash,
 configHash:entry.configHash,entrySha256:digest(entry),reason:entry.reason,rebindAt:entry.rebindAt});

// Run before Store opens a write connection or startup adds any ledger rows. For an activated restoration it returns the
// restored tenants and the pinned config rebindings in effect (recordConfigRebindings), otherwise null.
export function assertRecoveryActivation({dataDir,key,config}){return verifyActivation({dataDir,key,config});}
function verifyActivation({dataDir,key,config,allowUnpinnedHead=false}){
 const markerFile=join(dataDir,FILE),database=join(dataDir,'evidence.db'),pinFile=recoveryPinPath(dataDir),pub=createPublicKey(key);
 noLinks(dataDir);noLinks(markerFile);noLinks(database);noLinks(pinFile);noLinks(configRebindingPath(dataDir));noLinks(configRebindingPinPath(dataDir));
 if(existsSync(pinFile)){
  if(!lstatSync(pinFile).isFile()||lstatSync(pinFile).size>16*1024*1024)fail('invalid external restoration pin');
  const pin=JSON.parse(readFileSync(pinFile,'utf8')),{signature,...statement}=pin;
  if(statement.format!=='evidscope-restoration-pin-v1'||statement.dataDir!==resolve(dataDir)||!verify(null,Buffer.from(canonical(statement)),pub,Buffer.from(signature||'','base64')))fail('external restoration pin invalid');
  if(!existsSync(markerFile))fail('externally pinned restoration marker missing');
  if(!existsSync(database))fail('externally pinned restoration database missing');
  if(!lstatSync(markerFile).isFile()||lstatSync(markerFile).size>16*1024*1024)fail('invalid marker file');
  if(digest(JSON.parse(readFileSync(markerFile,'utf8')))!==statement.markerSha256)fail('external restoration pin mismatch');
 }
 if(!existsSync(database)){if(existsSync(markerFile))fail('marker without database');return null;}
 const db=new DatabaseSync(database,{readOnly:true,timeout:5000});
 try{
  const hasLedger=!!db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='ledger'").get();
  if(!existsSync(markerFile)){
   if(hasLedger&&db.prepare("SELECT 1 FROM ledger WHERE json_extract(body,'$.type')='recovery_restore' LIMIT 1").get())fail('restoration marker missing');
   return null;
  }
  if(!lstatSync(markerFile).isFile()||lstatSync(markerFile).size>16*1024*1024)fail('invalid marker file');
  if(!existsSync(pinFile))fail('external restoration pin missing');
  const marker=JSON.parse(readFileSync(markerFile,'utf8')),{signature,...statement}=marker;
  if(statement.format!==FORMAT||!verify(null,Buffer.from(canonical(statement)),pub,Buffer.from(signature||'','base64')))fail('marker signature');
  if(statement.status!=='accepted')fail('snapshot quarantined; latest independently pinned frontier required');
  if(!statement.restoreId||!statement.frontierSha256||!statement.checkpoints||!Object.keys(statement.checkpoints).length||!hasLedger)fail('incomplete accepted marker');
  // The configuration may change only through the signed, externally pinned rebinding chain of this restoration.
  let rebindings=rebindingChain(dataDir,marker,pub),pending=null;const pinned=pinnedRebindings(dataDir,marker,pub,rebindings);
  if(pinned!==rebindings.length){
   if(pinned!==rebindings.length-1)fail('external config rebinding pin missing or behind the rebinding record');
   if(!allowUnpinnedHead)fail('config rebinding not pinned; rerun the same rebind command to finish it');
   pending=rebindings.at(-1);rebindings=rebindings.slice(0,pinned);
  }
  const boundConfigHash=rebindings.at(-1)?.configHash??statement.configHash;
  if(boundConfigHash!==digest(config))fail('credential/config binding changed; record a signed config rebinding (scripts/vault-backup.mjs rebind)');
  const binding={restoreId:statement.restoreId,status:statement.status,archiveManifestSha256:statement.archiveManifestSha256,frontierSha256:statement.frontierSha256,configHash:statement.configHash};
  const tenants=db.prepare('SELECT tenant FROM checkpoints UNION SELECT tenant FROM ledger ORDER BY tenant').all().map(r=>r.tenant);
  for(const tenant of Object.keys(statement.checkpoints))if(!tenants.includes(tenant))fail('accepted tenant missing');
  for(const tenant of tenants){
   const cpRow=db.prepare('SELECT body FROM checkpoints WHERE tenant=?').get(tenant);if(!cpRow)fail('checkpoint missing');
   const cp=JSON.parse(cpRow.body),accepted=statement.checkpoints[tenant];verifyCheckpoint(cp,pub);
   if(cp.tenant!==tenant||!Number.isSafeInteger(cp.count)||cp.count<0)fail('checkpoint binding');
   if(accepted){verifyCheckpoint(accepted,pub);if(accepted.tenant!==tenant||cp.count<accepted.count)fail('accepted checkpoint rollback');}
   let previous='0'.repeat(64),sequence=0,lastRestore=null,lastRebinding=null,prefixFound=!accepted;
   for(const sql of db.prepare('SELECT seq,body,hash FROM ledger WHERE tenant=? ORDER BY seq').iterate(tenant)){
    if(Buffer.byteLength(sql.body)>16*1024*1024)fail('ledger row limit');
    const row=JSON.parse(sql.body);
    if(sql.seq!==++sequence||row.seq!==sequence||row.tenant!==tenant||row.previous!==previous||digest(row)!==sql.hash)fail('ledger integrity');
    previous=sql.hash;if(accepted&&sequence===accepted.count){if(previous!==accepted.head)fail('accepted checkpoint lineage');prefixFound=true;}
    if(row.type==='recovery_restore'){lastRestore=row.payload;lastRebinding=null;}
    if(row.type===REBIND_TYPE)lastRebinding=row.payload;
   }
   if(sequence!==cp.count||previous!==cp.head||!prefixFound)fail('truncated history');
   if(accepted&&canonical(lastRestore)!==canonical(binding)||!accepted&&lastRestore)fail('restoration binding changed');
   // The ledger already recorded this rebinding at an earlier start: an older (even consistently pinned) chain is a rollback.
   const recorded=lastRebinding&&rebindings[lastRebinding.sequence-1];
   if(lastRebinding&&(lastRebinding.restoreId!==statement.restoreId||!recorded||canonical(rebindingRecord(recorded))!==canonical(lastRebinding)))
    fail('config rebinding rollback');
  }
  return {marker,restoreId:statement.restoreId,tenants:Object.keys(statement.checkpoints),configHash:boundConfigHash,rebindings,pending};
 }finally{db.close();}
}

// Called in the vault's startup transaction: every restored tenant's signed ledger records the rebindings in effect, so the
// rebinding files cannot later be rolled back to an older, consistently pinned pair without failing activation.
export function recordConfigRebindings(store,activation){
 if(!activation?.rebindings?.length)return 0;
 const last=store.db.prepare(`SELECT body FROM ledger WHERE tenant=? AND json_extract(body,'$.type') IN ('recovery_restore','${REBIND_TYPE}')
  ORDER BY seq DESC LIMIT 1`);
 let appended=0;
 for(const tenant of activation.tenants){
  const row=last.get(tenant),body=row&&JSON.parse(row.body),recorded=body?.type===REBIND_TYPE?body.payload.sequence:0;
  for(const entry of activation.rebindings.slice(recorded)){store.append(tenant,REBIND_TYPE,rebindingRecord(entry),'vault-recovery');appended++;}
 }
 return appended;
}

// Records a signed rebinding of an activated restoration from the configuration it is bound to now (currentConfig) to a new
// one (scripts/vault-backup.mjs rebind). It writes the chain, then the external pin; the vault ledger records it at next start.
// Rerunning the same request after an interruption between the two writes only writes the missing pin.
export function rebindRecoveryConfig({dataDir,key,currentConfig,config,reason,now=new Date()}){
 if(!existsSync(join(dataDir,FILE)))fail('no restoration marker; only an activated restoration binds its configuration');
 if(typeof reason!=='string'||!reason.trim()||reason.length>2000)fail('a rebinding reason of 1 to 2000 characters is required');
 if(!currentConfig||typeof currentConfig!=='object')fail('the currently bound configuration is required');
 const principals=config?.principals;
 if(!config||typeof config!=='object'||Array.isArray(config)||!Array.isArray(principals))fail('the new configuration must be an object with principals');
 if(principals.some(p=>!p?.id||!p.tenant||typeof p.token!=='string'||p.token.length<32)||new Set(principals.map(p=>p.token)).size!==principals.length)
  fail('the new configuration has invalid credentials');
 const state=verifyActivation({dataDir,key,config:currentConfig,allowUnpinnedHead:true});
 if(!state)fail('no activated restoration to rebind');
 const {marker,rebindings,pending}=state,configHash=digest(config);
 if(pending){
  if(pending.configHash!==configHash)fail('an unpinned rebinding to another configuration is pending; rerun it with that configuration');
  return {rebound:true,completedInterruptedRun:true,sequence:pending.sequence,previousConfigHash:pending.previousConfigHash,configHash,
   record:configRebindingPath(dataDir),externalPin:pinRebinding(dataDir,marker,pending,key),ledgerRecordedAtNextStart:true};
 }
 const previous=rebindings.at(-1),previousConfigHash=state.configHash;
 if(configHash===previousConfigHash)fail('the new configuration is already bound');
 const entry=signed({format:REBIND_FORMAT,restoreId:marker.restoreId,markerSha256:digest(marker),sequence:rebindings.length+1,previousConfigHash,
  configHash,previousEntrySha256:previous?digest(previous):null,reason:reason.trim(),rebindAt:now.toISOString()},key);
 replaceJson(configRebindingPath(dataDir),{format:REBIND_CHAIN,entries:[...rebindings,entry]});
 return {rebound:true,sequence:entry.sequence,previousConfigHash,configHash,record:configRebindingPath(dataDir),
  externalPin:pinRebinding(dataDir,marker,entry,key),ledgerRecordedAtNextStart:true};
}
