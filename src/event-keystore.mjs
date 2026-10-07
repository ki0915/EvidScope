// Event keystore (round 2, audit S3): the per-tenant key-epoch secrets, kept in EVENT_KEYSTORE_DIR outside DATA_DIR instead of
// evidence.db. Each secret is a small file sealed by a sealer: by default the data key (HKDF purpose eventKeyEpoch). A KMS or the
// signer process can provide the same two calls, seal and unseal. Event keys in evidence.db are stored wrapped under these
// secrets (src/event-keys.mjs), so destroying an epoch file makes that epoch's event keys unreadable in every copy of the
// database and in every vault backup. Vault backups never include this directory.
//   <dir>/keystore.json                       {format, id, createdAt}
//   <dir>/epochs/t-<tenant hash>/<epoch>.json  sealed secret, AAD bound to keystore id, tenant, epoch, createdAt and data key id
//   <dir>/tombstones/t-<tenant hash>/<epoch>.json  destroyed epochs (not secret); an epoch with a tombstone is never re-created
//   <dir>/vault.json                          the one vault (signing key) this keystore serves, written when it is first attached
import {createCipheriv,createDecipheriv,createHash,randomBytes,randomUUID} from 'node:crypto';
import {
 closeSync,existsSync,fsyncSync,linkSync,mkdirSync,openSync,readFileSync,readdirSync,realpathSync,renameSync,statSync,unlinkSync,writeSync,
} from 'node:fs';
import {dirname,isAbsolute,join,relative,resolve,sep} from 'node:path';
import {canonical,equal} from './crypto.mjs';
import {KEY_ID_PATTERN,ensureDataKeyUsageTable,recordDataKeyUsage} from './data-keys.mjs';
import {EPOCH_SECRET_BYTES,checkEpoch,epochOperations,migrateEventKeys} from './event-keys.mjs';

export const KEYSTORE_FORMAT='evidscope-event-keystore-v1',EPOCH_FILE_FORMAT='evidscope-event-key-epoch-v1';
export const TOMBSTONE_FORMAT='evidscope-event-key-epoch-tombstone-v1',VAULT_FORMAT='evidscope-event-keystore-vault-v1';
const UUID=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/,MAX_FILE_BYTES=64*1024;

// Seals epoch secrets with the data key. kid is the data key id; previous data keys stay able to unseal until resealed.
export function dataKeySealer(keyring){
 if(!keyring?.separated)throw Error('EVENT_KEYSTORE_DIR requires DATA_KEY_FILE: the keystore is sealed by the data key');
 const aadOf=(aad,kid)=>Buffer.from(canonical({...aad,kid}));
 return {
  kind:'data-key',
  get kid(){return keyring.currentKeyId;},
  seal(aad,secret){
   const {kid,key}=keyring.writeKey('eventKeyEpoch'),iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(aadOf(aad,kid));
   const ciphertext=Buffer.concat([cipher.update(secret),cipher.final()]);
   return {kid,iv:iv.toString('base64'),ciphertext:ciphertext.toString('base64'),tag:cipher.getAuthTag().toString('base64')};
  },
  unseal(aad,sealed){
   if(!KEY_ID_PATTERN.test(sealed?.kid||''))throw Error('Event keystore file names no data key');
   const decipher=createDecipheriv('aes-256-gcm',keyring.key('eventKeyEpoch',sealed.kid),Buffer.from(sealed.iv,'base64'));
   decipher.setAAD(aadOf(aad,sealed.kid));decipher.setAuthTag(Buffer.from(sealed.tag,'base64'));
   return Buffer.concat([decipher.update(Buffer.from(sealed.ciphertext,'base64')),decipher.final()]);
  },
 };
}

const syncDir=path=>{if(process.platform==='win32')return;const fd=openSync(path,'r');try{fsyncSync(fd);}finally{closeSync(fd);}};
function writeTemp(file,text){
 const tmp=`${file}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`,fd=openSync(tmp,'wx',0o600);
 try{writeSync(fd,text);fsyncSync(fd);}finally{closeSync(fd);}
 return tmp;
}
// Exclusive and durable: two processes creating the same epoch cannot both win (the loser reads the winner's file).
function createExclusive(file,text){
 const tmp=writeTemp(file,text);
 try{linkSync(tmp,file);return true;}catch(error){if(error.code==='EEXIST')return false;throw error;}finally{unlinkSync(tmp);syncDir(dirname(file));}
}
function replaceFile(file,text){const tmp=writeTemp(file,text);renameSync(tmp,file);syncDir(dirname(file));}
// Overwrites before unlinking. Journaling filesystems and SSDs may still keep old blocks (docs/event-key-wrapping.md).
function scrub(file){
 const size=statSync(file).size,fd=openSync(file,'r+');
 try{writeSync(fd,Buffer.alloc(size));fsyncSync(fd);}finally{closeSync(fd);}
 unlinkSync(file);syncDir(dirname(file));
}
function readJson(file){
 const stat=statSync(file);if(!stat.isFile()||stat.size>MAX_FILE_BYTES)throw Error('Invalid event keystore file');
 return JSON.parse(readFileSync(file,'utf8'));
}
function outside(dir,dataDir){
 if(!dataDir)return;
 const root=existsSync(dataDir)?realpathSync(dataDir):resolve(dataDir),rel=relative(root,dir);
 if(!rel||!isAbsolute(rel)&&rel!=='..'&&!rel.startsWith('..'+sep))throw Error('EVENT_KEYSTORE_DIR must not be inside DATA_DIR');
}

// New keystore directory (idempotent). Returns its id.
export function createEventKeystore(dir){
 mkdirSync(dir,{recursive:true,mode:0o700});
 const file=join(dir,'keystore.json');
 if(!existsSync(file))createExclusive(file,JSON.stringify({format:KEYSTORE_FORMAT,id:randomUUID(),createdAt:new Date().toISOString()})+'\n');
 for(const name of ['epochs','tombstones'])mkdirSync(join(dir,name),{recursive:true,mode:0o700});
 return readJson(file).id;
}

export function openEventKeystore({dir,sealer,dataDir}){
 if(!sealer||typeof sealer.seal!=='function'||typeof sealer.unseal!=='function')throw Error('Event keystore requires a sealer');
 const root=realpathSync(resolve(dir));
 if(!statSync(root).isDirectory())throw Error('EVENT_KEYSTORE_DIR must be a directory');
 if(process.platform!=='win32'&&statSync(root).mode&0o007)throw Error('EVENT_KEYSTORE_DIR permissions too open (no access for other users)');
 outside(root,dataDir);
 const meta=readJson(join(root,'keystore.json'));
 if(meta.format!==KEYSTORE_FORMAT||!UUID.test(meta.id||''))throw Error('EVENT_KEYSTORE_DIR holds no event keystore (scripts/event-keys.mjs init)');
 const tenantDir=(kind,tenant)=>join(root,kind,'t-'+createHash('sha256').update('evidscope/event-keystore/tenant\0'+tenant).digest('hex').slice(0,40));
 const epochFile=(tenant,epoch)=>join(tenantDir('epochs',tenant),checkEpoch(epoch)+'.json');
 const tombstoneFile=(tenant,epoch)=>join(tenantDir('tombstones',tenant),checkEpoch(epoch)+'.json');
 const aadOf=(tenant,epoch,createdAt)=>({format:EPOCH_FILE_FORMAT,keystoreId:meta.id,tenant,epoch,createdAt});
 const cache=new Map(),cacheKey=(tenant,epoch)=>canonical([tenant,epoch]);
 const destroyed=(tenant,epoch)=>typeof tenant==='string'&&existsSync(tombstoneFile(tenant,epoch));
 const header=(file,tenant,epoch)=>{
  const value=readJson(file);
  if(value.format!==EPOCH_FILE_FORMAT||value.keystoreId!==meta.id||value.tenant!==tenant||value.epoch!==epoch||typeof value.createdAt!=='string')
   throw Error('Event keystore epoch file is invalid');
  return value;
 };
 function secret(tenant,epoch){
  const id=cacheKey(tenant,epoch);if(cache.has(id))return cache.get(id);
  const file=epochFile(tenant,epoch);if(destroyed(tenant,epoch)||!existsSync(file))return undefined;
  const value=header(file,tenant,epoch),plain=sealer.unseal(aadOf(tenant,epoch,value.createdAt),value.sealed);
  if(plain.length!==EPOCH_SECRET_BYTES)throw Error('Event keystore epoch secret is invalid');
  cache.set(id,plain);return plain;
 }
 const sealedFile=(tenant,epoch,value,createdAt)=>JSON.stringify({format:EPOCH_FILE_FORMAT,keystoreId:meta.id,tenant,epoch,createdAt,
  sealed:sealer.seal(aadOf(tenant,epoch,createdAt),value)})+'\n';
 function create(tenant,epoch,value,createdAt){
  if(destroyed(tenant,epoch))throw Error(`Event-key epoch ${epoch} was destroyed; it cannot take new events`);
  mkdirSync(tenantDir('epochs',tenant),{recursive:true,mode:0o700});
  createExclusive(epochFile(tenant,epoch),sealedFile(tenant,epoch,value,createdAt));
  return secret(tenant,epoch);
 }
 const entries=(kind,tenant)=>{
  const path=tenantDir(kind,tenant);if(!existsSync(path))return [];
  return readdirSync(path).filter(name=>/^\d{4}-\d{2}\.json$/.test(name)).sort().map(name=>name.slice(0,7));
 };
 const allTenants=kind=>{
  const path=join(root,kind);if(!existsSync(path))return [];
  return [...new Set(readdirSync(path).flatMap(dirName=>readdirSync(join(path,dirName)).filter(name=>/^\d{4}-\d{2}\.json$/.test(name))
   .map(name=>readJson(join(path,dirName,name)).tenant)).filter(tenant=>typeof tenant==='string'))].sort();
 };
 const epochs={
  kind:'keystore',id:meta.id,wrapsEventKeys:true,...epochOperations(secret,destroyed),destroyed,
  // An epoch file on disk, readable or not (a file restored next to its tombstone still holds the secret).
  present:(tenant,epoch)=>typeof tenant==='string'&&existsSync(epochFile(tenant,epoch)),
  ensure(tenant,epoch){if(!secret(tenant,epoch))create(tenant,epoch,randomBytes(EPOCH_SECRET_BYTES),new Date().toISOString());},
  // The same secret keeps the receipt tags and keys made with it valid; a different one for the same epoch is refused.
  importEpoch(tenant,epoch,value,createdAt){
   if(destroyed(tenant,epoch))throw Error(`Event-key epoch ${epoch} was destroyed in this keystore; evidence.db is an older copy and is not moved`);
   const existing=secret(tenant,epoch);
   const same=other=>equal(other.toString('hex'),Buffer.from(value).toString('hex'));
   if(existing){if(!same(existing))throw Error(`Event keystore already holds another secret for ${epoch}`);return;}
   if(!same(create(tenant,epoch,Buffer.from(value),createdAt)))throw Error('Event keystore import race');
  },
  importTombstone(tenant,epoch,destroyedAt){epochs.destroy(tenant,epoch,{at:destroyedAt});},
  // Tombstone first, so a crash in between can never leave an epoch that looks never created.
  destroy(tenant,epoch,{at=new Date().toISOString()}={}){
   const tombstone=tombstoneFile(tenant,epoch);mkdirSync(dirname(tombstone),{recursive:true,mode:0o700});
   if(!existsSync(tombstone))createExclusive(tombstone,JSON.stringify({format:TOMBSTONE_FORMAT,keystoreId:meta.id,tenant,epoch,destroyedAt:at})+'\n');
   const id=cacheKey(tenant,epoch);cache.get(id)?.fill(0);cache.delete(id);
   const file=epochFile(tenant,epoch);if(existsSync(file))scrub(file);
  },
  list:tenant=>entries('epochs',tenant).filter(epoch=>!destroyed(tenant,epoch)).map(epoch=>{
   const value=header(epochFile(tenant,epoch),tenant,epoch);return {tenant,epoch,createdAt:value.createdAt,kid:value.sealed?.kid};
  }),
  tombstones:tenant=>entries('tombstones',tenant).map(epoch=>{
   const value=readJson(tombstoneFile(tenant,epoch));
   if(value.format!==TOMBSTONE_FORMAT||value.tenant!==tenant||value.epoch!==epoch)throw Error('Event keystore tombstone is invalid');
   return {tenant,epoch,destroyedAt:value.destroyedAt};
  }),
  tenants:()=>[...new Set([...allTenants('epochs'),...allTenants('tombstones')])].sort(),
  // Data-key rotation: every epoch file sealed under another data key id is resealed under the current one.
  reseal(){
   const moved={};
   for(const tenant of epochs.tenants())for(const item of epochs.list(tenant)){
    if(item.kid===sealer.kid)continue;
    const value=secret(tenant,item.epoch);replaceFile(epochFile(tenant,item.epoch),sealedFile(tenant,item.epoch,value,item.createdAt));
    moved[item.kid]=(moved[item.kid]||0)+1;
   }
   return moved;
  },
  keyIds(){const counts={};for(const tenant of epochs.tenants())for(const item of epochs.list(tenant))counts[item.kid]=(counts[item.kid]||0)+1;return counts;},
  // One keystore serves one vault, named by its signing key: another vault with the same tenant names would share its epochs,
  // and destroying an epoch there would make this vault's retained events unreadable. A restored copy is the same vault.
  bindVault(publicKey,{create=true}={}){
   const file=join(root,'vault.json'),signingKey=createHash('sha256').update(publicKey.export({type:'spki',format:'der'})).digest('hex');
   if(!existsSync(file)){if(!create)return;createExclusive(file,JSON.stringify({format:VAULT_FORMAT,keystoreId:meta.id,signingKey})+'\n');}
   const value=readJson(file);
   if(value.format!==VAULT_FORMAT||value.keystoreId!==meta.id||value.signingKey!==signingKey)throw Error('EVENT_KEYSTORE_DIR already serves another vault');
  },
 };
 return epochs;
}

// Non-secret record in evidence.db of the keystore that wraps its event keys: without it, or with another one, the vault and
// its tools refuse to start instead of writing unwrapped keys beside wrapped ones. moved_at marks the completed first move:
// epoch rows that show up in evidence.db after it are never imported (they could plant a known secret or a tombstone).
export function ensureKeystoreUsageTable(db){
 db.exec('CREATE TABLE IF NOT EXISTS event_keystore_usage(id TEXT PRIMARY KEY,first_used_at TEXT NOT NULL,moved_at TEXT)');
}
const usageTable=db=>!!db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='event_keystore_usage'").get();
export function keystoreIdsInUse(db){return usageTable(db)?db.prepare('SELECT id FROM event_keystore_usage ORDER BY id').all().map(row=>row.id):[];}
export const keystoreMoved=db=>usageTable(db)&&!!db.prepare('SELECT 1 FROM event_keystore_usage WHERE moved_at IS NOT NULL').get();
export function assertEventKeystore(db,epochs){
 const ids=keystoreIdsInUse(db);if(!ids.length)return;
 if(!epochs?.wrapsEventKeys)throw Error(`Event keys of this vault are wrapped by event keystore ${ids.join(',')}; set EVENT_KEYSTORE_DIR and DATA_KEY_FILE`);
 if(ids.length!==1||ids[0]!==epochs.id)throw Error('EVENT_KEYSTORE_DIR names another event keystore than the one this vault uses');
}
export const openConfiguredKeystore=({dir,keyring,dataDir})=>dir?openEventKeystore({dir,sealer:dataKeySealer(keyring),dataDir}):null;

// Startup and scripts/event-keys.mjs: check the configured keystore against evidence.db, record it before any key is wrapped
// (a crash midway must still make a vault without the keystore refuse to start), then move remaining raw keys.
// migrate:false only reads (list).
export function attachEventKeystore(store,{dir,keyring,dataDir,migrate=true}){
 const epochs=openConfiguredKeystore({dir,keyring,dataDir});assertEventKeystore(store.db,epochs);
 if(!epochs)return null;
 const sealedBy=Object.keys(epochs.keyIds()),missing=sealedBy.filter(kid=>!keyring.keyIds.includes(kid));
 if(missing.length)throw Error('Event keystore secrets are sealed by data key(s) that are not configured: '+missing.join(','));
 epochs.bindVault(store.publicKey,{create:migrate});
 // Read-only use of a vault that has not moved to the keystore yet keeps reading the epochs where they still are.
 if(!migrate&&!keystoreIdsInUse(store.db).length)return {keystoreId:epochs.id,migrationPending:true};
 store.useEventKeys(epochs);if(!migrate)return {keystoreId:epochs.id};
 ensureKeystoreUsageTable(store.db);ensureDataKeyUsageTable(store.db);for(const kid of sealedBy)recordDataKeyUsage(store.db,kid);
 const firstMove=!keystoreMoved(store.db);
 store.db.prepare('INSERT OR IGNORE INTO event_keystore_usage VALUES(?,?,NULL)').run(epochs.id,new Date().toISOString());
 const moved=()=>store.db.prepare('UPDATE event_keystore_usage SET moved_at=? WHERE id=? AND moved_at IS NULL').run(new Date().toISOString(),epochs.id);
 return {keystoreId:epochs.id,...migrateEventKeys(store,{importEpochs:firstMove,moved})};
}
