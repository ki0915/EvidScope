// Data-encryption keys, kept separate from the Ed25519 signing key.
// A 32-byte random root key (DATA_KEY_FILE) feeds HKDF-SHA256 with one info label per purpose.
// Legacy material (sha256(label || signing PKCS8 DER)) stays decrypt-capable for data written before separation.
import {hkdfSync,createHash,createPrivateKey,createPublicKey,randomBytes} from 'node:crypto';
import {existsSync,readFileSync,realpathSync,statSync,writeFileSync} from 'node:fs';
import {delimiter,isAbsolute,relative,resolve,sep} from 'node:path';

export const DATA_KEY_BYTES=32;
export const LEGACY_KEY_ID='legacy-signing-v1';
export const KEY_ID_PATTERN=/^dk1-[a-f0-9]{32}$/;
export const PURPOSES=Object.freeze({
 governanceDocument:'evidscope/data-key/v1/governance-document',
 financeDocument:'evidscope/data-key/v1/finance-document',
 vaultBackup:'evidscope/data-key/v1/vault-backup',
});
const LEGACY_LABELS=Object.freeze({governanceDocument:'evidscope-governance-documents-v1',financeDocument:'evidscope-finance-documents-v1',vaultBackup:'evidscope-vault-backup-encryption-v1'});
const KEY_ID_INFO='evidscope/data-key/v1/key-id';
const hkdf=(root,info,length=32)=>Buffer.from(hkdfSync('sha256',root,Buffer.alloc(0),Buffer.from(info,'utf8'),length));
const toPrivate=key=>key&&typeof key==='object'&&key.type==='private'?key:createPrivateKey(key);

export function dataKeyId(root){
 if(!Buffer.isBuffer(root)||root.length!==DATA_KEY_BYTES)throw Error('Data key must be exactly 32 bytes');
 return 'dk1-'+hkdf(root,KEY_ID_INFO,16).toString('hex');
}

// Raw 32 bytes in a regular file (symlinks followed: Kubernetes secret volumes use ..data links).
// No group write and no other access (0600 locally; Kubernetes defaultMode 0440 with fsGroup passes).
export function readDataKeyFile(path){
 const stat=statSync(path);
 if(!stat.isFile())throw Error('Data key file must be a regular file');
 if(process.platform!=='win32'&&(stat.mode&0o027))throw Error('Data key file permissions too open (no group write, no other access)');
 const bytes=readFileSync(path);
 if(bytes.length!==DATA_KEY_BYTES)throw Error('Data key file must contain exactly 32 raw bytes');
 return bytes;
}

export function generateDataKeyFile(path){
 const root=randomBytes(DATA_KEY_BYTES);
 writeFileSync(path,root,{mode:0o600,flag:'wx'});
 return dataKeyId(root);
}

// A key stored beside the ciphertext (or on the same volume snapshot) defeats separation.
function assertOutsideDataDir(file,dataDir){
 if(!dataDir)return;
 const root=existsSync(dataDir)?realpathSync(dataDir):resolve(dataDir),rel=relative(root,realpathSync(file));
 if(!rel||!isAbsolute(rel)&&rel!=='..'&&!rel.startsWith('..'+sep))throw Error('Data key file must not be stored inside DATA_DIR');
}

export function dataKeysFromEnv(env=process.env){
 const previousFiles=(env.DATA_KEY_PREVIOUS_FILES||'').split(delimiter).filter(Boolean);
 if(previousFiles.length&&!env.DATA_KEY_FILE)throw Error('DATA_KEY_PREVIOUS_FILES requires DATA_KEY_FILE');
 for(const file of [env.DATA_KEY_FILE,...previousFiles].filter(Boolean))assertOutsideDataDir(file,env.DATA_DIR);
 return {dataKey:env.DATA_KEY_FILE?readDataKeyFile(env.DATA_KEY_FILE):undefined,previousDataKeys:previousFiles.map(readDataKeyFile)};
}

export function isKeyring(value){return !!value&&typeof value==='object'&&value.kind==='evidscope-keyring';}

// signingKey: Ed25519 private key (KeyObject/PEM). Only needed while legacy ciphertext must be readable.
export function createKeyring({signingKey,dataKey,previousDataKeys=[],onWrite}={}){
 const legacySource=signingKey?toPrivate(signingKey):null;
 const legacyKeys=new Map();
 const roots=new Map();
 for(const root of [dataKey,...previousDataKeys].filter(Boolean)){
  const kid=dataKeyId(root);if(roots.has(kid))throw Error('Duplicate data key');roots.set(kid,root);
 }
 const current=dataKey?dataKeyId(dataKey):null;
 const derived=new Map();
 function legacy(purpose){
  if(!Object.hasOwn(LEGACY_LABELS,purpose))throw Error('Unknown data key purpose');
  if(!legacySource)throw Error('Legacy signing-key-derived data requires the signing private key');
  if(!legacyKeys.has(purpose))legacyKeys.set(purpose,createHash('sha256').update(LEGACY_LABELS[purpose]).update(legacySource.export({type:'pkcs8',format:'der'})).digest());
  return legacyKeys.get(purpose);
 }
 function key(purpose,kid){
  if(!Object.hasOwn(PURPOSES,purpose))throw Error('Unknown data key purpose');
  if(kid===LEGACY_KEY_ID)return legacy(purpose);
  const root=roots.get(kid);if(!root)throw Error(`Data key ${typeof kid==='string'&&KEY_ID_PATTERN.test(kid)?kid:'(invalid id)'} is not configured`);
  const cacheKey=purpose+'\0'+kid;if(!derived.has(cacheKey))derived.set(cacheKey,hkdf(root,PURPOSES[purpose]));
  return derived.get(cacheKey);
 }
 return Object.freeze({
  kind:'evidscope-keyring',
  separated:!!current,
  currentKeyId:current,
  writeKeyId:current||LEGACY_KEY_ID,
  keyIds:Object.freeze([...roots.keys()]),
  legacyAvailable:!!legacySource,
  key,
  writeKey:purpose=>{const kid=current||LEGACY_KEY_ID,value=key(purpose,kid);onWrite?.(kid,purpose);return {kid,key:value};},
  status:()=>({configured:!!current,currentKeyId:current,decryptOnlyKeyIds:[...roots.keys()].filter(k=>k!==current),legacySigningKeyDerivedReadable:!!legacySource,newWritesUse:current||LEGACY_KEY_ID,signingKeyFingerprint:legacySource?createHash('sha256').update(createPublicKey(legacySource).export({type:'spki',format:'der'})).digest('hex'):null}),
 });
}

// Accept a keyring or (for existing call sites/tests) a bare signing key => legacy-only keyring.
export const asKeyring=value=>isKeyring(value)?value:createKeyring({signingKey:value});

// Non-secret record of every data key id that sealed stored data, kept inside evidence.db so it
// travels with backups. Operational fail-closed guard (misconfiguration/lost key), not a security control.
export function ensureDataKeyUsageTable(db){db.exec('CREATE TABLE IF NOT EXISTS data_key_usage(kid TEXT PRIMARY KEY,first_used_at TEXT NOT NULL,retired_at TEXT)');}
export function recordDataKeyUsage(db,kid){if(kid!==LEGACY_KEY_ID)db.prepare('INSERT OR IGNORE INTO data_key_usage(kid,first_used_at) VALUES(?,?)').run(kid,new Date().toISOString());}
export function assertDataKeysAvailable(db,keyring){
 const missing=db.prepare('SELECT kid FROM data_key_usage WHERE retired_at IS NULL ORDER BY kid').all().map(r=>r.kid).filter(kid=>!keyring.keyIds.includes(kid));
 if(missing.length)throw Error('Stored data was sealed with data key(s) that are not configured: '+missing.join(','));
}
