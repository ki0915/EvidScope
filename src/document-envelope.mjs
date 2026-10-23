// Content-addressed AES-256-GCM document envelopes shared by finance and governance storage.
// v1 (legacy): {iv,tag,data}; key=sha256(label||signing PKCS8); AAD=`${tenant}:${sha256}`.
// v2: {format,kid,iv,tag,data}; key=HKDF(data root, purpose label); AAD=canonical({format,purpose,kid,tenant,sha256}).
import {createCipheriv,createDecipheriv,createHash,randomBytes,randomUUID} from 'node:crypto';
import {existsSync,mkdirSync,renameSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {canonical} from './crypto.mjs';
import {readBoundedRegularFile} from './bounded-file.mjs';
import {LEGACY_KEY_ID,KEY_ID_PATTERN} from './data-keys.mjs';

export const DOCUMENT_ENVELOPE_V2='evidscope-document-envelope-v2';
const PURPOSE_NAMES={governanceDocument:'governance-document',financeDocument:'finance-document'};
const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');
const b64=value=>typeof value==='string'&&Buffer.from(value,'base64').toString('base64')===value;
const exactKeys=(value,names)=>Object.keys(value).length===names.length&&names.every(name=>Object.hasOwn(value,name));
const aad=(version,purpose,kid,tenant,hash)=>Buffer.from(version===1
 ?`${tenant}:${hash}`
 :canonical({format:DOCUMENT_ENVELOPE_V2,purpose:PURPOSE_NAMES[purpose],kid,tenant,sha256:hash}));

export function parseDocumentEnvelope(saved){
 if(!saved||typeof saved!=='object'||Array.isArray(saved))throw Error('Invalid encrypted document envelope');
 let version,kid;
 if(exactKeys(saved,['iv','tag','data'])){version=1;kid=LEGACY_KEY_ID;}
 else if(exactKeys(saved,['format','kid','iv','tag','data'])&&saved.format===DOCUMENT_ENVELOPE_V2&&typeof saved.kid==='string'&&KEY_ID_PATTERN.test(saved.kid)){
  version=2;kid=saved.kid;
 }
 else throw Error('Invalid encrypted document envelope');
 if(!['iv','tag','data'].every(name=>b64(saved[name])))throw Error('Invalid encrypted document envelope');
 const iv=Buffer.from(saved.iv,'base64'),tag=Buffer.from(saved.tag,'base64'),data=Buffer.from(saved.data,'base64');
 if(iv.length!==12||tag.length!==16||!data.length)throw Error('Invalid encrypted document envelope');
 return {version,kid,iv,tag,data};
}

export function createEncryptedDocumentStore({root,purpose,keyring,maxEnvelopeBytes,maxPlaintextBytes,
 invalidHash=()=>{throw Error('Invalid document digest');},verifyAfterWrite=true}){
 if(!Object.hasOwn(PURPOSE_NAMES,purpose))throw Error('Unknown document purpose');
 const location=(tenant,hash)=>{
  if(typeof hash!=='string'||!/^[a-f0-9]{64}$/.test(hash))invalidHash();
  return join(root,sha256(Buffer.from(tenant)),hash+'.json');
 };
 function open(tenant,hash){
  const envelope=parseDocumentEnvelope(JSON.parse(readBoundedRegularFile(location(tenant,hash),maxEnvelopeBytes).toString('utf8')));
  const decipher=createDecipheriv('aes-256-gcm',keyring.key(purpose,envelope.kid),envelope.iv);
  decipher.setAAD(aad(envelope.version,purpose,envelope.kid,tenant,hash));decipher.setAuthTag(envelope.tag);
  const bytes=Buffer.concat([decipher.update(envelope.data),decipher.final()]);
  if(bytes.length>maxPlaintextBytes||sha256(bytes)!==hash)throw Error('Document hash mismatch');
  return {bytes,kid:envelope.kid,version:envelope.version};
 }
 function seal(tenant,hash,bytes,path){
  const {kid,key}=keyring.writeKey(purpose),version=kid===LEGACY_KEY_ID?1:2,iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,iv);
  cipher.setAAD(aad(version,purpose,kid,tenant,hash));
  const data=Buffer.concat([cipher.update(bytes),cipher.final()]);
  const body={...(version===2?{format:DOCUMENT_ENVELOPE_V2,kid}:{}),iv:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64'),
   data:data.toString('base64')};
  const temporary=path+'.'+randomUUID()+'.tmp';
  writeFileSync(temporary,JSON.stringify(body),{flag:'wx',mode:0o600});renameSync(temporary,path);
  return kid;
 }
 // onCreate(path) runs only when this call wrote a new file, so a caller can remove it if its transaction rolls back.
 function put(tenant,bytes,onCreate){
  const hash=sha256(bytes),path=location(tenant,hash);if(existsSync(path)){open(tenant,hash);return hash;}
  mkdirSync(join(root,sha256(Buffer.from(tenant))),{recursive:true});
  seal(tenant,hash,bytes,path);onCreate?.(path);if(verifyAfterWrite)open(tenant,hash);return hash;
 }
 // Re-encrypt one referenced file under the current write key. Plaintext and path are unchanged.
 function reencrypt(tenant,hash){
  const current=open(tenant,hash);if(current.kid===keyring.writeKeyId)return {changed:false,from:current.kid,to:current.kid};
  seal(tenant,hash,current.bytes,location(tenant,hash));const after=open(tenant,hash);
  if(!after.bytes.equals(current.bytes))throw Error('Re-encryption verification failed');
  return {changed:true,from:current.kid,to:after.kid};
 }
 return {read:(tenant,hash)=>open(tenant,hash).bytes,open,put,reencrypt,location};
}
