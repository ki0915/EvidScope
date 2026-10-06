import {createCipheriv,createDecipheriv,createHash,createPrivateKey,randomBytes,randomUUID} from 'node:crypto';
import {existsSync,mkdirSync,renameSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {canonical,digest} from './crypto.mjs';
import {cleanText,fail,identifier} from './model.mjs';
import {readBoundedRegularFile} from './bounded-file.mjs';

export const MAX_GOVERNANCE_DOCUMENT_BYTES=4*1024*1024;
const MAX_DOCUMENT_BYTES=MAX_GOVERNANCE_DOCUMENT_BYTES;
const MAX_ENVELOPE_BYTES=Math.ceil(MAX_DOCUMENT_BYTES/3)*4+1024;
const RETENTION_BASIS='인공지능기본법 시행령 제27조제2항 조치 근거 문서 5년 보관; 로컬 접수·복구 검증 기록이며 5년 경과 보존 실적을 입증하지 않음';
const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');
const documentId=value=>{const id=identifier(value);if(id.includes('/'))fail(400,'문서 식별자에는 /를 사용할 수 없습니다');return id;};
const fiveYearsAfter=value=>{const until=new Date(value);until.setUTCFullYear(until.getUTCFullYear()+5);return until.toISOString();};

function decodeBase64(value){
 if(typeof value!=='string'||!value.length)fail(400,'문서 base64 형식 오류');
 if(value.length>Math.ceil(MAX_DOCUMENT_BYTES/3)*4)fail(413,'문서 전체 한도 4MiB');
 // A repeated-group regex over a multi-megabyte file can exhaust V8's stack.
 // Scan characters linearly; decode/re-encode below validates exact padding.
 if(value.length%4!==0||/[^A-Za-z0-9+/=]/.test(value))fail(400,'문서 base64 형식 오류');
 const bytes=Buffer.from(value,'base64');
 if(bytes.toString('base64')!==value)fail(400,'문서 base64 정규 형식 오류');
 if(!bytes.length||bytes.length>MAX_DOCUMENT_BYTES)fail(413,'문서 전체 한도 4MiB');
 return bytes;
}

export function createGovernanceDocumentStorage(dataDir,key){
 const root=join(dataDir,'governance-documents');
 const privateKey=typeof key==='string'||Buffer.isBuffer(key)?createPrivateKey(key):key;
 const master=createHash('sha256').update('evidscope-governance-documents-v1').update(privateKey.export({type:'pkcs8',format:'der'})).digest();
 const location=(tenant,hash)=>{
  if(!/^[a-f0-9]{64}$/.test(hash))throw Error('Invalid document digest');
  return join(root,sha256(Buffer.from(tenant)),hash+'.json');
 };
 function read(tenant,hash){
  const path=location(tenant,hash),saved=JSON.parse(readBoundedRegularFile(path,MAX_ENVELOPE_BYTES).toString('utf8'));
  const fields=['iv','tag','data'];if(!saved||typeof saved!=='object'||Array.isArray(saved)||Object.keys(saved).length!==fields.length||fields.some(name=>typeof saved[name]!=='string'||Buffer.from(saved[name],'base64').toString('base64')!==saved[name]))throw Error('Invalid encrypted document envelope');
  const iv=Buffer.from(saved.iv,'base64'),tag=Buffer.from(saved.tag,'base64'),data=Buffer.from(saved.data,'base64');if(iv.length!==12||tag.length!==16||!data.length)throw Error('Invalid encrypted document envelope');
  const decipher=createDecipheriv('aes-256-gcm',master,iv);
  decipher.setAAD(Buffer.from(`${tenant}:${hash}`));decipher.setAuthTag(tag);
  const bytes=Buffer.concat([decipher.update(data),decipher.final()]);
  if(bytes.length>MAX_DOCUMENT_BYTES||sha256(bytes)!==hash)throw Error('Document hash mismatch');return bytes;
 }
 function put(tenant,bytes){
  const hash=sha256(bytes),path=location(tenant,hash);if(existsSync(path)){read(tenant,hash);return hash;}
  mkdirSync(join(root,sha256(Buffer.from(tenant))),{recursive:true});
  const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',master,iv);cipher.setAAD(Buffer.from(`${tenant}:${hash}`));
  const encrypted=Buffer.concat([cipher.update(bytes),cipher.final()]);
  const temporary=path+'.'+randomUUID()+'.tmp';
  writeFileSync(temporary,JSON.stringify({iv:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64'),data:encrypted.toString('base64')}),{flag:'wx',mode:0o600});
  renameSync(temporary,path);read(tenant,hash);return hash;
 }
 return {read,put};
}

function validateSignedMetadata(value){
 const fields=['schemaVersion','id','systemId','version','sha256','bytes','displayName','mediaType','receivedAt','receivedBy','retentionUntil','retentionBasis','snapshotHash'];
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(key=>!fields.includes(key))||fields.some(key=>!Object.hasOwn(value,key))||value.schemaVersion!==1||!Number.isSafeInteger(value.version)||value.version<1)fail(409,'서명된 거버넌스 문서 메타데이터가 유효하지 않습니다');
 if(typeof value.id!=='string'||!/^[a-zA-Z0-9._:@-]{1,120}$/.test(value.id)||typeof value.systemId!=='string'||!/^[a-zA-Z0-9._:@/-]{1,120}$/.test(value.systemId)||typeof value.displayName!=='string'||!value.displayName.trim()||value.displayName.length>200||typeof value.mediaType!=='string'||!value.mediaType.trim()||value.mediaType.length>100||typeof value.receivedBy!=='string'||!value.receivedBy||!/^[a-f0-9]{64}$/.test(value.sha256||'')||!/^[a-f0-9]{64}$/.test(value.snapshotHash||''))fail(409,'서명된 거버넌스 문서 식별자가 유효하지 않습니다');
 if(!Number.isSafeInteger(value.bytes)||value.bytes<1||value.bytes>MAX_DOCUMENT_BYTES||typeof value.receivedAt!=='string'||new Date(value.receivedAt).toISOString()!==value.receivedAt||value.retentionUntil!==fiveYearsAfter(value.receivedAt)||value.retentionBasis!==RETENTION_BASIS)fail(409,'서명된 거버넌스 문서 보관 메타데이터가 유효하지 않습니다');
 const {snapshotHash,...snapshot}=value;if(digest(snapshot)!==snapshotHash)fail(409,'거버넌스 문서 스냅샷 해시가 일치하지 않습니다');return value;
}

export function checkGovernanceDocumentProjection(db,tenant,records){
 const latest=new Map(),versions=new Map(),history=[];
 for(const row of records){
  if(row.type!=='governance_document')continue;
  const value=validateSignedMetadata(row.payload),previous=latest.get(value.id);
  if(value.version!==(versions.get(value.id)||0)+1||previous&&previous.systemId!==value.systemId)fail(409,'거버넌스 문서 버전 원장이 연속적이지 않습니다');
  versions.set(value.id,value.version);latest.set(value.id,value);history.push(value);
 }
 const exists=!!db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='governance_documents'").get();
 if(!exists){if(latest.size)fail(409,'거버넌스 문서 조회 사본이 없습니다');return {valid:true,documents:0,revisions:0,latest,history};}
 const rows=db.prepare('SELECT id,body FROM governance_documents WHERE tenant=?').all(tenant);
 if(rows.length!==latest.size)fail(409,'거버넌스 문서 조회 사본이 서명 원장과 일치하지 않습니다');
 for(const row of rows){let value;try{value=JSON.parse(row.body);}catch{fail(409,'거버넌스 문서 조회 사본이 서명 원장과 일치하지 않습니다');}if(!latest.has(row.id)||canonical(value)!==canonical(latest.get(row.id)))fail(409,'거버넌스 문서 조회 사본이 서명 원장과 일치하지 않습니다');}
 return {valid:true,documents:latest.size,revisions:history.length,latest,history};
}

export function createGovernanceDocuments({store,dataDir,key,getSystem}){
 if(typeof getSystem!=='function')throw Error('Governance document system resolver is required');
 const storage=createGovernanceDocumentStorage(dataDir,key);
 store.db.exec('CREATE TABLE IF NOT EXISTS governance_documents(tenant TEXT NOT NULL,id TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(tenant,id))');
 const review=p=>{if(!['reviewer','admin'].includes(p.role))fail(403,'거버넌스 문서는 검토자 또는 관리자만 접근할 수 있습니다');};
 function verifiedState(p){
  const records=[];
  for(const row of store.verifiedRows(p.tenant,2*1024*1024)){
   if(row.oversized){const type=store.db.prepare("SELECT json_extract(body,'$.type') AS type FROM ledger WHERE tenant=? AND seq=?").get(p.tenant,row.seq)?.type;if(type==='governance_document')fail(413,'거버넌스 문서 메타데이터 한도 초과');continue;}
   if(row.type==='governance_document')records.push(row);
  }
  return checkGovernanceDocumentProjection(store.db,p.tenant,records).latest;
 }
 const current=(p,id)=>verifiedState(p).get(documentId(id))||fail(404,'동일 테넌트 거버넌스 문서를 찾을 수 없습니다');
 function retrieve(p,metadata){
  try{const bytes=storage.read(p.tenant,metadata.sha256);if(bytes.length!==metadata.bytes)throw Error('Document length mismatch');return bytes;}catch{fail(409,'거버넌스 문서를 복구하거나 해시 검증할 수 없습니다');}
 }
 function intake(p,x){
  review(p);const allowed=new Set(['id','systemId','name','mediaType','sha256','contentBase64']);if(Object.keys(x).some(name=>!allowed.has(name)))fail(400,'지원하지 않는 거버넌스 문서 필드');
  const id=documentId(x.id),systemId=identifier(x.systemId),system=getSystem(p,systemId),displayName=cleanText(x.name,200),mediaType=cleanText(x.mediaType||'application/octet-stream',100);
  if(!displayName.trim()||!mediaType.trim())fail(400,'문서 이름과 미디어 유형이 필요합니다');
  if(typeof x.sha256!=='string'||!/^[a-f0-9]{64}$/.test(x.sha256))fail(400,'문서 SHA-256 형식 오류');
  const bytes=decodeBase64(x.contentBase64);if(sha256(bytes)!==x.sha256)fail(400,'수신 문서 해시 불일치');
  const previous=verifiedState(p).get(id);if(previous&&previous.systemId!==systemId)fail(409,'기존 문서 ID의 시스템을 변경할 수 없습니다');
  if(previous&&previous.sha256===x.sha256&&previous.displayName===displayName&&previous.mediaType===mediaType){retrieve(p,previous);return previous;}
  storage.put(p.tenant,bytes);
  const receivedAt=new Date().toISOString(),snapshot={schemaVersion:1,id,systemId,version:(previous?.version||0)+1,sha256:x.sha256,bytes:bytes.length,displayName,mediaType,receivedAt,receivedBy:p.id,retentionUntil:fiveYearsAfter(receivedAt),retentionBasis:RETENTION_BASIS};
  const metadata={...snapshot,snapshotHash:digest(snapshot)};retrieve(p,metadata);
  store.append(p.tenant,'governance_document',metadata,p.id);
  store.db.prepare('INSERT INTO governance_documents VALUES(?,?,?) ON CONFLICT(tenant,id) DO UPDATE SET body=excluded.body').run(p.tenant,id,JSON.stringify(metadata));
  if(previous){const taskId=randomUUID();store.put(p,'governance_task',taskId,{id:taskId,systemId,requirementId:'KR-34-DOCUMENT',documentId:id,title:'조치 근거 문서 개정: 연결 평가 재검토',owner:system.owner,status:'open',previousHash:previous.snapshotHash,currentHash:metadata.snapshotHash});}
  return metadata;
 }
 function evidence(p,ref,systemId){
  const metadata=current(p,ref.slice('governance-document:'.length));if(metadata.systemId!==systemId)fail(400,'다른 시스템의 거버넌스 문서입니다');retrieve(p,metadata);
  return {version:String(metadata.version),contentHash:metadata.sha256,documentSnapshotHash:metadata.snapshotHash,verification:'governance_document_verified_at_assessment'};
 }
 function staleEvidence(p,assessment){
  return assessment.evidence.some(item=>item.ref?.startsWith('governance-document:')&&(()=>{try{const metadata=current(p,item.ref.slice('governance-document:'.length));retrieve(p,metadata);return metadata.systemId!==assessment.systemId||String(metadata.version)!==item.version||metadata.sha256!==item.contentHash||metadata.snapshotHash!==item.documentSnapshotHash||item.verification!=='governance_document_verified_at_assessment';}catch{return true;}})());
 }
 function handle(p,method,url,x){
  const path=url.pathname;if(!path.startsWith('/api/governance/documents'))return undefined;review(p);
  return store.transaction(()=>{
   if(path==='/api/governance/documents'&&method==='POST')return intake(p,x);
   const match=path.match(/^\/api\/governance\/documents\/([^/]+)(\/export)?$/);if(!match||method!=='GET')return undefined;
   let id;try{id=decodeURIComponent(match[1]);}catch{fail(400,'문서 식별자 인코딩 오류');}
   const metadata=current(p,id),bytes=retrieve(p,metadata);
   if(match[2])return {...metadata,contentBase64:bytes.toString('base64')};
   return {...metadata,verification:{status:'hash_verified_and_retrievable',checkedAt:new Date().toISOString()}};
  });
 }
 const list=p=>[...verifiedState(p).values()];
 return {handle,evidence,staleEvidence,current,list,limits:{maximumBytes:MAX_DOCUMENT_BYTES}};
}
