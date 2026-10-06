import {createHash} from 'node:crypto';
import {createDocumentAdapter} from './finance-evidence.mjs';
import {createGovernanceDocumentStorage,checkGovernanceDocumentProjection} from './governance-documents.mjs';

const MAX_REFERENCED_FILES=4096;
const MAX_REFERENCED_BYTES=256*1024*1024;
const digest=value=>createHash('sha256').update(value).digest('hex');
const validHash=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);

export function documentPath(kind,tenant,hash){
 if(!['finance','governance'].includes(kind)||typeof tenant!=='string'||!tenant||!validHash(hash))throw Error('Document file reference is invalid');
 return `${kind==='finance'?'finance-documents':'governance-documents'}/${digest(Buffer.from(tenant))}/${hash}.json`;
}

function addReference(files,{kind,tenant,sha256,bytes}){
 if(!validHash(sha256)||!Number.isSafeInteger(bytes)||bytes<1||bytes>64*1024)throw Error('Document file metadata is invalid');
 const key=`${kind}:${sha256}`,existing=files.get(key);
 if(existing&&existing.bytes!==bytes)throw Error('Document file length metadata conflicts with signed history');
 if(!existing){
  if(files.size>=MAX_REFERENCED_FILES)throw Error('Document file integrity scan limit exceeded');
  files.set(key,{kind,tenant,sha256,bytes,path:documentPath(kind,tenant,sha256)});
 }
}

// Verify only files referenced by authenticated history. Orphan files are not evidence
// and are deliberately excluded. Each file is authenticated at its individual read;
// this does not claim a filesystem snapshot, remote immutability, or elapsed retention.
export function checkDocumentFiles({db,tenant,records,dataDir,key}){
 if(!db||typeof tenant!=='string'||!Array.isArray(records)||!dataDir||!key)throw Error('Document integrity inputs are invalid');
 const governanceDocumentProjection=checkGovernanceDocumentProjection(db,tenant,records),files=new Map();
 for(const row of records){
  if(row.type!=='supplier_bundle')continue;
  const documents=row.payload?.documents;
  if(documents===undefined)continue;
  if(!Array.isArray(documents)||documents.length>10)throw Error('Supplier document metadata is invalid');
  for(const document of documents||[])addReference(files,{kind:'finance',tenant,sha256:document?.sha256,bytes:document?.bytes});
 }
 for(const metadata of governanceDocumentProjection.history)addReference(files,{kind:'governance',tenant,sha256:metadata.sha256,bytes:metadata.bytes});
 let plaintextBytes=0,financeFiles=0,governanceFiles=0;
 const finance=createDocumentAdapter(dataDir,key),governance=createGovernanceDocumentStorage(dataDir,key);
 for(const file of files.values()){
  const bytes=(file.kind==='finance'?finance:governance).read(file.tenant,file.sha256);
  if(bytes.length!==file.bytes)throw Error('Document file length differs from signed metadata');
  plaintextBytes+=bytes.length;
  if(plaintextBytes>MAX_REFERENCED_BYTES)throw Error('Document file integrity byte limit exceeded');
  if(file.kind==='finance')financeFiles++;else governanceFiles++;
 }
 return {
  summary:{valid:true,financeFiles,governanceFiles,uniqueFiles:files.size,plaintextBytes,verification:'referenced_ciphertext_decrypted_authenticated_and_hashed_per_file',unreferencedFilesScanned:false,filesystemSnapshotProven:false},
  governanceDocumentProjection:{valid:true,documents:governanceDocumentProjection.documents,revisions:governanceDocumentProjection.revisions},
  files:[...files.values()].sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0),
 };
}
