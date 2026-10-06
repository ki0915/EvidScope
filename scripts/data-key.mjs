// Data-encryption key operations. Never prints key material.
//   node scripts/data-key.mjs generate OUT_FILE
//   node scripts/data-key.mjs id KEY_FILE
//   DATA_KEY_FILE=new.key [DATA_KEY_PREVIOUS_FILES=old.key] node scripts/data-key.mjs migrate DATA_DIR SIGNING_KEY_FILE
// migrate: run with the vault stopped. Re-encrypts every document file referenced by verified signed history
// under the current data key, re-verifies, and retires data key ids no longer referenced.
import {readFileSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {Store} from '../src/store.mjs';
import {checkDocumentFiles} from '../src/document-integrity.mjs';
import {createGovernanceDocumentStorage} from '../src/governance-documents.mjs';
import {createDocumentAdapter} from '../src/finance-evidence.mjs';
import {createKeyring,dataKeysFromEnv,dataKeyId,generateDataKeyFile,readDataKeyFile,ensureDataKeyUsageTable,recordDataKeyUsage,LEGACY_KEY_ID} from '../src/data-keys.mjs';

export function migrateDocuments({dataDir,signingKey,dataKey,previousDataKeys=[]}){
 if(!dataKey)throw Error('migrate requires DATA_KEY_FILE');
 const store=new Store(dataDir,signingKey);
 try{
  ensureDataKeyUsageTable(store.db);
  const keyring=createKeyring({signingKey,dataKey,previousDataKeys,onWrite:kid=>recordDataKeyUsage(store.db,kid)});
  const storage={finance:createDocumentAdapter(dataDir,keyring),governance:createGovernanceDocumentStorage(dataDir,keyring)};
  const tenants=store.db.prepare('SELECT DISTINCT tenant FROM ledger ORDER BY tenant').all().map(r=>r.tenant),moved={},remaining={};
  // BEGIN IMMEDIATE blocks a concurrently running vault from document intake for the duration.
  store.transaction(()=>{
   for(const tenant of tenants){
    const bundle=store.bundle(tenant),checked=checkDocumentFiles({db:store.db,tenant,records:bundle.records,dataDir,keyring});
    for(const file of checked.files){const r=storage[file.kind].reencrypt(file.tenant,file.sha256);if(r.changed)moved[r.from]=(moved[r.from]||0)+1;}
    const after=checkDocumentFiles({db:store.db,tenant,records:bundle.records,dataDir,keyring});
    for(const [kid,n] of Object.entries(after.keyIds))remaining[kid]=(remaining[kid]||0)+n;
   }
   const now=new Date().toISOString(),retired=[];
   for(const {kid} of store.db.prepare('SELECT kid FROM data_key_usage WHERE retired_at IS NULL').all())if(kid!==keyring.currentKeyId&&!remaining[kid]){store.db.prepare('UPDATE data_key_usage SET retired_at=? WHERE kid=?').run(now,kid);retired.push(kid);}
   moved.retiredKeyIds=retired;
  });
  const {retiredKeyIds,...reencryptedFrom}=moved;
  return {migrated:true,currentKeyId:keyring.currentKeyId,tenants:tenants.length,reencryptedFrom,referencedFilesByKeyId:remaining,retiredKeyIds,legacyRemaining:remaining[LEGACY_KEY_ID]||0,
   nextSteps:['Create a new vault backup now (v2, sealed by the current data key).','Keep every retired data key and the signing PEM in offline escrow while any backup sealed with them is retained.','Unreferenced orphan files were not re-encrypted.']};
 }finally{store.close();}
}

if(process.argv[1]&&pathToFileURL(resolve(process.argv[1])).href===import.meta.url){
 const [mode,...args]=process.argv.slice(2);
 try{
  if(mode==='generate'&&args.length===1)console.log(JSON.stringify({created:true,file:resolve(args[0]),kid:generateDataKeyFile(resolve(args[0]))}));
  else if(mode==='id'&&args.length===1)console.log(JSON.stringify({kid:dataKeyId(readDataKeyFile(resolve(args[0])))}));
  else if(mode==='migrate'&&args.length===2)console.log(JSON.stringify(migrateDocuments({dataDir:resolve(args[0]),signingKey:readFileSync(resolve(args[1]),'utf8'),...dataKeysFromEnv(process.env)})));
  else throw Error('Usage: generate OUT_FILE | id KEY_FILE | migrate DATA_DIR SIGNING_KEY_FILE (env DATA_KEY_FILE, DATA_KEY_PREVIOUS_FILES)');
 }catch(error){console.error(JSON.stringify({ok:false,error:error.message}));process.exitCode=1;}
}
