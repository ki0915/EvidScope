// Data-encryption key operations. Never prints key material.
//   node scripts/data-key.mjs generate OUT_FILE
//   node scripts/data-key.mjs id KEY_FILE
//   DATA_KEY_FILE=new.key [DATA_KEY_PREVIOUS_FILES=old.key] node scripts/data-key.mjs migrate DATA_DIR SIGNING_KEY_FILE
// migrate: run with the vault stopped. Re-encrypts every document file referenced by verified signed history
// under the current data key, re-verifies, and retires data key ids no longer referenced. With an event keystore
// (EVENT_KEYSTORE_DIR, required once the vault uses one) its epoch secrets are resealed under the current key first.
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {Store} from '../src/store.mjs';
import {checkDocumentFiles} from '../src/document-integrity.mjs';
import {createGovernanceDocumentStorage} from '../src/governance-documents.mjs';
import {createDocumentAdapter} from '../src/finance-evidence.mjs';
import {attachEventKeystore} from '../src/event-keystore.mjs';
import {
 createKeyring,dataKeysFromEnv,dataKeyId,generateDataKeyFile,readDataKeyFile,ensureDataKeyUsageTable,recordDataKeyUsage,LEGACY_KEY_ID,
} from '../src/data-keys.mjs';

export function migrateDocuments({dataDir,signingKey,dataKey,previousDataKeys=[],eventKeystoreDir}){
 if(!dataKey)throw Error('migrate requires DATA_KEY_FILE');
 const store=new Store(dataDir,signingKey);
 try{
  ensureDataKeyUsageTable(store.db);
  const keyring=createKeyring({signingKey,dataKey,previousDataKeys,onWrite:kid=>recordDataKeyUsage(store.db,kid)});
  // Committed before any file is rewritten: a crash mid-migration must still make a vault without this key refuse to start.
  recordDataKeyUsage(store.db,keyring.currentKeyId);
  // Refuses when the vault's event keys are wrapped and the keystore is not given: retiring its data key would lose every event.
  const keystore=attachEventKeystore(store,{dir:eventKeystoreDir,keyring,dataDir,migrate:false}),epochs=keystore?store.eventKeyEpochs():null;
  const resealedEpochs=epochs?epochs.reseal():{};
  const storage={finance:createDocumentAdapter(dataDir,keyring),governance:createGovernanceDocumentStorage(dataDir,keyring)};
  const tenants=store.db.prepare('SELECT DISTINCT tenant FROM ledger ORDER BY tenant').all().map(r=>r.tenant),moved={},remaining={};
  let retiredKeyIds=[];
  // BEGIN IMMEDIATE blocks a concurrently running vault from document intake for the duration.
  store.transaction(()=>{
   for(const tenant of tenants){
    const bundle=store.bundle(tenant),checked=checkDocumentFiles({db:store.db,tenant,records:bundle.records,dataDir,keyring});
    for(const file of checked.files){const r=storage[file.kind].reencrypt(file.tenant,file.sha256);if(r.changed)moved[r.from]=(moved[r.from]||0)+1;}
    const after=checkDocumentFiles({db:store.db,tenant,records:bundle.records,dataDir,keyring});
    for(const [kid,n] of Object.entries(after.keyIds))remaining[kid]=(remaining[kid]||0)+n;
   }
   if(epochs)for(const [kid,n] of Object.entries(epochs.keyIds()))remaining[kid]=(remaining[kid]||0)+n;
   const now=new Date().toISOString(),active=store.db.prepare('SELECT kid FROM data_key_usage WHERE retired_at IS NULL').all().map(r=>r.kid);
   retiredKeyIds=active.filter(kid=>kid!==keyring.currentKeyId&&!remaining[kid]);
   for(const kid of retiredKeyIds)store.db.prepare('UPDATE data_key_usage SET retired_at=? WHERE kid=?').run(now,kid);
  });
  return {migrated:true,currentKeyId:keyring.currentKeyId,tenants:tenants.length,reencryptedFrom:moved,...(keystore?{resealedEpochs}:{}),
   referencedFilesByKeyId:remaining,retiredKeyIds,
   legacyRemaining:remaining[LEGACY_KEY_ID]||0,
   nextSteps:[
    'Create a new vault backup now (v2, sealed by the current data key).',
    'Keep every retired data key and the signing PEM in offline escrow while any backup sealed with them is retained.',
    'Unreferenced orphan files were not re-encrypted.',
   ]};
 }finally{store.close();}
}

// Referenced document files per data key id (read-only check, vault stopped). Callers use it to decide whether migrate is needed.
export function documentKeyUsage({dataDir,signingKey,dataKey,previousDataKeys=[],eventKeystoreDir}){
 const store=new Store(dataDir,signingKey);
 try{
  const keyring=createKeyring({signingKey,dataKey,previousDataKeys}),counts={};
  attachEventKeystore(store,{dir:eventKeystoreDir,keyring,dataDir,migrate:false});
  for(const {tenant} of store.db.prepare('SELECT DISTINCT tenant FROM ledger ORDER BY tenant').all()){
   const checked=checkDocumentFiles({db:store.db,tenant,records:store.bundle(tenant).records,dataDir,keyring});
   for(const [kid,n] of Object.entries(checked.keyIds))counts[kid]=(counts[kid]||0)+n;
  }
  return counts;
 }finally{store.close();}
}

if(process.argv[1]&&pathToFileURL(resolve(process.argv[1])).href===import.meta.url){
 const [mode,...args]=process.argv.slice(2);
 try{
  let out;
  if(mode==='generate'&&args.length===1)out={created:true,file:resolve(args[0]),kid:generateDataKeyFile(resolve(args[0]))};
  else if(mode==='id'&&args.length===1)out={kid:dataKeyId(readDataKeyFile(resolve(args[0])))};
  else if(mode==='migrate'&&args.length===2){
   const dataDir=resolve(args[0]);
   out=migrateDocuments({dataDir,signingKey:readFileSync(resolve(args[1]),'utf8'),...dataKeysFromEnv({...process.env,DATA_DIR:dataDir}),
    eventKeystoreDir:process.env.EVENT_KEYSTORE_DIR||undefined});
  }
  else throw Error('Usage: generate OUT_FILE | id KEY_FILE | migrate DATA_DIR SIGNING_KEY_FILE (env DATA_KEY_FILE, DATA_KEY_PREVIOUS_FILES)');
  console.log(JSON.stringify(out));
 }catch(error){console.error(JSON.stringify({ok:false,error:error.message}));process.exitCode=1;}
}
