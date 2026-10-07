// Event-key epoch operations (round 2, audit S3). Run with the vault stopped. Never prints key material.
//   node scripts/event-keys.mjs init KEYSTORE_DIR
//   DATA_KEY_FILE=... EVENT_KEYSTORE_DIR=... node scripts/event-keys.mjs migrate DATA_DIR SIGNING_KEY_FILE
//   node scripts/event-keys.mjs list DATA_DIR SIGNING_KEY_FILE [TENANT]
//   node scripts/event-keys.mjs destroy DATA_DIR SIGNING_KEY_FILE TENANT EPOCH REASON
// init: creates an event keystore directory (outside DATA_DIR). migrate: records the keystore in evidence.db, moves epoch
// secrets out of evidence.db and wraps every raw event key (the vault does the same at startup when EVENT_KEYSTORE_DIR is set).
// list: per tenant and key epoch (UTC month of retainUntil), retained and disposed events and whether the epoch can be destroyed.
// destroy: signs an event_key_epoch_destroyed record, then destroys the epoch secret. Allowed once the month has ended and every
// event of the epoch was disposed by a two-person retention plan. Irreversible. list and destroy need DATA_KEY_FILE and
// EVENT_KEYSTORE_DIR when the vault uses a keystore.
import {existsSync,readFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {Store} from '../src/store.mjs';
import {destroyEpoch,epochInventory,pendingEventKeyMigration} from '../src/event-keys.mjs';
import {attachEventKeystore,createEventKeystore} from '../src/event-keystore.mjs';
import {assertDataKeysAvailable,createKeyring,dataKeysFromEnv,ensureDataKeyUsageTable,recordDataKeyUsage} from '../src/data-keys.mjs';

const tenantsOf=store=>store.db.prepare('SELECT DISTINCT tenant FROM ledger ORDER BY tenant').all().map(row=>row.tenant);

// The vault's own startup checks: data keys in use must be configured, the keystore must be the recorded one.
function openVault({dataDir,signingKey,env,migrate}){
 if(!existsSync(join(dataDir,'evidence.db')))throw Error('DATA_DIR holds no evidence.db');
 const store=new Store(dataDir,signingKey);
 try{
  const {dataKey,previousDataKeys}=dataKeysFromEnv({...env,DATA_DIR:dataDir});ensureDataKeyUsageTable(store.db);
  const keyring=createKeyring({signingKey,dataKey,previousDataKeys,onWrite:kid=>recordDataKeyUsage(store.db,kid)});assertDataKeysAvailable(store.db,keyring);
  const keystore=attachEventKeystore(store,{dir:env.EVENT_KEYSTORE_DIR||undefined,keyring,dataDir,migrate});
  return {store,keystore};
 }catch(error){store.close();throw error;}
}

export function migrateEventKeystore({dataDir,signingKey,env=process.env}){
 if(!env.EVENT_KEYSTORE_DIR)throw Error('migrate requires EVENT_KEYSTORE_DIR (and DATA_KEY_FILE)');
 const {store,keystore}=openVault({dataDir,signingKey,env,migrate:true});
 try{return {migrated:true,...keystore,nextSteps:['Create a new vault backup now; older backups and copies of evidence.db still hold raw event keys.',
  'Back up EVENT_KEYSTORE_DIR separately (docs/event-key-wrapping.md); it is never part of a vault backup.']};}
 finally{store.close();}
}

export function listEventKeyEpochs({dataDir,signingKey,tenant,now=Date.now(),env=process.env}){
 const {store,keystore}=openVault({dataDir,signingKey,env,migrate:false});
 try{
  const pending=pendingEventKeyMigration(store.db);
  return {storage:store.eventKeyEpochs().kind,...keystore,pendingMigration:pending,
   epochs:(tenant?[tenant]:tenantsOf(store)).flatMap(name=>epochInventory(store,name,{now}))};
 }finally{store.close();}
}

export function destroyEventKeyEpoch({dataDir,signingKey,tenant,epoch,reason,now=Date.now(),env=process.env}){
 const {store,keystore}=openVault({dataDir,signingKey,env,migrate:true});
 try{
  if(!tenantsOf(store).includes(tenant))throw Error('Unknown tenant');
  const result=destroyEpoch(store,{tenant,epoch,reason,now});
  return {...result,nextSteps:keystore
   ?['Every copy of evidence.db and every vault backup can no longer open this epoch\'s event keys or compare its receipt tags.',
    'Copies of evidence.db made before the events were disposed still hold their plaintext search projection; retire them.',
    'Keystore backups made before now still hold the epoch secret; destroy them under the keystore backup schedule.']
   :['Older database copies and vault backups still hold this epoch secret and the raw event keys; only a keystore prevents that.',
    'Create a new vault backup and retire older ones under the backup retention procedure.']};
 }finally{store.close();}
}

if(process.argv[1]&&pathToFileURL(resolve(process.argv[1])).href===import.meta.url){
 const [mode,...args]=process.argv.slice(2);
 try{
  let out;
  const common=()=>({dataDir:resolve(args[0]),signingKey:readFileSync(resolve(args[1]),'utf8')});
  if(mode==='init'&&args.length===1)out={created:true,keystoreDir:resolve(args[0]),keystoreId:createEventKeystore(resolve(args[0]))};
  else if(mode==='migrate'&&args.length===2)out=migrateEventKeystore(common());
  else if(mode==='list'&&(args.length===2||args.length===3))out=listEventKeyEpochs({...common(),tenant:args[2]});
  else if(mode==='destroy'&&args.length===5)out=destroyEventKeyEpoch({...common(),tenant:args[2],epoch:args[3],reason:args[4]});
  else throw Error('Usage: init KEYSTORE_DIR | migrate DATA_DIR SIGNING_KEY_FILE | list DATA_DIR SIGNING_KEY_FILE [TENANT]'
   +' | destroy DATA_DIR SIGNING_KEY_FILE TENANT EPOCH REASON');
  console.log(JSON.stringify(out));
 }catch(error){console.error(JSON.stringify({ok:false,error:error.message}));process.exitCode=1;}
}
