// Event-key epoch operations (round 2, audit S3). Run with the vault stopped. Never prints key material.
//   node scripts/event-keys.mjs list DATA_DIR SIGNING_KEY_FILE [TENANT]
//   node scripts/event-keys.mjs destroy DATA_DIR SIGNING_KEY_FILE TENANT EPOCH REASON
// list: per tenant and key epoch (UTC month of retainUntil), retained and disposed events and whether the epoch can be destroyed.
// destroy: signs an event_key_epoch_destroyed record, then deletes the epoch secret. Allowed once the month has ended and every
// event of the epoch was disposed by a two-person retention plan. Irreversible.
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {Store} from '../src/store.mjs';
import {destroyEpoch,epochInventory} from '../src/event-keys.mjs';

const tenantsOf=store=>store.db.prepare('SELECT DISTINCT tenant FROM ledger ORDER BY tenant').all().map(row=>row.tenant);

export function listEventKeyEpochs({dataDir,signingKey,tenant,now=Date.now()}){
 const store=new Store(dataDir,signingKey);
 try{return {epochs:(tenant?[tenant]:tenantsOf(store)).flatMap(name=>epochInventory(store,name,{now}))};}
 finally{store.close();}
}

export function destroyEventKeyEpoch({dataDir,signingKey,tenant,epoch,reason,now=Date.now()}){
 const store=new Store(dataDir,signingKey);
 try{
  if(!tenantsOf(store).includes(tenant))throw Error('Unknown tenant');
  return {...destroyEpoch(store,{tenant,epoch,reason,now}),nextSteps:[
   'Older database copies and vault backups still hold this epoch secret unless the epoch keys live in a keystore outside DATA_DIR.',
   'Create a new vault backup and retire older ones under the backup retention procedure.']};
 }finally{store.close();}
}

if(process.argv[1]&&pathToFileURL(resolve(process.argv[1])).href===import.meta.url){
 const [mode,...args]=process.argv.slice(2);
 try{
  let out;
  const common=()=>({dataDir:resolve(args[0]),signingKey:readFileSync(resolve(args[1]),'utf8')});
  if(mode==='list'&&(args.length===2||args.length===3))out=listEventKeyEpochs({...common(),tenant:args[2]});
  else if(mode==='destroy'&&args.length===5)out=destroyEventKeyEpoch({...common(),tenant:args[2],epoch:args[3],reason:args[4]});
  else throw Error('Usage: list DATA_DIR SIGNING_KEY_FILE [TENANT] | destroy DATA_DIR SIGNING_KEY_FILE TENANT EPOCH REASON');
  console.log(JSON.stringify(out));
 }catch(error){console.error(JSON.stringify({ok:false,error:error.message}));process.exitCode=1;}
}
