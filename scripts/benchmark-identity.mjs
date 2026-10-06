// Synthetic, local authentication-state comparison. This is not an HTTP SLO.
import {mkdtempSync,mkdirSync,writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {generateKeyPairSync} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import assert from 'node:assert/strict';
import {Store} from '../src/store.mjs';
import {createIdentityState} from '../src/identity-state.mjs';

const rows=Number(process.argv[2]||20000),output=process.argv[3];
if(!Number.isInteger(rows)||rows<100||rows>50000||!output)throw Error('Usage: node scripts/benchmark-identity.mjs <100..50000 rows> <report.json>');
mkdirSync('.test-runs',{recursive:true});
const dir=mkdtempSync(resolve('.test-runs','identity-benchmark-')),store=new Store(dir,generateKeyPairSync('ed25519').privateKey);
try{
 const principal={id:'benchmark-admin',tenant:'synthetic'},binding={id:'benchmark-user',tenant:principal.tenant};
 store.transaction(()=>{
  for(let i=0;i<rows;i++)store.append(principal.tenant,'audit_access',{index:i,synthetic:true,padding:'x'.repeat(1024)},principal.id);
  store.put(principal,'identity_access',binding.id,{id:binding.id,epoch:1,disabled:false});
 });
 const cached=createIdentityState(store),legacy=()=>store.ledgerObjects(binding.tenant,'identity_access').find(s=>s.id===binding.id);
 function measured(call,count){const values=[];for(let i=0;i<count;i++){const start=performance.now();assert.equal(call().epoch,1);values.push(performance.now()-start);}values.sort((a,b)=>a-b);return {calls:count,p50Ms:values[Math.floor(count*.5)],p95Ms:values[Math.min(count-1,Math.floor(count*.95))],maxMs:values.at(-1)};}
 const initialStart=performance.now();assert.equal(cached(binding).epoch,1);const initialVerificationMs=performance.now()-initialStart;
 const report={measuredAt:new Date().toISOString(),scope:'Direct SQLite authentication-state reads over synthetic signed data, single process; not HTTP throughput, isolated CPU timing or enterprise SLO',node:process.version,rows:rows+1,ledgerBytes:store.db.prepare('SELECT sum(length(CAST(body AS BLOB))) bytes FROM ledger').get().bytes,initialVerificationMs,wholeLedgerEachRead:measured(legacy,10),verifiedIncrementalCache:measured(()=>cached(binding),100)};
 store.transaction(()=>{store.append(principal.tenant,'audit_access',{newRecord:true},principal.id);store.put(principal,'identity_access',binding.id,{id:binding.id,epoch:2,disabled:true});});
 const start=performance.now(),changed=cached(binding);assert.equal(changed.disabled,true);assert.equal(changed.epoch,2);report.twoRecordExtensionMs=performance.now()-start;
 writeFileSync(output,JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
}finally{store.close();}
