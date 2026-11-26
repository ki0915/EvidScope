// Regression tests for round-2 re-audit finding S6 (from the reviewer's PoC r2-poc-worker-duplicate-id): worker tenant
// scopes were keyed by principal id and ids were not required to be unique, so a worker credential bound to alpha
// received beta's decrypted analysis snapshots and could sign beta evaluations. Ids are now unique at config load, the
// analysis keys scopes and leases by the credential that authenticated, and one credential's live leases are capped.
import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {existsSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {createService} from '../src/service.mjs';
import {createAnalysis,analysisLimits} from '../src/analysis.mjs';
import {credentialFingerprint} from '../src/credentials.mjs';
import {rebindRecoveryConfig} from '../src/recovery-state.mjs';
import {Store} from '../src/store.mjs';
import {evaluateJob} from '../src/worker.mjs';
import {upgradeLocal} from '../scripts/upgrade-local.mjs';

const requirements=JSON.parse(readFileSync(new URL('../data/requirements.json',import.meta.url),'utf8'));
const alphaWorker={id:'analysis-worker',role:'worker',tenant:'alpha',tenants:['alpha'],token:'w'.repeat(40)};
const betaWorker={id:'analysis-worker',role:'worker',tenant:'beta',tenants:['beta'],token:'v'.repeat(40)};
const principals=[
 {id:'alpha-admin',role:'admin',tenant:'alpha',token:'A'.repeat(40)},
 {id:'beta-admin',role:'admin',tenant:'beta',token:'B'.repeat(40)},
 // One deployment of the worker for alpha only, one for beta only, the same id reused across deployments.
 alphaWorker,betaWorker,
];
const scratch=(t,name)=>{const dir=mkdtempSync(join(tmpdir(),name));t.after(()=>rmSync(dir,{recursive:true,force:true}));return dir;};
function store(t){
 const dir=scratch(t,'evidscope-r2-worker-'),value=new Store(dir,generateKeyPairSync('ed25519').privateKey);t.after(()=>value.close());
 return {dir,store:value};
}
function event(store,tenant,actionId,id=actionId+'-event'){
 store.transaction(()=>{
  const at=new Date().toISOString();
  const e={id,actionId,traceId:'trace',tenant,source:'tool-source',sourceKind:'tool',kind:'result',status:'success',occurredAt:at,receivedAt:at,fingerprint:id};
  const record=store.append(tenant,'event',e,e.source);store.project({...e,seq:record.seq,hash:record.hash});
  store.db.prepare('INSERT INTO actions(tenant,id,version) VALUES(?,?,1) ON CONFLICT(tenant,id) DO UPDATE SET version=version+1').run(tenant,actionId);
 });
}
const evaluations=(store,tenant)=>store.db.prepare(`SELECT COUNT(*) n FROM ledger WHERE tenant=? AND json_extract(body,'$.type')='evaluation'`).get(tenant).n;

test('R2 S6: a configuration whose principals share an id is refused before the vault opens anything',t=>{
 const dir=scratch(t,'evidscope-r2-worker-config-');
 assert.throws(()=>createService({dataDir:dir,key:generateKeyPairSync('ed25519').privateKey,config:{principals},requirements}),
  /Invalid credential configuration: principal ids must be unique \(duplicate: analysis-worker\)/);
 assert.equal(existsSync(join(dir,'evidence.db')),false,'no database was created for the refused configuration');
 // Any role: a source and a reviewer sharing an id are refused as well.
 const mixed=[{id:'shared',role:'source',kind:'tool',tenant:'alpha',token:'s'.repeat(40),hmacSecret:'h'.repeat(40)},
  {id:'shared',role:'reviewer',tenant:'beta',token:'r'.repeat(40)}];
 assert.throws(()=>createService({dataDir:dir,key:generateKeyPairSync('ed25519').privateKey,config:{principals:mixed},requirements}),/duplicate: shared/);
 // A configuration with one worker per id keeps working.
 const service=createService({dataDir:dir,key:generateKeyPairSync('ed25519').privateKey,config:{principals:[principals[0],alphaWorker]},requirements});
 service.store.close();
});

test('R2 S6: the analysis keys scopes and leases by credential, so a shared id does not share a tenant scope',t=>{
 const {store:s}=store(t);event(s,'beta','beta-action','beta-secret-event');
 // Called directly, without the configuration check: the analysis itself must not merge the two entries.
 const analysis=createAnalysis(s,principals);
 assert.deepEqual(analysis.claim(alphaWorker).jobs,[],'the alpha-bound credential is not served beta jobs');
 const claimed=analysis.claim(betaWorker);assert.deepEqual(claimed.jobs.map(job=>job.tenant),['beta']);
 const job=claimed.jobs[0],result=evaluateJob(job);
 // The lease records the claiming credential's fingerprint, neither the token nor only the id.
 const lease=s.db.prepare('SELECT worker,credential FROM analysis_leases WHERE id=?').get(job.leaseId);
 assert.equal(lease.worker,'analysis-worker');assert.equal(lease.credential,credentialFingerprint(betaWorker));
 assert.ok(!lease.credential.includes(betaWorker.token)&&lease.credential!==credentialFingerprint(alphaWorker));
 assert.throws(()=>analysis.commit(alphaWorker,{leaseId:job.leaseId,result}),error=>error.status===403,'another credential cannot commit the lease');
 // A rotated token (same id, new credential) cannot commit a lease the old token claimed either.
 const rotated={...betaWorker,token:'u'.repeat(40)},after=createAnalysis(s,[rotated]);
 assert.throws(()=>after.commit(rotated,{leaseId:job.leaseId,result}),error=>error.status===403);
 assert.equal(evaluations(s,'beta'),0);
 assert.equal(analysis.commit(betaWorker,{leaseId:job.leaseId,result}).accepted,true);assert.equal(evaluations(s,'beta'),1);
 // The same credential listed twice is ambiguous and refused.
 assert.throws(()=>createAnalysis(s,[alphaWorker,{...alphaWorker,id:'copy'}]),/Duplicate worker credential/);
});

test('R2 S6: leases claimed before credential binding are ended on upgrade and claimed again',t=>{
 const {dir,store:s}=store(t);event(s,'alpha','old-action');
 // The analysis_leases table as it was before the credential column existed, with one live lease.
 const legacy=new DatabaseSync(join(dir,'evidence.db'));
 legacy.exec(`CREATE TABLE analysis_leases(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,action_id TEXT NOT NULL,version INTEGER NOT NULL,
  worker TEXT NOT NULL,expires INTEGER NOT NULL,analysis_time INTEGER NOT NULL,snapshot_hash TEXT NOT NULL,state TEXT NOT NULL,
  result_hash TEXT,evaluation_id TEXT)`);
 legacy.prepare('INSERT INTO analysis_leases VALUES(?,?,?,?,?,?,?,?,?,NULL,NULL)').run('old-lease','alpha','old-action',1,'analysis-worker',Date.now()+60000,
  Date.now(),'0'.repeat(64),'leased');
 legacy.close();
 const analysis=createAnalysis(s,[alphaWorker]);
 assert.deepEqual({...s.db.prepare('SELECT state,credential FROM analysis_leases WHERE id=?').get('old-lease')},{state:'expired',credential:null});
 assert.throws(()=>analysis.commit(alphaWorker,{leaseId:'old-lease',result:{findings:[],authority:'not_observed',effect:'unconfirmed',limitations:[],
  coverage:{totalFindings:0,returnedFindings:0,truncated:false}}}),error=>error.status===409);
 const job=analysis.claim(alphaWorker).jobs[0];assert.equal(job.actionId,'old-action');
 assert.equal(analysis.commit(alphaWorker,{leaseId:job.leaseId,result:evaluateJob(job)}).accepted,true);
});

test('R2: one credential holds a bounded number of live leases and ended leases are pruned',t=>{
 const {store:s}=store(t),cap=analysisLimits.liveLeasesPerCredential,actions=cap+analysisLimits.jobs+3;
 for(let i=0;i<actions;i++)event(s,'alpha',`action-${String(i).padStart(3,'0')}`);
 const other={id:'alpha-worker-2',role:'worker',tenant:'alpha',token:'x'.repeat(40)},analysis=createAnalysis(s,[alphaWorker,other]);
 let held=0;for(let i=0;i<Math.ceil(cap/analysisLimits.jobs)+2;i++)held+=analysis.claim(alphaWorker).jobs.length;
 assert.equal(held,cap,'a credential that never completes stops at the live-lease cap');
 assert.deepEqual(analysis.claim(alphaWorker).jobs,[]);
 assert.equal(analysis.claim(other).jobs.length,analysisLimits.jobs,'another credential still gets work from the same tenant');
 // Expired and rejected leases claimed longer ago than the retention are deleted at the next claim; completed ones are kept.
 const old=Date.now()-analysisLimits.leaseRetentionMs-1000;
 s.db.prepare(`UPDATE analysis_leases SET state=CASE WHEN rowid%2 THEN 'expired' ELSE 'rejected' END,analysis_time=?,expires=? WHERE credential=?`)
  .run(old,old+analysisLimits.leaseMs,credentialFingerprint(alphaWorker));
 const fresh=analysis.claim(alphaWorker);assert.equal(fresh.jobs.length,analysisLimits.jobs,'the cap counts live leases only');
 assert.equal(s.db.prepare(`SELECT COUNT(*) n FROM analysis_leases WHERE state IN ('expired','rejected')`).get().n,0);
 const job=fresh.jobs[0];analysis.commit(alphaWorker,{leaseId:job.leaseId,result:evaluateJob(job)});
 s.db.prepare('UPDATE analysis_leases SET analysis_time=?,expires=? WHERE id=?').run(old,old+analysisLimits.leaseMs,job.leaseId);analysis.claim(alphaWorker);
 assert.equal(s.db.prepare('SELECT state FROM analysis_leases WHERE id=?').get(job.leaseId).state,'completed');
});

test('R2 S6: a signed config rebinding and the local upgrade refuse duplicate principal ids',t=>{
 const dataDir=scratch(t,'evidscope-r2-rebind-');writeFileSync(join(dataDir,'vault-restoration.json'),'{}');
 const config={profile:'synthetic-local',principals};
 assert.throws(()=>rebindRecoveryConfig({dataDir,key:generateKeyPairSync('ed25519').privateKey,currentConfig:{principals:[]},config,reason:'CHG-2'}),
  /principal ids must be unique \(duplicate: analysis-worker\)/);
 const local=scratch(t,'evidscope-r2-upgrade-');
 writeFileSync(join(local,'config.json'),JSON.stringify(config));writeFileSync(join(local,'signing-private.pem'),'unused');
 assert.throws(()=>upgradeLocal({dir:local,dryRun:true}),/duplicate principal ids \(analysis-worker\)/);
});
