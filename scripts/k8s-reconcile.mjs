// Independent audit read: no source or signing credentials. Loopback TLS forwards
// may be used for export verification, never as evidence of Service balancing.
import {readFileSync,writeFileSync} from 'node:fs';
import {verifyBundle,verifyCheckpoint} from '../src/crypto.mjs';
import {parseArgs} from 'node:util';
const {values,positionals}=parseArgs({options:{url:{type:'string'},config:{type:'string'},trust:{type:'string'},out:{type:'string'},previous:{type:'string'}},allowPositionals:true});
if(!values.out||!values.trust||!positionals.length)throw Error('Explicit --out, --trust and receipt report files required');
const base=new URL(values.url);if(base.protocol!=='https:'||base.username||base.password)throw Error('HTTPS origin required');
if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw Error('TLS verification must remain enabled');
const parse=f=>JSON.parse(readFileSync(f,'utf8').replace(/^\uFEFF/,''));
const config=parse(values.config);if(!config.principals?.length||config.principals.some(p=>p.role!=='auditor'||p.hmacSecret))throw Error('Auditor-only configuration required');
const response=await fetch(new URL('/api/export',base),{headers:{authorization:`Bearer ${config.principals[0].token}`},redirect:'error',signal:AbortSignal.timeout(30000)});
if(!response.ok)throw Error('Audit export returned '+response.status);
const bundle=await response.json(),verification=verifyBundle(bundle,readFileSync(values.trust,'utf8'));
let continuity=null;
if(values.previous){const prior=parse(values.previous).checkpoint;verifyCheckpoint(prior,readFileSync(values.trust,'utf8'));const preserved=prior.tenant===bundle.checkpoint.tenant&&bundle.checkpoint.count>=prior.count&&(prior.count===0?prior.head==='0'.repeat(64):bundle.records[prior.count-1]?.hash===prior.head);continuity={priorFile:values.previous,priorCount:prior.count,priorHead:prior.head,preserved};if(!preserved)throw Error('Previously trusted checkpoint is not a prefix of the current signed ledger');}
const events=bundle.disclosures.map(d=>d.event),key=e=>JSON.stringify([e.tenant,e.source,e.id]);
const counts=new Map();for(const event of events)counts.set(key(event),(counts.get(key(event))||0)+1);
const receipts=positionals.map(file=>{const r=parse(file);const accepted=r.outcomes.filter(o=>o.accepted===true);const missing=accepted.filter(o=>!counts.has(key(o))).map(o=>({tenant:o.tenant,source:o.source,id:o.id}));const duplicates=accepted.filter(o=>counts.get(key(o))>1).map(o=>o.id);return {file,runId:r.runId,attempted:r.outcomes.length,accepted:accepted.length,unconfirmed:r.outcomes.length-accepted.length,missing,duplicates,pass:missing.length===0&&duplicates.length===0};});
const report={format:'evidscope-k8s-reconciliation-v1',at:new Date().toISOString(),target:base.origin,verification,continuity,checkpoint:bundle.checkpoint,disclosedEvents:events.length,receipts,pass:receipts.every(r=>r.pass),scope:'Independent trusted-key verification and accepted receipt reconciliation. Does not prove original event truth, complete attempted delivery, or load balancing.'};
writeFileSync(values.out,JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));if(!report.pass)process.exitCode=1;
