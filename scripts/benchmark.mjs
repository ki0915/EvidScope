import {mkdirSync,writeFileSync} from 'node:fs';
import {cpus,totalmem} from 'node:os';
import {harness} from '../test/harness.mjs';
import {submit} from '../src/client.mjs';
import {verifyBundle} from '../src/crypto.mjs';
import {verifyCaseReport} from '../src/report-verifier.mjs';
const started=new Date().toISOString(),h=await harness(),phases=[],samples=[];
const workerToken=h.config.principals.find(p=>p.role==='worker').token;
const worker=await h.start('worker',{VAULT_URL:h.vault.url,WORKER_TOKEN:workerToken});
const worker2=await h.start('worker',{VAULT_URL:h.vault.url,WORKER_TOKEN:workerToken});
let sampleBusy=false,sampleErrors=0,generated=0;const investigationLatencies=[];
const timer=setInterval(async()=>{if(sampleBusy)return;sampleBusy=true;try{const m=await h.api('/api/metrics');if(m.status===200)samples.push({at:new Date().toISOString(),...m.body});else sampleErrors++;const begin=performance.now(),query=await h.api('/api/investigations?q=benchmark&limit=25');investigationLatencies.push(performance.now()-begin);if(query.status!==200)sampleErrors++;}catch{sampleErrors++;}finally{sampleBusy=false;}},500);
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function phase(name,count,eps,concurrency){
 const latencies=[],statuses={},sizes=[],t0=performance.now();let accepted=0,duplicates=0,index=0;const sourceKinds=['agent','tool','telemetry'];
 async function send(i){const kind=sourceKinds[i%3],id=`benchmark-${name}-${i}`;const event={id,kind:{agent:'intent',tool:'result',telemetry:'notice'}[kind],occurredAt:new Date().toISOString(),actionId:id,traceId:id,actor:'bench-agent',tool:'bench-tool',action:'read',resource:'synthetic',policyVersion:'v1',status:'success',note:'benchmark '+'.'.repeat(768)};sizes.push(Buffer.byteLength(JSON.stringify(event)));generated++;const begin=performance.now();try{const r=await submit(h.ingress.url,h.principal(kind),event,{timeoutMs:10000});statuses[r.status]=(statuses[r.status]||0)+1;if(r.status===202){accepted++;if(r.body.duplicate)duplicates++;}}catch(e){statuses[e.name]=(statuses[e.name]||0)+1;}latencies.push(performance.now()-begin);}
 if(eps){const tasks=[];for(let i=0;i<count;i++){await sleep(Math.max(0,t0+i*1000/eps-performance.now()));tasks.push(send(i));}await Promise.all(tasks);}else await Promise.all(Array.from({length:concurrency},async()=>{while(index<count)await send(index++);}));
 latencies.sort((a,b)=>a-b);const percentile=p=>+latencies[Math.min(latencies.length-1,Math.ceil(latencies.length*p)-1)].toFixed(2);const durationMs=performance.now()-t0;
 const result={name,generated:count,attempts:count,accepted,duplicates,statuses,requestedEPS:eps,concurrency,elapsedMs:+durationMs.toFixed(2),observedEPS:+(count*1000/durationMs).toFixed(2),eventBytes:{min:Math.min(...sizes),max:Math.max(...sizes)},latencyMs:{p50:percentile(.5),p95:percentile(.95),p99:percentile(.99)},pass:accepted===count&&duplicates===0&&(!eps||percentile(.95)<1000)};
 phases.push(result);console.log(JSON.stringify(result));
}
try{
 await h.api('/api/assets',{role:'reviewer',body:{id:'bench',actor:'bench-agent',tool:'bench-tool',owner:'synthetic',purpose:'benchmark',destinations:[]}});
 await h.api('/api/rules',{role:'reviewer',body:{id:'bench-rule',title:'합성 벤치마크 룰',field:'note',op:'contains',value:'benchmark',severity:'low'}});
 await h.api('/api/rules/bench-rule/test',{role:'reviewer',body:{version:1}});await h.api('/api/rules/bench-rule/approve',{role:'admin',body:{version:1}});
 await phase('normal',200,20,1);await phase('burst',200,0,20);await phase('sustained',600,20,1);
 const deadline=Date.now()+30000;let metrics;do{await sleep(250);metrics=(await h.api('/api/metrics')).body;}while(metrics.backlog&&Date.now()<deadline);
 const bundle=(await h.api('/api/export')).body,integrity=verifyBundle(bundle,h.publicKey);const stored=bundle.records.filter(r=>r.type==='event').length;
 const report={started,finished:new Date().toISOString(),environment:{node:process.version,platform:process.platform,arch:process.arch,cpu:cpus()[0]?.model,logicalCpus:cpus().length,hostMemoryBytes:totalmem(),storage:'local SQLite WAL FULL',apiWriters:1,workers:2,sourceCount:3,userRules:1,queryIntervalMs:500,kubernetes:false},criteriaFile:'docs/validation-plan.md',phases,generated,accepted:phases.reduce((n,p)=>n+p.accepted,0),stored,searchProjection:metrics.events,analyzedEvents:metrics.analyzedEvents,backlog:metrics.backlog,integrity,sampleErrors,peakVaultRssBytes:Math.max(...samples.map(s=>s.vaultRssBytes)),peakBacklog:Math.max(...samples.map(s=>s.backlog)),samples,pass:phases.every(p=>p.pass)&&stored===generated&&metrics.events===generated&&metrics.analyzedEvents===generated&&metrics.backlog===0&&sampleErrors===0,limitations:['Local synthetic pilot measurement, not HA or large-scale certification','OS page cache/disk power-loss protection not tested','Kubernetes/HPA, node memory pressure, remote storage/network and paid provider integration not tested']};
 clearInterval(timer);while(sampleBusy)await sleep(10);
 const investigation=(await h.api('/api/investigations?limit=25')).body;
 const caseResult=await h.api('/api/cases',{body:{title:'합성 1000건 중 단일 행동 보고서 성능',actionId:'benchmark-normal-0',owner:'benchmark-auditor'}});if(caseResult.status!==200)throw Error('Benchmark case creation failed');
 const reportLatencies=[];for(let i=0;i<5;i++){const begin=performance.now(),exported=await h.api(`/api/cases/${caseResult.body.id}/report`);reportLatencies.push(performance.now()-begin);if(exported.status!==200)throw Error('Benchmark report export failed');verifyCaseReport(exported.body,h.publicKey);}
 const p95=values=>+[...values].sort((a,b)=>a-b)[Math.max(0,Math.ceil(values.length*.95)-1)].toFixed(2);
 report.workbench={query:'/api/investigations?q=benchmark&limit=25',querySamples:investigationLatencies.length,queryP95Ms:p95(investigationLatencies),matchedActions:investigation.total,reportSamples:reportLatencies.length,reportP95Ms:p95(reportLatencies),reportScope:'one action among 1000 events, complete tenant ledger validation',pass:sampleErrors===0&&investigation.total===generated&&p95(investigationLatencies)<1000&&p95(reportLatencies)<2000};
 report.pass=report.pass&&report.workbench.pass;report.finished=new Date().toISOString();
 mkdirSync('reports',{recursive:true});const file='reports/benchmark-'+started.replaceAll(/[:.]/g,'-')+'.json';writeFileSync(file,JSON.stringify(report,null,2));writeFileSync('reports/benchmark-latest.json',JSON.stringify(report,null,2));console.log(JSON.stringify({report:file,pass:report.pass,generated,stored,analyzedEvents:metrics.analyzedEvents,backlog:metrics.backlog,workbench:report.workbench,peakVaultRssBytes:report.peakVaultRssBytes}));if(!report.pass)process.exitCode=1;
}finally{clearInterval(timer);while(sampleBusy)await sleep(10);await h.close();}
