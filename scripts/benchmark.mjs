import {mkdirSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {cpus,totalmem} from 'node:os';
import {harness} from '../test/harness.mjs';
import {submit} from '../src/client.mjs';
import {verifyBundle} from '../src/crypto.mjs';
import {verifyCaseReport} from '../src/report-verifier.mjs';
import http from 'node:http';
import {upstreamRequest} from '../src/upstream-http.mjs';
import {cpuPerEvent,cpuSnapshot,pinLayout,pinProcesses} from './benchmark-process.mjs';
const started=new Date().toISOString(),h=await harness(),phases=[],samples=[];
// Round 7 (docs/performance.md, stage 3). BENCHMARK_CLIENT=http sends from a node:http keep-alive pool instead of fetch (the
// default, comparable with earlier rounds); BENCHMARK_PIN=1 (or vault:0,ingress:1,client:2,other:3) pins the processes with taskset.
// Every load phase reports cpuMsPerEvent per process from /proc, so the vault's cost is separate from the load generator's.
const clientMode=process.env.BENCHMARK_CLIENT||'fetch';if(!['fetch','http'].includes(clientMode))throw Error('Invalid BENCHMARK_CLIENT');
const agent=clientMode==='http'?new http.Agent({keepAlive:true,maxSockets:64}):undefined;
const environment={client:clientMode,node:process.version,platform:process.platform,arch:process.arch,cpu:cpus()[0]?.model,logicalCpus:cpus().length,hostMemoryBytes:totalmem(),storage:'local SQLite WAL FULL',apiWriters:1,workers:2,sourceCount:3,userRules:1,queryIntervalMs:500,kubernetes:false};
const limitations=['Local synthetic pilot measurement, not HA or large-scale certification','OS page cache/disk power-loss protection not tested','Kubernetes/HPA, node memory pressure, remote storage/network and paid provider integration not tested'];
// BENCHMARK_PHASES=burst50,otlp runs a subset (profiling); BENCHMARK_REPORT_DIR keeps scratch runs out of reports/.
const only=new Set((process.env.BENCHMARK_PHASES||'').split(',').filter(Boolean)),selected=name=>!only.size||only.has(name);
const reportDir=process.env.BENCHMARK_REPORT_DIR||'reports',reportPath=join(reportDir,'benchmark-'+started.replaceAll(/[:.]/g,'-')+'.json');
function persist(report){mkdirSync(reportDir,{recursive:true});writeFileSync(reportPath,JSON.stringify(report,null,2));writeFileSync(join(reportDir,'benchmark-latest.json'),JSON.stringify(report,null,2));}
const workerToken=h.config.principals.find(p=>p.role==='worker').token;
const worker=await h.start('worker',{VAULT_URL:h.vault.url,WORKER_TOKEN:workerToken});
const worker2=await h.start('worker',{VAULT_URL:h.vault.url,WORKER_TOKEN:workerToken});
const pids={vault:h.vault.child.pid,ingress:h.ingress.child.pid,audit:h.audit.child.pid,workers:worker.child.pid,workers2:worker2.child.pid,client:process.pid};
environment.pinning=pinProcesses(pinLayout(process.env.BENCHMARK_PIN,cpus().length),{vault:[pids.vault],ingress:[pids.ingress],client:[pids.client],other:[pids.audit,pids.workers,pids.workers2]});
const cpuUsage=(before,count)=>{const out=cpuPerEvent(before,cpuSnapshot(pids),count);if(out.workers2!==undefined){out.workers=+(out.workers+out.workers2).toFixed(3);delete out.workers2;}return out;};
let sampleBusy=false,sampleErrors=0,generated=0,stage='setup',firstActionId;const investigationLatencies=[];
const timer=setInterval(async()=>{if(sampleBusy)return;sampleBusy=true;try{const m=await h.api('/api/metrics');if(m.status===200)samples.push({at:new Date().toISOString(),...m.body});else sampleErrors++;const begin=performance.now(),query=await h.api('/api/investigations?q=benchmark&limit=25');investigationLatencies.push(performance.now()-begin);if(query.status!==200)sampleErrors++;}catch{sampleErrors++;}finally{sampleBusy=false;}},500);
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const summarize=(latencies,durationMs,count)=>{latencies.sort((a,b)=>a-b);const percentile=p=>+latencies[Math.min(latencies.length-1,Math.ceil(latencies.length*p)-1)].toFixed(2);
 return {elapsedMs:+durationMs.toFixed(2),observedEPS:+(count*1000/durationMs).toFixed(2),latencyMs:{p50:percentile(.5),p95:percentile(.95),p99:percentile(.99)}};};
async function phase(name,count,eps,concurrency){
 const latencies=[],statuses={},sizes=[],cpu0=cpuSnapshot(pids),t0=performance.now();let accepted=0,duplicates=0,index=0;const sourceKinds=['agent','tool','telemetry'];
 async function send(i){const kind=sourceKinds[i%3],id=`benchmark-${name}-${i}`;const event={id,kind:{agent:'intent',tool:'result',telemetry:'notice'}[kind],occurredAt:new Date().toISOString(),actionId:id,traceId:id,actor:'bench-agent',tool:'bench-tool',action:'read',resource:'synthetic',policyVersion:'v1',status:'success',note:'benchmark '+'.'.repeat(768)};sizes.push(Buffer.byteLength(JSON.stringify(event)));generated++;firstActionId??=id;const begin=performance.now();try{const r=await submit(h.ingress.url,h.principal(kind),event,{timeoutMs:10000,agent});statuses[r.status]=(statuses[r.status]||0)+1;if(r.status===202){accepted++;if(r.body.duplicate)duplicates++;}}catch(e){statuses[e.name]=(statuses[e.name]||0)+1;}latencies.push(performance.now()-begin);}
 if(eps){const tasks=[];for(let i=0;i<count;i++){await sleep(Math.max(0,t0+i*1000/eps-performance.now()));tasks.push(send(i));}await Promise.all(tasks);}else await Promise.all(Array.from({length:concurrency},async()=>{while(index<count)await send(index++);}));
 const stats=summarize(latencies,performance.now()-t0,count);
 const result={name,generated:count,attempts:count,accepted,duplicates,statuses,requestedEPS:eps,concurrency,elapsedMs:stats.elapsedMs,observedEPS:stats.observedEPS,eventBytes:{min:Math.min(...sizes),max:Math.max(...sizes)},latencyMs:stats.latencyMs,cpuMsPerEvent:cpuUsage(cpu0,count),pass:accepted===count&&duplicates===0&&(!eps||stats.latencyMs.p95<1000)};
 phases.push(result);console.log(JSON.stringify(result));
}
// OTLP/HTTP JSON export of GenAI chat spans through the ingress gateway, `batch` spans per request (one trace per span).
async function otlpPhase(name,count,batch,concurrency){
 const token=h.principal('otlp').token,latencies=[],statuses={},cpu0=cpuSnapshot(pids),t0=performance.now();let accepted=0,rejected=0,next=0,bytes=0;
 const span=i=>{const hex=createHash('sha256').update(`${started}:${name}:${i}`).digest('hex'),start=BigInt(Date.now()-1000)*1000000n;
  return {traceId:hex.slice(0,32),spanId:hex.slice(32,48),name:'chat bench-model',kind:3,startTimeUnixNano:String(start),endTimeUnixNano:String(start+50000000n),status:{},
   attributes:[['gen_ai.operation.name','chat'],['gen_ai.provider.name','anthropic'],['gen_ai.request.model','bench-model'],['gen_ai.agent.name','bench-agent']]
    .map(([key,value])=>({key,value:{stringValue:value}})).concat([{key:'gen_ai.usage.input_tokens',value:{intValue:'512'}}])};};
 async function send(from){const n=Math.min(batch,count-from),spans=Array.from({length:n},(_,k)=>span(from+k));generated+=n;
  const body=JSON.stringify({resourceSpans:[{resource:{attributes:[{key:'service.name',value:{stringValue:'bench-otlp'}}]},scopeSpans:[{scope:{name:'benchmark'},spans}]}]});bytes+=body.length;
  const begin=performance.now();
  try{const headers={'content-type':'application/json',authorization:`Bearer ${token}`},r=agent
    ?await upstreamRequest(h.ingress.url+'/v1/traces',{method:'POST',headers,body,timeoutMs:30000,agent})
    :await fetch(h.ingress.url+'/v1/traces',{method:'POST',headers,body,signal:AbortSignal.timeout(30000)});
   const out=agent?JSON.parse(r.body.toString('utf8')):await r.json();statuses[r.status]=(statuses[r.status]||0)+1;if(r.status===200){const lost=Number(out.partialSuccess?.rejectedSpans||0);accepted+=n-lost;rejected+=lost;}}
  catch(e){statuses[e.name]=(statuses[e.name]||0)+1;}latencies.push(performance.now()-begin);}
 await Promise.all(Array.from({length:concurrency},async()=>{while(next<count){const from=next;next+=batch;await send(from);}}));
 const stats=summarize(latencies,performance.now()-t0,count);
 const result={name,generated:count,requests:latencies.length,spansPerRequest:batch,accepted,rejected,statuses,concurrency,elapsedMs:stats.elapsedMs,observedEPS:stats.observedEPS,requestBytes:bytes,requestLatencyMs:stats.latencyMs,cpuMsPerEvent:cpuUsage(cpu0,count),pass:accepted===count};
 phases.push(result);console.log(JSON.stringify(result));
}
try{
 stage='policy_setup';
 await h.api('/api/assets',{role:'reviewer',body:{id:'bench',actor:'bench-agent',tool:'bench-tool',owner:'synthetic',purpose:'benchmark',destinations:[]}});
 await h.api('/api/rules',{role:'reviewer',body:{id:'bench-rule',title:'합성 벤치마크 룰',field:'note',op:'contains',value:'benchmark',severity:'low'}});
 await h.api('/api/rules/bench-rule/test',{role:'reviewer',body:{version:1}});await h.api('/api/rules/bench-rule/approve',{role:'admin',body:{version:1}});
 if(selected('normal')){stage='normal_load';await phase('normal',200,20,1);}
 if(selected('burst')){stage='burst_load';await phase('burst',200,0,20);}
 // Higher-concurrency burst and OTLP batch export of the same volume (round 5, docs/performance.md).
 if(selected('burst50')){stage='burst50_load';await phase('burst50',2000,0,50);}
 if(selected('otlp')){stage='otlp_load';await otlpPhase('otlp',2000,500,2);}
 if(selected('sustained')){stage='sustained_load';await phase('sustained',600,20,1);}
 stage='analysis_drain';
 const deadline=Date.now()+30000+generated*20;let metrics;do{await sleep(250);metrics=(await h.api('/api/metrics')).body;}while(metrics.backlog&&Date.now()<deadline);
 stage='signed_export';const exported=await h.api('/api/export');if(exported.status!==200)throw Error(`Benchmark export failed with HTTP ${exported.status}`);const bundle=exported.body,integrity=verifyBundle(bundle,h.publicKey);const stored=bundle.records.filter(r=>r.type==='event').length;
 const report={started,finished:new Date().toISOString(),environment,criteriaFile:'docs/validation-plan.md',phases,generated,accepted:phases.reduce((n,p)=>n+p.accepted,0),stored,searchProjection:metrics.events,analyzedEvents:metrics.analyzedEvents,backlog:metrics.backlog,integrity,sampleErrors,peakVaultRssBytes:Math.max(...samples.map(s=>s.vaultRssBytes)),peakBacklog:Math.max(...samples.map(s=>s.backlog)),samples,pass:phases.every(p=>p.pass)&&stored===generated&&metrics.events===generated&&metrics.analyzedEvents===generated&&metrics.backlog===0&&sampleErrors===0,limitations};
 clearInterval(timer);while(sampleBusy)await sleep(10);
 stage='workbench';const investigation=(await h.api('/api/investigations?limit=25')).body;
 const caseResult=await h.api('/api/cases',{body:{title:`합성 ${generated}건 중 단일 행동 보고서 성능`,actionId:firstActionId||'benchmark-normal-0',owner:'benchmark-auditor'}});if(caseResult.status!==200)throw Error('Benchmark case creation failed');
 const reportLatencies=[];for(let i=0;i<5;i++){const begin=performance.now(),exported=await h.api(`/api/cases/${caseResult.body.id}/report`);reportLatencies.push(performance.now()-begin);if(exported.status!==200)throw Error('Benchmark report export failed');verifyCaseReport(exported.body,h.publicKey);}
 const p95=values=>+[...values].sort((a,b)=>a-b)[Math.max(0,Math.ceil(values.length*.95)-1)].toFixed(2);
 report.workbench={query:'/api/investigations?q=benchmark&limit=25',querySamples:investigationLatencies.length,queryP95Ms:p95(investigationLatencies),matchedActions:investigation.total,reportSamples:reportLatencies.length,reportP95Ms:p95(reportLatencies),reportScope:`one action among ${generated} events, complete tenant ledger validation`,pass:sampleErrors===0&&investigation.total===generated&&p95(investigationLatencies)<1000&&p95(reportLatencies)<2000};
 report.pass=report.pass&&report.workbench.pass;report.finished=new Date().toISOString();
 persist(report);console.log(JSON.stringify({report:reportPath,pass:report.pass,generated,stored,analyzedEvents:metrics.analyzedEvents,backlog:metrics.backlog,workbench:report.workbench,peakVaultRssBytes:report.peakVaultRssBytes}));if(!report.pass)process.exitCode=1;
}catch(error){
 clearInterval(timer);while(sampleBusy)await sleep(10);
 const report={started,finished:new Date().toISOString(),environment,criteriaFile:'docs/validation-plan.md',phases,generated,accepted:phases.reduce((n,p)=>n+p.accepted,0),sampleErrors,samples,stage,pass:false,failure:{name:error?.name||'Error',message:String(error?.message||error).slice(0,500)},limitations};
 persist(report);console.error(JSON.stringify({report:reportPath,pass:false,stage,failure:report.failure}));process.exitCode=1;
}finally{clearInterval(timer);while(sampleBusy)await sleep(10);agent?.destroy();await h.close();}
