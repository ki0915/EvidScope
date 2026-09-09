// Bounded synthetic receipt test against the existing loopback UI fixture only.
import {readFileSync,writeFileSync} from 'node:fs';
import {submit} from '../src/client.mjs';
import {setTimeout as sleep} from 'node:timers/promises';
const config=JSON.parse(readFileSync('.test-runs/ui/config.json','utf8'));
if(config.profile!=='synthetic-local')throw Error('Synthetic local fixture required');
const tool=config.principals.find(p=>p.id==='alpha-tool'),auditor=config.principals.find(p=>p.id==='alpha-auditor');
const run='live-chart-'+Date.now(),receipts=[],errors=[];
const read=async()=>{const r=await fetch('http://127.0.0.1:9082/api/monitoring?range=10m',{headers:{authorization:'Bearer '+auditor.token}});if(r.status!==200)throw Error('Monitoring query failed '+r.status);return r.json();};
const before=await read();
for(const [wave,count] of [2,5,1,4].entries()){
 if(wave)await sleep(10000);
 for(let i=0;i<count;i++){
  const event={id:`${run}-${wave}-${i}`,actionId:run,traceId:run,kind:'result',status:i%3===0?'failure':'success',occurredAt:new Date().toISOString(),actor:'synthetic-monitor-test',tool:'synthetic-service',note:'Bounded synthetic live chart verification; no external operation'};
  let accepted=false;for(let attempt=1;attempt<=3;attempt++){try{const result=await submit('http://127.0.0.1:9081',tool,event);if(result.status!==202)throw Error('status '+result.status);receipts.push({wave,status:result.status,duplicate:result.body.duplicate,attempt});accepted=true;break;}catch(error){errors.push({id:event.id,attempt,error:error.cause?.code||error.message});await sleep(250);}}
  if(!accepted){writeFileSync('reports/live-monitor-retry-failure.json',JSON.stringify({run,receipts,errors,pass:false},null,2));console.log(JSON.stringify({errors}));throw Error('Synthetic receipt exhausted retries');}
 }
 console.log(JSON.stringify({wave:wave+1,received:count,total:receipts.length}));
}
const after=await read(),count=d=>d.points.reduce((n,p)=>n+p.received,0);
const report={startedAt:before.generatedAt,finishedAt:after.generatedAt,scope:'12 real signed receipts from a synthetic local source; no external AI traffic; up to 3 attempts per event, same id and body on retry',run,receipts,errors,before:count(before),after:count(after),delta:count(after)-count(before),pass:count(after)-count(before)===12,points:after.points.filter(p=>p.received)};
writeFileSync('reports/live-monitor-smoke.json',JSON.stringify(report,null,2));console.log(JSON.stringify({pass:report.pass,delta:report.delta,report:'reports/live-monitor-smoke.json'}));if(!report.pass)process.exitCode=1;
