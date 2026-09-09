import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
const config=JSON.parse(readFileSync('.test-runs/ui/config.json','utf8'));
assert.equal(config.profile,'synthetic-local');
const auditor=config.principals.find(p=>p.id==='alpha-auditor'),source=config.principals.find(p=>p.id==='alpha-agent');
async function get(query,principal=auditor){const r=await fetch('http://127.0.0.1:9082/api/agents?'+new URLSearchParams(query),{headers:{authorization:'Bearer '+principal.token},signal:AbortSignal.timeout(10000)});return {status:r.status,data:await r.json()};}
const list=await get({range:'7d',sort:'attention'});assert.equal(list.status,200);assert.ok(list.data.items.length);
const details=[];
for(const item of list.data.items){const r=await get({id:item.id,range:'7d',end:list.data.window.end});assert.equal(r.status,200);assert.equal(r.data.window.end,list.data.window.end);assert.equal(r.data.item.actions,item.actions);assert.deepEqual(r.data.item.counts,item.counts);assert.equal(r.data.trend.reduce((n,p)=>n+p.actions,0),item.actions);details.push({actor:item.actor,actions:item.actions,counts:item.counts,trendActions:r.data.trend.reduce((n,p)=>n+p.actions,0)});}
const violations=await get({range:'7d',focus:'violation'});assert.equal(violations.status,200);assert.ok(violations.data.items.every(a=>a.counts.violation>0));
const forbidden=await get({range:'7d'},source);assert.equal(forbidden.status,403);
const invalid=await get({range:'1s'});assert.equal(invalid.status,400);
const report={checkedAt:new Date().toISOString(),origin:'http://127.0.0.1:9082',window:list.data.window,agents:list.data.total,details,checks:{listDetailCounts:true,anchoredWindow:true,trendTotals:true,violationFilter:true,sourceReadRejected:forbidden.status,invalidRangeRejected:invalid.status},limitations:['기존 로컬 합성 자료와 이전 로컬 AI 시험 기록 기준','대규모 성능·Kubernetes 재배포 검증이 아님']};
writeFileSync('reports/agent-operations-http.json',JSON.stringify(report,null,2));console.log(JSON.stringify(report));
