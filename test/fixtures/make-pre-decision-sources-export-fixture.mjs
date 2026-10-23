// Provenance of pre-decision-sources-export-503c185.json. Run from a checkout of commit 503c185 (round 3 closed, before OTLP
// decision spans and the Cedar adapter): node <this file> OUT.json
// Builds tenant alpha in-process: an OTLP source sending GenAI spans and a 0033 decision span (not stored at 503c185), an
// enforcement source with OPA-style deny and allow decisions, tool executions, worker evaluations (engines v1 and v2) and an export.
import {generateKeyPairSync,randomUUID} from 'node:crypto';
import {mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const load=path=>import(pathToFileURL(resolve(process.cwd(),path)).href);
const {createService}=await load('src/service.mjs'),{mac}=await load('src/crypto.mjs'),{evaluateJob}=await load('src/worker.mjs');
const {decodeTraceRequest,mapTraceRequest,OTLP_BATCH_FORMAT,OTLP_MAPPING_VERSION}=await load('src/otlp.mjs');
const dir=mkdtempSync(join(tmpdir(),'evidscope-pre-decision-sources-')),{privateKey,publicKey}=generateKeyPairSync('ed25519'),token=s=>s.repeat(40).slice(0,40);
const principals=[{id:'alpha-otlp',tenant:'alpha',role:'source',kind:'otlp',token:token('po')},
 {id:'alpha-tool',tenant:'alpha',role:'source',kind:'tool',token:token('pt'),hmacSecret:token('pk')},
 {id:'alpha-gateway',tenant:'alpha',role:'source',kind:'enforcement',token:token('pg'),hmacSecret:token('pq')},
 {id:'alpha-reviewer',tenant:'alpha',role:'reviewer',token:token('pr')},
 {id:'analysis-worker',tenant:'internal',role:'worker',tenants:['alpha'],token:token('pw')}];
const service=createService({dataDir:dir,key:privateKey,config:{principals}}),principal=id=>principals.find(p=>p.id===id);
const ingest=async(source,event)=>{
 const body=JSON.stringify(event),stamp=String(Date.now()),nonce=randomUUID(),p=principal(source);
 const r=await service.handle('POST',new URL('/api/ingest','http://local'),{authorization:'Bearer '+p.token,'x-evid-timestamp':stamp,'x-evid-nonce':nonce,
  'x-evid-signature':mac(p.hmacSecret,stamp,nonce,body)},body);
 if(r.accepted!==true)throw Error('ingest failed');
};
const analyze=()=>{
 const worker=principal('analysis-worker');
 for(let round=0;round<10;round++){const {jobs}=service.analysis.claim(worker);if(!jobs.length)return;
  for(const job of jobs)service.analysis.commit(worker,{leaseId:job.leaseId,result:evaluateJob(JSON.parse(JSON.stringify(job)))});}
};
// GenAI spans of the repository fixture plus a gateway trace with a proposal-0033 decision span (event.action) that names its target.
const genai=JSON.parse(readFileSync('test/fixtures/otlp/sdk-genai.json','utf8')),trace='f5a9d214e6b8c7a9d1e2f3a4b5c6d7e8';
const attr=(key,stringValue)=>({key,value:{stringValue}});
const decisionSpan={traceId:trace,spanId:'7a8b9c1d00000001',name:'mcp.authorization',kind:1,startTimeUnixNano:'1791364800000000000',
 endTimeUnixNano:'1791364800015000000',status:{code:2},attributes:[attr('security_rule.ruleset.name','crm_data_access_policy'),attr('event.action','deny'),
  attr('event.outcome','success'),attr('gen_ai.agent.id','claude-agent-prod-001'),attr('gen_ai.tool.name','delete_customer_data')]};
const otlpRequest={resourceSpans:[...genai.resourceSpans,{resource:{attributes:[attr('service.name','mcp-gateway')]},
 scopeSpans:[{scope:{name:'gateway'},spans:[decisionSpan]}]}]};
const mapped=mapTraceRequest(decodeTraceRequest(JSON.stringify(otlpRequest),'json'),{now:Date.parse('2026-10-07T00:00:00Z')});
const otlpResult=await service.handle('POST',new URL('/api/ingest/otlp','http://local'),{authorization:'Bearer '+principal('alpha-otlp').token},
 JSON.stringify({format:OTLP_BATCH_FORMAT,mapping:OTLP_MAPPING_VERSION,events:mapped.events}));
const minute=60000,at=offset=>new Date(Date.now()-10*minute+offset).toISOString();
const target={actor:'pay-agent',tool:'payment_transfer',action:'refund',resource:'order-7'};
const decision={...target,engine:'opa',enforcementPointId:'gw-1',policyId:'payments.refund',policyVersion:'p1',kind:'policy_decision'};
await ingest('alpha-gateway',{...decision,id:'d-1',actionId:'pay-1',traceId:'t-1',decision:'deny',decisionId:'dec-1',occurredAt:at(0)});
await ingest('alpha-tool',{...target,id:'x-1',kind:'execution',actionId:'pay-1',traceId:'t-1',status:'success',occurredAt:at(4000)});
await ingest('alpha-gateway',{...decision,id:'d-2',actionId:'pay-2',traceId:'t-2',decision:'allow',decisionId:'dec-2',occurredAt:at(0)});
await ingest('alpha-tool',{...target,id:'x-2',kind:'execution',actionId:'pay-2',traceId:'t-2',status:'success',occurredAt:at(4000)});
analyze();
const exportBundle=service.store.exportBundle('alpha');service.store.close();
writeFileSync(process.argv[2],JSON.stringify({
 format:'evidscope-test-fixture-v1',
 description:'Export written by commit 503c185 (before OTLP decision spans and the Cedar adapter): tenant alpha, OTLP GenAI events, a 0033 '
  +'decision span the OTLP source could not store, OPA-style decisions, executions and v1/v2 evaluations.',
 baseCommit:'503c185',publicKeyPem:publicKey.export({format:'pem',type:'spki'}),otlpRequest,otlpEvents:mapped.events,otlpRejected:mapped.rejected,
 otlpResult:{accepted:otlpResult.accepted,rejected:otlpResult.rejected},exportBundle,
},null,1)+'\n');
rmSync(dir,{recursive:true,force:true});
const evaluations=exportBundle.records.filter(r=>r.type==='evaluation');
console.log(JSON.stringify({ok:true,records:exportBundle.records.length,evaluations:evaluations.length,otlp:otlpResult.accepted,rejected:mapped.rejected,
 findings:[...new Set(evaluations.flatMap(r=>r.payload.findings.map(f=>f.code)))].sort(),engines:[...new Set(evaluations.map(r=>r.payload.replay?.engine))]}));
