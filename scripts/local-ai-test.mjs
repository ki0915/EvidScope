import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {setTimeout as sleep} from 'node:timers/promises';
import {Observer} from '../src/client.mjs';
import {guideTool,readGuide,modelReference,localChat} from '../src/local-ai-pilot.mjs';
const config=JSON.parse(readFileSync('.test-runs/ui/config.json','utf8'));
if(config.profile!=='synthetic-local')throw Error('Run only against the named synthetic UI fixture');
const model='qwen3:0.6b',run='local-ai-'+Date.now(),observers={},events=[],hash=s=>createHash('sha256').update(s).digest('hex');
for(const kind of ['agent','tool']){const p=config.principals.find(p=>p.id==='alpha-'+kind&&p.role==='source'&&p.kind===kind);if(!p)throw Error('Required source principal absent');observers[kind]=new Observer('http://127.0.0.1:9081',p,{capacity:20,attempts:3,timeoutMs:2000});}
const base={actionId:run,traceId:run,actor:'local-qwen-pilot',model,tool:'read_product_guide',action:'read',resource:'product-guide',destination:'local-synthetic-fixture',purpose:'Real local AI inference with synthetic documents',dataCategories:['synthetic-public-guide']};
function observe(kind,event){const complete={...base,id:run+'-'+events.length,occurredAt:new Date().toISOString(),...event};events.push({id:complete.id,source:'alpha-'+kind,kind:complete.kind,status:complete.status});observers[kind].observe(complete);}
const report={run,model,startedAt:new Date().toISOString(),inference:'not_started',toolExecuted:false,citationMatches:false,events,limitations:['Real model, synthetic guide and local tool only; no external business operation','Source keys are distinct but the pilot harness is one trusted local process, not independently isolated hardware','The model receives no source/auditor credentials, ledger access or arbitrary execution tool','No hidden reasoning is collected; evidence notes retain hashes and reference metadata','No grant or human approval record is fabricated; missing authority remains visible']};
mkdirSync('reports',{recursive:true});
try{
 const tags=await fetch('http://127.0.0.1:11434/api/tags',{signal:AbortSignal.timeout(5000),redirect:'error'}).then(r=>r.json());
 const installed=tags.models?.find(m=>m.name===model);if(!installed)throw Error('Local model not installed');report.modelDigest=installed.digest;
 const messages=[{role:'system',content:'You are an assistant that calls tools. Use the provided function to retrieve the requested guide. Do not answer from memory.'},{role:'user',content:'Use read_product_guide to read version 2.'}];
 observe('agent',{kind:'intent',status:'started',note:'Local pilot application requested a guide answer; no model answer yet'});
 let started=Date.now();const first=await localChat({model,messages,tools:[guideTool],stream:false,think:false,options:{temperature:0,num_predict:256,num_ctx:2048},keep_alive:'5m'});
 report.inference='responded';report.firstLatencyMs=Date.now()-started;report.firstDone=first.done===true;report.firstAnswer=first.message?.content||'';report.firstDoneReason=first.done_reason;report.firstTokens=first.eval_count;
 const calls=first.message?.tool_calls||[];report.requestedTools=calls.map(c=>({name:c.function?.name,arguments:c.function?.arguments}));
 if(calls.length!==1)throw Error('Expected one actual model tool call, received '+calls.length);
 const call=calls[0];observe('tool',{kind:'execution',status:'started',note:'Local runtime received a model tool request'});
 let result;try{result=readGuide(call);report.toolExecuted=true;report.toolReference=result.reference;observe('tool',{kind:'result',status:'success',dataRefs:[result.reference],note:'Local runtime successfully read fixed synthetic guide bytes'});}catch(error){observe('tool',{kind:'result',status:'failure',note:'Unsupported tool name or arguments; fixed fixture was not read'});throw error;}
 // Thinking is disabled; only the assistant tool call and supplied tool result are forwarded.
 messages.push({role:'assistant',content:first.message.content||'',tool_calls:calls},{role:'tool',tool_name:'read_product_guide',content:JSON.stringify(result.guide)});
 messages.push({role:'user',content:'Now answer using the tool result. Return JSON with answer (a short Korean sentence) and reference (id and version copied from the guide).'});
 started=Date.now();const final=await localChat({model,messages,stream:false,think:false,format:'json',options:{temperature:0,num_predict:256,num_ctx:2048},keep_alive:'5m'});
 report.finalLatencyMs=Date.now()-started;report.finalDone=final.done===true;report.answer=final.message?.content||'';report.answerHash=hash(report.answer);report.outputTokens=final.eval_count??null;
 const reference=modelReference(report.answer);report.modelReference=reference;report.citationMatches=!!reference&&reference.id===result.reference.id&&reference.version===result.reference.version;
 observe('agent',{kind:'self_report',status:report.finalDone&&report.answer?'success':'unknown',...(reference?{dataRefs:[reference]}:{}),note:`Local model response; sha256=${report.answerHash}; referenceMatch=${report.citationMatches}; content kept only in synthetic pilot report`});
}catch(error){report.error=error.message;observe('agent',{kind:'self_report',status:'failure',note:'Local pilot did not complete: '+error.message.slice(0,220)});}
// Receipt flushing is outside business inference, never a gate on tool/model execution.
for(let i=0;i<100&&Object.values(observers).some(o=>o.running||o.queue.length);i++)await sleep(100);
report.observers=Object.fromEntries(Object.entries(observers).map(([k,o])=>[k,{...o.metrics,stillRunning:o.running}]));
report.finishedAt=new Date().toISOString();report.pass=!report.error&&report.firstDone&&report.finalDone&&report.toolExecuted&&report.citationMatches&&Object.values(report.observers).every(o=>o.dropped===0&&!o.stillRunning&&o.accepted===o.observed);
writeFileSync(`reports/${run}.json`,JSON.stringify(report,null,2));writeFileSync('reports/local-ai-latest.json',JSON.stringify(report,null,2));
console.log(JSON.stringify({run,pass:report.pass,inference:report.inference,toolExecuted:report.toolExecuted,citationMatches:report.citationMatches,error:report.error,report:`reports/${run}.json`}));if(!report.pass)process.exitCode=1;
