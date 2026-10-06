import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {normalizeAIObservation,validateAIObservation,observationEvent,failedObservationEvent,AI_OBSERVATION_SIGNALS} from '../src/ai-observations.mjs';
import {CIPHER_MODEL,languageSignals} from '../src/content-screening.mjs';

const canary='RAW-SECRET-CANARY-민감정보';
const unsafe={status:'complete',safety:'unsafe',categories:['Credential/Secret'],processedChunks:1,totalChunks:1,model:CIPHER_MODEL};

test('SDK/local observations allow metadata only and preserve token zero without making up missing counts',()=>{
 const raw={provider:'openai',model:'gpt-example',usage:{input_tokens:0,output_tokens:12,secret:canary},prompt:canary,response:canary,authorization:canary,cookie:canary,body:{text:canary},error:canary};
 const observation=normalizeAIObservation('sdk',raw,{assetRef:'ai-app'});assert.equal(observation.model,'gpt-example');assert.deepEqual(observation.usage,{inputTokens:0,outputTokens:12});assert.equal(observation.coverage.mode,'metadata');assert.equal(observation.languageSignals,undefined);assert.ok(!JSON.stringify(observation).includes(canary));
 const content=normalizeAIObservation('local',raw,{contentObserved:true,languageSignals:languageSignals({prompt:canary}),screening:unsafe});assert.equal(content.coverage.mode,'content');assert.deepEqual(content.signals,['DLP_SENSITIVE_CONTENT']);assert.equal(content.languageSignals.classification,'mixed_script');assert.ok(!JSON.stringify(content).includes(canary));
});

test('HTTP adapter removes URL query credentials fragments headers and body, retaining destination metadata',()=>{
 const observation=normalizeAIObservation('http',{url:`https://user:${canary}@api.example.com/v1/path?token=${canary}#${canary}`,headers:{authorization:canary,cookie:canary},body:canary,prompt:canary});
 assert.deepEqual(observation.network,{destinationHost:'api.example.com',destinationPort:443,transport:'tls'});assert.equal(observation.coverage.mode,'metadata');assert.ok(!JSON.stringify(observation).includes(canary));assert.equal(observation.correlation.confidence,'unknown');
});

test('OTLP extracts approved gen_ai/span attributes while content events and arbitrary keys are excluded',()=>{
 const attr=(key,value)=>({key,value:{stringValue:value}});
 const raw={traceId:'a'.repeat(32),spanId:'b'.repeat(16),parentSpanId:'c'.repeat(16),name:canary,events:[{body:canary}],attributes:[attr('gen_ai.provider.name','anthropic'),attr('gen_ai.request.model','claude-example'),{key:'gen_ai.usage.input_tokens',value:{intValue:'42'}},attr('gen_ai.prompt',canary),attr('gen_ai.output.messages',canary),attr('server.address','api.example.com'),attr('url.full',`https://example.com/?secret=${canary}`)]};
 const observation=normalizeAIObservation('otlp',raw);assert.equal(observation.provider,'anthropic');assert.equal(observation.usage.inputTokens,42);assert.equal(observation.correlation.confidence,'exact');assert.equal(observation.span.parentSpanId,'c'.repeat(16));assert.ok(!JSON.stringify(observation).includes(canary));
});

test('Zeek never claims TLS content observation, AI model attribution, or exact flow-to-user identity',()=>{
 const observation=normalizeAIObservation('zeek',{server_name:'api.example.com','id.resp_p':443,service:'ssl',orig_bytes:100,resp_bytes:200,model:'invented',provider:'openai',body:canary,prompt:canary},{contentObserved:true,screening:unsafe,languageSignals:languageSignals({text:'English'})});
 assert.equal(observation.coverage.reason,'encrypted_body_unavailable');assert.equal(observation.coverage.mode,'metadata');assert.equal(observation.screening.status,'unobserved');assert.equal(observation.languageSignals,undefined);assert.equal(observation.model,'unknown');assert.equal(observation.provider,'unknown');assert.equal(observation.correlation.confidence,'probable');assert.deepEqual(observation.signals,[]);
});

test('v2 schema is a strict nested allowlist and rejects raw payloads without echoing keys or values',()=>{
 const base=normalizeAIObservation('sdk',{});
 for(const candidate of [{...base,[canary]:canary},{...base,collector:{...base.collector,secret:canary}},{...base,usage:{prompt:canary}},{...base,screening:{...unsafe,text:canary}},{...base,network:{destinationHost:`example.com/?${canary}`}},{...base,span:{traceId:'a'.repeat(32),spanId:'b'.repeat(16),payload:canary}},{...base,signals:['DLP_SENSITIVE_CONTENT']},{...base,correlation:{method:'trace',confidence:'exact'}}]){
  assert.throws(()=>validateAIObservation(candidate),error=>error.status===400&&!error.message.includes(canary));
 }
 assert.equal(AI_OBSERVATION_SIGNALS.length,8);
});

test('collector gaps and invalid input leave minimal audit evidence, not an invented successful audit',()=>{
 const event=observationEvent('local',{model:'local-model',error:canary},{id:'event-1',now:0,collectionGap:true});assert.equal(event.kind,'notice');assert.equal(event.occurredAt,'1970-01-01T00:00:00.000Z');assert.equal(event.status,'partial');assert.deepEqual(event.aiObservation.signals,['COLLECTION_GAP']);
 const failure=failedObservationEvent('sdk',{id:'failed-1'});assert.equal(failure.status,'unobserved');assert.equal(failure.aiObservation.coverage.reason,'invalid_record');assert.equal(failure.aiObservation.screening.safety,'unknown');assert.ok(!JSON.stringify(failure).includes(canary));
});

test('source times survive adapters and absent timestamps are explicitly collector received',()=>{
 const timestamp='2026-09-12T01:02:03.000Z';
 for(const [kind,raw] of [['sdk',{occurredAt:timestamp}],['zeek',{ts:Date.parse(timestamp)/1000}],['otlp',{startTimeUnixNano:String(BigInt(Date.parse(timestamp))*1000000n)}]]){const event=observationEvent(kind,raw,{now:0});assert.equal(event.occurredAt,timestamp);assert.equal(event.aiObservation.timeBasis,'source_observed');}
 const event=observationEvent('http',{timestamp:canary},{now:0});assert.equal(event.occurredAt,'1970-01-01T00:00:00.000Z');assert.equal(event.aiObservation.timeBasis,'collector_received');
});

test('stdin collector emits minimized events including malformed records without source text in stdout/stderr',()=>{
 const result=spawnSync(process.execPath,['scripts/collect-ai-observations.mjs','sdk','test-asset'],{input:[JSON.stringify({provider:'openai',model:'test-model',prompt:canary,headers:{authorization:canary}}),`INVALID-${canary}`,JSON.stringify({usage:{inputTokens:3}})].join('\n'),encoding:'utf8'});
 assert.equal(result.status,1);assert.ok(!result.stdout.includes(canary));assert.ok(!result.stderr.includes(canary));
 const events=result.stdout.trim().split('\n').map(JSON.parse);assert.equal(events.length,3);assert.equal(events[0].aiObservation.screening.status,'off');assert.equal(events[1].status,'unobserved');assert.equal(events[2].aiObservation.coverage.mode,'metadata');
});

test('stdin screening requires explicit Pod TLS configuration and remains fail-closed when unavailable',()=>{
 for(const flags of [['--screen'],['--screen','--tls-config','missing-config.json']]){
  const result=spawnSync(process.execPath,['scripts/collect-ai-observations.mjs','sdk',...flags],{input:JSON.stringify({prompt:canary}),encoding:'utf8'});
  assert.equal(result.status,0);const event=JSON.parse(result.stdout.trim());assert.equal(event.aiObservation.screening.status,'error');assert.equal(event.aiObservation.screening.safety,'unknown');assert.ok(!result.stdout.includes(canary));assert.ok(!result.stderr.includes(canary));
 }
 const off=spawnSync(process.execPath,['scripts/collect-ai-observations.mjs','sdk','--tls-config','missing-config.json'],{input:JSON.stringify({prompt:canary}),encoding:'utf8'});assert.equal(JSON.parse(off.stdout.trim()).aiObservation.screening.status,'off');
});
