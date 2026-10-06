import {randomUUID} from 'node:crypto';
import {validateLanguageSignals,validateScreening,screeningUnavailable} from './content-screening.mjs';

export const OBSERVATION_KINDS=Object.freeze(['sdk','http','otlp','zeek','local']);
export const AI_OBSERVATION_SIGNALS=Object.freeze(['UNREGISTERED_AI','DESTINATION_OUTSIDE_POLICY','DLP_SENSITIVE_CONTENT','PROMPT_INJECTION_SIGNAL','TOOL_AUTHORITY_UNVERIFIED','COLLECTION_GAP','EVIDENCE_CONFLICT','STOP_UNCONFIRMED']);
const providers=['openai','anthropic','google','aws','azure','ollama','llama.cpp','vllm','huggingface','local','other','unknown'];
function invalid(){const error=new Error('Invalid AI observation metadata');error.status=400;throw error;}
function object(raw,keys){if(!raw||Array.isArray(raw)||typeof raw!=='object'||Object.keys(raw).some(key=>!keys.includes(key)))invalid();return raw;}
function id(value,max=128){if(typeof value!=='string'||value.length>max||!/^[A-Za-z0-9._:@/-]+$/.test(value))invalid();return value;}
function integer(value,max=Number.MAX_SAFE_INTEGER){if(!Number.isSafeInteger(value)||value<0||value>max)invalid();return value;}
function choice(value,values){if(!values.includes(value))invalid();return value;}
function maybeId(value,fallback='unknown'){try{return id(value);}catch{return fallback;}}
function natural(value){if(typeof value==='string'&&/^\d{1,15}$/.test(value))value=Number(value);return Number.isSafeInteger(value)&&value>=0?value:undefined;}

export function validateAIObservation(raw){
 object(raw,['version','assetRef','collector','provider','model','usage','span','network','correlation','coverage','languageSignals','screening','signals','timeBasis']);
 if(raw.version!==2)invalid();object(raw.collector,['kind','id','version']);object(raw.correlation,['method','confidence']);object(raw.coverage,['mode','status','reason']);
 const value={version:2,assetRef:id(raw.assetRef),collector:{kind:choice(raw.collector.kind,OBSERVATION_KINDS),id:id(raw.collector.id),version:id(raw.collector.version)},provider:choice(raw.provider,providers),model:id(raw.model),correlation:{method:choice(raw.correlation.method,['trace','flow','temporal','none']),confidence:choice(raw.correlation.confidence,['exact','probable','unknown'])},coverage:{mode:choice(raw.coverage.mode,['content','metadata','unobserved']),status:choice(raw.coverage.status,['observed','partial','unobserved']),reason:choice(raw.coverage.reason,['instrumented','metadata_only','encrypted_body_unavailable','collector_gap','invalid_record','body_unavailable'])}};
 if(value.correlation.method==='none'&&value.correlation.confidence!=='unknown')invalid();
 if(value.correlation.confidence==='exact'&&value.correlation.method!=='trace')invalid();
 if(value.coverage.mode==='unobserved'&&value.coverage.status!=='unobserved')invalid();
 if(raw.timeBasis!==undefined)value.timeBasis=choice(raw.timeBasis,['source_observed','collector_received']);
 if(raw.usage!==undefined){object(raw.usage,['inputTokens','outputTokens','totalTokens']);value.usage={};for(const key of ['inputTokens','outputTokens','totalTokens'])if(raw.usage[key]!==undefined)value.usage[key]=integer(raw.usage[key]);}
 if(raw.span!==undefined){object(raw.span,['traceId','spanId','parentSpanId']);value.span={};for(const key of ['traceId','spanId','parentSpanId'])if(raw.span[key]!==undefined){if(typeof raw.span[key]!=='string'||!(key==='traceId'?/^[a-f0-9]{32}$/i:/^[a-f0-9]{16}$/i).test(raw.span[key])||/^0+$/.test(raw.span[key]))invalid();value.span[key]=raw.span[key].toLowerCase();}if(!value.span.traceId||!value.span.spanId)invalid();}
 if(value.correlation.method==='trace'&&!value.span)invalid();
 if(raw.network!==undefined){object(raw.network,['destinationHost','destinationPort','transport','bytesSent','bytesReceived']);value.network={};
  if(raw.network.destinationHost!==undefined){if(typeof raw.network.destinationHost!=='string'||raw.network.destinationHost.length>253||!/^([a-zA-Z0-9][a-zA-Z0-9.-]*|\[[0-9a-fA-F:]+\])$/.test(raw.network.destinationHost))invalid();value.network.destinationHost=raw.network.destinationHost.toLowerCase();}
  for(const key of ['destinationPort','bytesSent','bytesReceived'])if(raw.network[key]!==undefined)value.network[key]=integer(raw.network[key],key==='destinationPort'?65535:Number.MAX_SAFE_INTEGER);
  if(raw.network.transport!==undefined)value.network.transport=choice(raw.network.transport,['tls','http','unknown']);
 }
 if(raw.languageSignals!==undefined)value.languageSignals=validateLanguageSignals(raw.languageSignals);
 if(raw.screening!==undefined)value.screening=validateScreening(raw.screening);
 if(!Array.isArray(raw.signals)||raw.signals.length>8||new Set(raw.signals).size!==raw.signals.length)invalid();value.signals=raw.signals.map(s=>choice(s,AI_OBSERVATION_SIGNALS));
 if(value.signals.includes('DLP_SENSITIVE_CONTENT')&&value.screening?.safety!=='unsafe')invalid();
 if(value.collector.kind==='zeek'&&(value.coverage.mode==='content'||value.languageSignals||value.screening&&value.screening.status!=='unobserved'))invalid();
 if(value.coverage.mode!=='content'&&(value.languageSignals||value.screening&&['complete','partial'].includes(value.screening.status)))invalid();
 if(value.coverage.mode!=='content'&&value.screening?.safety==='unsafe')invalid();
 return value;
}

// The OTLP adapter takes one span, never a log body or all attributes wholesale.
function attribute(span,key){const entry=Array.isArray(span.attributes)?span.attributes.find(item=>item?.key===key):null;return entry?.value?.stringValue??entry?.value?.intValue??entry?.value?.doubleValue;}
function hostOnly(candidate){try{const url=new URL(candidate);return ['http:','https:'].includes(url.protocol)?url.hostname:undefined;}catch{return undefined;}}
function safeHost(value){return typeof value==='string'&&value.length<=253&&/^([a-zA-Z0-9][a-zA-Z0-9.-]*|\[[0-9a-fA-F:]+\])$/.test(value)?value.toLowerCase():undefined;}
function providerName(value){return providers.includes(value)?value:'unknown';}

export function normalizeAIObservation(kind,raw,options={}){
 if(!OBSERVATION_KINDS.includes(kind)||!raw||typeof raw!=='object'||Array.isArray(raw))invalid();
 const span=kind==='otlp'?(raw.span??raw):raw,contentObserved=kind!=='zeek'&&options.contentObserved===true;
 const observation={version:2,assetRef:options.assetRef??'unregistered',collector:{kind,id:options.collectorId??'ai-collector',version:options.collectorVersion??'1.0.0'},provider:providerName(kind==='otlp'?(attribute(span,'gen_ai.provider.name')??attribute(span,'gen_ai.system')):raw.provider),model:maybeId(kind==='otlp'?attribute(span,'gen_ai.request.model'):raw.model),correlation:{method:'none',confidence:'unknown'},coverage:{mode:contentObserved?'content':'metadata',status:'observed',reason:kind==='zeek'?'encrypted_body_unavailable':contentObserved?'instrumented':'metadata_only'},screening:kind==='zeek'?screeningUnavailable('unobserved','body_unavailable'):options.screening??screeningUnavailable(),signals:[...(options.signals??[])]};
 if(contentObserved&&options.languageSignals)observation.languageSignals=options.languageSignals;
 const usage=kind==='otlp'?{inputTokens:attribute(span,'gen_ai.usage.input_tokens'),outputTokens:attribute(span,'gen_ai.usage.output_tokens')}:raw.usage;
 if(usage&&typeof usage==='object'){const normalized={};for(const [target,aliases] of Object.entries({inputTokens:['inputTokens','input_tokens','prompt_tokens'],outputTokens:['outputTokens','output_tokens','completion_tokens'],totalTokens:['totalTokens','total_tokens']})){for(const key of aliases){const n=natural(usage[key]);if(n!==undefined){normalized[target]=n;break;}}}if(Object.keys(normalized).length)observation.usage=normalized;}
 if(typeof span.traceId==='string'&&/^[a-f0-9]{32}$/i.test(span.traceId)&&!/^0+$/.test(span.traceId)&&typeof span.spanId==='string'&&/^[a-f0-9]{16}$/i.test(span.spanId)&&!/^0+$/.test(span.spanId)){observation.span={traceId:span.traceId,spanId:span.spanId};if(typeof span.parentSpanId==='string'&&/^[a-f0-9]{16}$/i.test(span.parentSpanId)&&!/^0+$/.test(span.parentSpanId))observation.span.parentSpanId=span.parentSpanId;observation.correlation={method:'trace',confidence:'exact'};}
 const network={};let destinationHost,port,transport;
 if(kind==='zeek'){destinationHost=safeHost(raw.server_name??raw.host??raw['id.resp_h']);port=natural(raw['id.resp_p']);transport=raw.server_name||raw.service==='ssl'?'tls':'unknown';network.bytesSent=natural(raw.orig_bytes);network.bytesReceived=natural(raw.resp_bytes);observation.correlation={method:'flow',confidence:'probable'};observation.provider='unknown';observation.model='unknown';}
 else if(kind==='http'){destinationHost=safeHost(raw.host??hostOnly(raw.url));try{const url=new URL(raw.url);port=natural(url.port)||(['http:','https:'].includes(url.protocol)?(url.protocol==='https:'?443:80):undefined);transport=url.protocol==='https:'?'tls':url.protocol==='http:'?'http':'unknown';}catch{transport='unknown';}}
 else if(kind==='otlp'){destinationHost=safeHost(attribute(span,'server.address'));port=natural(attribute(span,'server.port'));}
 if(destinationHost)network.destinationHost=destinationHost;if(port!==undefined&&port<=65535)network.destinationPort=port;if(transport)network.transport=transport;
 const cleanNetwork=Object.fromEntries(Object.entries(network).filter(([,value])=>value!==undefined));if(Object.keys(cleanNetwork).length)observation.network=cleanNetwork;
 if(options.collectionGap===true){observation.coverage.status='partial';observation.coverage.reason='collector_gap';observation.signals.push('COLLECTION_GAP');}
 if(observation.screening.safety==='unsafe')observation.signals.push('DLP_SENSITIVE_CONTENT');
 observation.signals=[...new Set(observation.signals)];return validateAIObservation(observation);
}

export function observationEvent(kind,raw,options={}){
 const aiObservation=normalizeAIObservation(kind,raw,options),eventId=maybeId(options.id,`ai-${randomUUID()}`);let observed;
 for(const timestamp of [raw.occurredAt,raw.timestamp])if(typeof timestamp==='string'&&/^\d{4}-\d\d-\d\dT.*(?:Z|[+-]\d\d:\d\d)$/.test(timestamp)&&Number.isFinite(Date.parse(timestamp))){observed=Date.parse(timestamp);break;}
 if(observed===undefined&&kind==='zeek'&&typeof raw.ts==='number'&&Number.isFinite(raw.ts)&&raw.ts>=0)observed=raw.ts*1000;
 if(observed===undefined&&kind==='otlp'){const value=(raw.span??raw).startTimeUnixNano;if(typeof value==='string'&&/^\d{1,20}$/.test(value)){const milliseconds=Number(BigInt(value)/1000000n);if(Number.isSafeInteger(milliseconds))observed=milliseconds;}}
 const date=new Date(observed??options.now??Date.now());aiObservation.timeBasis=observed===undefined?'collector_received':'source_observed';
 if(!Number.isFinite(date.getTime()))invalid();
 return {id:eventId,kind:'notice',occurredAt:date.toISOString(),traceId:aiObservation.span?.traceId??maybeId(options.traceId,eventId),actionId:maybeId(options.actionId,eventId),tool:'ai-observation-collector',action:'ai_usage_observed',status:aiObservation.coverage.status,aiObservation};
}

export function failedObservationEvent(kind,options={}){
 const event=observationEvent(OBSERVATION_KINDS.includes(kind)?kind:'local',{},options);event.status='unobserved';event.aiObservation.coverage={mode:'unobserved',status:'unobserved',reason:'invalid_record'};event.aiObservation.screening=screeningUnavailable('unobserved','body_unavailable');event.aiObservation.signals=['COLLECTION_GAP'];return event;
}
