import {observationEvent,failedObservationEvent,OBSERVATION_KINDS} from '../src/ai-observations.mjs';
import {screenContent,languageSignals,TEXT_FIELDS} from '../src/content-screening.mjs';
import {createScreeningClient,loadModelTlsConfig} from '../src/isolated-inference-client.mjs';

// Explicit stdin input only. Emits minimized metadata; does not read local files or send events.
const [kind,...args]=process.argv.slice(2);let assetRef='unregistered',screenRequested=false,tlsConfigPath,badArguments=!OBSERVATION_KINDS.includes(kind),assetSeen=false;
for(let index=0;index<args.length;index++){
 if(args[index]==='--screen'&&!screenRequested)screenRequested=true;
 else if(args[index]==='--tls-config'&&!tlsConfigPath&&args[index+1]&&!args[index+1].startsWith('--'))tlsConfigPath=args[++index];
 else if(!args[index].startsWith('--')&&!assetSeen){assetRef=args[index];assetSeen=true;}
 else badArguments=true;
}
if(badArguments){process.stderr.write('usage: node scripts/collect-ai-observations.mjs <sdk|http|otlp|zeek|local> [asset-ref] [--screen --tls-config <path>]\n');process.exit(2);}
const enabled=screenRequested&&kind!=='zeek';let client;
// Configuration is trusted local mTLS material only. No host model or URL fallback exists.
if(enabled&&tlsConfigPath)try{client=createScreeningClient(loadModelTlsConfig(tlsConfigPath));}catch{/* Preserve a minimized classifier_error record for each input. */}
let sequence=0,invalid=0,emitted=0,pending='',discarding=false;
async function record(line,tooLarge=false){
 if(!line.trim()&&!tooLarge)return;sequence++;const options={assetRef,collectorId:`stdin-${kind}`,id:`stdin-${kind}-${sequence}`};let event;
 try{
  if(tooLarge)throw new Error('Input limit');const raw=JSON.parse(line);
  const contentObserved=kind!=='zeek'&&TEXT_FIELDS.some(field=>typeof raw?.[field]==='string'&&raw[field].length>0);
  const screening=await screenContent(contentObserved?raw:{},{enabled,client});
  event=observationEvent(kind,raw,{...options,contentObserved,screening,...(contentObserved?{languageSignals:languageSignals(raw)}:{})});
 }catch{invalid++;try{event=failedObservationEvent(kind,options);}catch{event=failedObservationEvent(kind,{collectorId:`stdin-${kind}`,id:`stdin-${kind}-${sequence}`});}}
 process.stdout.write(JSON.stringify(event)+'\n');emitted++;
}
process.stdin.setEncoding('utf8');
for await(const chunk of process.stdin){let start=0;for(let index=0;index<chunk.length;index++)if(chunk[index]==='\n'){const fragment=chunk.slice(start,index);if(!discarding&&pending.length+fragment.length<=524288)pending+=fragment;else discarding=true;await record(pending,discarding);pending='';discarding=false;start=index+1;}const rest=chunk.slice(start);if(!discarding&&pending.length+rest.length<=524288)pending+=rest;else{pending='';discarding=true;}}
if(pending||discarding)await record(pending,discarding);
process.stderr.write(JSON.stringify({kind,emitted,invalid,policy:'allowlist_metadata_only',rawContentStored:false})+'\n');if(invalid)process.exitCode=1;
