// Converts an OPA decision log (a JSON array as OPA uploads it, gzip or plain, or one event) into policy_decision records and
// optionally submits them as the matching enforcement source (docs/agent-registry.md). Preview is the default.
//   node scripts/collect-opa-decisions.mjs --log decisions.json[.gz] --collector trusted-collector.json
//     [--send --config config.json --base https://ingress/]
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {gunzipSync} from 'node:zlib';
import {adaptOpaDecisions} from '../src/opa-decision-adapter.mjs';
import {submit} from '../src/client.mjs';

const MAX_BYTES=8*1024*1024;
function load(file){
 const bytes=readFileSync(file);if(bytes.length>MAX_BYTES)throw Error('Bounded input exceeds 8MiB');
 const text=bytes[0]===0x1f&&bytes[1]===0x8b?gunzipSync(bytes,{maxOutputLength:MAX_BYTES}):bytes;
 return JSON.parse(text.toString('utf8'));
}
export async function collectOpaDecisions({logFile,collectorFile,configFile,base,send=false}){
 const collector=load(collectorFile),result=adaptOpaDecisions(load(logFile),collector);
 if(!send)return {mode:'preview',...result};
 const url=new URL(base);
 const loopback=url.protocol==='http:'&&['127.0.0.1','[::1]','localhost'].includes(url.hostname);
 if(url.username||url.password||url.search||url.hash||url.pathname!=='/'||!(url.protocol==='https:'||loopback))
  throw Error('Use undecorated HTTPS or loopback ingress base');
 const config=load(configFile);
 const principal=config.principals?.find(p=>p.id===collector.id&&p.tenant===collector.tenant&&p.role==='source'&&p.kind==='enforcement');
 if(!principal)throw Error('Matching enforcement source credential required');
 const submissions=[];
 for(const event of result.events){
  const response=await submit(url.href,principal,event);
  if(response.status!==202)throw Error(`Decision ingestion failed: HTTP ${response.status}; resubmitting reuses the same event IDs`);
  submissions.push({id:event.id,accepted:true,duplicate:!!response.body.duplicate});
 }
 return {mode:'submitted',submissions,rejected:result.rejected,assurance:result.assurance};
}
if(process.argv[1]&&resolve(process.argv[1])===resolve('scripts/collect-opa-decisions.mjs')){
 const args=process.argv.slice(2),value=key=>args[args.indexOf(key)+1];
 if(!args.includes('--log')||!args.includes('--collector'))
  throw Error('Usage: --log decisions.json[.gz] --collector trusted-collector.json [--send --config config.json --base https://ingress/]');
 const result=await collectOpaDecisions({logFile:value('--log'),collectorFile:value('--collector'),configFile:value('--config'),base:value('--base'),
  send:args.includes('--send')});
 console.log(JSON.stringify(result,null,2));
 if(result.rejected?.length)process.exitCode=1;
}
