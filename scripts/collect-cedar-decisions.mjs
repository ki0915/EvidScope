// Converts Cedar decisions (Amazon Verified Permissions CloudTrail data events, or an application log embedding Cedar
// authorization responses; JSON, gzip or plain) into policy_decision records and optionally submits them as the matching
// enforcement source (docs/agent-registry.md). Preview is the default.
//   node scripts/collect-cedar-decisions.mjs --log cloudtrail.json[.gz] --collector trusted-collector.json
//     [--send --config config.json --base https://ingress/]
import {resolve} from 'node:path';
import {adaptCedarDecisions} from '../src/cedar-decision-adapter.mjs';
import {load,submitDecisions} from './collect-opa-decisions.mjs';

export async function collectCedarDecisions({logFile,collectorFile,configFile,base,send=false}){
 const collector=load(collectorFile),result=adaptCedarDecisions(load(logFile),collector);
 if(!send)return {mode:'preview',...result};
 return submitDecisions({collector,result,configFile,base});
}
if(process.argv[1]&&resolve(process.argv[1])===resolve('scripts/collect-cedar-decisions.mjs')){
 const args=process.argv.slice(2),value=key=>args[args.indexOf(key)+1];
 if(!args.includes('--log')||!args.includes('--collector'))
  throw Error('Usage: --log decisions.json[.gz] --collector trusted-collector.json [--send --config config.json --base https://ingress/]');
 const result=await collectCedarDecisions({logFile:value('--log'),collectorFile:value('--collector'),configFile:value('--config'),base:value('--base'),
  send:args.includes('--send')});
 console.log(JSON.stringify(result,null,2));
 if(result.rejected?.length)process.exitCode=1;
}
