import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {adaptAgtApproval} from '../src/agt-approval-adapter.mjs';
import {submit} from '../src/client.mjs';

export async function collectAgtApproval({receiptFile,collectorFile,configFile,base,send=false}){
 const load=file=>{const bytes=readFileSync(file);if(bytes.length>262144)throw Error('Bounded JSON input exceeds 256KiB');return JSON.parse(bytes.toString('utf8'));};
 const collector=load(collectorFile),receipt=load(receiptFile),result=adaptAgtApproval(receipt,collector);
 if(!send)return {mode:'preview',...result};
 const url=new URL(base);if(url.username||url.password||url.search||url.hash||url.pathname!=='/'||!(url.protocol==='https:'||url.protocol==='http:'&&['127.0.0.1','[::1]','localhost'].includes(url.hostname)))throw Error('Use undecorated HTTPS or loopback ingress base');
 const config=load(configFile),principal=config.principals?.find(p=>p.id===collector.id&&p.tenant===collector.tenant&&p.role==='source'&&p.kind==='authority');if(!principal)throw Error('Matching authority source credential required');
 const submissions=[];for(const event of result.events){const response=await submit(url.href,principal,event);if(response.status!==202)throw Error(`Authority ingestion failed: HTTP ${response.status}; reuse event IDs for bounded retry`);submissions.push({id:event.id,accepted:true,duplicate:!!response.body.duplicate});}
 return {mode:'submitted',submissions,assurance:result.assurance};
}
if(process.argv[1]&&resolve(process.argv[1])===resolve('scripts/collect-agt-approval.mjs')){
 const args=process.argv.slice(2),value=key=>args[args.indexOf(key)+1];
 if(!args.includes('--receipt')||!args.includes('--collector'))throw Error('Usage: --receipt receipt.json --collector trusted-collector.json [--send --config config.json --base https://ingress/]');
 const result=await collectAgtApproval({receiptFile:value('--receipt'),collectorFile:value('--collector'),configFile:value('--config'),base:value('--base'),send:args.includes('--send')});console.log(JSON.stringify(result,null,2));
}
