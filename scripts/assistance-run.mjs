import {readFileSync} from 'node:fs';
import {runIsolatedAssistance} from '../src/isolated-session.mjs';

const args=process.argv.slice(2),value=name=>{const index=args.indexOf(name);if(index<0||!args[index+1])throw Error(`Missing ${name}`);return args[index+1];};
try{
 if(!args.includes('--execute-isolated-model'))throw Error('Explicit --execute-isolated-model is required');
 const file=value('--credential'),baseUrl=value('--base-url'),tlsConfigPath=value('--tls-config'),runtimeConfigPath=value('--runtime-config'),parsed=JSON.parse(readFileSync(file,'utf8')),credential=parsed.credential||parsed,receipts=[];
 const result=await runIsolatedAssistance({credential,baseUrl,tlsConfigPath,runtimeConfigPath,onReceipt:r=>receipts.push(r)});
 const finalReceipt=receipts.at(-1);if(finalReceipt?.terminationConfirmed!==true)throw Error('MODEL_STOP_UNCONFIRMED');
 process.stdout.write(JSON.stringify({runId:credential.runId,state:result.state,accepted:result.accepted,modelStarted:true,terminationConfirmed:true})+'\n');
}catch(error){process.stderr.write(JSON.stringify({error:error.message,status:error.status||null})+'\n');process.exitCode=1;}
