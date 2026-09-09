import {readFileSync} from 'node:fs';
import {runAssistance} from '../src/assistance-runner.mjs';

const args=process.argv.slice(2),value=name=>{const index=args.indexOf(name);if(index<0||!args[index+1])throw Error(`Missing ${name}`);return args[index+1];};
try{
 const file=value('--credential'),baseUrl=value('--base-url'),parsed=JSON.parse(readFileSync(file,'utf8')),credential=parsed.credential||parsed;
 const result=await runAssistance({credential,baseUrl});process.stdout.write(JSON.stringify({runId:credential.runId,state:result.state,accepted:result.accepted})+'\n');
}catch(error){process.stderr.write(JSON.stringify({error:error.message,status:error.status||null})+'\n');process.exitCode=1;}
