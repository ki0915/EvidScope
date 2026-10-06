import {readFileSync} from 'node:fs';
import {DurableObserver} from '../src/durable-observer.mjs';

const args=process.argv.slice(2);let configPath,spoolPath,retryFailed=false,bad=false;
for(let index=0;index<args.length;index++){
 if(args[index]==='--source-config'&&!configPath&&args[index+1]&&!args[index+1].startsWith('--'))configPath=args[++index];
 else if(args[index]==='--spool'&&!spoolPath&&args[index+1]&&!args[index+1].startsWith('--'))spoolPath=args[++index];
 else if(args[index]==='--retry-failed'&&!retryFailed)retryFailed=true;
 else bad=true;
}
if(bad||!configPath||!spoolPath){process.stderr.write('usage: node scripts/send-ai-observations.mjs --source-config <json> --spool <sqlite> [--retry-failed]\n');process.exit(2);}
let observer;
try{const config=JSON.parse(readFileSync(configPath,'utf8'));if(!config||typeof config!=='object'||Object.keys(config).some(key=>!['url','principal'].includes(key)))throw Error();observer=new DurableObserver({spoolPath,url:config.url,principal:config.principal});}catch{process.stderr.write(JSON.stringify({status:'configuration_or_spool_unavailable'})+'\n');process.exit(2);}
let stopping=false,received=0,invalid=0,pending='',discarding=false;
const stop=()=>{stopping=true;process.stdin.destroy();void observer.stop();};process.on('SIGINT',stop);process.on('SIGTERM',stop);
function accept(line,tooLarge=false){if(!line.trim()&&!tooLarge)return;received++;try{if(tooLarge)throw Error();const result=observer.enqueue(JSON.parse(line));if(!result.queued&&result.outcome!=='duplicate')invalid++;}catch{invalid++;}}
try{
 if(retryFailed)observer.retryFailed();process.stdin.setEncoding('utf8');
 for await(const chunk of process.stdin){if(stopping)break;let start=0;for(let index=0;index<chunk.length;index++)if(chunk[index]==='\n'){const fragment=chunk.slice(start,index);if(!discarding&&pending.length+fragment.length<=32768)pending+=fragment;else discarding=true;accept(pending,discarding);pending='';discarding=false;start=index+1;}const rest=chunk.slice(start);if(!discarding&&pending.length+rest.length<=32768)pending+=rest;else{pending='';discarding=true;}}
 if(pending||discarding)accept(pending,discarding);if(!stopping)await observer.drain();
}catch{invalid++;}
const metrics=observer.stats();await observer.close();process.stdout.write(JSON.stringify({received,invalid,stopped:stopping,...metrics})+'\n');if(invalid||!metrics.available||metrics.queue.pending||metrics.queue.inflight||metrics.queue.rejected||metrics.queue.retry_exhausted)process.exitCode=1;
