import {pathToFileURL} from 'node:url';
import {inspectTrainingReadiness,createIsolatedTrainingSession} from '../src/isolated-training-session.mjs';

export async function runTrainingCommand(args,{inspect=inspectTrainingReadiness,createSession=createIsolatedTrainingSession,signal}={}){
 const options={};let execute=false;
 for(let i=0;i<args.length;i++){
  if(args[i]==='--execute-isolated-training'){if(execute)throw Error('duplicate_training_execute_flag');execute=true;}
  else if(args[i]==='--check-only'){options.checkOnly=true;}
  else if(['--runtime-config','--data'].includes(args[i])){const key=args[i]==='--data'?'dataPath':'runtimeConfigPath';if(options[key]||!args[i+1]||args[i+1].startsWith('--'))throw Error('training_argument_invalid');options[key]=args[++i];}
  else throw Error('usage: training-run.mjs --data reviewed.jsonl --runtime-config runtime.json [--check-only | --execute-isolated-training]');
 }
 if(execute&&options.checkOnly)throw Error('training_execution_mode_conflict');
 const preflight=await inspect(options);
 if(!execute||!preflight.allowed)return {...preflight,mode:execute?'execution-blocked':'check-only'};
 if(signal?.aborted)return {...preflight,mode:'execution-cancelled',allowed:false,started:false,trainingRunCompleted:false,reasons:['cancelled_before_start']};
 try{const session=createSession(options),result=await session.run({signal});return {schemaVersion:1,mode:'execution',preflight,result,trainingRunCompleted:result.trainingRunCompleted===true};}
 catch(error){return {schemaVersion:1,mode:'execution-error',trainingRunCompleted:false,error:error.message,terminationConfirmed:error.terminationConfirmed===true,leaseRetained:error.leaseRetained===true,...(error.recovery?{recovery:error.recovery}:{})};}
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 const controller=new AbortController(),cancel=()=>controller.abort();process.on('SIGINT',cancel);process.on('SIGTERM',cancel);
 try{const result=await runTrainingCommand(process.argv.slice(2),{signal:controller.signal});process.stdout.write(JSON.stringify(result,null,2)+'\n');process.exitCode=result.mode==='execution'?(result.trainingRunCompleted?0:2):(result.mode==='check-only'&&result.allowed?0:2);}
 catch(error){process.stdout.write(JSON.stringify({schemaVersion:1,mode:'configuration-error',started:false,trainingRunCompleted:false,error:error.message},null,2)+'\n');process.exitCode=2;}
 finally{process.removeListener('SIGINT',cancel);process.removeListener('SIGTERM',cancel);}
}
