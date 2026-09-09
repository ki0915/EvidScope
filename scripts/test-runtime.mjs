import {resolve} from 'node:path';
import {createTestRuntime,runOwnedTestProcess} from './test-runtime-lib.mjs';

const args=process.argv.slice(2),operation=args.shift(),runtime=createTestRuntime({root:resolve('.')});
const option=name=>{const index=args.indexOf(name);if(index<0)return null;const value=args[index+1];args.splice(index,2);return value;};
const resources=()=>{const value=option('--resources');if(!value)throw Error('--resources ollama|k3d|all is required');if(value==='all')return ['ollama','k3d'];if(value==='ollama'||value==='k3d')return [value];throw Error('--resources must be ollama, k3d, or all');};
try{
 if(operation==='status')console.log(JSON.stringify(runtime.status(),null,2));
 else if(operation==='start'){const ownerLabel=option('--owner')||'explicit-test',idleMs=Number(option('--idle-ms')||1800000),selected=resources(),lease=runtime.start({mode:'manual',ownerLabel,idleMs,resources:selected});console.log(JSON.stringify({leaseId:lease.leaseId,startedResources:lease.startedResources,idleExpiresAt:lease.idleExpiresAt}));}
 else if(operation==='stop'){const leaseId=option('--lease');if(!leaseId)throw Error('--lease is required');console.log(JSON.stringify(runtime.stop(leaseId)));}
 else if(operation==='reconcile'){const leaseId=option('--lease');if(!leaseId)throw Error('--lease is required');console.log(JSON.stringify(runtime.reconcile(leaseId)));}
 else if(operation==='with'){
  const selected=resources();if(args[0]==='--')args.shift();if(!args.length)throw Error('usage: node scripts/test-runtime.mjs with --resources ollama|k3d|all -- <executable> [args]');const [program,...programArgs]=args,result=await runOwnedTestProcess(runtime,{program,args:programArgs,resources:selected});if(result.exit.code!==0||result.exit.signal||result.interruptedBy)process.exitCode=result.exit.code??1;
 }else{console.error('usage: node scripts/test-runtime.mjs <status|start|stop|reconcile|with>');process.exitCode=2;}
}catch(error){console.error(JSON.stringify({error:error.code||'TEST_RUNTIME_ERROR',message:error.message}));process.exitCode=1;}
