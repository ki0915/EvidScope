import {boundedEvaluation} from './model.mjs';
import {analysisLimits} from './analysis.mjs';

export function evaluateJob(job){return boundedEvaluation(job,analysisLimits);}
async function post(base,token,path,body,maxBytes){
 const response=await fetch(new URL(path,base),{method:'POST',headers:{authorization:`Bearer ${token}`,'content-type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(10000),redirect:'error'});
 const chunks=[];let size=0;
 for await(const chunk of response.body){size+=chunk.length;if(size>maxBytes)throw Error('Worker response exceeds bounded size');chunks.push(chunk);}
 const value=JSON.parse(Buffer.concat(chunks).toString('utf8'));
 if(!response.ok){const error=new Error(value.error||`Worker HTTP ${response.status}`);error.status=response.status;throw error;}
 return value;
}
// 409: the lease went stale. 422: the vault's own recomputation differs (for example a worker running another engine
// version); the vault frees the action for another claim and the worker reports the count.
export async function tick(base,token){
 const claim=await post(base,token,'/internal/claim',{},analysisLimits.snapshotBytes);let processed=0,stale=0,rejected=0,backlog=claim.backlog;
 for(const job of claim.jobs){
  const result=evaluateJob(job);
  try{const completed=await post(base,token,'/internal/complete',{leaseId:job.leaseId,result},65536);processed++;backlog=completed.backlog;}
  catch(error){if(error.status===409){stale++;continue;}if(error.status===422){rejected++;continue;}throw error;}
 }
 return {processed,stale,rejected,backlog,coverage:claim.coverage};
}
