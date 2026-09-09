import {evaluate} from './model.mjs';
import {analysisLimits} from './analysis.mjs';

export function evaluateJob(job){
 const result=evaluate(job.events,job.assets,job.rules,job.exceptions,job.analysisTime);
 const totalFindings=result.findings.length;result.findings=result.findings.slice(0,analysisLimits.findings);
 const coverage=()=>({totalFindings,returnedFindings:result.findings.length,truncated:totalFindings>result.findings.length});
 result.coverage=coverage();
 while(Buffer.byteLength(JSON.stringify(result))>analysisLimits.resultBytes-1024&&result.findings.length){result.findings.pop();result.coverage=coverage();}
 return result;
}
async function post(base,token,path,body,maxBytes){
 const response=await fetch(new URL(path,base),{method:'POST',headers:{authorization:`Bearer ${token}`,'content-type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(10000),redirect:'error'});
 const chunks=[];let size=0;
 for await(const chunk of response.body){size+=chunk.length;if(size>maxBytes)throw Error('Worker response exceeds bounded size');chunks.push(chunk);}
 const value=JSON.parse(Buffer.concat(chunks).toString('utf8'));
 if(!response.ok){const error=new Error(value.error||`Worker HTTP ${response.status}`);error.status=response.status;throw error;}
 return value;
}
export async function tick(base,token){
 const claim=await post(base,token,'/internal/claim',{},analysisLimits.snapshotBytes);let processed=0,stale=0,backlog=claim.backlog;
 for(const job of claim.jobs){
  const result=evaluateJob(job);
  try{const completed=await post(base,token,'/internal/complete',{leaseId:job.leaseId,result},65536);processed++;backlog=completed.backlog;}
  catch(error){if(error.status===409){stale++;continue;}throw error;}
 }
 return {processed,stale,backlog,coverage:claim.coverage};
}
