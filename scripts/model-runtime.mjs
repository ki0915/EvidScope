import {execFileSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
import {modelRuntimeStatus} from '../src/model-runtime.mjs';
const namespace='evidscope-models';
export function observeModelPods({kubectl='kubectl',execute=execFileSync,now=Date.now()}={}){
 try{
  const raw=execute(kubectl,['--namespace',namespace,'get','pods','--selector','evidscope.io/managed=true,evidscope.io/component=isolated-model','--request-timeout=5s','-o','json'],{encoding:'utf8',timeout:7000,maxBuffer:1024*1024,windowsHide:true,stdio:['ignore','pipe','pipe']});
  const pods=JSON.parse(raw).items;if(!Array.isArray(pods))throw Error('invalid_pod_list');
  const models=['foundation-sec','cipherguard'].map(id=>{const matches=pods.filter(p=>p.metadata?.labels?.['evidscope.io/model']===id);if(matches.length===0)return {id,phase:'Absent',ready:false};if(matches.length!==1)return {id,phase:'Pending',ready:false};const p=matches[0],containers=p.status?.containerStatuses||[];return {id,uid:p.metadata.uid,phase:p.status?.phase||'Pending',ready:p.metadata.deletionTimestamp?false:containers.length===2&&containers.every(c=>c.ready===true&&c.state?.running),allContainersTerminated:containers.length===2&&containers.every(c=>c.state?.terminated)};});
  return {schemaVersion:1,source:'kubernetes_api',observedAt:new Date(now).toISOString(),models};
 }catch{return {schemaVersion:1,source:'unavailable',observedAt:new Date(now).toISOString(),models:[],errorCode:'cluster_observation_unavailable'};}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){if(process.argv[2]&&process.argv[2]!=='status')throw Error('Only read-only status supported here. Launch through a trusted dispatcher after isolation checks.');const receipt=observeModelPods();process.stdout.write(JSON.stringify({receipt,status:modelRuntimeStatus({receipt})},null,2)+'\n');}
