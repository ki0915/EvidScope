import {existsSync,mkdirSync,readFileSync,writeFileSync,renameSync,unlinkSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {randomUUID} from 'node:crypto';
import {spawn,spawnSync} from 'node:child_process';

export const TEST_RUNTIME_SCOPE=Object.freeze({container:'evidscope-ollama-assistance-20260909',cluster:'evidscope-lab-20260908',context:'k3d-evidscope-lab-20260908',kubeconfig:'.local/k8s-lab-20260908/kubeconfig.yaml'});
function failure(message,code='TEST_RUNTIME_INVALID'){const error=Error(message);error.code=code;throw error;}
function command(program,args){const result=spawnSync(program,args,{encoding:'utf8',windowsHide:true,shell:false});return {status:result.status??1,stdout:result.stdout||'',stderr:result.stderr||'',error:result.error};}
function readJson(path){try{return JSON.parse(readFileSync(path,'utf8'));}catch(error){if(error.code==='ENOENT')return null;throw error;}}
function atomic(path,value){const temporary=`${path}.${process.pid}.${Date.now()}.tmp`;writeFileSync(temporary,JSON.stringify(value,null,2)+'\n',{flag:'wx'});renameSync(temporary,path);}
function assertSuccess(result,label){if(result.error||result.status!==0)failure(`${label} 실패`,result.error?.code||'TEST_RUNTIME_COMMAND');return result.stdout.trim();}
function alive(pid){if(!Number.isInteger(pid)||pid<=0)return false;try{process.kill(pid,0);return true;}catch{return false;}}

export function createTestRuntime({root=resolve('.'),run=command,clock=()=>Date.now(),pidAlive=alive}={}){
 const repo=resolve(root),stateDir=join(repo,'.local','test-runtime'),leasePath=join(stateDir,'lease.json'),expectedKubeconfig=resolve(repo,TEST_RUNTIME_SCOPE.kubeconfig);mkdirSync(stateDir,{recursive:true});
 function dockerState(){const result=run('docker',['inspect','--format','{{.Name}}\t{{.State.Running}}\t{{.State.Status}}',TEST_RUNTIME_SCOPE.container]);if(result.status!==0)return {exists:false,running:false,status:'missing_or_daemon_unavailable'};const [name,running,status]=result.stdout.trim().split(/\t/);if(name!==`/${TEST_RUNTIME_SCOPE.container}`)failure('Docker inspect 대상 이름 불일치','TEST_RUNTIME_SCOPE');return {exists:true,running:running==='true',status:status||'unknown'};}
 function clusterState(){const result=run('k3d',['cluster','list','-o','json']);if(result.status!==0)return {exists:false,running:false,status:'missing_or_daemon_unavailable'};let clusters;try{clusters=JSON.parse(result.stdout);}catch{failure('k3d cluster list JSON 오류','TEST_RUNTIME_COMMAND');}const matches=clusters.filter(value=>value.name===TEST_RUNTIME_SCOPE.cluster);if(matches.length>1)failure('동일 이름 k3d cluster가 중복됩니다','TEST_RUNTIME_SCOPE');const cluster=matches[0];if(!cluster)return {exists:false,running:false,status:'missing'};const running=cluster.serversRunning>0||cluster.agentsRunning>0;return {exists:true,running,status:running?'running':'stopped'};}
 function kubeconfigState(){if(!existsSync(expectedKubeconfig))return {path:expectedKubeconfig,exists:false,context:'unknown',valid:false};const result=run('kubectl',['--kubeconfig',expectedKubeconfig,'config','current-context']);const context=result.status===0?result.stdout.trim():'unknown';return {path:expectedKubeconfig,exists:true,context,valid:context===TEST_RUNTIME_SCOPE.context};}
 function leaseState(){const lease=readJson(leasePath);if(!lease)return null;const ownerAlive=lease.mode==='wrapper'?pidAlive(lease.ownerPid):null,idleExpired=clock()>=lease.idleExpiresAt;return {...lease,ownerAlive,idleExpired,reconciliationRequired:(lease.mode==='wrapper'&&!ownerAlive)||(lease.mode==='manual'&&idleExpired)};}
 function status(){return {scope:TEST_RUNTIME_SCOPE,ollama:dockerState(),k3d:clusterState(),kubeconfig:kubeconfigState(),lease:leaseState(),defaultState:'stopped_unless_explicit_test_start'};}
 function updateLease(lease){lease.updatedAt=clock();atomic(leasePath,lease);}
 function ensureLease(leaseId){const lease=readJson(leasePath);if(!lease)failure('활성 test-runtime lease가 없습니다','TEST_RUNTIME_NO_LEASE');if(lease.leaseId!==leaseId)failure('leaseId 불일치','TEST_RUNTIME_OWNER');return lease;}
 function stopAttempted(lease){const stopped=[];for(const resource of [...lease.startAttempted].reverse()){
   if(resource==='k3d'){const state=clusterState();if(state.running){assertSuccess(run('k3d',['cluster','stop',TEST_RUNTIME_SCOPE.cluster]),'전용 k3d stop');stopped.push('k3d');}}
   if(resource==='ollama'){const state=dockerState();if(state.running){assertSuccess(run('docker',['stop','--time','10',TEST_RUNTIME_SCOPE.container]),'전용 Ollama stop');stopped.push('ollama');}}
  }return stopped;
 }
 function start({mode='manual',ownerLabel='explicit-test',idleMs=30*60*1000,ownerPid=process.pid,resources}={}){
  if(!['manual','wrapper'].includes(mode)||typeof ownerLabel!=='string'||!ownerLabel.trim())failure('start mode/ownerLabel 오류');if(!Array.isArray(resources)||!resources.length||resources.some(value=>!['ollama','k3d'].includes(value))||new Set(resources).size!==resources.length)failure('resources는 ollama, k3d 또는 둘 다를 명시해야 합니다');if(!Number.isSafeInteger(idleMs)||idleMs<60000||idleMs>4*60*60*1000)failure('idleMs는 1분~4시간이어야 합니다');if(readJson(leasePath))failure('기존 lease를 status/stop/reconcile로 먼저 처리하세요','TEST_RUNTIME_LEASE_EXISTS');
  const before={};if(resources.includes('ollama'))before.ollama=dockerState();if(resources.includes('k3d')){before.k3d=clusterState();before.kubeconfig=kubeconfigState();}if(Object.values(before).some(value=>value.exists===false))failure('지정된 전용 시험 자원이 존재해야 합니다','TEST_RUNTIME_MISSING');if(before.ollama?.running||before.k3d?.running)failure('기존 실행 자원은 소유권을 추정하지 않고 거부합니다','TEST_RUNTIME_PREEXISTING');if(before.kubeconfig&&!before.kubeconfig.valid)failure('지정 kubeconfig/context 검증 실패','TEST_RUNTIME_SCOPE');
  const current=clock(),lease={schemaVersion:1,leaseId:randomUUID(),mode,ownerLabel:ownerLabel.trim().slice(0,120),ownerPid,createdAt:current,updatedAt:current,idleExpiresAt:current+idleMs,resources:[...resources],scope:TEST_RUNTIME_SCOPE,initialState:Object.fromEntries(resources.map(value=>[value,'stopped'])),startAttempted:[],startedResources:[]};writeFileSync(leasePath,JSON.stringify(lease,null,2)+'\n',{flag:'wx'});
  try{for(const resource of resources){lease.startAttempted.push(resource);updateLease(lease);if(resource==='ollama')assertSuccess(run('docker',['start',TEST_RUNTIME_SCOPE.container]),'전용 Ollama start');else assertSuccess(run('k3d',['cluster','start',TEST_RUNTIME_SCOPE.cluster]),'전용 k3d start');lease.startedResources.push(resource);updateLease(lease);}return {...lease};}catch(error){try{stopAttempted(lease);}finally{if(existsSync(leasePath))unlinkSync(leasePath);}throw error;}
 }
 function renew(leaseId,{idleMs=30*60*1000}={}){const lease=ensureLease(leaseId);if(!Number.isSafeInteger(idleMs)||idleMs<60000||idleMs>4*60*60*1000)failure('idleMs는 1분~4시간이어야 합니다');lease.idleExpiresAt=clock()+idleMs;updateLease(lease);return {...lease};}
 function stop(leaseId){const lease=ensureLease(leaseId),stopped=stopAttempted(lease);unlinkSync(leasePath);return {leaseId,stopped,deleted:false,volumesPreserved:true};}
 function reconcile(leaseId){const lease=ensureLease(leaseId),ownerDead=lease.mode==='wrapper'&&!pidAlive(lease.ownerPid),idleExpired=lease.mode==='manual'&&clock()>=lease.idleExpiresAt;if(!ownerDead&&!idleExpired)failure('live owner 또는 유효 manual lease는 reconcile할 수 없습니다','TEST_RUNTIME_LIVE_OWNER');const stopped=stopAttempted(lease);unlinkSync(leasePath);return {leaseId,reason:ownerDead?'dead_wrapper_owner':'manual_idle_expired',stopped,deleted:false,volumesPreserved:true};}
 return {leasePath,status,start,renew,stop,reconcile};
}

export async function runOwnedTestProcess(runtime,{program,args=[],resources,spawnChild=(file,values)=>spawn(file,values,{stdio:'inherit',shell:false,windowsHide:true}),signalEmitter=process}={}){
 if(typeof program!=='string'||!program)failure('test executable이 필요합니다');const lease=runtime.start({mode:'wrapper',ownerLabel:`test:${program}`,ownerPid:process.pid,resources});let child,interruptedBy=null,cleanup;
 const forward=signal=>{interruptedBy=signal;if(child&&!child.killed)child.kill(signal);};const onInterrupt=()=>forward('SIGINT'),onTerminate=()=>forward('SIGTERM');signalEmitter.once('SIGINT',onInterrupt);signalEmitter.once('SIGTERM',onTerminate);
 try{child=spawnChild(program,args);const exit=await new Promise((accept,reject)=>{child.once('error',reject);child.once('exit',(code,signal)=>accept({code,signal}));});return {exit,interruptedBy};}finally{signalEmitter.removeListener('SIGINT',onInterrupt);signalEmitter.removeListener('SIGTERM',onTerminate);if(child&&!child.killed&&child.exitCode===null)child.kill('SIGTERM');cleanup=runtime.stop(lease.leaseId);if(cleanup)process.stderr.write(JSON.stringify({cleanup:'complete',...cleanup})+'\n');}
}
