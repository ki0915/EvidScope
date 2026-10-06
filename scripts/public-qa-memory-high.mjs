import {execFile} from 'node:child_process';
import {promisify} from 'node:util';

const executeFile=promisify(execFile);
const NODE='k3d-evidscope-training-server-0';
const HIGH=2147483648;
const HARD=12884901888;
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
async function execute(program,args){return (await executeFile(program,args,{encoding:'utf8',windowsHide:true,timeout:15000,maxBuffer:2*1024*1024})).stdout;}

function identity(pod,nodeName){
 const uid=pod?.metadata?.uid,name=pod?.metadata?.name;
 const status=pod?.status?.containerStatuses?.find(c=>c.name==='training');
 const id=status?.containerID?.match(/^containerd:\/\/([a-f0-9]{64})$/)?.[1];
 if(nodeName!==NODE||pod?.spec?.nodeName!==nodeName||pod?.metadata?.namespace!=='evidscope-training'||!UUID.test(uid??'')||!/^public-qa-[a-z0-9-]+$/.test(name??'')||!id||!status.state?.running)throw Error('memory_high_pod_identity_invalid');
 return {uid,name,id};
}

function checkCri(value,target){
 const s=value?.status,labels=s?.labels,pid=value?.info?.pid;
 if(s?.id!==target.id||s?.state!=='CONTAINER_RUNNING'||labels?.['io.kubernetes.pod.uid']!==target.uid||labels?.['io.kubernetes.pod.name']!==target.name||labels?.['io.kubernetes.pod.namespace']!=='evidscope-training'||labels?.['io.kubernetes.container.name']!=='training'||!Number.isSafeInteger(pid)||pid<2)throw Error('memory_high_cri_identity_mismatch');
 return pid;
}

// Static script; all variable values are separate execFile argv, never shell text.
// The path must be the container leaf, never its Pod or a shared ancestor.
const READ=String.raw`set -eu
pid="$1"
expected="$2"
actual=$(sed -n 's/^0:://p' "/proc/$pid/cgroup")
test "$actual" = "$expected"
directory="/sys/fs/cgroup$expected"
test "$(readlink -f "$directory")" = "$directory"
grep -qx "$pid" "$directory/cgroup.procs"
printf 'high=%s\nmax=%s\ncurrent=%s\n' "$(cat "$directory/memory.high")" "$(cat "$directory/memory.max")" "$(cat "$directory/memory.current")"
`;
const WRITE=String.raw`set -eu
pid="$1"
expected="$2"
hard="$3"
high="$4"
actual=$(sed -n 's/^0:://p' "/proc/$pid/cgroup")
test "$actual" = "$expected"
directory="/sys/fs/cgroup$expected"
test "$(readlink -f "$directory")" = "$directory"
grep -qx "$pid" "$directory/cgroup.procs"
test "$(cat "$directory/memory.max")" = "$hard"
before=$(cat "$directory/memory.high")
case "$before" in max|2147483648) ;; *) exit 44 ;; esac
printf '%s' "$high" > "$directory/memory.high"
test "$(cat "$directory/memory.high")" = "$high"
test "$(cat "$directory/memory.max")" = "$hard"
printf 'before=%s\nafter=%s\nmax=%s\n' "$before" "$(cat "$directory/memory.high")" "$(cat "$directory/memory.max")"
`;
const fields=raw=>Object.fromEntries(raw.trim().split('\n').map(line=>line.trim().split('=')));

async function locate({pod,nodeName,command}){
 const target=identity(pod,nodeName);
 const docker=args=>command('docker',['exec',nodeName,...args]);
 const inspect=()=>docker(['crictl','inspect',target.id]).then(JSON.parse);
 const pid=checkCri(await inspect(),target);
 const raw=await docker(['cat',`/proc/${pid}/cgroup`]);
 const lines=raw.trim().split('\n');
 if(lines.length!==1||!lines[0].startsWith('0::'))throw Error('memory_high_requires_unified_cgroup_v2');
 const relative=lines[0].slice(3).trim();
 const allowed=[`/kubepods/burstable/pod${target.uid}/${target.id}`,`/kubepods/pod${target.uid}/${target.id}`];
 if(!allowed.includes(relative))throw Error('memory_high_container_leaf_mismatch');
 const current=fields(await docker(['sh','-c',READ,'--',String(pid),relative]));
 if(checkCri(await inspect(),target)!==pid)throw Error('memory_high_container_changed');
 return {target,docker,inspect,pid,relative,current};
}

export async function inspectMemoryHigh({pod,nodeName=NODE,command=execute}){
 const r=await locate({pod,nodeName,command});
 return {podUid:r.target.uid,containerID:r.target.id,pid:r.pid,path:`/sys/fs/cgroup${r.relative}`,memoryHigh:r.current.high,memoryMax:r.current.max,memoryCurrent:r.current.current};
}

export async function enforceMemoryHigh({pod,nodeName=NODE,command=execute}){
 const c=pod?.spec?.containers?.find(item=>item.name==='training');
 if(pod?.metadata?.name==='public-qa-stager'||c?.resources?.limits?.memory!=='12Gi'||c?.resources?.limits?.cpu!=='2'||String(c?.resources?.limits?.['nvidia.com/gpu'])!=='1')throw Error('memory_high_training_limits_invalid');
 const r=await locate({pod,nodeName,command});
 if(r.current.max!==String(HARD)||!['max',String(HIGH)].includes(r.current.high))throw Error('memory_high_existing_limit_invalid');
 const written=fields(await r.docker(['sh','-c',WRITE,'--',String(r.pid),r.relative,String(HARD),String(HIGH)]));
 if(checkCri(await r.inspect(),r.target)!==r.pid||written.after!==String(HIGH)||written.max!==String(HARD))throw Error('memory_high_write_unconfirmed');
 return {observedAt:new Date().toISOString(),nodeName,podUid:r.target.uid,containerID:r.target.id,pid:r.pid,path:`/sys/fs/cgroup${r.relative}`,previousMemoryHigh:written.before,memoryHigh:written.after,memoryMax:written.max,containerLeafOnly:true,markerReleased:false};
}
