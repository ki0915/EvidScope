import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,existsSync,readFileSync,renameSync,readdirSync,rmSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {EventEmitter} from 'node:events';
import {createTestRuntime,TEST_RUNTIME_SCOPE,runOwnedTestProcess,writeTestRuntimeLease} from '../scripts/test-runtime-lib.mjs';

function fixture({ollama=false,k3d=false,failK3dStart=false,clock=()=>1000,pidAlive=()=>true}={}){mkdirSync('.test-runs',{recursive:true});const root=mkdtempSync(resolve('.test-runs/test-runtime-')),kubeconfig=join(root,...TEST_RUNTIME_SCOPE.kubeconfig.split('/'));mkdirSync(resolve(kubeconfig,'..'),{recursive:true});writeFileSync(kubeconfig,'synthetic kubeconfig; never parsed by test\n');const calls=[];let dockerRunning=ollama,clusterRunning=k3d;
 const run=(program,args)=>{calls.push([program,...args]);if(program==='docker'&&args[0]==='inspect')return {status:0,stdout:`/${TEST_RUNTIME_SCOPE.container}\t${dockerRunning}\t${dockerRunning?'running':'exited'}\n`,stderr:''};if(program==='docker'&&args[0]==='start'){dockerRunning=true;return {status:0,stdout:TEST_RUNTIME_SCOPE.container,stderr:''};}if(program==='docker'&&args[0]==='stop'){dockerRunning=false;return {status:0,stdout:TEST_RUNTIME_SCOPE.container,stderr:''};}if(program==='k3d'&&args[1]==='list')return {status:0,stdout:JSON.stringify([{name:TEST_RUNTIME_SCOPE.cluster,serversRunning:clusterRunning?1:0,agentsRunning:clusterRunning?2:0}]),stderr:''};if(program==='k3d'&&args[1]==='start'){if(failK3dStart)return {status:1,stdout:'',stderr:'not exposed'};clusterRunning=true;return {status:0,stdout:'',stderr:''};}if(program==='k3d'&&args[1]==='stop'){clusterRunning=false;return {status:0,stdout:'',stderr:''};}if(program==='kubectl')return {status:0,stdout:TEST_RUNTIME_SCOPE.context+'\n',stderr:''};throw Error(`unexpected command ${program}`);};return {runtime:createTestRuntime({root,run,clock,pidAlive}),calls,state:()=>({dockerRunning,clusterRunning}),root};}

test('test runtime refuses pre-existing resources and never adopts another owner',()=>{const f=fixture({ollama:true});assert.throws(()=>f.runtime.start({resources:['ollama']}),e=>e.code==='TEST_RUNTIME_PREEXISTING');assert.equal(f.calls.some(call=>call[1]==='start'),false);assert.equal(existsSync(f.runtime.leasePath),false);});

test('explicit lease starts and stops only exact EvidScope names without delete commands',()=>{const f=fixture(),lease=f.runtime.start({mode:'manual',ownerLabel:'unit-test',resources:['ollama','k3d']});assert.deepEqual(lease.startedResources,['ollama','k3d']);assert.deepEqual(f.state(),{dockerRunning:true,clusterRunning:true});const stopped=f.runtime.stop(lease.leaseId);assert.deepEqual(stopped.stopped,['k3d','ollama']);assert.deepEqual(f.state(),{dockerRunning:false,clusterRunning:false});assert.ok(f.calls.some(call=>call.join(' ')==='docker start evidscope-ollama-assistance-20260909'));assert.ok(f.calls.some(call=>call.join(' ')==='k3d cluster start evidscope-lab-20260908'));assert.ok(f.calls.every(call=>!call.includes('rm')&&!call.includes('delete')));assert.equal(stopped.volumesPreserved,true);});

test('partial start failure cleans its own attempted resource and removes lease',()=>{const f=fixture({failK3dStart:true});assert.throws(()=>f.runtime.start({resources:['ollama','k3d']}),e=>e.code==='TEST_RUNTIME_COMMAND');assert.deepEqual(f.state(),{dockerRunning:false,clusterRunning:false});assert.equal(existsSync(f.runtime.leasePath),false);assert.ok(f.calls.some(call=>call[0]==='docker'&&call[1]==='stop'));assert.equal(f.calls.filter(call=>call[0]==='docker'&&call[1]==='start').length,1);assert.equal(f.calls.filter(call=>call[0]==='k3d'&&call[1]==='cluster'&&call[2]==='start').length,1);});

test('manual idle and dead wrapper require explicit reconcile before cleanup',()=>{let now=1000;const manual=fixture({clock:()=>now}),first=manual.runtime.start({mode:'manual',idleMs:60000,resources:['ollama']});assert.throws(()=>manual.runtime.reconcile(first.leaseId),e=>e.code==='TEST_RUNTIME_LIVE_OWNER');now+=60001;assert.equal(manual.runtime.status().lease.reconciliationRequired,true);manual.runtime.reconcile(first.leaseId);assert.deepEqual(manual.state(),{dockerRunning:false,clusterRunning:false});const wrapper=fixture({pidAlive:()=>false}),second=wrapper.runtime.start({mode:'wrapper',ownerPid:99999,resources:['k3d']});assert.equal(wrapper.runtime.status().lease.reconciliationRequired,true);assert.equal(wrapper.runtime.reconcile(second.leaseId).reason,'dead_wrapper_owner');});

test('owned wrapper cleans resources after normal exit, child error, and interrupt',async()=>{for(const outcome of ['normal','error','interrupt']){const f=fixture(),signals=new EventEmitter(),child=new EventEmitter();child.killed=false;child.exitCode=null;child.kill=signal=>{child.killed=true;queueMicrotask(()=>child.emit('exit',null,signal));return true;};const promise=runOwnedTestProcess(f.runtime,{program:'synthetic-test',resources:['ollama'],signalEmitter:signals,spawnChild:()=>{if(outcome==='normal')queueMicrotask(()=>{child.exitCode=0;child.emit('exit',0,null);});if(outcome==='error')queueMicrotask(()=>child.emit('error',Error('synthetic failure')));if(outcome==='interrupt')queueMicrotask(()=>signals.emit('SIGINT'));return child;}});if(outcome==='error')await assert.rejects(promise,/synthetic failure/);else{const result=await promise;if(outcome==='interrupt')assert.equal(result.interruptedBy,'SIGINT');}assert.deepEqual(f.state(),{dockerRunning:false,clusterRunning:false});assert.equal(existsSync(f.runtime.leasePath),false);}});

function publicationFixture(t){
 const parent=resolve('.test-runs');mkdirSync(parent,{recursive:true});
 const root=mkdtempSync(join(parent,'lease-publication-'));
 t.after(()=>rmSync(root,{recursive:true,force:true}));
 const path=join(root,'lease.json'),before='{"leaseId":"previous-owner","updatedAt":1}\n';
 writeFileSync(path,before,{flag:'wx'});return {root,path,before};
}
test('lease publication normally replaces once using an exclusive UUID temporary',t=>{
 const f=publicationFixture(t),calls=[],pauses=[],value={leaseId:'same-owner',updatedAt:2};
 writeTestRuntimeLease(f.path,value,{platform:'win32',pause:ms=>pauses.push(ms),renameFile:(source,target)=>{
  assert.equal(target,f.path);assert(source.startsWith(f.path+'.'));
  calls.push([source,target]);assert.equal(readFileSync(target,'utf8'),f.before);
  assert.equal(readFileSync(source,'utf8'),JSON.stringify(value,null,2)+'\n');
  assert.match(source,/lease\.json\.\d+\.[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\.tmp$/);
  assert.throws(()=>writeFileSync(source,'collision',{flag:'wx'}),error=>error.code==='EEXIST');
  // Model a successful publication deterministically. Actual Windows replace
  // locks belong to the real-runtime and explicit retry tests, not this count.
  writeFileSync(target,readFileSync(source));rmSync(source);
 }});
 assert.equal(calls.length,1);assert.deepEqual(pauses,[]);assert.deepEqual(JSON.parse(readFileSync(f.path)),value);assert.deepEqual(readdirSync(f.root),['lease.json']);
});
test('Windows EPERM and EBUSY retry only the identical publication with unchanged written bytes',t=>{
 for(const code of ['EPERM','EBUSY']){
  const f=publicationFixture(t),calls=[],pauses=[],value={leaseId:'same-owner',updatedAt:2},expected=JSON.stringify(value,null,2)+'\n';
  writeTestRuntimeLease(f.path,value,{platform:'win32',pause:ms=>pauses.push(ms),renameFile:(source,target)=>{
   calls.push([source,target]);assert.equal(readFileSync(source,'utf8'),expected);assert.equal(readFileSync(target,'utf8'),f.before);
   value.updatedAt++;if(calls.length<3)throw Object.assign(Error('injected publication lock'),{code});renameSync(source,target);
  }});
  assert.equal(calls.length,3);assert(calls.every(call=>call[0]===calls[0][0]&&call[1]===f.path));assert.deepEqual(pauses,[20,40]);
  assert.equal(readFileSync(f.path,'utf8'),expected);assert.deepEqual(readdirSync(f.root),['lease.json']);
 }
});
test('permanent Windows publication lock exhausts a bounded wait and preserves prior lease and failed temporary',t=>{
 for(const code of ['EPERM','EBUSY']){
  const f=publicationFixture(t),calls=[],pauses=[],error=Object.assign(Error('persistent injected lock'),{code}),value={leaseId:'same-owner',updatedAt:2};
  assert.throws(()=>writeTestRuntimeLease(f.path,value,{platform:'win32',pause:ms=>pauses.push(ms),renameFile:(source,target)=>{calls.push([source,target]);throw error;}}),caught=>caught===error);
  assert.equal(calls.length,5);assert.deepEqual(pauses,[20,40,60,80]);assert(pauses.reduce((sum,ms)=>sum+ms,0)<=250);
  assert(calls.every(call=>call[0]===calls[0][0]&&call[1]===f.path));assert.equal(readFileSync(f.path,'utf8'),f.before);
  assert.equal(readFileSync(calls[0][0],'utf8'),JSON.stringify(value,null,2)+'\n');assert.equal(readdirSync(f.root).length,2);
 }
});
test('non-Windows locks and other publication errors fail closed without a retry',t=>{
 for(const [platform,code]of [['linux','EPERM'],['darwin','EBUSY'],['win32','EACCES'],['win32','ENOENT'],['win32','EXDEV']]){
  const f=publicationFixture(t),calls=[],pauses=[],error=Object.assign(Error('nonretryable injected error'),{code});
  assert.throws(()=>writeTestRuntimeLease(f.path,{leaseId:'same-owner'},{platform,pause:ms=>pauses.push(ms),renameFile:(source,target)=>{calls.push([source,target]);throw error;}}),caught=>caught===error);
  assert.equal(calls.length,1);assert.deepEqual(pauses,[]);assert.equal(readFileSync(f.path,'utf8'),f.before);assert.equal(readdirSync(f.root).length,2);
 }
});
