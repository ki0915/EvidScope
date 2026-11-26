// Process-level measurement for scripts/benchmark.mjs (round 7, docs/performance.md): CPU time per process from /proc, and
// optional CPU pinning with taskset, so the vault's capacity can be told apart from what the load generator costs.
import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';

let ticks;
// Clock ticks per second of /proc/<pid>/stat (USER_HZ); 100 on Linux unless getconf says otherwise.
export function clockTicks(){
 if(ticks===undefined){try{ticks=Number(execFileSync('getconf',['CLK_TCK'],{encoding:'utf8'}).trim())||100;}catch{ticks=100;}}
 return ticks;
}
// utime+stime in ms of a process (all threads) or of one thread; null where /proc is not available.
function statMs(path){
 try{const fields=readFileSync(path,'utf8').split(') ')[1].split(' ');return (Number(fields[11])+Number(fields[12]))*1000/clockTicks();}catch{return null;}
}
export const processCpuMs=pid=>statMs(`/proc/${pid}/stat`);
// The main thread is the JavaScript thread: SQLite, crypto and HTTP of the vault all run there, so it bounds throughput.
export const mainThreadCpuMs=pid=>statMs(`/proc/${pid}/task/${pid}/stat`);

// Snapshot of named processes: {name: pid}. delta(before, count) gives CPU ms per event for each, plus the vault main thread.
export function cpuSnapshot(pids){
 const out={};for(const [name,pid] of Object.entries(pids))out[name]={total:processCpuMs(pid),main:mainThreadCpuMs(pid)};return out;
}
export function cpuPerEvent(before,after,count){
 const out={};
 for(const name of Object.keys(after)){
  const a=after[name],b=before[name];if(!b||a.total===null||b.total===null)continue;
  out[name]=+((a.total-b.total)/count).toFixed(3);
  if(name==='vault'&&a.main!==null&&b.main!==null)out.vaultMainThread=+((a.main-b.main)/count).toFixed(3);
 }
 return out;
}

// BENCHMARK_PIN=1 pins vault, ingress, the load client and the rest (audit, workers) to CPUs 0, 1, 2 and 3; a custom layout is
// "vault:0,ingress:1,client:2-3,other:3". Every thread of a process is pinned (taskset -a). Returns the layout applied or null.
export function pinLayout(spec,cpuCount){
 if(!spec)return null;
 if(spec==='1'){if(cpuCount<4)return null;return {vault:'0',ingress:'1',client:'2',other:'3'};}
 const layout={};
 for(const part of spec.split(',')){
  const [name,cpus]=part.split(':');
  if(!/^(vault|ingress|client|other)$/.test(name)||!/^\d+(-\d+)?$/.test(cpus||''))throw Error('Invalid BENCHMARK_PIN');
  layout[name]=cpus;
 }
 return layout;
}
export function pinProcesses(layout,groups){
 if(!layout)return null;
 try{execFileSync('taskset',['-V'],{stdio:'ignore'});}catch{return null;}
 const applied={};
 for(const [name,pids] of Object.entries(groups)){
  const cpus=layout[name]??layout.other;if(cpus===undefined)continue;
  for(const pid of pids)execFileSync('taskset',['-a','-pc',cpus,String(pid)],{stdio:'ignore'});
  applied[name]=cpus;
 }
 return applied;
}
