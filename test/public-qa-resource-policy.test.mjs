import test from 'node:test';
import assert from 'node:assert/strict';
import {PUBLIC_QA_RESOURCE_PROFILE as policy,publicQaStartDecision,publicQaContinueDecision} from '../src/public-qa-resource-policy.mjs';

const now=Date.parse('2026-09-22T10:00:00Z');
function sample(at=now,{idleSeconds=90,cgroup=false}={}){
 const observedAt=new Date(at).toISOString();
 return {schemaVersion:1,source:'public_qa_manual_host_probe',observedAt,host:{schemaVersion:1,source:'trusted_windows_host_probe',observedAt,idleSeconds,cpuPercent:10,freeMemoryGiB:8,onAcPower:true,gpu:{memoryUsedMiB:1200,memoryTotalMiB:12288,utilizationPercent:0,temperatureC:53,computeProcessCount:25}},windows:{physicalFreeGiB:8,commitFreeGiB:16,commitUsedPercent:75,pagesInputPerSecond:0},gpuInventory:{count:25,classification:'wddm_inventory_not_compute_proof'},guest:{observedAt,memAvailableGiB:12,memoryFullAvg10:0},...(cgroup?{cgroup:{observedAt,memoryCurrentGiB:6,memoryLimitGiB:12,oomCount:0,oomKillCount:0}}:{})};
}
const stable=()=>[sample(now-20000,{idleSeconds:70}),sample(now-10000,{idleSeconds:80}),sample()];
test('measured model loading headroom blocks a repeat of the 11GiB commit failure',()=>{
 const values=stable();for(const value of values)value.windows.commitFreeGiB=11;
 assert.ok(publicQaStartDecision(values,{now,interactiveUseApproved:true}).reasons.includes('windows_memory_start_pressure'));
});
test('explicit interactive approval changes input and graphics concurrency only, preserving memory and thermal stops',()=>{
 const values=stable();for(const value of values){value.host.idleSeconds=0;value.host.gpu.utilizationPercent=47;}
 assert.equal(publicQaStartDecision(values,{now}).allowed,false);
 assert.equal(publicQaStartDecision(values,{now,interactiveUseApproved:true}).allowed,true);
 const current=sample(now,{idleSeconds:0,cgroup:true}),previous=sample(now-2000),baseline=sample(now-20000);
 assert.equal(publicQaContinueDecision(current,{previous,baseline,now,interactiveUseApproved:true}).allowed,true);
 current.host.gpu.temperatureC=81;current.windows.physicalFreeGiB=1;
 const blocked=publicQaContinueDecision(current,{previous,baseline,now,interactiveUseApproved:true});
 assert.ok(blocked.reasons.includes('windows_memory_pressure'));assert.ok(blocked.reasons.includes('gpu_memory_or_temperature_pressure'));
});
test('three stable readings admit only explicit manual profile without interpreting WDDM graphics as ML',()=>{
 const result=publicQaStartDecision(stable(),{now});
 assert.equal(result.allowed,true);assert.equal(result.automaticStartAllowed,false);assert.equal(result.gpuInventoryInterpretedAsActiveCompute,false);assert.equal(policy.maxOptimizerSteps,20);
});
test('one fresh sample or stale/missing guest observation cannot claim stable admission',()=>{
 assert.equal(publicQaStartDecision([sample()],{now}).allowed,false);
 const values=stable();delete values[2].guest;assert.equal(publicQaStartDecision(values,{now}).allowed,false);
 const stale=stable();stale[2].host.observedAt=new Date(now-6000).toISOString();assert.ok(publicQaStartDecision(stale,{now}).reasons.includes('resource_receipt_stale_or_missing'));
});
test('Windows and guest memory are never summed to cover Windows pressure',()=>{
 const values=stable();values[2].windows.physicalFreeGiB=1;values[2].guest.memAvailableGiB=30;
 assert.ok(publicQaStartDecision(values,{now}).reasons.includes('windows_memory_start_pressure'));
});
test('new input after admission pauses but elapsed idle baseline does not',()=>{
 const baseline=sample(now-20000,{idleSeconds:30}),previous=sample(now-2000,{idleSeconds:48}),current=sample(now,{idleSeconds:50,cgroup:true});
 assert.equal(publicQaContinueDecision(current,{previous,baseline,now}).allowed,true);
 current.host.idleSeconds=1;
 assert.ok(publicQaContinueDecision(current,{previous,baseline,now}).reasons.includes('interactive_use_resumed'));
});
test('continue requires actual cgroup telemetry and immediately stops OOM and commit pressure',()=>{
 const previous=sample(now-2000,{idleSeconds:88}),baseline=sample(now-20000,{idleSeconds:70});
 assert.equal(publicQaContinueDecision(sample(),{previous,baseline,now}).allowed,false);
 const current=sample(now,{cgroup:true});current.cgroup.oomKillCount=1;current.windows.commitUsedPercent=98;
 const result=publicQaContinueDecision(current,{previous,baseline,now});
 assert.ok(result.reasons.includes('training_cgroup_oom'));assert.ok(result.reasons.includes('windows_memory_pressure'));
});
test('sustained cgroup and guest PSI pressure stops without blocking normal busy training GPU',()=>{
 const previous=sample(now-2000,{idleSeconds:88,cgroup:true}),baseline=sample(now-20000,{idleSeconds:70}),current=sample(now,{cgroup:true});
 current.host.gpu.utilizationPercent=100;current.host.gpu.memoryUsedMiB=9000;
 assert.equal(publicQaContinueDecision(current,{previous,baseline,now}).allowed,true);
 for(const value of [current,previous]){value.cgroup.memoryCurrentGiB=10.5;value.guest.memoryFullAvg10=6;}
 const result=publicQaContinueDecision(current,{previous,baseline,now});assert.ok(result.reasons.includes('guest_memory_stall'));assert.ok(result.reasons.includes('training_cgroup_memory_pressure'));
});
