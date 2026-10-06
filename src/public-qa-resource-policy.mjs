// Separate policy for one explicitly requested bounded public-QA stage. This module does
// not start jobs, change the automatic idle guard, or add Windows/guest memory.
export const PUBLIC_QA_RESOURCE_PROFILE=Object.freeze({
  name:'manual_public_qa_bounded_measured_v2',automaticStartAllowed:false,maxOptimizerSteps:20,maxRuntimeMs:3600000,
  cpuLimit:2,memoryLimitGiB:12,gpuMemoryFraction:0.65,
  receiptMaxAgeMs:5000,startSamples:3,startSampleSpanMs:20000,inputClockToleranceSeconds:3,
  minStartIdleSeconds:30,maxStartCpuPercent:50,minStartWindowsFreeGiB:4,minStartCommitFreeGiB:14,maxStartCommitPercent:85,
  minStartGuestAvailableGiB:10,maxStartGuestMemoryFullAvg10:1,minStartGpuFreeMiB:9216,maxStartGpuUtilizationPercent:10,maxStartGpuTemperatureC:75,
  minContinueWindowsFreeGiB:2,minContinueCommitFreeGiB:3,maxContinueCommitPercent:92,minContinueGuestAvailableGiB:1.5,
  maxContinueGuestMemoryFullAvg10:5,maxContinueCgroupGiB:10,minContinueGpuFreeMiB:1024,maxContinueGpuTemperatureC:80,
});
const P=PUBLIC_QA_RESOURCE_PROFILE;
const finite=(v,min=0,max=Number.MAX_SAFE_INTEGER)=>typeof v==='number'&&Number.isFinite(v)&&v>=min&&v<=max;
const time=value=>typeof value==='string'?Date.parse(value):NaN;
function validate(r,{now,maxAge=P.receiptMaxAgeMs,requireCgroup=false}={}) {
  const problems=[];
  if(!r||r.schemaVersion!==1||r.source!=='public_qa_manual_host_probe')return ['manual_host_receipt_invalid'];
  const dates=[r.observedAt,r.host?.observedAt,r.guest?.observedAt,...(requireCgroup?[r.cgroup?.observedAt]:[])];
  if(dates.some(d=>!Number.isFinite(time(d))||time(d)>now||now-time(d)>maxAge))problems.push('resource_receipt_stale_or_missing');
  const h=r.host,w=r.windows,g=h?.gpu;
  if(h?.schemaVersion!==1||h.source!=='trusted_windows_host_probe'||!finite(h.idleSeconds)||!finite(h.cpuPercent,0,100)||!finite(h.freeMemoryGiB)||typeof h.onAcPower!=='boolean')problems.push('host_values_invalid');
  if(!w||!finite(w.physicalFreeGiB)||!finite(w.commitFreeGiB)||!finite(w.commitUsedPercent,0,100)||!finite(w.pagesInputPerSecond))problems.push('windows_memory_values_invalid');
  if(!g||!finite(g.memoryTotalMiB,1)||!finite(g.memoryUsedMiB,0,g.memoryTotalMiB)||!finite(g.utilizationPercent,0,100)||!finite(g.temperatureC,0,150)||!Number.isSafeInteger(g.computeProcessCount)||g.computeProcessCount<0)problems.push('gpu_values_invalid');
  if(r.gpuInventory?.classification!=='wddm_inventory_not_compute_proof'||r.gpuInventory.count!==g?.computeProcessCount)problems.push('gpu_inventory_semantics_missing');
  if(!r.guest||!finite(r.guest.memAvailableGiB)||!finite(r.guest.memoryFullAvg10,0,100))problems.push('guest_memory_values_missing');
  if(requireCgroup||r.cgroup){const c=r.cgroup;if(!c||!finite(c.memoryCurrentGiB)||!finite(c.memoryLimitGiB,0.01,P.memoryLimitGiB)||!Number.isSafeInteger(c.oomCount)||c.oomCount<0||!Number.isSafeInteger(c.oomKillCount)||c.oomKillCount<0)problems.push('training_cgroup_values_missing');}
  return problems;
}
const result=(reasons,extra={})=>({allowed:reasons.length===0,reasons:[...new Set(reasons)],profile:P.name,automaticStartAllowed:false,...extra});
function startReasons(r,interactiveUseApproved=false){
  const h=r.host,w=r.windows,g=h.gpu,reasons=[];
  if(!h.onAcPower)reasons.push('host_not_on_ac_power');
  if(!interactiveUseApproved&&h.idleSeconds<P.minStartIdleSeconds)reasons.push('request_input_not_yet_idle');
  if(h.cpuPercent>P.maxStartCpuPercent)reasons.push('host_cpu_busy');
  if(Math.min(h.freeMemoryGiB,w.physicalFreeGiB)<P.minStartWindowsFreeGiB||w.commitFreeGiB<P.minStartCommitFreeGiB||w.commitUsedPercent>P.maxStartCommitPercent)reasons.push('windows_memory_start_pressure');
  if(r.guest.memAvailableGiB<P.minStartGuestAvailableGiB||r.guest.memoryFullAvg10>=P.maxStartGuestMemoryFullAvg10)reasons.push('guest_memory_start_pressure');
  if(g.memoryTotalMiB-g.memoryUsedMiB<P.minStartGpuFreeMiB||g.utilizationPercent>(interactiveUseApproved?80:P.maxStartGpuUtilizationPercent)||g.temperatureC>P.maxStartGpuTemperatureC)reasons.push('gpu_start_pressure');
  if(r.cgroup&&(r.cgroup.oomCount>0||r.cgroup.oomKillCount>0))reasons.push('training_cgroup_oom');
  return reasons;
}
export function publicQaStartDecision(samples,{now=Date.now(),interactiveUseApproved=false}={}) {
  if(!Array.isArray(samples)||samples.length!==P.startSamples)return result(['three_stable_samples_required']);
  const reasons=[];
  for(let i=0;i<samples.length;i++){
    const errors=validate(samples[i],{now,maxAge:i===samples.length-1?P.receiptMaxAgeMs:60000});
    reasons.push(...errors);
    if(!errors.length)reasons.push(...startReasons(samples[i],interactiveUseApproved===true));
    if(i&&time(samples[i].observedAt)-time(samples[i-1].observedAt)<5000)reasons.push('start_samples_not_separated');
  }
  if(time(samples.at(-1)?.observedAt)-time(samples[0]?.observedAt)<P.startSampleSpanMs)reasons.push('start_stability_window_short');
  return result(reasons,{gpuInventoryInterpretedAsActiveCompute:false,memoryDomainsSummed:false,interactiveUseApproved:interactiveUseApproved===true});
}
function newInput(current,prior){
  const elapsed=(time(current.host.observedAt)-time(prior.host.observedAt))/1000;
  return current.host.idleSeconds < prior.host.idleSeconds+elapsed-P.inputClockToleranceSeconds;
}
export function publicQaContinueDecision(current,{previous,baseline,now=Date.now(),interactiveUseApproved=false}={}) {
  const reasons=validate(current,{now,requireCgroup:true});
  if(!previous||!baseline||validate(previous,{now,maxAge:60000}).length||validate(baseline,{now,maxAge:P.maxRuntimeMs+60000}).length)return result([...reasons,'previous_or_start_baseline_invalid']);
  if(reasons.length)return result(reasons);
  if(time(current.observedAt)<=time(previous.observedAt))return result(['observation_not_monotonic']);
  const h=current.host,w=current.windows,g=h.gpu,c=current.cgroup;
  if(!h.onAcPower)reasons.push('host_power_changed');
  if(!interactiveUseApproved&&newInput(current,previous)&&newInput(current,baseline))reasons.push('interactive_use_resumed');
  if(Math.min(h.freeMemoryGiB,w.physicalFreeGiB)<P.minContinueWindowsFreeGiB||w.commitFreeGiB<P.minContinueCommitFreeGiB||w.commitUsedPercent>P.maxContinueCommitPercent)reasons.push('windows_memory_pressure');
  if(current.guest.memAvailableGiB<P.minContinueGuestAvailableGiB)reasons.push('guest_memory_pressure');
  if(current.guest.memoryFullAvg10>P.maxContinueGuestMemoryFullAvg10&&previous.guest.memoryFullAvg10>P.maxContinueGuestMemoryFullAvg10)reasons.push('guest_memory_stall');
  if(c.memoryCurrentGiB>P.maxContinueCgroupGiB&&previous.cgroup?.memoryCurrentGiB>P.maxContinueCgroupGiB)reasons.push('training_cgroup_memory_pressure');
  if(c.oomCount>0||c.oomKillCount>0)reasons.push('training_cgroup_oom');
  if(g.memoryTotalMiB-g.memoryUsedMiB<P.minContinueGpuFreeMiB||g.temperatureC>=P.maxContinueGpuTemperatureC)reasons.push('gpu_memory_or_temperature_pressure');
  if(now-time(baseline.observedAt)>=P.maxRuntimeMs)reasons.push('manual_run_deadline');
  return result(reasons,{gpuInventoryInterpretedAsActiveCompute:false,memoryDomainsSummed:false});
}
