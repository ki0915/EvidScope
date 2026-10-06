export const TRAINING_RESOURCE_POLICY=Object.freeze({receiptMaxAgeMs:5000,minIdleSeconds:900,maxStartCpuPercent:20,minStartFreeMemoryGiB:18,maxStartGpuMemoryUsedMiB:1024,maxStartGpuUtilizationPercent:10,maxGpuTemperatureC:80,minContinueIdleSeconds:30,minContinueFreeMemoryGiB:8,minContinueGpuFreeMiB:1024,checkIntervalMs:2000,maxStopPolls:40});
const number=(value,min,max)=>typeof value==='number'&&Number.isFinite(value)&&value>=min&&value<=max;

export function validateHostResourceReceipt(receipt,{now=Date.now()}={}){
 if(!receipt||receipt.schemaVersion!==1||receipt.source!=='trusted_windows_host_probe'||Object.keys(receipt).some(k=>!['schemaVersion','source','observedAt','idleSeconds','cpuPercent','freeMemoryGiB','onAcPower','gpu'].includes(k)))throw Error('host_resource_receipt_invalid');
 const observedAt=Date.parse(receipt.observedAt);if(!Number.isFinite(observedAt)||observedAt>now||now-observedAt>TRAINING_RESOURCE_POLICY.receiptMaxAgeMs)throw Error('host_resource_receipt_stale');
 if(!number(receipt.idleSeconds,0,Number.MAX_SAFE_INTEGER)||!number(receipt.cpuPercent,0,100)||!number(receipt.freeMemoryGiB,0,1048576)||typeof receipt.onAcPower!=='boolean')throw Error('host_resource_receipt_invalid');
 const gpu=receipt.gpu;if(!gpu||Object.keys(gpu).some(k=>!['memoryUsedMiB','memoryTotalMiB','utilizationPercent','temperatureC','computeProcessCount'].includes(k))||!number(gpu.memoryUsedMiB,0,1048576)||!number(gpu.memoryTotalMiB,1,1048576)||gpu.memoryUsedMiB>gpu.memoryTotalMiB||!number(gpu.utilizationPercent,0,100)||!number(gpu.temperatureC,0,150)||!Number.isSafeInteger(gpu.computeProcessCount)||gpu.computeProcessCount<0)throw Error('host_resource_receipt_invalid');
 return structuredClone(receipt);
}

export function trainingStartDecision(receipt,options={}){
 let r;try{r=validateHostResourceReceipt(receipt,options);}catch(error){return {allowed:false,reasons:[error.message]};}
 const p=TRAINING_RESOURCE_POLICY,reasons=[];
 if(r.idleSeconds<p.minIdleSeconds)reasons.push('interactive_session_not_idle');
 if(r.cpuPercent>p.maxStartCpuPercent)reasons.push('host_cpu_busy');
 if(r.freeMemoryGiB<p.minStartFreeMemoryGiB)reasons.push('host_memory_reserve_low');
 if(!r.onAcPower)reasons.push('host_not_on_ac_power');
 if(r.gpu.memoryUsedMiB>p.maxStartGpuMemoryUsedMiB)reasons.push('gpu_memory_in_use');
 if(r.gpu.utilizationPercent>p.maxStartGpuUtilizationPercent)reasons.push('gpu_busy');
 if(r.gpu.temperatureC>p.maxGpuTemperatureC)reasons.push('gpu_temperature_high');
 if(r.gpu.computeProcessCount>0)reasons.push('other_gpu_compute_active');
 return {allowed:reasons.length===0,reasons};
}

export function trainingContinueDecision(receipt,options={}){
 let r;try{r=validateHostResourceReceipt(receipt,options);}catch(error){return {allowed:false,reasons:[error.message]};}
 const p=TRAINING_RESOURCE_POLICY,reasons=[];
 if(r.idleSeconds<p.minContinueIdleSeconds)reasons.push('interactive_use_resumed');
 if(r.freeMemoryGiB<p.minContinueFreeMemoryGiB)reasons.push('host_memory_pressure');
 if(!r.onAcPower)reasons.push('host_power_changed');
 if(r.gpu.temperatureC>p.maxGpuTemperatureC)reasons.push('gpu_temperature_high');
 if(r.gpu.memoryTotalMiB-r.gpu.memoryUsedMiB<p.minContinueGpuFreeMiB)reasons.push('gpu_memory_pressure');
 return {allowed:reasons.length===0,reasons};
}

// The launcher is a trusted control-plane adapter. The training container never sees
// host processes, input state, kubectl credentials, or this receipt.
export function createIdleTrainingGuard({probe,launcher,clock=()=>Date.now(),wait=ms=>new Promise(resolve=>setTimeout(resolve,ms))}={}){
 if(typeof probe!=='function'||!launcher||['start','observe','stop'].some(k=>typeof launcher[k]!=='function'))throw Error('training_guard_dependencies_required');
 async function stopAndConfirm(workload,reason){
  for(let attempt=0;attempt<TRAINING_RESOURCE_POLICY.maxStopPolls;attempt++){
   // A timeout is ambiguous. Keep observing the same identity and retry only
   // its UID-preconditioned deletion, never a namespace or process-wide stop.
   try{await launcher.stop({...workload,reason});}catch{}
   try{const state=await launcher.observe(workload);if(state?.terminationConfirmed===true&&state?.state==='absent')return {state:'stopped',reason,terminationConfirmed:true,leaseRetained:state.leaseRetained===true};}catch{}
   await wait(TRAINING_RESOURCE_POLICY.checkIntervalMs);
  }
  throw Error('TRAINING_STOP_UNCONFIRMED');
 }
 return {async run(options={}){
  if(options.signal?.aborted)return {state:'cancelled',started:false,terminationConfirmed:true};
  const start=trainingStartDecision(await probe(),{now:clock()});if(!start.allowed)return {state:'blocked_host_busy',started:false,reasons:start.reasons,terminationConfirmed:true};
  if(options.signal?.aborted)return {state:'cancelled',started:false,terminationConfirmed:true};
  let workload;
  try{
   workload=await launcher.start(options);if(!workload?.uid||!workload?.name)throw Error('training_start_unconfirmed');const startedAt=clock();
   for(;;){
    if(options.signal?.aborted)return stopAndConfirm(workload,'cancelled');
    await wait(TRAINING_RESOURCE_POLICY.checkIntervalMs);
    if(options.signal?.aborted)return stopAndConfirm(workload,'cancelled');
    if(clock()-startedAt>=3600000)return stopAndConfirm(workload,'runtime_deadline');
    const decision=trainingContinueDecision(await probe(),{now:clock()});if(!decision.allowed){const stopped=await stopAndConfirm(workload,decision.reasons[0]);return {...stopped,state:'stopped_for_host_activity',reasons:decision.reasons};}
    const state=await launcher.observe(workload);
    if(state?.state==='succeeded')return stopAndConfirm(workload,'completed');
    if(state?.state==='failed')return stopAndConfirm(workload,'failed');
   }
  }catch(error){if(error.message==='TRAINING_STOP_UNCONFIRMED')throw error;workload??=error.workload;if(workload){try{const stopped=await stopAndConfirm(workload,'guard_error');error.terminationConfirmed=stopped.terminationConfirmed;error.leaseRetained=stopped.leaseRetained;}catch(cleanup){throw cleanup;}}throw error;}
  }};
}
