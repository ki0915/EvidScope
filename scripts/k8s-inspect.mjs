import {spawnSync} from 'node:child_process';
import {mkdirSync,writeFileSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseArgs} from 'node:util';

const text=value=>typeof value==='string'?value:null;
const number=value=>Number.isFinite(value)?value:null;
const objects=value=>Array.isArray(value)?value.filter(item=>item&&typeof item==='object'):[];
const condition=(conditions,type)=>objects(conditions).find(c=>c.type===type)?.status??null;
const list=object=>objects(object?.items);
const resources=['namespace','nodes','pods','endpointSlices','hpas'];
const metadata=item=>({name:text(item?.metadata?.name),uid:text(item?.metadata?.uid),resourceVersion:text(item?.metadata?.resourceVersion)});
const metric=m=>{const observed=m.resource?.current||m.containerResource?.current||m.pods?.current||m.object?.current||m.external?.current||{};return {type:text(m.type),resource:text(m.resource?.name||m.containerResource?.name),averageUtilization:number(observed.averageUtilization),averageValue:text(observed.averageValue),value:text(observed.value)};};

// Pure summarization of supplied API responses. Synthetic unit fixtures are not
// observations of a running Kubernetes cluster. No environment, keys or commands
// are consulted here; raw Pod specs and annotations are deliberately not exported.
export function summarizeCluster(snapshot){
 const namespaceName=snapshot.namespaceName||'evidscope',failures=(snapshot.failures||[]).map(f=>({resource:f.resource,reason:f.reason,exitCode:f.exitCode??null}));
 for(const resource of resources){
  const valid=resource==='namespace'?snapshot.namespace?.kind==='Namespace'&&snapshot.namespace.metadata?.name===namespaceName&&!!snapshot.namespace.metadata?.uid:Array.isArray(snapshot[resource]?.items)&&snapshot[resource].items.every(item=>item&&typeof item==='object'&&item.metadata?.name&&item.metadata?.uid);
  if(!valid&&!failures.some(f=>f.resource===resource))failures.push({resource,reason:'missing_or_invalid_response',exitCode:null});
 }
 const nodes=list(snapshot.nodes).map(n=>({...metadata(n),ready:condition(n.status?.conditions,'Ready')==='True',capacity:{cpu:text(n.status?.capacity?.cpu),memory:text(n.status?.capacity?.memory)},allocatable:{cpu:text(n.status?.allocatable?.cpu),memory:text(n.status?.allocatable?.memory)}}));
 const nodeNames=new Set(nodes.filter(n=>n.ready&&n.name&&n.uid).map(n=>n.name));
 const pods=list(snapshot.pods).filter(p=>p.metadata?.namespace===namespaceName).map(p=>({
  ...metadata(p),namespace:namespaceName,application:text(p.metadata?.labels?.['app.kubernetes.io/name']),component:text(p.metadata?.labels?.['app.kubernetes.io/component']),
  nodeName:text(p.spec?.nodeName),phase:text(p.status?.phase),ready:condition(p.status?.conditions,'Ready')==='True'&&p.status?.phase==='Running'&&!p.metadata?.deletionTimestamp,
  terminating:!!p.metadata?.deletionTimestamp,podIPs:objects(p.status?.podIPs).map(ip=>text(ip.ip)).filter(Boolean),
  containers:objects(p.status?.containerStatuses).map(c=>({name:text(c.name),ready:c.ready===true,restarts:number(c.restartCount)})),
 }));
 const byName=new Map(pods.map(p=>[p.name,p]));
 const endpointSlices=list(snapshot.endpointSlices).filter(s=>s.metadata?.namespace===namespaceName).map(s=>({
  ...metadata(s),namespace:namespaceName,serviceName:text(s.metadata?.labels?.['kubernetes.io/service-name']),addressType:text(s.addressType),
  endpoints:objects(s.endpoints).map(e=>{
   const target=e.targetRef||{},pod=byName.get(target.name),reasons=[];
   const service=s.metadata?.labels?.['kubernetes.io/service-name'];
   if(!['ingress','audit'].includes(service))reasons.push('not_target_gateway_service');
   if(e.conditions?.ready===false)reasons.push('endpoint_not_ready');
   if(e.conditions?.terminating===true)reasons.push('endpoint_terminating');
   if(!Array.isArray(e.addresses)||!e.addresses.some(a=>typeof a==='string'&&a.length>0))reasons.push('endpoint_addresses_missing');
   if(target.kind!=='Pod'||!target.name||!target.uid)reasons.push('pod_target_identity_missing');
   if(target.namespace&&target.namespace!==namespaceName)reasons.push('target_namespace_mismatch');
   if(!pod||pod.uid!==target.uid)reasons.push('pod_name_uid_mismatch');
   if(pod&&!pod.podIPs.length)reasons.push('pod_ip_not_observed');
   if(pod&&Array.isArray(e.addresses)&&e.addresses.some(address=>typeof address!=='string'||!pod.podIPs.includes(address)))reasons.push('endpoint_pod_ip_mismatch');
   if(pod&&(pod.application!=='evidscope'||pod.component!==service))reasons.push('pod_service_label_mismatch');
   if(pod&&!pod.ready)reasons.push('pod_not_ready');
   if(pod&&!nodeNames.has(pod.nodeName))reasons.push('node_not_observed_ready');
   if(e.nodeName&&pod&&e.nodeName!==pod.nodeName)reasons.push('endpoint_node_mismatch');
   return {addresses:(Array.isArray(e.addresses)?e.addresses:[]).map(text).filter(Boolean),ready:typeof e.conditions?.ready==='boolean'?e.conditions.ready:null,terminating:e.conditions?.terminating===true,targetRef:{kind:text(target.kind),name:text(target.name),uid:text(target.uid),namespace:text(target.namespace)},podMapping:pod?{name:pod.name,uid:pod.uid,nodeName:pod.nodeName,ready:pod.ready}:null,eligible:reasons.length===0,reasons};
  }),
 }));
 const gateways={};
 for(const component of ['ingress','audit']){
  const readyPods=pods.filter(p=>p.application==='evidscope'&&p.component===component&&p.ready&&p.uid&&nodeNames.has(p.nodeName));
  const endpoints=endpointSlices.filter(s=>s.serviceName===component).flatMap(s=>s.endpoints).filter(e=>e.eligible);
  // IPv4/IPv6 EndpointSlices and repeated addresses for the same Pod never count
  // as extra replicas. Node spread is checked on the actually mapped endpoints.
  const mapped=new Map(endpoints.map(e=>[e.podMapping.uid,e.podMapping]));
  const endpointNodes=[...new Set([...mapped.values()].map(p=>p.nodeName))].sort();
  gateways[component]={readyPodCount:readyPods.length,readyEndpointPodCount:mapped.size,eligibleEndpointEntryCount:endpoints.length,readyPods:readyPods.map(p=>({name:p.name,uid:p.uid,nodeName:p.nodeName})),endpointPods:[...mapped.values()],distinctReadyEndpointNodes:endpointNodes,topologyReady:readyPods.length>=2&&mapped.size>=2&&endpointNodes.length>=2};
 }
 const hpas=list(snapshot.hpas).filter(h=>h.metadata?.namespace===namespaceName).map(h=>{const metrics=objects(h.status?.currentMetrics).map(metric);return {...metadata(h),namespace:namespaceName,target:{kind:text(h.spec?.scaleTargetRef?.kind),name:text(h.spec?.scaleTargetRef?.name)},currentReplicas:number(h.status?.currentReplicas),desiredReplicas:number(h.status?.desiredReplicas),minReplicas:number(h.spec?.minReplicas),maxReplicas:number(h.spec?.maxReplicas),observedGeneration:number(h.status?.observedGeneration),generation:number(h.metadata?.generation),lastScaleTime:text(h.status?.lastScaleTime),scalingActive:condition(h.status?.conditions,'ScalingActive')==='True',ableToScale:condition(h.status?.conditions,'AbleToScale')==='True',metricsAvailable:metrics.some(m=>m.averageUtilization!==null||m.averageValue!==null||m.value!==null),metrics,autoscalingOccurred:null};});
 return {format:'evidscope-k8s-inspection-v1',collectedAt:snapshot.collectedAt??null,collectionEndedAt:snapshot.collectionEndedAt??null,context:snapshot.context??null,namespace:{name:namespaceName,uid:text(snapshot.namespace?.metadata?.uid),resourceVersion:text(snapshot.namespace?.metadata?.resourceVersion)},collection:{complete:failures.length===0,failures,resourceVersions:Object.fromEntries(resources.map(name=>[name,text(snapshot[name]?.metadata?.resourceVersion)]))},nodes,pods,endpointSlices,gateways,hpas,topologyReady:failures.length===0&&Object.values(gateways).every(g=>g.topologyReady),autoscalingOccurred:null,limitations:[
  'This is a read-only Kubernetes API observation, not a load-balancing, network isolation, recovery or autoscaling experiment.',
  'Requests are sequential and not an atomic cross-resource snapshot. Namespace UID, Pod UID and resource versions identify the observed state.',
  'Eligible endpoints match service label and live Pod name/UID, every EndpointSlice address matches an observed Pod.status.podIPs address, and Pod readiness and observed Ready nodes are required. Missing endpoint ready is treated as unknown/eligible by Kubernetes convention; Pod readiness is still required.',
  'Two ready endpoint Pods on two nodes establish observed gateway topology only. Self-reported HTTP instance headers must be correlated with this evidence and a real traffic probe.',
  'HPA replica counts, lastScaleTime and current metrics alone do not establish a measured scale-out or scale-in event. autoscalingOccurred remains null.',
  'Pod environment values, volumes, Secret references, annotations, kubeconfig contents and kubectl error output are not included.',
 ]};
}

export function inspectionCommands({context,namespace='evidscope',kubeconfig}){
 if(typeof context!=='string'||!context.trim()||/[\r\n\0]/.test(context))throw Error('--context is required and must be explicit');
 if(!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(namespace))throw Error('Invalid namespace');
 if(kubeconfig!==undefined&&(typeof kubeconfig!=='string'||!kubeconfig||/[\r\n\0]/.test(kubeconfig)))throw Error('Invalid --kubeconfig path');
 const common=[`--context=${context}`,'--request-timeout=10s',...(kubeconfig?[`--kubeconfig=${kubeconfig}`]:[])];
 return [
  {resource:'namespace',args:[...common,'get','namespace',namespace,'-o','json']},
  {resource:'nodes',args:[...common,'get','nodes','-o','json']},
  ...[['pods','pods'],['endpointSlices','endpointslices.discovery.k8s.io'],['hpas','hpa']].map(([resource,kind])=>({resource,args:[...common,'-n',namespace,'get',kind,'-o','json']})),
 ];
}
export function collectCluster(options,run=spawnSync){
 const snapshot={context:options.context,namespaceName:options.namespace||'evidscope',collectedAt:new Date().toISOString(),failures:[]};
 for(const command of inspectionCommands(options)){
  let result;
  try{result=run('kubectl',command.args,{encoding:'utf8',shell:false,windowsHide:true,timeout:12000,maxBuffer:16*1024*1024,stdio:['ignore','pipe','pipe']});}
  catch{snapshot.failures.push({resource:command.resource,reason:'kubectl_unavailable',exitCode:null});continue;}
  if(result.error||result.status!==0){snapshot.failures.push({resource:command.resource,reason:result.error?'kubectl_execution_failed':'kubectl_nonzero_exit',exitCode:result.status??null});continue;}
  try{snapshot[command.resource]=JSON.parse(result.stdout);}catch{snapshot.failures.push({resource:command.resource,reason:'invalid_json_response',exitCode:0});}
 }
 snapshot.collectionEndedAt=new Date().toISOString();return summarizeCluster(snapshot);
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  const {values}=parseArgs({options:{context:{type:'string'},out:{type:'string'},kubeconfig:{type:'string'},namespace:{type:'string',default:'evidscope'}},strict:true,allowPositionals:false});
  if(!values.out||!values.out.trim())throw Error('--out is required');
  const commands=inspectionCommands(values);if(commands.length!==5)throw Error('Unexpected collector command set');
  const output=resolve(values.out),report=collectCluster(values);mkdirSync(dirname(output),{recursive:true});writeFileSync(output,JSON.stringify(report,null,2)+'\n',{mode:0o600});
  process.stdout.write(JSON.stringify({output,collectionComplete:report.collection.complete,topologyReady:report.topologyReady,autoscalingOccurred:null})+'\n');
  if(!report.collection.complete||!report.topologyReady)process.exitCode=1;
 }catch(error){process.stderr.write(JSON.stringify({error:error.message})+'\n');process.exitCode=1;}
}
