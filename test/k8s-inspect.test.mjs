import test from 'node:test';
import assert from 'node:assert/strict';
import {summarizeCluster,inspectionCommands,collectCluster} from '../scripts/k8s-inspect.mjs';

// Every object below is synthetic. These tests never execute kubectl, create a
// cluster, or prove real Kubernetes routing, failover, isolation or autoscaling.
function fixture(){
 const namespace='evidscope',pods=['ingress','audit'].flatMap(component=>[1,2].map(i=>({metadata:{namespace,name:`${component}-${i}`,uid:`uid-${component}-${i}`,labels:{'app.kubernetes.io/name':'evidscope','app.kubernetes.io/component':component}},spec:{nodeName:`node-${i}`,containers:[{env:[{name:'TOKEN',value:'synthetic-secret-canary'}]}]},status:{phase:'Running',conditions:[{type:'Ready',status:'True'}],podIPs:[{ip:`10.0.${component==='ingress'?1:2}.${i}`}],containerStatuses:[{name:component,ready:true,restartCount:0}]}})));
 return {context:'synthetic-only',namespaceName:namespace,collectedAt:'2026-09-08T00:00:00.000Z',namespace:{kind:'Namespace',metadata:{name:namespace,uid:'namespace-uid'}},nodes:{items:[1,2].map(i=>({metadata:{name:`node-${i}`,uid:`node-uid-${i}`},status:{conditions:[{type:'Ready',status:'True'}],capacity:{cpu:'4',memory:'8Gi'},allocatable:{cpu:'3',memory:'7Gi'}}}))},pods:{items:pods},endpointSlices:{items:['ingress','audit'].map(component=>({metadata:{namespace,name:`${component}-slice`,uid:`slice-${component}`,labels:{'kubernetes.io/service-name':component}},addressType:'IPv4',endpoints:pods.filter(p=>p.metadata.labels['app.kubernetes.io/component']===component).map(p=>({addresses:p.status.podIPs.map(ip=>ip.ip),conditions:{ready:true,terminating:false},targetRef:{kind:'Pod',name:p.metadata.name,uid:p.metadata.uid,namespace},nodeName:p.spec.nodeName}))}))},hpas:{items:[{metadata:{namespace,name:'ingress',uid:'hpa-uid',generation:2},spec:{minReplicas:2,maxReplicas:6,scaleTargetRef:{kind:'Deployment',name:'ingress'}},status:{currentReplicas:3,desiredReplicas:3,observedGeneration:2,conditions:[{type:'ScalingActive',status:'True'},{type:'AbleToScale',status:'True'}],currentMetrics:[{type:'Resource',resource:{name:'cpu',current:{averageUtilization:55,averageValue:'55m'}}}]}}]}};
}

test('synthetic two-node gateway topology is linked by service label and Pod UID without asserting autoscaling',()=>{
 const source=fixture(),before=structuredClone(source),report=summarizeCluster(source);assert.deepEqual(source,before);assert.equal(report.topologyReady,true);assert.equal(report.namespace.uid,'namespace-uid');
 for(const role of ['ingress','audit']){assert.equal(report.gateways[role].readyPodCount,2);assert.equal(report.gateways[role].readyEndpointPodCount,2);assert.equal(report.gateways[role].distinctReadyEndpointNodes.length,2);}
 assert.equal(report.autoscalingOccurred,null);assert.equal(report.hpas[0].currentReplicas,3);assert.equal(report.hpas[0].metricsAvailable,true);assert.equal(report.hpas[0].autoscalingOccurred,null);
 assert.ok(!JSON.stringify(report).includes('synthetic-secret-canary'));assert.ok(!JSON.stringify(report).includes('TOKEN'));
});
test('synthetic stale, terminating, wrong-service and wrong-UID endpoints cannot count as ready topology',()=>{
 for(const mutate of [e=>e.conditions.ready=false,e=>e.conditions.terminating=true,e=>e.addresses=[],e=>e.targetRef.kind='Service',e=>e.targetRef.uid='previous-pod-uid',e=>e.targetRef.name='different-pod',e=>e.targetRef.namespace='other',e=>e.nodeName='different-node']){
  const source=fixture();mutate(source.endpointSlices.items[0].endpoints[1]);const report=summarizeCluster(source);assert.equal(report.topologyReady,false);assert.equal(report.gateways.ingress.readyEndpointPodCount,1);assert.ok(report.endpointSlices[0].endpoints[1].reasons.length);
 }
 const source=fixture();source.endpointSlices.items[0].metadata.labels['kubernetes.io/service-name']='other';assert.equal(summarizeCluster(source).gateways.ingress.readyEndpointPodCount,0);
});
test('synthetic duplicate EndpointSlices and same-node replicas do not fabricate node diversity',()=>{
 const source=fixture();source.endpointSlices.items.push(structuredClone(source.endpointSlices.items[0]));let report=summarizeCluster(source);assert.equal(report.gateways.ingress.readyEndpointPodCount,2);assert.equal(report.gateways.ingress.eligibleEndpointEntryCount,4);
 for(const pod of source.pods.items)pod.spec.nodeName='node-1';for(const slice of source.endpointSlices.items)for(const endpoint of slice.endpoints)endpoint.nodeName='node-1';report=summarizeCluster(source);assert.equal(report.topologyReady,false);assert.equal(report.gateways.ingress.distinctReadyEndpointNodes.length,1);
 source.nodes.items[0].status.conditions[0].status='False';assert.equal(summarizeCluster(source).gateways.ingress.readyEndpointPodCount,0);
});
test('synthetic Pod UID matches do not validate unrelated or partly mismatched endpoint addresses',()=>{
 for(const addresses of [['10.99.99.99'],['10.0.1.2','10.99.99.99']]){
  const source=fixture();source.endpointSlices.items[0].endpoints[1].addresses=addresses;const report=summarizeCluster(source);
  assert.equal(report.topologyReady,false);assert.equal(report.gateways.ingress.readyEndpointPodCount,1);assert.ok(report.endpointSlices[0].endpoints[1].reasons.includes('endpoint_pod_ip_mismatch'));
 }
 const missing=fixture();delete missing.pods.items[1].status.podIPs;const report=summarizeCluster(missing);assert.equal(report.topologyReady,false);assert.ok(report.endpointSlices[0].endpoints[1].reasons.includes('pod_ip_not_observed'));
 const dual=fixture(),ipv6=structuredClone(dual.endpointSlices.items[0]);ipv6.metadata.name='ingress-ipv6';ipv6.metadata.uid='ingress-ipv6-uid';ipv6.addressType='IPv6';
 for(let i=0;i<2;i++){const ip=`fd00::${i+1}`;dual.pods.items[i].status.podIPs.push({ip});ipv6.endpoints[i].addresses=[ip];}dual.endpointSlices.items.push(ipv6);
 const dualReport=summarizeCluster(dual);assert.equal(dualReport.topologyReady,true);assert.equal(dualReport.gateways.ingress.readyEndpointPodCount,2);assert.equal(dualReport.gateways.ingress.eligibleEndpointEntryCount,4);
});
test('synthetic unknown endpoint readiness still requires a live Ready Pod and correct service binding',()=>{
 const source=fixture();delete source.endpointSlices.items[0].endpoints[1].conditions.ready;assert.equal(summarizeCluster(source).topologyReady,true);
 source.pods.items[1].metadata.deletionTimestamp='2026-09-08T00:00:01Z';assert.equal(summarizeCluster(source).topologyReady,false);
 delete source.pods.items[1].metadata.deletionTimestamp;source.pods.items[1].metadata.labels['app.kubernetes.io/component']='worker';assert.equal(summarizeCluster(source).topologyReady,false);
});
test('collector command contract is read-only and pins context and timeout on every command',()=>{
 assert.throws(()=>inspectionCommands({}),/context/);assert.throws(()=>inspectionCommands({context:'x',namespace:'bad;namespace'}),/namespace/);
 const commands=inspectionCommands({context:'chosen-cluster',namespace:'evidscope',kubeconfig:'C:\\explicit path\\config'});assert.equal(commands.length,5);
 for(const {args} of commands){assert.ok(args.includes('--context=chosen-cluster'));assert.ok(args.includes('--request-timeout=10s'));assert.ok(args.includes('--kubeconfig=C:\\explicit path\\config'));assert.ok(args.includes('get'));assert.ok(!args.some(v=>['secret','secrets','config','configmap','apply','delete'].includes(v)));}
});
test('fake kubectl runner failures remain failures and neither stderr nor raw Pod env reaches the report',()=>{
 const source=fixture(),commands=inspectionCommands({context:'explicit'});let index=0;
 const report=collectCluster({context:'explicit'},(executable,args,options)=>{assert.equal(executable,'kubectl');assert.deepEqual(args,commands[index].args);assert.equal(options.windowsHide,true);assert.equal(options.shell,false);const resource=commands[index++].resource;if(resource==='endpointSlices')return {status:1,stderr:'synthetic credential must not be copied',stdout:''};return {status:0,stdout:JSON.stringify(source[resource])};});
 assert.equal(index,5);assert.equal(report.collection.complete,false);assert.equal(report.topologyReady,false);assert.equal(report.collection.failures[0].resource,'endpointSlices');assert.ok(!JSON.stringify(report).includes('synthetic credential'));assert.ok(!JSON.stringify(report).includes('synthetic-secret-canary'));
});
