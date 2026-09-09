// Network-only, unauthenticated /healthz observations. This script never reads
// identity files, Kubernetes credentials, or private keys, and never mutates APIs.
import https from 'node:https';
import {realpathSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {resolve} from 'node:path';

const timeoutMs=3000;
const preparationMs=10000,attemptsPerTarget=3,intervalMs=1000,postObservationHoldMs=30000;
const pause=ms=>new Promise(resolvePause=>setTimeout(resolvePause,ms));
const safe=value=>String(value||'').replace(/[^A-Za-z0-9._-]/g,'_').slice(0,120);
export function classifyProbe(observation,expected){
 let classification;
 if(observation.httpStatus!==null)classification='http_response';
 else if(!observation.dnsResolved)classification=['ENOTFOUND','EAI_AGAIN','EAI_FAIL'].includes(observation.errorCode)?'dns_failure':'dns_or_setup_failure';
 else if(!observation.tcpConnected&&['ETIMEDOUT','EVIDSCOPE_NETWORK_TIMEOUT'].includes(observation.errorCode))classification='connect_timeout_after_dns';
 else if(observation.tcpConnected&&observation.errorCode==='EVIDSCOPE_NETWORK_TIMEOUT')classification='post_connect_timeout';
 else if(observation.tcpConnected&&!observation.tlsAuthorized)classification='tls_or_post_connect_failure';
 else classification='connection_failure_ambiguous';
 const pass=expected==='allow'?classification==='http_response'&&observation.httpStatus===200&&observation.tlsAuthorized&&observation.healthMatches===true:expected==='deny'&&classification==='connect_timeout_after_dns';
 return {...observation,expected,classification,pass,denialObservation:classification==='connect_timeout_after_dns'?'resolved_target_not_tcp_reachable_within_deadline':'not_established',cause:classification==='connect_timeout_after_dns'?'TCP connection timed out after successful DNS resolution; consistent with a dropped network path. Correlate with NetworkPolicy and independently healthy target endpoints.':classification==='http_response'?'An HTTP response proves the network path was reachable, including 401/403/503 responses.':'DNS, TLS, rejected connection or post-connect failures do not establish the expected network drop.'};
}
export async function probeTarget(target,namespace){
 return new Promise(resolveProbe=>{
  const started=performance.now(),observation={target,url:`https://${target}.${namespace}.svc:8080/healthz`,dnsResolved:false,resolvedAddress:null,tcpConnected:false,tlsAuthorized:false,httpStatus:null,healthMatches:false,instance:null,errorCode:null};
  let done=false,timer;
  const finish=()=>{if(done)return;done=true;clearTimeout(timer);resolveProbe({...observation,elapsedMs:Math.round(performance.now()-started)});};
  const request=https.request(observation.url,{method:'GET',headers:{accept:'application/json'},agent:false,rejectUnauthorized:true},response=>{
   observation.httpStatus=response.statusCode;observation.instance=response.headers['x-evidscope-instance']?safe(response.headers['x-evidscope-instance']):null;
   const chunks=[];let size=0;
   response.on('data',chunk=>{size+=chunk.length;if(size>4096){observation.errorCode='RESPONSE_TOO_LARGE';response.destroy();finish();return;}chunks.push(chunk);});
   response.on('end',()=>{try{const body=JSON.parse(Buffer.concat(chunks).toString('utf8'));observation.healthMatches=body.status==='ready'&&body.component===target;}catch{observation.errorCode='INVALID_HEALTH_JSON';}finish();});
   response.on('error',error=>{observation.errorCode=error.code||'RESPONSE_ERROR';finish();});
  });
  request.on('socket',socket=>{
   socket.once('lookup',(error,address)=>{if(!error&&address){observation.dnsResolved=true;observation.resolvedAddress=address;}});
   socket.once('connect',()=>{observation.tcpConnected=true;});
   socket.once('secureConnect',()=>{observation.tlsAuthorized=socket.authorized===true;});
  });
  request.on('error',error=>{observation.errorCode=error.code||'REQUEST_ERROR';finish();});
  timer=setTimeout(()=>{const error=new Error('Probe network deadline');error.code='EVIDSCOPE_NETWORK_TIMEOUT';request.destroy(error);},timeoutMs);
  request.end();
 });
}
export async function runNetworkProbe({profile,namespace='evidscope',podName='',podUid='',nodeName=''}){
 if(!['collector','auditor','unlabeled'].includes(profile))throw Error('PROBE_PROFILE must be collector, auditor or unlabeled');
 if(!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(namespace))throw Error('Invalid probe namespace');
 const results=[],startedAt=new Date().toISOString();await pause(preparationMs);const observationStartedAt=new Date().toISOString();
 for(const target of ['ingress','audit','vault']){
  const expected=profile==='collector'&&target==='ingress'||profile==='auditor'&&target==='audit'?'allow':'deny';
  for(let attempt=1;attempt<=attemptsPerTarget;attempt++){
   if(attempt>1)await pause(intervalMs);
   results.push({...classifyProbe(await probeTarget(target,namespace),expected),attempt});
  }
 }
 return {format:'evidscope-k8s-network-probe-v1',startedAt,observationStartedAt,observedAt:new Date().toISOString(),profile,namespace,pod:{name:safe(podName),uid:safe(podUid),nodeName:safe(nodeName)},timeoutMs,preparationMs,attemptsPerTarget,intervalMs,postObservationHoldMs,pass:results.every(result=>result.pass),results,limitations:[
  'This probe sends only unauthenticated HTTPS GET /healthz requests, with CA and server hostname verification enabled. It does not test application authorization.',
  'A DNS failure, HTTP denial, TLS failure, connection refusal or timeout after TCP connection is not counted as a successful network-denial test.',
  'A pre-connect timeout after DNS resolution observes an unreachable TCP path, not the identity of the component that dropped it. Correlate with applied policies, independent target readiness and the paired allowed-client controls.',
  'Three observations per target follow an explicit 10-second startup preparation and 1-second inter-attempt interval. Results describe this Pod and observation window only, not every node, protocol, port or future state.',
  'After writing this report the process remains idle for 30 seconds without additional requests so an authorized external observer can capture live Pod network-policy rules and counters. Connection refusals remain unproven without that external evidence and paired allowed controls.',
  'Collector and auditor connectivity uses existing client egress policies. The probe-specific policy adds DNS only and never grants gateway or vault egress.',
 ]};
}
// Kubernetes ConfigMap volumes are symlinks; Node resolves the module's URL to
// the versioned real path, so compare the real CLI entrypoint as well.
if(process.argv[1]&&pathToFileURL(realpathSync(resolve(process.argv[1]))).href===import.meta.url){
 try{const report=await runNetworkProbe({profile:process.env.PROBE_PROFILE,namespace:process.env.PROBE_NAMESPACE||'evidscope',podName:process.env.POD_NAME,podUid:process.env.POD_UID,nodeName:process.env.NODE_NAME});process.stdout.write(JSON.stringify(report)+'\n');if(!report.pass)process.exitCode=1;await pause(postObservationHoldMs);}
 catch{process.stderr.write(JSON.stringify({format:'evidscope-k8s-network-probe-v1',pass:false,error:'invalid_configuration_or_probe_failure'})+'\n');process.exitCode=1;}
}
