import http from 'node:http';
import https from 'node:https';
import {readFileSync} from 'node:fs';
import {resolve,dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createService} from './service.mjs';
import {HttpError,isRawResponse} from './model.mjs';
import {tick} from './worker.mjs';
import {dataKeysFromEnv} from './data-keys.mjs';
import {createOtlpHttp,localForwarder,remoteForwarder,otlpLimits,OTLP_TRACES_PATH} from './otlp-http.mjs';
import {prepareTransparency} from './transparency.mjs';
import {ingestBatchOptions} from './ingest-batch.mjs';
import {upstreamRequest} from './upstream-http.mjs';
import {createForwardCoalescer,forwardedIngest,INGEST_FORWARD_HEADER,INGEST_FORWARD_MAX_BYTES,INGEST_FORWARD_PATH} from './ingest-forward.mjs';
import {ENFORCEMENT_PREFIX,STATUS_MAX_BYTES,STATUS_PATH} from './enforcement-service.mjs';
import {FACTSHEETS_PATH,FACTSHEET_MAX_BYTES} from './governance-model-service.mjs';
import {vaultRouter,vaultTenants} from './vault-tenants.mjs';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const mode=process.env.MODE||'vault',host=process.env.HOST||'127.0.0.1',port=Number(process.env.PORT||8080);
if(!['vault','ingress','audit','worker'].includes(mode))throw Error('Unknown service mode');
const tls=process.env.TLS_CERT_FILE&&process.env.TLS_KEY_FILE?{cert:readFileSync(process.env.TLS_CERT_FILE),key:readFileSync(process.env.TLS_KEY_FILE),minVersion:'TLSv1.2'}:null;
if(!tls&&!['127.0.0.1','::1','localhost'].includes(host))throw Error('Non-loopback listeners require TLS');
const base=process.env.VAULT_URL||'http://127.0.0.1:8080';
const runtimeReceiptFile=process.env.MODEL_RUNTIME_RECEIPT_FILE;
const runtimeReceipt=()=>{if(!runtimeReceiptFile)return undefined;try{const raw=readFileSync(runtimeReceiptFile);if(raw.length>65536)throw Error();return JSON.parse(raw.toString('utf8'));}catch{return undefined;}};
const ingestPaths=new Set(['/api/ingest','/api/development-runs/events']);
// Enforcement points open approval requests and poll for answers through the ingestion gateway (docs/approval-queue.md).
const enforcementPaths=new Set(['/api/approvals/requests','/api/approvals/token']);
const authPaths=new Set(['/auth/config','/auth/login','/auth/callback','/auth/session','/auth/logout']);
// Enforcement points pull bundles and deny-lists and post OPA status through the ingress gateway or the vault (docs/kill-switch.md).
const enforcementRoute=(method,pathname)=>pathname.startsWith(ENFORCEMENT_PREFIX)&&(method==='GET'&&pathname!==ENFORCEMENT_PREFIX||method==='POST'&&STATUS_PATH.test(pathname));
// Optional OPA bundle signing key (RSA or P-256 PEM) and the key id OPA's verification config names.
const bundleSigning=process.env.OPA_BUNDLE_SIGNING_KEY_FILE?{key:readFileSync(process.env.OPA_BUNDLE_SIGNING_KEY_FILE,'utf8'),keyId:process.env.OPA_BUNDLE_SIGNING_KEY_ID||'evidscope'}:undefined;
if(mode!=='vault'&&!/^https:/.test(base)&&!['127.0.0.1','localhost','[::1]'].includes(new URL(base).hostname))throw Error('Remote vault requires verified TLS');
// Tenant shards (src/vault-tenants.mjs): gateways send each credential's requests to the vault of its tenant (VAULT_ROUTES_FILE).
const vaultFor=mode==='vault'?()=>base:vaultRouter(process.env.VAULT_ROUTES_FILE,base,{allowed:url=>url.protocol==='https:'
 ||url.protocol==='http:'&&['127.0.0.1','localhost','[::1]'].includes(url.hostname)});
const routedForwarder=()=>{const forwarders=new Map();return (authorization,body)=>{const vault=vaultFor(authorization);
 if(!forwarders.has(vault))forwarders.set(vault,remoteForwarder(vault,{timeoutMs:otlpHttpLimits.forwardTimeoutMs}));return forwarders.get(vault)(authorization,body);};};
// Async witness probe before createService, which stays synchronous and re-checks the pin before opening Store.
const transparency=mode==='vault'?await prepareTransparency({dataDir:process.env.DATA_DIR||join(root,'.local','data'),key:readFileSync(process.env.SIGNING_KEY_FILE||join(root,'.local','signing-private.pem'),'utf8')}):undefined;
// Optional access-log sealing knobs (milliseconds / entry count); defaults live in src/access-log.mjs.
const accessLogEnv=Object.fromEntries([['sealIntervalMs','ACCESS_LOG_SEAL_INTERVAL_MS'],['sealThreshold','ACCESS_LOG_SEAL_THRESHOLD'],['maxUnsealedAgeMs','ACCESS_LOG_MAX_UNSEALED_AGE_MS']]
 .filter(([,name])=>process.env[name]).map(([option,name])=>{const value=Number(process.env[name]);if(!Number.isSafeInteger(value)||value<1)throw Error('Invalid '+name);return [option,value];}));
// Scheduled retention rotation (docs/retention-rotation.md): off unless an interval is set, and a tenant still needs a rotation
// policy that two people activated before anything is erased.
const rotationIntervalMs=process.env.RETENTION_ROTATION_INTERVAL_MS?Number(process.env.RETENTION_ROTATION_INTERVAL_MS):0;
if(!Number.isSafeInteger(rotationIntervalMs)||rotationIntervalMs<0||rotationIntervalMs>0&&rotationIntervalMs<1000)throw Error('Invalid RETENTION_ROTATION_INTERVAL_MS');
// Optional links to the same trace in Langfuse or Phoenix (src/trace-links.mjs): a JSON array kept outside config.json, so changing
// it never needs a signed config rebinding after a restoration.
const traceLinks=mode==='vault'&&process.env.TRACE_LINKS_FILE?JSON.parse(readFileSync(process.env.TRACE_LINKS_FILE,'utf8')):undefined;
let service;if(mode==='vault')service=createService({transparency,accessLog:accessLogEnv,retentionRotation:{intervalMs:rotationIntervalMs},traceLinks,dataDir:process.env.DATA_DIR||join(root,'.local','data'),config:JSON.parse(readFileSync(process.env.CONFIG_FILE||join(root,'.local','config.json'),'utf8')),key:readFileSync(process.env.SIGNING_KEY_FILE||join(root,'.local','signing-private.pem'),'utf8'),...dataKeysFromEnv(process.env),eventKeystoreDir:process.env.EVENT_KEYSTORE_DIR||undefined,bundleSigning,ingestBatch:ingestBatchOptions(),tenants:vaultTenants(),tenantRegistryDir:process.env.VAULT_TENANT_REGISTRY_DIR||undefined,requirements:JSON.parse(readFileSync(join(root,'data','requirements.json'),'utf8')),runtimeReceipt});
const otlpHttpLimits=otlpLimits(),otlp=mode==='vault'||mode==='ingress'?createOtlpHttp({limits:otlpHttpLimits,forward:mode==='vault'?localForwarder(service):routedForwarder(),log:e=>process.stderr.write(JSON.stringify(e)+'\n')}):null;
const security={'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Cache-Control':'no-store','X-Frame-Options':'DENY'};
// A public, sanitized serving-instance label, never a credential or upstream label.
const instance=(process.env.POD_NAME||'').replace(/[^a-zA-Z0-9._-]/g,'_').slice(0,120);
let active=0,stopping=false,lastWorkerSuccess=0,workerBusy=false;
let readinessFlight=null,readinessCache=null;
async function checkReadiness(){
 if(stopping)return false;
 if(mode==='vault'){try{service.store.db.prepare('SELECT 1').get();return true;}catch{return false;}}
 if(mode==='worker')return lastWorkerSuccess>0&&Date.now()-lastWorkerSuccess<=30000;
 if(readinessCache&&Date.now()-readinessCache.at<500)return readinessCache.ready;
 if(!readinessFlight)readinessFlight=(async()=>{
  let ready=false;
  try{
   const response=await fetch(new URL('/healthz',base),{method:'GET',headers:{accept:'application/json'},signal:AbortSignal.timeout(1500),redirect:'error'});
   if(response.status===200){
    const chunks=[];let size=0;
    for await(const chunk of response.body){if((size+=chunk.length)>4096)throw Error('Readiness response too large');chunks.push(chunk);}
    const result=JSON.parse(Buffer.concat(chunks).toString('utf8'));ready=result.status==='ready'&&result.component==='vault';
   }else await response.body?.cancel();
  }catch{ready=false;}
  readinessCache={ready,at:Date.now()};return ready;
 })().finally(()=>{readinessFlight=null;});
 return readinessFlight;
}
async function requestBody(req,limit=16384){let size=0;const parts=[];for await(const chunk of req){size+=chunk.length;if(size>limit)throw new HttpError(413,`요청 크기 한도 ${limit} bytes 초과`);parts.push(chunk);}return Buffer.concat(parts).toString('utf8');}
async function upstream(path,method,headers,body){
 const vault=vaultFor(headers.authorization),isAuth=authPaths.has(new URL(path,vault).pathname);
 const forwarded={'content-type':'application/json',authorization:headers.authorization||'','x-evid-timestamp':headers['x-evid-timestamp']||'','x-evid-nonce':headers['x-evid-nonce']||'','x-evid-signature':headers['x-evid-signature']||'',cookie:headers.cookie||'','x-evid-csrf':headers['x-evid-csrf']||''};
 // Legacy bearer clients are checked at this gateway. Session requests also
 // carry the browser Origin to the vault's configured public-origin check.
 if(headers.origin&&(isAuth||/(?:^|;\s*)(?:__Host-)?evidscope-session=/.test(headers.cookie||'')))forwarded.origin=headers.origin;
 // node:http keep-alive rather than fetch (src/upstream-http.mjs); redirects come back as they are, as with redirect:'manual'.
 const response=await upstreamRequest(new URL(path,vault),{method,headers:forwarded,body:method==='GET'?undefined:body,timeoutMs:isAuth?10000:6000}),cookies=response.headers['set-cookie']||[];
 return {status:response.status,body:response.body.toString('utf8'),headers:isAuth?{...(response.headers.location!==undefined?{location:response.headers.location}:{}),...(cookies.length?{'set-cookie':cookies}:{})}:{}};
}
// Source events through the ingress gateway go up in envelopes (src/ingest-forward.mjs); INGRESS_FORWARD_MAX_EVENTS=1 sends each
// event in its own call as before.
const forwardMaxEvents=Number(process.env.INGRESS_FORWARD_MAX_EVENTS||64);
if(!Number.isSafeInteger(forwardMaxEvents)||forwardMaxEvents<1||forwardMaxEvents>64)throw Error('Invalid INGRESS_FORWARD_MAX_EVENTS');
const forwarder=mode==='ingress'&&forwardMaxEvents>1?createForwardCoalescer({maxEvents:forwardMaxEvents,
 send:(authorization,text)=>upstreamRequest(new URL(INGEST_FORWARD_PATH,vaultFor(authorization)),{method:'POST',headers:{'content-type':'application/json',authorization},body:text,timeoutMs:6000}),
 single:(headers,body)=>upstream('/api/ingest','POST',headers,body)}):null;
// Binary-safe pass-through for enforcement points at the ingress gateway: bearer token, If-None-Match and the JSON body go up;
// status, ETag, Content-Type and the (bounded) bytes come back, so a bundle's gzip bytes and a 304 arrive unchanged.
async function enforcementUpstream(path,method,headers,body){
 const forwarded={authorization:headers.authorization||'',...(headers['if-none-match']?{'if-none-match':headers['if-none-match']}:{}),...(method==='POST'?{'content-type':'application/json'}:{})};
 let response;
 try{response=await fetch(new URL(path,vaultFor(headers.authorization)),{method,headers:forwarded,body:method==='GET'?undefined:body,signal:AbortSignal.timeout(6000),redirect:'manual'});}
 catch{throw new HttpError(503,'vault 연결 실패');}
 const chunks=[];let size=0;
 for await(const chunk of response.body||[]){if((size+=chunk.length)>16*1024*1024)throw new HttpError(503,'vault 응답 한도 초과');chunks.push(chunk);}
 const out={};for(const name of ['etag','content-type'])if(response.headers.has(name))out[name]=response.headers.get(name);
 return {status:response.status,headers:out,body:Buffer.concat(chunks)};
}
// Large uploads through the audit gateway are authorized by the vault before the gateway buffers them (S12a).
async function preauthorizeUpstream(path,headers){
 const output=await upstream('/internal/preauthorize','POST',headers,JSON.stringify({path}));if(output.status===200)return;
 let message='인증이 필요합니다';try{message=JSON.parse(output.body).error||message;}catch{}throw new HttpError(output.status,message);
}
async function route(req,res){
 for(const[k,v]of Object.entries(security))res.setHeader(k,v);res.setHeader('Content-Type','application/json; charset=utf-8');
 if(instance)res.setHeader('x-evidscope-instance',instance);
 if(stopping||active>=100){if(otlp&&new URL(req.url,'http://localhost').pathname===OTLP_TRACES_PATH)return otlp.unavailable(req,res);res.writeHead(503);res.end(JSON.stringify({error:'서비스가 혼잡하거나 종료 중입니다'}));return;}
 active++;
 try{
  const url=new URL(req.url,'http://localhost');
  if(mode==='vault'&&url.pathname===INGEST_FORWARD_PATH)res.setHeader(INGEST_FORWARD_HEADER,'1');
  if(otlp&&url.pathname===OTLP_TRACES_PATH){await otlp.handle(req,res,{originAllowed:origin=>origin===(mode==='vault'&&service.identity.enabled?service.identity.origin:(tls?'https':'http')+'://'+req.headers.host)});return;}
  if(req.headers.origin){const expected=mode==='vault'&&service.identity.enabled?service.identity.origin:(tls?'https':'http')+'://'+req.headers.host;if(req.headers.origin!==expected)throw new HttpError(403,'교차 출처 요청이 금지됩니다');}
  if(url.pathname==='/healthz'&&req.method==='GET'){
   if(mode==='vault')service.store.db.prepare('SELECT 1').get();
   res.end(JSON.stringify({status:'ready',component:mode}));return;
  }
  if(url.pathname==='/readyz'&&req.method==='GET'){
   const ready=await checkReadiness();res.statusCode=ready&&!stopping?200:503;res.end(JSON.stringify({status:res.statusCode===200?'ready':'not_ready',component:mode}));return;
  }
  if(mode==='audit'&&req.method==='GET'&&['/','/index.html','/app.js','/style.css','/live-graphs.js','/graphs.css','/k8s-chart-data.js','/k8s-evidence.js',
   '/k8s-evidence.css','/team-support.js','/team-support.css','/console.js','/console.css','/registry.js','/approvals.js','/home.js',
   '/governance-model.js','/theme-dark-base.css','/theme-dark.css','/ops.css','/ops.js'].includes(url.pathname)){
   const file=url.pathname==='/'?'index.html':url.pathname.slice(1);res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript; charset=utf-8':file.endsWith('.css')?'text/css; charset=utf-8':'text/html; charset=utf-8');res.end(readFileSync(join(root,'public',file)));return;
  }
  const enforcementPath=enforcementRoute(req.method,url.pathname);
  if(mode==='ingress'&&!enforcementPath&&(!ingestPaths.has(url.pathname)&&!enforcementPaths.has(url.pathname)||req.method!=='POST'))throw new HttpError(403,'수집 게이트웨이는 이벤트 제출만 허용합니다');
  if(mode==='audit'&&url.pathname.startsWith(ENFORCEMENT_PREFIX))throw new HttpError(403,'집행 지점 경로는 수집 게이트웨이에서 제공합니다');
  if(mode==='audit'&&(!url.pathname.startsWith('/api/')&&!authPaths.has(url.pathname)||ingestPaths.has(url.pathname)||enforcementPaths.has(url.pathname)||url.pathname==='/api/ingest/otlp'))throw new HttpError(403,'감사 게이트웨이에서 허용하지 않는 경로입니다');
  if(mode==='worker')throw new HttpError(403,'worker는 외부 API를 제공하지 않습니다');
  if(!['GET','POST'].includes(req.method))throw new HttpError(405,'허용되지 않은 메서드');
  if(req.method==='POST'&&!String(req.headers['content-type']||'').startsWith('application/json'))throw new HttpError(415,'application/json 필요');
  const largeBody=url.pathname==='/api/governance/documents'||url.pathname==='/api/ingest/otlp',post=req.method==='POST';
  const vaultResult=mode==='vault'&&(url.pathname==='/internal/complete'||url.pathname.endsWith('/result')&&url.pathname.startsWith('/internal/assistance/'));
  // Catalog import (docs/agent-registry.md): up to 20 documents of 256 KiB each, bounded again per document by the importer.
  const limit=!post?16384:vaultResult?1024*1024:largeBody?6*1024*1024:url.pathname==='/api/governance/bundles'?128*1024
   :url.pathname==='/api/registry/import'?2*1024*1024
   :url.pathname===FACTSHEETS_PATH?FACTSHEET_MAX_BYTES
   :mode==='vault'&&url.pathname===INGEST_FORWARD_PATH?INGEST_FORWARD_MAX_BYTES
   :STATUS_PATH.test(url.pathname)?STATUS_MAX_BYTES:16384;
  // Credentials and role are checked before anything above the 16 KiB default is buffered (S12a).
  if(limit>16384){if(mode==='vault')service.preauthorize(req.method,url,req.headers);else await preauthorizeUpstream(url.pathname,req.headers);}
  const body=await requestBody(req,limit);
  if(mode==='vault'){
   if(authPaths.has(url.pathname)){const output=await service.identity.http(req.method,url,req.headers);if(!output)throw new HttpError(404,'인증 경로 또는 메서드 없음');res.statusCode=output.status;for(const [name,value]of Object.entries(output.headers||{}))res.setHeader(name,value);res.end(JSON.stringify(output.body));return;}
   if(url.pathname===INGEST_FORWARD_PATH&&req.method==='POST'){
    // Each item counts toward the concurrency bound, as the requests it replaces did.
    let admitted=0;
    try{
     const output=await forwardedIngest((headers,text)=>service.handle('POST',new URL('/api/ingest','http://localhost'),headers,text),req.headers,body,{
      admit:n=>{if(active-1+n>100)throw new HttpError(503,'서비스가 혼잡하거나 종료 중입니다');admitted=n-1;active+=admitted;},
      log:error=>process.stderr.write(JSON.stringify({component:mode,error:error?.code||error?.name})+'\n')});
     res.statusCode=200;res.end(JSON.stringify(output));return;
    }finally{active-=admitted;}
   }
   const output=await service.handle(req.method,url,req.headers,body);
   if(isRawResponse(output)){res.statusCode=output.status;for(const [name,value] of Object.entries(output.headers))res.setHeader(name,value);res.end(output.body);return;}
   res.statusCode=ingestPaths.has(url.pathname)?202:200;res.end(JSON.stringify(output));
  }else if(mode==='ingress'&&enforcementPath){
   const output=await enforcementUpstream(url.pathname,req.method,req.headers,body);res.statusCode=output.status;
   for(const [name,value] of Object.entries(output.headers))res.setHeader(name,value);res.end(output.body);
  }else{const output=forwarder&&url.pathname==='/api/ingest'?await forwarder.forward(req.headers,body):await upstream(url.pathname+url.search,req.method,req.headers,body);res.statusCode=output.status;for(const [name,value]of Object.entries(output.headers||{}))res.setHeader(name,value);if(url.pathname==='/api/export')res.setHeader('Content-Disposition',`attachment; filename="evidscope-evidence${url.searchParams.has('attest')?'-attested':''}.json"`);res.end(output.body);}
 }catch(caught){
  const error=caught instanceof URIError?new HttpError(400,'경로의 퍼센트 인코딩 형식 오류'):caught;
  res.statusCode=error.status||503;res.end(JSON.stringify({error:error.status?error.message:'저장소 또는 서비스 연결 실패; 접수 성공이 아닙니다',...(error.status&&error.details||{})}));if(!error.status)process.stderr.write(JSON.stringify({component:mode,error:error.code||error.name})+'\n');}
 finally{active--;}
}
const server=(tls?https:http).createServer(tls||{},route);server.requestTimeout=10000;server.headersTimeout=10000;server.keepAliveTimeout=5000;server.maxHeadersCount=40;
server.listen(port,host,()=>{service?.transparency.start();service?.accessLog.start();service?.retention.rotation.start();
 const address=server.address();process.stdout.write(JSON.stringify({component:mode,address:host,port:address.port,tls:!!tls})+'\n');if(process.send)process.send({ready:true,port:address.port});});
const workerTimer=mode==='worker'?setInterval(async()=>{if(workerBusy||stopping)return;workerBusy=true;
 try{const result=await tick(base,process.env.WORKER_TOKEN);lastWorkerSuccess=Date.now();
  // Results the vault's own recomputation rejected (S6), e.g. a worker on another engine version.
  if(result.rejected)process.stderr.write(JSON.stringify({component:'worker',rejectedResults:result.rejected})+'\n');}
 catch(e){process.stderr.write(`worker unavailable ${e.name} ${e.status||''}\n`);}finally{workerBusy=false;}},200):null;
function shutdown(){if(stopping)return;stopping=true;if(workerTimer)clearInterval(workerTimer);service?.retention.rotation.stop();const transparencyStopped=service?.transparency.stop();
 server.close(async()=>{await transparencyStopped;try{service?.accessLog.stop();}catch{}service?.store.close();process.exit(0);});setTimeout(()=>process.exit(1),8000).unref();}
process.on('SIGTERM',shutdown);process.on('SIGINT',shutdown);process.on('message',m=>{if(m==='shutdown')shutdown();});
