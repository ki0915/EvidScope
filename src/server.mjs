import http from 'node:http';
import https from 'node:https';
import {readFileSync} from 'node:fs';
import {resolve,dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createService} from './service.mjs';
import {HttpError} from './model.mjs';
import {tick} from './worker.mjs';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const mode=process.env.MODE||'vault',host=process.env.HOST||'127.0.0.1',port=Number(process.env.PORT||8080);
if(!['vault','ingress','audit','worker'].includes(mode))throw Error('Unknown service mode');
const tls=process.env.TLS_CERT_FILE&&process.env.TLS_KEY_FILE?{cert:readFileSync(process.env.TLS_CERT_FILE),key:readFileSync(process.env.TLS_KEY_FILE),minVersion:'TLSv1.2'}:null;
if(!tls&&!['127.0.0.1','::1','localhost'].includes(host))throw Error('Non-loopback listeners require TLS');
const base=process.env.VAULT_URL||'http://127.0.0.1:8080';
const runtimeReceiptFile=process.env.MODEL_RUNTIME_RECEIPT_FILE;
const runtimeReceipt=()=>{if(!runtimeReceiptFile)return undefined;try{const raw=readFileSync(runtimeReceiptFile);if(raw.length>65536)throw Error();return JSON.parse(raw.toString('utf8'));}catch{return undefined;}};
const ingestPaths=new Set(['/api/ingest','/api/development-runs/events']);
const authPaths=new Set(['/auth/config','/auth/login','/auth/callback','/auth/session','/auth/logout']);
if(mode!=='vault'&&!/^https:/.test(base)&&!['127.0.0.1','localhost','[::1]'].includes(new URL(base).hostname))throw Error('Remote vault requires verified TLS');
let service;if(mode==='vault')service=createService({dataDir:process.env.DATA_DIR||join(root,'.local','data'),config:JSON.parse(readFileSync(process.env.CONFIG_FILE||join(root,'.local','config.json'),'utf8')),key:readFileSync(process.env.SIGNING_KEY_FILE||join(root,'.local','signing-private.pem'),'utf8'),requirements:JSON.parse(readFileSync(join(root,'data','requirements.json'),'utf8')),runtimeReceipt});
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
 const isAuth=authPaths.has(new URL(path,base).pathname),controller=new AbortController();const timer=setTimeout(()=>controller.abort(),isAuth?10000:6000);
 const forwarded={'content-type':'application/json',authorization:headers.authorization||'','x-evid-timestamp':headers['x-evid-timestamp']||'','x-evid-nonce':headers['x-evid-nonce']||'','x-evid-signature':headers['x-evid-signature']||'',cookie:headers.cookie||'','x-evid-csrf':headers['x-evid-csrf']||''};
 // Legacy bearer clients are checked at this gateway. Session requests also
 // carry the browser Origin to the vault's configured public-origin check.
 if(headers.origin&&(isAuth||/(?:^|;\s*)(?:__Host-)?evidscope-session=/.test(headers.cookie||'')))forwarded.origin=headers.origin;
 try{const response=await fetch(new URL(path,base),{method,headers:forwarded,body:method==='GET'?undefined:body,signal:controller.signal,redirect:'manual'});return {status:response.status,body:await response.text(),headers:isAuth?{...(response.headers.has('location')?{location:response.headers.get('location')}:{}),...(response.headers.getSetCookie().length?{'set-cookie':response.headers.getSetCookie()}:{})}:{}};}finally{clearTimeout(timer);}
}
async function route(req,res){
 for(const[k,v]of Object.entries(security))res.setHeader(k,v);res.setHeader('Content-Type','application/json; charset=utf-8');
 if(instance)res.setHeader('x-evidscope-instance',instance);
 if(stopping||active>=100){res.writeHead(503);res.end(JSON.stringify({error:'서비스가 혼잡하거나 종료 중입니다'}));return;}
 active++;
 try{
  const url=new URL(req.url,'http://localhost');
  if(req.headers.origin){const expected=mode==='vault'&&service.identity.enabled?service.identity.origin:(tls?'https':'http')+'://'+req.headers.host;if(req.headers.origin!==expected)throw new HttpError(403,'교차 출처 요청이 금지됩니다');}
  if(url.pathname==='/healthz'&&req.method==='GET'){
   if(mode==='vault')service.store.db.prepare('SELECT 1').get();
   res.end(JSON.stringify({status:'ready',component:mode}));return;
  }
  if(url.pathname==='/readyz'&&req.method==='GET'){
   const ready=await checkReadiness();res.statusCode=ready&&!stopping?200:503;res.end(JSON.stringify({status:res.statusCode===200?'ready':'not_ready',component:mode}));return;
  }
  if(mode==='audit'&&req.method==='GET'&&['/','/index.html','/app.js','/style.css','/live-graphs.js','/graphs.css','/k8s-chart-data.js','/k8s-evidence.js','/k8s-evidence.css','/team-support.js','/team-support.css','/console.js','/console.css'].includes(url.pathname)){
   const file=url.pathname==='/'?'index.html':url.pathname.slice(1);res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript; charset=utf-8':file.endsWith('.css')?'text/css; charset=utf-8':'text/html; charset=utf-8');res.end(readFileSync(join(root,'public',file)));return;
  }
  if(mode==='ingress'&&(!ingestPaths.has(url.pathname)||req.method!=='POST'))throw new HttpError(403,'수집 게이트웨이는 이벤트 제출만 허용합니다');
  if(mode==='audit'&&(!url.pathname.startsWith('/api/')&&!authPaths.has(url.pathname)||ingestPaths.has(url.pathname)))throw new HttpError(403,'감사 게이트웨이에서 허용하지 않는 경로입니다');
  if(mode==='worker')throw new HttpError(403,'worker는 외부 API를 제공하지 않습니다');
  if(!['GET','POST'].includes(req.method))throw new HttpError(405,'허용되지 않은 메서드');
  if(req.method==='POST'&&!String(req.headers['content-type']||'').startsWith('application/json'))throw new HttpError(415,'application/json 필요');
  const body=await requestBody(req,mode==='vault'&&(url.pathname==='/internal/complete'||url.pathname.endsWith('/result')&&url.pathname.startsWith('/internal/assistance/'))?1024*1024:url.pathname==='/api/governance/documents'?6*1024*1024:url.pathname==='/api/governance/bundles'?128*1024:16384);
  if(mode==='vault'){
   if(authPaths.has(url.pathname)){const output=await service.identity.http(req.method,url,req.headers);if(!output)throw new HttpError(404,'인증 경로 또는 메서드 없음');res.statusCode=output.status;for(const [name,value]of Object.entries(output.headers||{}))res.setHeader(name,value);res.end(JSON.stringify(output.body));return;}
   const output=await service.handle(req.method,url,req.headers,body);res.statusCode=ingestPaths.has(url.pathname)?202:200;res.end(JSON.stringify(output));
  }else{const output=await upstream(url.pathname+url.search,req.method,req.headers,body);res.statusCode=output.status;for(const [name,value]of Object.entries(output.headers||{}))res.setHeader(name,value);if(url.pathname==='/api/export')res.setHeader('Content-Disposition','attachment; filename="evidscope-evidence.json"');res.end(output.body);}
 }catch(error){res.statusCode=error.status||503;res.end(JSON.stringify({error:error.status?error.message:'저장소 또는 서비스 연결 실패; 접수 성공이 아닙니다'}));if(!error.status)process.stderr.write(JSON.stringify({component:mode,error:error.code||error.name})+'\n');}
 finally{active--;}
}
const server=(tls?https:http).createServer(tls||{},route);server.requestTimeout=10000;server.headersTimeout=10000;server.keepAliveTimeout=5000;server.maxHeadersCount=40;
server.listen(port,host,()=>{const address=server.address();process.stdout.write(JSON.stringify({component:mode,address:host,port:address.port,tls:!!tls})+'\n');if(process.send)process.send({ready:true,port:address.port});});
const workerTimer=mode==='worker'?setInterval(async()=>{if(workerBusy||stopping)return;workerBusy=true;try{await tick(base,process.env.WORKER_TOKEN);lastWorkerSuccess=Date.now();}catch(e){process.stderr.write(`worker unavailable ${e.name} ${e.status||''}\n`);}finally{workerBusy=false;}},200):null;
function shutdown(){if(stopping)return;stopping=true;if(workerTimer)clearInterval(workerTimer);server.close(()=>{service?.store.close();process.exit(0);});setTimeout(()=>process.exit(1),8000).unref();}
process.on('SIGTERM',shutdown);process.on('SIGINT',shutdown);process.on('message',m=>{if(m==='shutdown')shutdown();});
