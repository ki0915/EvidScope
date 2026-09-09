import test from 'node:test';
import assert from 'node:assert/strict';
import {fork,spawn,spawnSync} from 'node:child_process';
import {mkdirSync,mkdtempSync,writeFileSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {randomUUID} from 'node:crypto';
import http from 'node:http';
import {initialize} from '../scripts/init.mjs';
import {mac} from '../src/crypto.mjs';

// All CA material, credentials, evidence, and listeners belong to this synthetic test.
// Fresh child processes are essential: Node reads NODE_EXTRA_CA_CERTS at startup.
const clientProgram=`
let input='';for await(const chunk of process.stdin)input+=chunk;
const {url,options}=JSON.parse(input);
try{const r=await fetch(url,{...options,signal:AbortSignal.timeout(5000),redirect:'error'});
 console.log(JSON.stringify({status:r.status,body:await r.json()}));}
catch(e){console.log(JSON.stringify({error:e.name,code:e.cause?.code||e.code,message:e.cause?.message||e.message}));}
`;

test('실제 TLS 인증서·호스트 검증과 gateway → vault 신뢰 경계', {timeout:60000}, async t=>{
 mkdirSync('.test-runs',{recursive:true});
 const dir=mkdtempSync(resolve('.test-runs','tls-')),config=initialize(dir),children=[];
 const ca=join(dir,'ca.pem'),key=join(dir,'server.key'),cert=join(dir,'server.pem');
 const wrongCert=join(dir,'wrong-host.pem');
 const openssl=process.env.EVIDSCOPE_TEST_OPENSSL||(process.platform==='win32'?'C:\\Program Files\\Git\\usr\\bin\\openssl.exe':'openssl');
 function generate(args){const result=spawnSync(openssl,args,{encoding:'utf8',timeout:15000,windowsHide:true});assert.equal(result.error,undefined,result.error?.message);assert.equal(result.status,0,result.stderr);}
 const opensslConfig=join(dir,'openssl.cnf');
 writeFileSync(opensslConfig,'[req]\ndistinguished_name=dn\nx509_extensions=root_ca\n[dn]\n[root_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n');
 generate(['req','-config',opensslConfig,'-x509','-newkey','rsa:2048','-nodes','-sha256','-days','1','-subj','/CN=EvidScope Synthetic TLS Test CA','-keyout',join(dir,'ca.key'),'-out',ca]);
 generate(['req','-config',opensslConfig,'-new','-newkey','rsa:2048','-nodes','-sha256','-subj','/CN=localhost','-keyout',key,'-out',join(dir,'server.csr')]);
 for(const [filename,san,serial]of [[cert,'DNS:localhost,IP:127.0.0.1','10'],[wrongCert,'DNS:wrong-host.invalid','11']]){
  const ext=filename+'.ext';writeFileSync(ext,`basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=${san}\n`);
  generate(['x509','-req','-in',join(dir,'server.csr'),'-CA',ca,'-CAkey',join(dir,'ca.key'),'-set_serial',serial,'-days','1','-sha256','-extfile',ext,'-out',filename]);
  generate(['verify','-CAfile',ca,filename]);
 }
 const cleanEnv={...process.env};delete cleanEnv.NODE_TLS_REJECT_UNAUTHORIZED;delete cleanEnv.NODE_EXTRA_CA_CERTS;
 // Do not inherit runtime preloads, custom certificate trust, or TLS bypasses.
 delete cleanEnv.NODE_OPTIONS;
 t.after(async()=>{await Promise.all(children.map(child=>new Promise(resolveExit=>{
  if(child.exitCode!==null||child.signalCode!==null)return resolveExit();
  const timer=setTimeout(()=>child.kill(),3000);timer.unref();
  child.once('exit',()=>{clearTimeout(timer);resolveExit();});
  if(child.connected)child.send('shutdown');else child.kill();
 })));});
 async function start(mode,{trust=false,certificate=cert,vault}={}){
  return new Promise((resolveStart,reject)=>{
   const child=fork('src/server.mjs',[],{env:{...cleanEnv,MODE:mode,HOST:'127.0.0.1',PORT:'0',DATA_DIR:join(dir,'data'),CONFIG_FILE:join(dir,'config.json'),SIGNING_KEY_FILE:join(dir,'signing-private.pem'),TLS_CERT_FILE:certificate,TLS_KEY_FILE:key,...(trust?{NODE_EXTRA_CA_CERTS:ca}:{}),...(vault?{VAULT_URL:vault}:{})},execArgv:[],stdio:['ignore','pipe','pipe','ipc'],windowsHide:true});
   children.push(child);let logs='';child.stdout.on('data',b=>logs+=b);child.stderr.on('data',b=>logs+=b);
   const timer=setTimeout(()=>reject(Error(`${mode} TLS startup timeout: ${logs}`)),10000);
   child.once('message',m=>{if(m.ready){clearTimeout(timer);resolveStart({url:`https://127.0.0.1:${m.port}`,port:m.port});}});
   child.once('error',e=>{clearTimeout(timer);reject(e);});
   child.once('exit',code=>{clearTimeout(timer);reject(Error(`${mode} startup/exit ${code}: ${logs}`));});
  });
 }
 async function request(url,{trust=true,options={}}={}){
  return new Promise((resolveRequest,reject)=>{
   const child=spawn(process.execPath,['--input-type=module','-e',clientProgram],{env:{...cleanEnv,...(trust?{NODE_EXTRA_CA_CERTS:ca}:{})},stdio:['pipe','pipe','pipe'],windowsHide:true});
   let out='',err='';const timer=setTimeout(()=>{child.kill();reject(Error('TLS client timeout'));},8000);
   child.stdout.on('data',b=>out+=b);child.stderr.on('data',b=>err+=b);
   child.once('error',e=>{clearTimeout(timer);reject(e);});
   child.once('exit',code=>{clearTimeout(timer);try{assert.equal(code,0,err);resolveRequest(JSON.parse(out));}catch(e){reject(e);}});
   child.stdin.end(JSON.stringify({url,options}));
  });
 }
 const source=config.principals.find(p=>p.id==='alpha-agent'),auditor=config.principals.find(p=>p.id==='alpha-auditor');
 function ingest(id){const body=JSON.stringify({id,kind:'intent',actionId:'tls-action',traceId:'tls-trace',occurredAt:new Date().toISOString(),actor:'agent',tool:'tool',action:'read',resource:'synthetic'}),timestamp=String(Date.now()),nonce=randomUUID();return {method:'POST',body,headers:{'content-type':'application/json',authorization:`Bearer ${source.token}`,'x-evid-timestamp':timestamp,'x-evid-nonce':nonce,'x-evid-signature':mac(source.hmacSecret,timestamp,nonce,body)}};}
 const vault=await start('vault');
 await t.test('신뢰하지 않은 CA는 클라이언트 TLS handshake 실패',async()=>{
  const result=await request(vault.url+'/healthz',{trust:false});
  assert.ok(['UNABLE_TO_VERIFY_LEAF_SIGNATURE','UNABLE_TO_GET_ISSUER_CERT_LOCALLY','SELF_SIGNED_CERT_IN_CHAIN'].includes(result.code),JSON.stringify(result));assert.equal(result.status,undefined);
 });
 await t.test('NODE_EXTRA_CA_CERTS로 신뢰한 CA와 IP·DNS SAN은 성공',async()=>{
  for(const base of [vault.url,vault.url.replace('127.0.0.1','localhost')]){
   const result=await request(base+'/healthz');assert.equal(result.status,200,JSON.stringify(result));assert.equal(result.body.component,'vault');
  }
 });
 const wrongVault=await start('vault',{certificate:wrongCert});
 await t.test('신뢰한 CA도 SAN 불일치 서버는 거부',async()=>{
  const result=await request(wrongVault.url+'/healthz');assert.equal(result.code,'ERR_TLS_CERT_ALTNAME_INVALID');assert.equal(result.status,undefined);
 });
 const untrustedIngress=await start('ingress',{vault:vault.url}),trustedIngress=await start('ingress',{trust:true,vault:vault.url}),wrongHostIngress=await start('ingress',{trust:true,vault:wrongVault.url});
 await t.test('gateway의 vault CA 미신뢰·SAN 불일치는 503 및 미접수',async()=>{
  for(const [base,id]of [[untrustedIngress.url,'tls-untrusted'],[wrongHostIngress.url,'tls-wrong-host']]){
   const result=await request(base+'/api/ingest',{options:ingest(id)});assert.equal(result.status,503);
  }
  const stored=await request(vault.url+'/api/events',{options:{headers:{authorization:`Bearer ${auditor.token}`}}});assert.equal(stored.status,200);assert.equal(stored.body.total,0);
 });
 await t.test('신뢰한 gateway → vault는 202 반환 및 지속성 조회 확인',async()=>{
  const result=await request(trustedIngress.url+'/api/ingest',{options:ingest('tls-accepted')});assert.equal(result.status,202);
  const stored=await request(vault.url+'/api/events',{options:{headers:{authorization:`Bearer ${auditor.token}`}}});assert.equal(stored.body.total,1);assert.equal(stored.body.items[0].id,'tls-accepted');
 });
 const audit=await start('audit',{trust:true,vault:vault.url});
 await t.test('TLS에서도 source는 vault·audit·ingress 증거 조회 및 export 403',async()=>{
  for(const server of [vault,audit,trustedIngress])for(const path of ['/api/events','/api/export'])assert.equal((await request(server.url+path,{options:{headers:{authorization:`Bearer ${source.token}`}}})).status,403);
 });
 await t.test('TLS listener는 평문 HTTP로 API 응답을 제공하지 않음',async()=>{
  const result=await new Promise((resolvePlain,reject)=>{
   const req=http.get({host:'127.0.0.1',port:vault.port,path:'/healthz',timeout:3000},res=>{let body='';res.on('data',b=>body+=b);res.on('end',()=>resolvePlain({status:res.statusCode,body}));});
   req.on('timeout',()=>{req.destroy();reject(Error('Plaintext rejection timed out'));});req.on('error',e=>resolvePlain({code:e.code}));
  });
  assert.ok(result.code==='ECONNRESET'||result.status===400,JSON.stringify(result));assert.ok(!result.body?.includes('ready'));
 });
});
