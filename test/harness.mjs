import {fork} from 'node:child_process';
import {mkdirSync,mkdtempSync,readFileSync,writeFileSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import {resolve,join} from 'node:path';
import {initialize} from '../scripts/init.mjs';
import {tick} from '../src/worker.mjs';
export async function harness({vaultOnly=false}={}){
 mkdirSync('.test-runs',{recursive:true});const dir=mkdtempSync(resolve('.test-runs','run-')),config=initialize(dir),children=[],servers=[];let vault;
 const host=process.env.EVIDSCOPE_TEST_HOST||'127.0.0.1';if(!['127.0.0.1','::1'].includes(host))throw Error('Tests require numeric loopback host');const urlHost=host==='::1'?'[::1]':host;
 const env={DATA_DIR:join(dir,'data'),CONFIG_FILE:join(dir,'config.json'),SIGNING_KEY_FILE:join(dir,'signing-private.pem'),HOST:host,PORT:'0'};
 const redact=value=>{
  let text=String(value);for(const principal of config.principals)if(principal.token)text=text.split(principal.token).join('[REDACTED]');return text;
 };
 const describeError=(error,seen=new WeakSet())=>{
  if(error===null||typeof error!=='object')return redact(error);
  if(seen.has(error))return '[Circular error]';seen.add(error);
  const result={};for(const key of ['name','message','stack','code','errno','syscall','address','port'])if(error[key]!==undefined)result[key]=typeof error[key]==='string'?redact(error[key]):error[key];
  if(error.cause!==undefined)result.cause=describeError(error.cause,seen);
  if(Array.isArray(error.errors))result.errors=error.errors.map(item=>describeError(item,seen));
  return result;
 };
 const diagnose=(error,operation)=>{
  const path=join(dir,`harness-failure-${randomUUID()}.json`);
  // Allowlisted metadata only: never serialize request bodies, headers or config.
  const diagnostic={fixture:dir,occurredAt:new Date().toISOString(),operation,error:describeError(error),servers:servers.map(({mode,child,url,logs})=>({mode,url,pid:child.pid,exitCode:child.exitCode,signalCode:child.signalCode,killed:child.killed,connected:child.connected,combinedLog:redact(logs())}))};
  try{
   writeFileSync(path,JSON.stringify(diagnostic,null,2)+'\n',{flag:'wx'});
   Object.defineProperty(error,'harnessDiagnosticPath',{value:path,configurable:true});
   error.message+=`\nHarness diagnostic: ${path}`;
  }catch(writeError){
   // Diagnostic failures must not replace the original network/body error or cause.
   if(error&&typeof error==='object')try{error.message+=`\nHarness diagnostic unavailable: ${writeError.code||writeError.name}`;}catch{}
  }
 };
 async function start(mode,extra={}){
  try{return await new Promise((res,rej)=>{
   const child=fork('src/server.mjs',[],{env:{...process.env,...env,MODE:mode,...extra},stdio:['ignore','pipe','pipe','ipc']});let logs='';
   const server={mode,child,url:null,logs:()=>logs};servers.push(server);
   child.stdout.on('data',b=>logs+=b);child.stderr.on('data',b=>logs+=b);children.push(child);
   const timer=setTimeout(()=>{child.kill();rej(Error(`${mode} startup timeout: ${logs}`));},10000);
   child.once('message',m=>{clearTimeout(timer);server.url=`http://${urlHost}:${m.port}`;res({child,url:server.url,port:m.port,logs:()=>logs});});
   child.once('error',rej);child.once('exit',code=>{clearTimeout(timer);if(code)rej(Error(`${mode} exit ${code}: ${logs}`));});
  });}catch(error){diagnose(error,{operation:'startup',mode,host});throw error;}
 }
 async function close(){await Promise.all(children.map(c=>new Promise(r=>{if(c.exitCode!==null||c.signalCode!==null)return r();c.once('exit',r);if(c.connected)c.send('shutdown');else c.kill();setTimeout(()=>{c.kill();r();},2500).unref();})));}
 let ingress,audit;
 try{vault=await start('vault');if(vaultOnly){ingress=vault;audit=vault;}else{ingress=await start('ingress',{VAULT_URL:vault.url});audit=await start('audit',{VAULT_URL:vault.url});}}
 catch(error){await close();throw error;}
 const principal=(role,tenant='alpha')=>config.principals.find(p=>p.tenant===tenant&&(p.role===role||p.kind===role));
 async function api(path,{body,role='auditor',tenant='alpha',base=audit.url,headers={}}={}){
  const method=body!==undefined?'POST':'GET';let phase='fetch',status;
  try{const r=await fetch(base+path,{method,headers:{'content-type':'application/json',authorization:`Bearer ${principal(role,tenant)?.token||'invalid'}`,...headers},body:body!==undefined?JSON.stringify(body):undefined});phase='response_json';status=r.status;return {status:r.status,body:await r.json()};}
  catch(error){diagnose(error,{operation:'api',phase,method,path:redact(path),base:redact(base),role,tenant,...(status===undefined?{}:{status})});throw error;}
 }
 async function analyze(){const token=config.principals.find(p=>p.role==='worker').token;try{return {status:200,body:await tick(vault.url,token)};}catch(error){diagnose(error,{operation:'analyze',phase:'worker_tick',method:'POST',base:vault.url,role:'worker',endpointCandidates:['/internal/claim','/internal/complete']});throw error;}}
 return {dir,config,principal,api,analyze,start,ingress,audit,get vault(){return vault;},async restart(){const port=vault.port;vault.child.kill('SIGKILL');await new Promise(r=>vault.child.once('exit',r));vault=await start('vault',{PORT:String(port)});return vault;},close,publicKey:readFileSync(join(dir,'trust-anchor.pem'),'utf8')};
}
