import {fork} from 'node:child_process';
import {mkdirSync,mkdtempSync,readFileSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {initialize} from '../scripts/init.mjs';
import {tick} from '../src/worker.mjs';
export async function harness({vaultOnly=false}={}){
 mkdirSync('.test-runs',{recursive:true});const dir=mkdtempSync(resolve('.test-runs','run-')),config=initialize(dir),children=[];let vault;
 const env={DATA_DIR:join(dir,'data'),CONFIG_FILE:join(dir,'config.json'),SIGNING_KEY_FILE:join(dir,'signing-private.pem'),HOST:'127.0.0.1',PORT:'0'};
 async function start(mode,extra={}){return new Promise((res,rej)=>{const child=fork('src/server.mjs',[],{env:{...process.env,...env,MODE:mode,...extra},stdio:['ignore','pipe','pipe','ipc']});let logs='';child.stdout.on('data',b=>logs+=b);child.stderr.on('data',b=>logs+=b);children.push(child);const timer=setTimeout(()=>{child.kill();rej(Error(`${mode} startup timeout: ${logs}`));},10000);child.once('message',m=>{clearTimeout(timer);res({child,url:`http://127.0.0.1:${m.port}`,port:m.port,logs:()=>logs});});child.once('error',rej);child.once('exit',code=>{clearTimeout(timer);if(code)rej(Error(`${mode} exit ${code}: ${logs}`));});});}
 async function close(){await Promise.all(children.map(c=>new Promise(r=>{if(c.exitCode!==null||c.signalCode!==null)return r();c.once('exit',r);if(c.connected)c.send('shutdown');else c.kill();setTimeout(()=>{c.kill();r();},2500).unref();})));}
 let ingress,audit;
 try{vault=await start('vault');if(vaultOnly){ingress=vault;audit=vault;}else{ingress=await start('ingress',{VAULT_URL:vault.url});audit=await start('audit',{VAULT_URL:vault.url});}}
 catch(error){await close();throw error;}
 const principal=(role,tenant='alpha')=>config.principals.find(p=>p.tenant===tenant&&(p.role===role||p.kind===role));
 async function api(path,{body,role='auditor',tenant='alpha',base=audit.url,headers={}}={}){const r=await fetch(base+path,{method:body!==undefined?'POST':'GET',headers:{'content-type':'application/json',authorization:`Bearer ${principal(role,tenant)?.token||'invalid'}`,...headers},body:body!==undefined?JSON.stringify(body):undefined});return {status:r.status,body:await r.json()};}
 async function analyze(){const token=config.principals.find(p=>p.role==='worker').token;return {status:200,body:await tick(vault.url,token)};}
 return {dir,config,principal,api,analyze,start,ingress,audit,get vault(){return vault;},async restart(){const port=vault.port;vault.child.kill('SIGKILL');await new Promise(r=>vault.child.once('exit',r));vault=await start('vault',{PORT:String(port)});return vault;},close,publicKey:readFileSync(join(dir,'trust-anchor.pem'),'utf8')};
}
