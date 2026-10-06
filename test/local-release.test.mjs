import test from 'node:test';
import assert from 'node:assert/strict';
import {fork,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdirSync,mkdtempSync,readFileSync,existsSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {createServer} from 'node:net';
import {randomInt} from 'node:crypto';
import {createLocalRuntime} from '../scripts/local.mjs';

const execute=promisify(execFile),host=process.env.EVIDSCOPE_TEST_HOST||'::1';
const urlHost=host==='::1'?'[::1]':host;
const directory=()=>{mkdirSync('.test-runs',{recursive:true});return mkdtempSync(resolve('.test-runs','release-local-'));};
const alive=pid=>{try{process.kill(pid,0);return true;}catch(error){if(error.code==='ESRCH')return false;throw error;}};
async function exitOf(child){
 if(child.exitCode!==null||child.signalCode!==null)return {code:child.exitCode,signal:child.signalCode};
 return new Promise((res,rej)=>{const timer=setTimeout(()=>rej(Error('Launcher termination timeout')),15000);child.once('exit',(code,signal)=>{clearTimeout(timer);res({code,signal});});});
}
async function launch(t,dir,portBase=0){
 const child=fork(resolve('scripts/local.mjs'),[],{execArgv:[],env:{...process.env,EVIDSCOPE_LOCAL_HOST:host,EVIDSCOPE_LOCAL_DIR:dir,EVIDSCOPE_LOCAL_PORT_BASE:String(portBase)},stdio:['ignore','pipe','pipe','ipc']});
 let logs='';for(const stream of [child.stdout,child.stderr])stream.on('data',bytes=>{logs=(logs+bytes).slice(-32768);});
 t.after(async()=>{if(child.exitCode===null&&child.signalCode===null){if(child.connected)child.send('shutdown');else child.kill('SIGTERM');await exitOf(child);}});
 const ready=await new Promise((res,rej)=>{const timer=setTimeout(()=>rej(Error('Launcher readiness timeout: '+logs)),45000);child.once('message',message=>{clearTimeout(timer);res(message);});child.once('exit',code=>{clearTimeout(timer);rej(Error('Launcher early exit '+code+': '+logs));});child.once('error',error=>{clearTimeout(timer);rej(error);});});
 assert.equal(ready.ready,true);assert.equal(ready.childPids.length,4);
 return {child,ready};
}
async function listen(port){const server=createServer();await new Promise((res,rej)=>{server.once('error',rej);server.listen(port,host,res);});return server;}
const close=server=>new Promise(res=>server.close(res));
async function reservePorts(){for(let attempt=0;attempt<20;attempt++){const base=randomInt(24000,49000),servers=[];try{for(let i=0;i<4;i++)servers.push(await listen(base+i));return {base,servers};}catch{await Promise.all(servers.map(close));}}throw Error('No contiguous local ports');}
async function api(url,config,path,body){const token=config.principals.find(p=>p.id==='alpha-reviewer').token;return fetch(url+path,{method:body?'POST':'GET',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:body?JSON.stringify(body):undefined});}

test('release launcher starts four real services, authenticates UI API, preserves data and confirms shutdown/restart',async t=>{
 const dir=directory(),first=await launch(t,dir),configBytes=readFileSync(join(dir,'config.json')),config=JSON.parse(configBytes);
 for(const [mode,url]of Object.entries(first.ready.endpoints)){const response=await fetch(url+'/healthz');assert.equal(response.status,200);assert.equal((await response.json()).component,mode);}
 assert.match(await (await fetch(first.ready.endpoints.audit+'/')).text(),/EvidScope/);
 let workerReady=false;for(let i=0;i<30;i++){if((await fetch(first.ready.endpoints.worker+'/readyz')).status===200){workerReady=true;break;}await new Promise(res=>setTimeout(res,100));}assert.equal(workerReady,true);
 const saved=await api(first.ready.endpoints.audit,config,'/api/governance/systems',{id:'release-persist',name:'합성 출시 재시작',owner:'검토팀',purpose:'합성 금융 검토',markets:['KR'],krRoles:[],aiBusinessOperator:false,modelId:'release-test',modelVersion:'v1'});assert.equal(saved.status,200);
 first.child.send('shutdown');assert.equal((await exitOf(first.child)).code,0);assert.ok(first.ready.childPids.every(pid=>!alive(pid)));
 const second=await launch(t,dir);assert.deepEqual(readFileSync(join(dir,'config.json')),configBytes);
 assert.ok((await (await api(second.ready.endpoints.audit,config,'/api/governance')).json()).systems.some(system=>system.id==='release-persist'));
 second.child.send('shutdown');assert.equal((await exitOf(second.child)).code,0);assert.ok(second.ready.childPids.every(pid=>!alive(pid)));
});

test('release demo CLI targets the selected directory and loopback ports; signal shutdown leaves no service children',async t=>{
 const {base,servers}=await reservePorts();await Promise.all(servers.map(close));
 const dir=directory(),runtime=await launch(t,dir,base);
 const result=await execute(process.execPath,[resolve('scripts/demo.mjs')],{env:{...process.env,EVIDSCOPE_LOCAL_HOST:host,EVIDSCOPE_LOCAL_DIR:dir,EVIDSCOPE_LOCAL_PORT_BASE:String(base)},timeout:30000,maxBuffer:128*1024});
 const demo=JSON.parse(result.stdout);assert.equal(demo.synthetic,true);assert.ok(demo.events>=10);assert.ok(demo.systems>=2);
 if(process.platform==='win32')runtime.child.send('shutdown');else runtime.child.kill('SIGINT');
 assert.equal((await exitOf(runtime.child)).code,0);assert.ok(runtime.ready.childPids.every(pid=>!alive(pid)));
});

test('release startup conflict cleans earlier services and preserves the unrelated listener',async t=>{
 const {base,servers}=await reservePorts(),occupied=servers[1];await Promise.all(servers.filter(server=>server!==occupied).map(close));t.after(()=>close(occupied));
 const runtime=createLocalRuntime({host,portBase:base,directory:directory()});t.after(()=>runtime.stop());
 await assert.rejects(runtime.start(),/ingress.*exited|ingress.*failed/);
 assert.ok(runtime.childPids.length>=2);assert.ok(runtime.childPids.every(pid=>!alive(pid)));assert.equal(occupied.listening,true);
 const recovered=await listen(base);await close(recovered);
});

test('release HTTP launcher rejects inherited TLS configuration before creating credentials or listeners',async()=>{
 const dir=directory();
 await assert.rejects(execute(process.execPath,[resolve('scripts/local.mjs')],{env:{...process.env,EVIDSCOPE_LOCAL_DIR:dir,EVIDSCOPE_LOCAL_HOST:host,TLS_CERT_FILE:join(dir,'cert.pem'),TLS_KEY_FILE:join(dir,'key.pem')},timeout:10000}),error=>error.code===1&&/Local launcher uses loopback HTTP/.test(error.stderr));
 assert.equal(existsSync(join(dir,'config.json')),false);
});
