import {mkdirSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fork} from 'node:child_process';
import {initialize} from './init.mjs';
import {demo} from './demo.mjs';
import {submit} from '../src/client.mjs';
const dir=resolve('.test-runs/ui');mkdirSync(dir,{recursive:true});const config=initialize(dir);for(const role of ['auditor','reviewer','admin'])config.principals.find(p=>p.id==='alpha-'+role).token=`evidscope-ui-synthetic-${role}-only-20260908`;writeFileSync(dir+'/config.json',JSON.stringify(config));
const children=[];for(const[mode,port]of [['vault',9080],['ingress',9081],['audit',9082],['worker',9083]])await new Promise((res,rej)=>{const c=fork('src/server.mjs',[],{env:{...process.env,MODE:mode,PORT:String(port),HOST:'127.0.0.1',DATA_DIR:dir+'/data',CONFIG_FILE:dir+'/config.json',SIGNING_KEY_FILE:dir+'/signing-private.pem',VAULT_URL:'http://127.0.0.1:9080',WORKER_TOKEN:config.principals.find(p=>p.role==='worker').token},stdio:['ignore','inherit','inherit','ipc']});children.push(c);c.once('message',res);c.once('error',rej);});
if(!process.argv.includes('--reuse')) {
console.log(await demo({config,ingress:'http://127.0.0.1:9081',audit:'http://127.0.0.1:9082'}));
await fetch('http://127.0.0.1:9082/api/retention/policy',{method:'POST',headers:{authorization:'Bearer '+config.principals.find(p=>p.id==='alpha-reviewer').token,'content-type':'application/json'},body:JSON.stringify({retentionSeconds:1,purpose:'합성 UI 보존 시험',reason:'실제 개인정보 없는 1초 시험'})});
await submit('http://127.0.0.1:9081',config.principals.find(p=>p.id==='alpha-agent'),{id:'ui-retention-'+Date.now(),kind:'intent',actionId:'ui-retention',traceId:'ui-retention',occurredAt:new Date().toISOString(),note:'synthetic only'});
}
process.on('SIGINT',()=>children.forEach(c=>c.send('shutdown')));
