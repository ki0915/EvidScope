import {fork} from 'node:child_process';
import {initialize} from './init.mjs';
const config=initialize(),children=[];
async function start(mode,port){return new Promise((resolve,reject)=>{const child=fork('src/server.mjs',[],{env:{...process.env,MODE:mode,PORT:String(port),HOST:'127.0.0.1',VAULT_URL:'http://127.0.0.1:8080',WORKER_TOKEN:config.principals.find(p=>p.role==='worker').token},stdio:['inherit','inherit','inherit','ipc']});children.push(child);child.once('message',resolve);child.once('error',reject);child.once('exit',code=>{if(code)reject(Error(`${mode}: ${code}`));});});}
await start('vault',8080);await start('ingress',8081);await start('audit',8082);await start('worker',8083);
console.log('EvidScope 감사 화면: http://127.0.0.1:8082 · 수집: 8081 · 자격: .local/config.json');
function stop(){for(const c of children)if(c.connected)c.send('shutdown');setTimeout(()=>process.exit(0),1000);}
process.on('SIGINT',stop);process.on('SIGTERM',stop);
