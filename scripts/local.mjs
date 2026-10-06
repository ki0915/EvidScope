import {fork} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {resolve,join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {initialize} from './init.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
export function localOptions(env=process.env){
 if(env.TLS_CERT_FILE||env.TLS_KEY_FILE)throw Error('Local launcher uses loopback HTTP; clear TLS_CERT_FILE/TLS_KEY_FILE or use the separate TLS deployment');
 const host=env.EVIDSCOPE_LOCAL_HOST||'127.0.0.1',rawPort=env.EVIDSCOPE_LOCAL_PORT_BASE??'8080';
 if(!['127.0.0.1','::1'].includes(host))throw Error('Local launcher requires numeric loopback HOST');
 if(!/^\d+$/.test(rawPort))throw Error('Local base port must be an integer');
 const portBase=Number(rawPort);
 if(portBase!==0&&(portBase<1024||portBase>65532))throw Error('Local base port must be 0 or 1024..65532');
 return {host,portBase,directory:resolve(env.EVIDSCOPE_LOCAL_DIR||join(root,'.local'))};
}
function exited(child){return child.exitCode!==null||child.signalCode!==null;}
function waitForExit(child,timeout){
 if(exited(child))return Promise.resolve(true);
 return new Promise(resolve=>{
  const done=value=>{clearTimeout(timer);child.removeListener('exit',onExit);resolve(value);};
  const onExit=()=>done(true),timer=setTimeout(()=>done(false),timeout);
  child.once('exit',onExit);
 });
}
export function createLocalRuntime(options=localOptions()){
 const {host,portBase,directory}=options;
 localOptions({...process.env,EVIDSCOPE_LOCAL_HOST:host,EVIDSCOPE_LOCAL_PORT_BASE:String(portBase),EVIDSCOPE_LOCAL_DIR:directory});
 const children=[],endpoints={};let stopping=false,started=false,stopFlight,failure=null;
 async function stop(){
  if(stopFlight)return stopFlight;
  stopping=true;
  stopFlight=(async()=>{
   for(const child of children)if(!exited(child)){
    try{if(child.connected)child.send('shutdown',()=>{});else child.kill('SIGTERM');}catch{}
   }
   const finished=await Promise.all(children.map(child=>waitForExit(child,9000)));
   for(let i=0;i<children.length;i++)if(!finished[i])children[i].kill('SIGKILL');
   const confirmed=await Promise.all(children.map(child=>waitForExit(child,3000)));
   if(confirmed.some(value=>!value))throw Error('Local child termination unconfirmed');
   return {terminationConfirmed:true,childPids:children.map(child=>child.pid)};
  })();
  return stopFlight;
 }
 async function start(){
  if(started||stopping)throw Error('Local runtime cannot be started twice');
  started=true;
  try{
   const config=initialize(directory),worker=config.principals.find(p=>p.role==='worker');
   if(!worker?.token)throw Error('Local worker identity is missing');
   for(const [index,mode]of ['vault','ingress','audit','worker'].entries()){
    if(stopping)throw Error('Local startup cancelled');
    const port=portBase===0?0:portBase+index;
    const address=await new Promise((res,rej)=>{
     const child=fork(join(root,'src/server.mjs'),[],{cwd:root,execArgv:[],env:{...process.env,MODE:mode,PORT:String(port),HOST:host,DATA_DIR:join(directory,'data'),CONFIG_FILE:join(directory,'config.json'),SIGNING_KEY_FILE:join(directory,'signing-private.pem'),VAULT_URL:endpoints.vault||`http://${host==='::1'?'[::1]':host}:${port}`,WORKER_TOKEN:worker.token},stdio:['ignore','inherit','inherit','ipc']});
     children.push(child);
     let settled=false;
     const finish=(error,value)=>{if(settled)return;settled=true;clearTimeout(timer);if(error)rej(error);else res(value);};
     const timer=setTimeout(()=>finish(Error(`${mode} startup timeout`)),10000);
     child.once('message',message=>{
      if(stopping)return finish(Error('Local startup cancelled'));
      if(!message?.ready||!Number.isInteger(message.port)||message.port<1)return finish(Error(`${mode} invalid readiness`));
      finish(null,`http://${host==='::1'?'[::1]':host}:${message.port}`);
     });
     child.once('error',error=>finish(Error(`${mode} startup failed: ${error.code||error.name}`)));
     child.once('exit',(code,signal)=>{
      finish(Error(`${mode} exited before readiness: ${signal||code}`));
      if(!stopping){failure=Error(`${mode} exited unexpectedly: ${signal||code}`);options.onFailure?.(failure);void stop().catch(error=>options.onFailure?.(error));}
     });
    });
    endpoints[mode]=address;
   }
   if(stopping||failure)throw failure||Error('Local startup cancelled');
   return {endpoints:{...endpoints},childPids:children.map(child=>child.pid),configurationFile:join(directory,'config.json'),profile:config.profile};
  }catch(error){await stop();throw error;}
 }
 return {start,stop,get failure(){return failure;},get childPids(){return children.map(child=>child.pid);}};
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 let runtime,interrupted=false;
 const disconnect=()=>{if(process.connected)process.disconnect();};
 const failed=error=>{process.exitCode=1;console.error(error.message);};
 try{
  runtime=createLocalRuntime({...localOptions(),onFailure:error=>{failed(error);void runtime.stop().then(disconnect,failed);}});
  const interrupt=()=>{interrupted=true;void runtime.stop().then(disconnect,failed);};
  process.once('SIGINT',interrupt);process.once('SIGTERM',interrupt);
  process.on('message',message=>{if(message==='shutdown')interrupt();});
  process.once('disconnect',interrupt);
  const ready=await runtime.start();
  const version=JSON.parse(readFileSync(join(root,'package.json'),'utf8')).version;
  console.log(`EvidScope ${version} · 감사 ${ready.endpoints.audit} · 수집 ${ready.endpoints.ingress} · 자격 파일 ${ready.configurationFile}`);
  process.send?.({ready:true,...ready});
 }catch(error){if(!interrupted)failed(error);disconnect();}
}
