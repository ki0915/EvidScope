// Ingest throughput stage 3 (round 7, docs/performance.md): the SDK client on a node:http keep-alive pool, the benchmark's
// process measurement, and the vault-side changes that keep every guarantee of stages 1 and 2.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {submit} from '../src/client.mjs';
import {mac} from '../src/crypto.mjs';
import {cpuPerEvent,pinLayout} from '../scripts/benchmark-process.mjs';

async function server(handler){
 const sockets=new Set(),requests=[];
 const s=http.createServer((req,res)=>{
  const chunks=[];req.on('data',c=>chunks.push(c));
  req.on('end',()=>{const body=Buffer.concat(chunks).toString('utf8');requests.push({headers:req.headers,body,path:req.url});handler(req,res,body);});
 });
 s.on('connection',socket=>sockets.add(socket));
 await new Promise(r=>s.listen(0,'127.0.0.1',r));
 return {url:`http://127.0.0.1:${s.address().port}`,requests,sockets,close:()=>new Promise(r=>{s.closeAllConnections();s.close(r);})};
}
const principal={token:'t'.repeat(40),hmacSecret:'h'.repeat(40)};

test('SDK submit over a keep-alive agent: same request as fetch, one connection, redirects refused, deadline enforced', async()=>{
 const srv=await server((req,res,body)=>{
  const {id}=JSON.parse(body);
  if(id==='redirect'){res.writeHead(302,{location:'/elsewhere','content-type':'application/json'});res.end('{}');return;}
  if(id==='slow'){res.writeHead(202,{'content-type':'application/json'});res.write('{"accepted":');setTimeout(()=>res.end('true}'),400);return;}
  res.writeHead(202,{'content-type':'application/json'});res.end(JSON.stringify({accepted:true,id:JSON.parse(body).id}));
 });
 const agent=new http.Agent({keepAlive:true,maxSockets:4});
 try{
  const options={nonce:'n-1',timestamp:'1700000000000'};
  const viaFetch=await submit(srv.url,principal,{id:'e-1'},options),viaAgent=await submit(srv.url,principal,{id:'e-1'},{...options,agent});
  assert.deepEqual(viaAgent,viaFetch);assert.deepEqual(viaAgent,{status:202,body:{accepted:true,id:'e-1'}});
  const [a,b]=srv.requests.slice(-2);
  for(const name of ['authorization','content-type','x-evid-timestamp','x-evid-nonce','x-evid-signature'])assert.equal(b.headers[name],a.headers[name],name);
  assert.equal(b.body,a.body);assert.equal(b.path,'/api/ingest');
  assert.equal(b.headers['x-evid-signature'],mac(principal.hmacSecret,'1700000000000','n-1',JSON.stringify({id:'e-1'})));
  const before=srv.sockets.size;
  for(let i=0;i<10;i++)assert.equal((await submit(srv.url,principal,{id:'k-'+i},{agent})).status,202);
  assert.equal(srv.sockets.size,before,'ten sequential submits reuse the kept-alive connection');
  await assert.rejects(submit(srv.url,principal,{id:'redirect'},{agent}),/redirect refused/);
  await assert.rejects(submit(srv.url,principal,{id:'slow'},{agent,timeoutMs:100}),error=>error.name==='TimeoutError'||error.name==='AbortError');
 }finally{agent.destroy();await srv.close();}
});

test('benchmark process measurement: CPU per event per process and the pinning layout', ()=>{
 const before={vault:{total:100,main:90},ingress:{total:50,main:50},client:{total:null,main:null}};
 const after={vault:{total:300,main:250},ingress:{total:90,main:80},client:{total:10,main:10}};
 assert.deepEqual(cpuPerEvent(before,after,200),{vault:1,vaultMainThread:0.8,ingress:0.2});
 assert.deepEqual(pinLayout('1',4),{vault:'0',ingress:'1',client:'2',other:'3'});
 assert.equal(pinLayout('1',2),null);assert.equal(pinLayout('',4),null);
 assert.deepEqual(pinLayout('vault:0,client:2-3,other:1',4),{vault:'0',client:'2-3',other:'1'});
 assert.throws(()=>pinLayout('vault:0;rm',4),/Invalid BENCHMARK_PIN/);
});
