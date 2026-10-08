import {randomUUID} from 'node:crypto';
import {mac} from './crypto.mjs';
import {upstreamRequest} from './upstream-http.mjs';
// agent (round 7, docs/performance.md): an http.Agent or https.Agent, e.g. new http.Agent({keepAlive:true}), sends over node:http on
// that pool instead of fetch, at less CPU per event for the source. Same contract: redirects are refused, TLS is verified as by
// fetch (Node's trust store), the deadline covers the response body, and the answer is {status, body}.
export async function submit(url,principal,event,{timeoutMs=2000,nonce=randomUUID(),timestamp=String(Date.now()),signature,agent}={}) {
 const body=JSON.stringify(event);
 if(agent){
  const response=await upstreamRequest(new URL('/api/ingest',url),{method:'POST',headers:{'content-type':'application/json',authorization:`Bearer ${principal.token}`,'x-evid-timestamp':timestamp,'x-evid-nonce':nonce,
   'x-evid-signature':signature??mac(principal.hmacSecret,timestamp,nonce,body)},body,timeoutMs,maxBytes:1024*1024,agent});
  if(response.status>=300&&response.status<400)throw TypeError('Ingest redirect refused');
  return {status:response.status,body:JSON.parse(response.body.toString('utf8'))};
 }
 const response=await fetch(new URL('/api/ingest',url),{method:'POST',headers:{'content-type':'application/json',authorization:`Bearer ${principal.token}`,'x-evid-timestamp':timestamp,'x-evid-nonce':nonce,'x-evid-signature':signature??mac(principal.hmacSecret,timestamp,nonce,body)},body,signal:AbortSignal.timeout(timeoutMs),redirect:'error'});
 return {status:response.status,body:await response.json()};
}
// Call observe() after/outside business execution. It never waits on collector availability.
export class Observer {
 constructor(url,principal,{capacity=100,attempts=3,timeoutMs=1000}={}){this.url=url;this.principal=principal;this.capacity=capacity;this.attempts=attempts;this.timeoutMs=timeoutMs;this.queue=[];this.running=false;this.metrics={observed:0,accepted:0,dropped:0,retries:0};}
 observe(event){this.metrics.observed++;if(this.queue.length>=this.capacity){this.metrics.dropped++;return false;}this.queue.push(structuredClone(event));this.drain();return true;}
 async drain(){if(this.running)return;this.running=true;while(this.queue.length){const e=this.queue.shift();let accepted=false;for(let n=0;n<this.attempts;n++){try{const r=await submit(this.url,this.principal,e,{timeoutMs:this.timeoutMs});if(r.status===202){accepted=true;break;}if(r.status<500)break;}catch{}if(n+1<this.attempts){this.metrics.retries++;await new Promise(r=>setTimeout(r,Math.min(500,50*2**n)));}}if(accepted)this.metrics.accepted++;else this.metrics.dropped++;}this.running=false;}
}
