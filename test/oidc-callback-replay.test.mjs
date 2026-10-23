// Regression tests for round-2 re-audit finding S9 (from the reviewer's PoC r2-poc-oidc-replay): the record of used
// callback states was a map bounded at 10,000 that dropped its oldest entry when full, and every anonymous
// login/callback pair cost one confidential-client token request. 10,000 anonymous pairs evicted a real user's used
// state, after which a replay of that callback reached the IdP token endpoint again. Token exchanges now pass a
// process-wide token bucket and a concurrency cap first, and a used state stays recorded until its flow expires.
import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {startOidcProvider} from './oidc-provider.mjs';
import {createIdentity} from '../src/identity.mjs';
import {Store} from '../src/store.mjs';

const origin='http://127.0.0.1:9';
async function fixture(t,oidc={}){
 const provider=await startOidcProvider({host:process.env.EVIDSCOPE_TEST_HOST||'127.0.0.1'});t.after(()=>provider.close());
 const dir=mkdtempSync(join(tmpdir(),'evidscope-r2-oidc-')),{privateKey}=generateKeyPairSync('ed25519'),store=new Store(dir,privateKey);
 t.after(()=>{store.close();rmSync(dir,{recursive:true,force:true});});
 const config={profile:'synthetic-local',principals:[],oidc:{enabled:true,syntheticLocalIdp:true,issuer:provider.issuer,publicOrigin:origin,
  clientId:provider.clientId,clientSecret:provider.clientSecret,bindings:[{id:'alice-admin',subject:'alice',tenant:'alpha',role:'admin'}],...oidc}};
 const clock={at:Date.now(),advance(ms){clock.at+=ms;}},identity=createIdentity({store,config,now:()=>clock.at});
 const login=async()=>{const r=await identity.http('GET',new URL(origin+'/auth/login'));
  return {location:r.headers.location,cookie:r.headers['set-cookie'][0].split(';')[0]};};
 const callback=async(url,flow)=>(await identity.http('GET',url,{cookie:flow.cookie})).headers.location;
 const authorized=async()=>{const flow=await login();return {flow,url:await provider.authorize(flow.location)};};
 // What anyone can send without an account: the state of a fresh login flow and a made-up code.
 const anonymous=async i=>{
  const flow=await login(),url=new URL(origin+'/auth/callback');url.searchParams.set('code','x'+i);
  url.searchParams.set('state',new URL(flow.location).searchParams.get('state'));url.searchParams.set('iss',provider.issuer);
  return callback(url,flow);
 };
 const refused=async(send,message)=>{const before=provider.counters.token;assert.equal(await send(),'/?auth=failed',message);
  assert.equal(provider.counters.token,before,`${message}: refused before any token request`);};
 return {provider,config,store,clock,identity,login,callback,authorized,anonymous,refused};
}

test('R2 S9: an anonymous callback flood is rate limited and cannot make the vault forget a used state',{timeout:600000},async t=>{
 const h=await fixture(t);
 // A real user logs in; replaying that callback right away is refused before any token request.
 const real=await h.authorized();
 assert.equal(await h.callback(real.url,real.flow),'/');
 await h.refused(()=>h.callback(real.url,real.flow),'immediate replay');
 // 10,000 anonymous login/callback pairs, 20 ms apart: 200 s in all, inside the real flow's 5 minutes.
 const N=10000,before=h.provider.counters.token;
 for(let i=0;i<N;i++){assert.equal(await h.anonymous(i),'/?auth=failed');h.clock.advance(20);}
 // The bucket admits its burst of 20 (the real login spent one) plus 60 per minute: about 19 + 200 of the 10,000.
 const exchanged=h.provider.counters.token-before;
 assert.ok(exchanged>=19&&exchanged<=220,`anonymous token requests: ${exchanged} of ${N}`);
 // 30 s later the bucket has refilled, and the used state is still recorded: the replay never reaches the IdP ...
 h.clock.advance(30000);
 await h.refused(()=>h.callback(real.url,real.flow),'replay after the flood');
 // ... while a new real login exchanges its code and completes.
 const next=await h.authorized(),beforeNext=h.provider.counters.token;
 assert.equal(await h.callback(next.url,next.flow),'/');assert.equal(h.provider.counters.token,beforeNext+1);
});

test('R2 S9: at most four token exchanges run at once, and a callback refused for that keeps its code',async t=>{
 const h=await fixture(t),flows=[];for(let i=0;i<5;i++)flows.push(await h.authorized());
 const before=h.provider.counters.token;
 // Four callbacks start their exchange; the fifth arrives while they are in flight.
 const running=flows.slice(0,4).map(({url,flow})=>h.callback(url,flow));
 assert.equal(await h.callback(flows[4].url,flows[4].flow),'/?auth=failed');
 assert.deepEqual(await Promise.all(running),['/','/','/','/']);
 assert.equal(h.provider.counters.token,before+4,'the fifth callback made no token request');
 // Its state was not used and its code not redeemed, so the same callback completes afterwards.
 assert.equal(await h.callback(flows[4].url,flows[4].flow),'/');
});

test('R2 S9: the exchange limit is validated, and a full used-state record fails closed',async t=>{
 const h=await fixture(t,{tokenExchangesPerMinute:1});
 for(const value of [0,-1,601,1.5,'60'])
  assert.throws(()=>createIdentity({store:h.store,config:{...h.config,oidc:{...h.config.oidc,tokenExchangesPerMinute:value}}}),
   /Invalid OIDC token exchange limit/,String(value));
 // One exchange per minute: a burst of 1 and a record of 1 + 5 used states. While the clock runs forward the record
 // cannot fill, since an entry lives at most 5 minutes after use. Flows dated an hour ahead (a clock stepped back
 // after they were issued) stay recorded for over an hour, which is the case the fail-closed branch covers.
 const start=h.clock.at;h.clock.advance(3600000);
 const flows=[];for(let i=0;i<7;i++)flows.push(await h.authorized());
 h.clock.at=start;
 for(let i=0;i<6;i++){assert.equal(await h.callback(flows[i].url,flows[i].flow),'/');h.clock.advance(60000);}
 // Six unexpired used states and a refilled bucket: the seventh exchange is refused rather than forgetting one.
 h.clock.advance(600000);
 await h.refused(()=>h.callback(flows[6].url,flows[6].flow),'used-state record full');
 // Once those flows have expired, logins work again.
 h.clock.at=start+3600000+300000;
 const next=await h.authorized();assert.equal(await h.callback(next.url,next.flow),'/');
});
