import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {startOidcProvider} from './oidc-provider.mjs';
import {createIdentity} from '../src/identity.mjs';
import {Store} from '../src/store.mjs';

// Regression tests for adversarial-audit finding S9: the OIDC login flow is a sealed, short-lived browser cookie, so an
// anonymous /auth/login flood keeps no vault state and cannot lock other users out of login.
async function fixture(t){
 const provider=await startOidcProvider({host:process.env.EVIDSCOPE_TEST_HOST||'127.0.0.1'});t.after(()=>provider.close());
 const dir=mkdtempSync(join(tmpdir(),'evidscope-oidc-flow-')),{privateKey}=generateKeyPairSync('ed25519'),store=new Store(dir,privateKey);
 t.after(()=>{store.close();rmSync(dir,{recursive:true,force:true});});
 const origin='http://127.0.0.1:9',config={profile:'synthetic-local',principals:[],oidc:{enabled:true,syntheticLocalIdp:true,issuer:provider.issuer,
  publicOrigin:origin,clientId:provider.clientId,clientSecret:provider.clientSecret,bindings:[{id:'alice-admin',subject:'alice',tenant:'alpha',role:'admin'}]}};
 let now=Date.now();const clock={advance:ms=>{now+=ms;}};
 const make=()=>createIdentity({store,config,now:()=>now}),identity=make();
 async function login(instance=identity){
  const start=await instance.http('GET',new URL(origin+'/auth/login'));assert.equal(start.status,302);
  return {location:start.headers.location,cookie:start.headers['set-cookie'][0].split(';')[0],setCookie:start.headers['set-cookie'][0]};
 }
 const callback=(flow,cookie=flow.cookie,instance=identity)=>provider.authorize(flow.location).then(url=>instance.http('GET',url,{cookie}));
 return {provider,identity,make,login,callback,clock};
}

test('S9: a login flood keeps no server state and a real login still completes',{timeout:60000},async t=>{
 const h=await fixture(t);
 for(let i=0;i<1500;i++)await h.login();
 const result=await h.callback(await h.login());
 assert.equal(result.headers.location,'/');assert.ok(result.headers['set-cookie'].some(c=>c.startsWith('evidscope-session=')));
});

test('S9: the flow cookie is sealed, bound to its state and single-use',{timeout:60000},async t=>{
 const h=await fixture(t),flow=await h.login(),location=new URL(flow.location),value=flow.cookie.split('=')[1];
 for(const name of ['state','nonce'])assert.equal(value.includes(location.searchParams.get(name)),false,`${name} is not readable from the cookie`);
 assert.match(flow.setCookie,/HttpOnly/);assert.match(flow.setCookie,/SameSite=Lax/);assert.match(flow.setCookie,/Max-Age=300/);
 const failed=async(promise,message)=>{const before=h.provider.counters.token;assert.equal((await promise).headers.location,'/?auth=failed',message);
  assert.equal(h.provider.counters.token,before,`${message}: no token request`);};
 const flipped=value.slice(0,-2)+(value.at(-2)==='A'?'B':'A')+value.at(-1);
 await failed(h.callback(flow,`evidscope-flow=${flipped}`),'tampered cookie');
 const other=await h.login();await failed(h.callback(flow,other.cookie),'another flow cookie for this state');
 const foreign=h.make(),foreignFlow=await h.login(foreign);await failed(h.callback(foreignFlow),'cookie sealed by another vault process');
 await failed(h.callback(flow,''),'missing cookie');
 const first=await h.provider.authorize(flow.location);
 assert.equal((await h.identity.http('GET',first,{cookie:flow.cookie})).headers.location,'/');
 await failed(h.identity.http('GET',first,{cookie:flow.cookie}),'replayed callback');
 const late=await h.login();h.clock.advance(300001);await failed(h.callback(late),'expired flow');
});
