import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {harness} from './harness.mjs';
import {startOidcProvider} from './oidc-provider.mjs';
import {submit} from '../src/client.mjs';
import {createIdentity} from '../src/identity.mjs';
import {Store} from '../src/store.mjs';
import {createVaultBackup,restoreVaultBackup} from '../src/vault-recovery.mjs';

function browser(base){
 const jar=new Map();let csrf;
 return {
  get cookie(){return [...jar].map(([k,v])=>`${k}=${v}`).join('; ');},
  get csrf(){return csrf;},
  async request(path,{body,headers={},origin=base,sendCsrf=true}={}){
   const response=await fetch(new URL(path,base),{method:body===undefined?'GET':'POST',redirect:'manual',headers:{cookie:this.cookie,...(body!==undefined?{'content-type':'application/json',...(origin?{origin}:{}),...(sendCsrf&&csrf?{'x-evid-csrf':csrf}:{})}:{}),...headers},body:body===undefined?undefined:JSON.stringify(body)});
   const setCookies=response.headers.getSetCookie();for(const cookie of setCookies){const pair=cookie.split(';')[0],at=pair.indexOf('=');if(cookie.includes('Max-Age=0;')||cookie.endsWith('Max-Age=0'))jar.delete(pair.slice(0,at));else jar.set(pair.slice(0,at),pair.slice(at+1));}
   const text=await response.text();let value;try{value=JSON.parse(text);}catch{value=text;}
   if(path==='/auth/session'&&response.status===200)csrf=value.csrfToken;
   return {status:response.status,body:value,location:response.headers.get('location'),cookies:setCookies};
  }
 };
}

test('OIDC provider → audit gateway → vault: authenticated identity, isolation and revocation',{timeout:60000},async t=>{
 const provider=await startOidcProvider({host:process.env.EVIDSCOPE_TEST_HOST||'127.0.0.1'});t.after(()=>provider.close());
 const h=await harness();t.after(()=>h.close());
 h.config.oidc={enabled:true,syntheticLocalIdp:true,issuer:provider.issuer,publicOrigin:h.audit.url,clientId:provider.clientId,clientSecret:provider.clientSecret,requiredAcrValues:['urn:evidscope:test:mfa'],bindings:[
  {id:'alice-admin',subject:'alice',tenant:'alpha',role:'admin'},
  {id:'bob-auditor',subject:'bob',tenant:'alpha',role:'auditor'},
  {id:'carol-reviewer',subject:'carol',tenant:'alpha',role:'reviewer'},
  {id:'dave-beta',subject:'dave',tenant:'beta',role:'admin'},
  {id:'eve-gamma',subject:'eve',tenant:'gamma',role:'reviewer'}
 ]};
 writeFileSync(join(h.dir,'config.json'),JSON.stringify(h.config));await h.restart();
 const secrets=[];
 async function begin(b){const start=await b.request('/auth/login');assert.equal(start.status,302,JSON.stringify(start));const url=new URL(start.location);for(const name of ['state','nonce'])secrets.push(url.searchParams.get(name));assert.equal(url.searchParams.get('code_challenge_method'),'S256');assert.equal(url.searchParams.get('redirect_uri'),h.audit.url+'/auth/callback');return start;}
 async function login(subject='alice',overrides={}){const b=browser(h.audit.url),start=await begin(b),callback=await provider.authorize(start.location,{claims:{sub:subject,...overrides.claims},...overrides});secrets.push(callback.searchParams.get('code'));const result=await b.request(callback.href);if(result.location==='/'){const session=await b.request('/auth/session');assert.equal(session.status,200);secrets.push(b.cookie.split('; ').find(x=>x.startsWith('evidscope-session='))?.split('=')[1],session.body.csrfToken);}return {b,result,callback,start};}
 let admin,auditor;
 await t.test('server-owned issuer/subject mapping ignores injected role and tenant claims',async()=>{
  assert.equal((await browser(h.audit.url).request('/auth/config')).body.mode,'oidc');
  const result=await login('alice',{claims:{sub:'alice',role:'auditor',tenant:'beta',email:'forged@example.invalid'}});assert.equal(result.result.location,'/');admin=result.b;
  const session=await admin.request('/auth/session');assert.deepEqual(session.body.principal,{id:'alice-admin',tenant:'alpha',role:'admin'});assert.ok(!JSON.stringify(session.body).includes('access_token'));assert.ok(!JSON.stringify(session.body).includes('id_token'));
  assert.ok(result.result.cookies.some(c=>c.includes('HttpOnly')&&c.includes('SameSite=Lax')&&c.includes('Path=/')));
  auditor=(await login('bob')).b;
  assert.equal((await h.api('/api/overview')).status,401,'human static bearer must be disabled when OIDC is enabled');
  assert.equal((await admin.request('/api/overview',{headers:{authorization:'Bearer '+h.principal('admin').token}})).status,400);
  assert.equal((await browser(h.ingress.url).request('/auth/login')).status,403);
 });
 await t.test('invalid token claims, signature, authentication strength and response state never create sessions',async()=>{
  const cases=[{claims:{nonce:'wrong'}},{claims:{iss:'https://wrong.invalid'}},{claims:{aud:'wrong-client'}},{claims:{exp:Math.floor(Date.now()/1000)-3600}},{claims:{auth_time:Math.floor(Date.now()/1000)-3600}},{claims:{acr:'password-only'}},{claims:{sub:'unmapped'}},{badSignature:true},{omitIdToken:true},{authorizationResponse:{state:'wrong-state'}},{authorizationResponse:{iss:'https://wrong.invalid'}}];
  for(const override of cases){const attempt=await login('alice',override);assert.equal(attempt.result.location,'/?auth=failed',JSON.stringify(override));assert.equal((await attempt.b.request('/auth/session')).status,401);assert.ok(!attempt.result.cookies.some(c=>c.startsWith('evidscope-session=')));}
 });
 await t.test('callback replay and swapped browser flow cookies cannot issue sessions',async()=>{
  const one=browser(h.audit.url),two=browser(h.audit.url),start=await begin(one);await begin(two);
  const callback=await provider.authorize(start.location);const count=provider.counters.token;
  assert.equal((await two.request(callback.href)).location,'/?auth=failed');assert.equal(provider.counters.token,count);
  assert.equal((await one.request(callback.href)).location,'/');
  assert.equal((await one.request(callback.href)).location,'/?auth=failed');assert.equal(provider.counters.token,count+1);
 });
 await t.test('cookie mutations require fixed Origin and CSRF; role and tenant checks still apply',async()=>{
  const body={id:'oidc-asset',actor:'synthetic',tool:'credit-score',owner:'carol'};
  for(const options of [{origin:null},{origin:'https://attacker.invalid'},{sendCsrf:false},{headers:{'x-evid-csrf':'wrong'}}])assert.equal((await admin.request('/api/assets',{body,...options})).status,403);
  assert.equal((await auditor.request('/api/assets',{body})).status,403);
  assert.equal((await auditor.request('/api/access')).status,403);
  assert.equal((await admin.request('/api/assets',{body})).status,200);
  assert.equal((await admin.request('/api/access/subjects/dave-beta',{body:{action:'disable',reason:'other tenant'}})).status,404);
  assert.equal((await admin.request('/api/access/subjects/alice-admin',{body:{action:'disable',reason:'self'}})).status,409);
  const beta=(await login('dave')).b;assert.equal((await beta.request('/api/assets')).body.items.length,0);
  const gamma=(await login('eve')).b,exported=await gamma.request('/api/export');assert.ok(exported.body.records.some(r=>r.type==='catalog'),'OIDC-only tenant has a catalog snapshot');
 });
 await t.test('collector HMAC and worker service credentials remain usable',async()=>{
  const event={id:'oidc-source-event',kind:'intent',actionId:'oidc-action',traceId:'oidc-trace',occurredAt:new Date().toISOString(),actor:'synthetic',tool:'credit-score',action:'read',resource:'synthetic-record'};
  assert.equal((await submit(h.ingress.url,h.principal('agent'),event)).status,202);
  assert.equal((await h.analyze()).status,200);
  assert.equal((await h.api('/api/access',{role:'agent'})).status,403);
 });
 await t.test('revocation is immediate, disable blocks new login, enable does not revive old sessions',async()=>{
  const old=auditor.cookie;
  assert.equal((await admin.request('/api/access/subjects/bob-auditor',{body:{action:'revoke_sessions',reason:'session test'}})).status,200);
  assert.equal((await auditor.request('/api/overview')).status,401);
  const next=await login('bob');assert.equal(next.result.location,'/');auditor=next.b;
  assert.equal((await admin.request('/api/access/subjects/bob-auditor',{body:{action:'disable',reason:'access withdrawn'}})).status,200);
  assert.equal((await auditor.request('/api/overview')).status,401);assert.equal((await login('bob')).result.location,'/?auth=failed');
  assert.equal((await admin.request('/api/access/subjects/bob-auditor',{body:{action:'enable',reason:'review complete'}})).status,200);
  assert.equal((await browser(h.audit.url).request('/api/overview',{headers:{cookie:old}})).status,401);
  assert.equal((await login('bob')).result.location,'/');
 });
 await t.test('logout ends only the app session and verifies CSRF',async()=>{
  const b=(await login('bob')).b;assert.equal((await b.request('/auth/logout',{body:{},sendCsrf:false})).status,403);
  const result=await b.request('/auth/logout',{body:{}});assert.deepEqual(result.body,{loggedOut:true,idpSessionEnded:false});assert.ok(result.cookies.some(c=>c.includes('Max-Age=0')));assert.equal((await b.request('/auth/session')).status,401);
 });
 await t.test('restart invalidates sessions; signed access state survives projection tampering and backup recovery',async()=>{
  await admin.request('/api/access/subjects/bob-auditor',{body:{action:'disable',reason:'persistent access withdrawal'}});
  const old=admin.cookie;await h.restart();assert.equal((await admin.request('/auth/session')).status,401);assert.equal((await login('bob')).result.location,'/?auth=failed');admin=(await login()).b;
  const db=new DatabaseSync(join(h.dir,'data','evidence.db'));try{db.prepare("UPDATE objects SET body=? WHERE tenant='alpha' AND type='identity_access' AND id='bob-auditor'").run(JSON.stringify({id:'bob-auditor',disabled:false,epoch:0}));}finally{db.close();}
  assert.equal((await login('bob')).result.location,'/?auth=failed','forged projection cannot enable signed disabled account');
  // A normal change rebuilds this projection only from the authenticated ledger.
  await admin.request('/api/access/subjects/bob-auditor',{body:{action:'disable',reason:'restore signed projection'}});
  const privateKey=readFileSync(join(h.dir,'signing-private.pem'),'utf8'),backupDir=join(h.dir,'backup'),restoreDir=join(h.dir,'restored');
  const anchor=await createVaultBackup({dataDir:join(h.dir,'data'),backupDir,privateKey,publicKey:h.publicKey});
  await restoreVaultBackup({backupDir,restoreDir,privateKey,publicKey:h.publicKey,anchor});
  const recovered=await h.start('vault',{DATA_DIR:restoreDir});
  assert.equal((await browser(recovered.url).request('/auth/session',{headers:{cookie:old}})).status,401);
  const recoveredDb=new DatabaseSync(join(restoreDir,'evidence.db'),{readOnly:true});try{const item=JSON.parse(recoveredDb.prepare("SELECT body FROM objects WHERE tenant='alpha' AND type='identity_access' AND id='bob-auditor'").get().body);assert.equal(item.disabled,true);}finally{recoveredDb.close();}
 });
 await t.test('audit exports, database files and process logs contain no authentication secrets',async()=>{
  const bundle=await admin.request('/api/export');assert.equal(bundle.status,200);const serialized=JSON.stringify(bundle.body)+h.vault.logs()+h.audit.logs();
  const bytes=Buffer.concat(['evidence.db','evidence.db-wal'].flatMap(name=>{try{return [readFileSync(join(h.dir,'data',name))];}catch{return [];}}));
  for(const secret of [...secrets,provider.clientSecret].filter(Boolean)){assert.ok(!serialized.includes(secret),'authentication secret in exported evidence or logs');assert.ok(!bytes.includes(Buffer.from(secret)),'authentication secret in persistent database');}
  assert.ok(bundle.body.records.some(r=>r.type==='identity_session'&&r.payload.operation==='session_authorized'));assert.ok(bundle.body.records.some(r=>r.type==='identity_access'));
 });
 await t.test('absolute and idle expiration are enforced on the server; expired login flow is never exchanged',async()=>{
  const store=new Store(join(h.dir,'clock-state'),readFileSync(join(h.dir,'signing-private.pem'),'utf8'));let now=Date.now();
  try{
   const identity=createIdentity({store,config:{...h.config,oidc:{...h.config.oidc,sessionTtlSeconds:60,idleTtlSeconds:30}},now:()=>now});
   async function flow(){const start=await identity.http('GET',new URL(h.audit.url+'/auth/login'));const cookie=start.headers['set-cookie'][0].split(';')[0];const callback=await provider.authorize(start.headers.location);return {cookie,callback};}
   async function session(){const f=await flow(),result=await identity.http('GET',f.callback,{cookie:f.cookie});assert.equal(result.headers.location,'/');return result.headers['set-cookie'].find(c=>c.startsWith('evidscope-session=')).split(';')[0];}
   const idle=await session();now+=30001;assert.throws(()=>identity.authenticate({cookie:idle}),e=>e.status===401);
   const absolute=await session();now+=20000;assert.equal(identity.authenticate({cookie:absolute}).id,'alice-admin');now+=20000;assert.equal(identity.authenticate({cookie:absolute}).id,'alice-admin');now+=20001;assert.throws(()=>identity.authenticate({cookie:absolute}),e=>e.status===401);
   const expired=await flow(),before=provider.counters.token;now+=300001;assert.equal((await identity.http('GET',expired.callback,{cookie:expired.cookie})).headers.location,'/?auth=failed');assert.equal(provider.counters.token,before);
  }finally{store.close();}
 });
 await t.test('untrusted discovery issuer or endpoint origins are rejected before authorization redirect',async()=>{
  const store=new Store(join(h.dir,'metadata-state'),readFileSync(join(h.dir,'signing-private.pem'),'utf8'));
  try{for(const metadata of [{issuer:'https://wrong.invalid'},{jwks_uri:'https://wrong.invalid/jwks'},{authorization_endpoint:'https://wrong.invalid/authorize'},{token_endpoint:'https://wrong.invalid/token'}]){provider.controls.metadata=metadata;const identity=createIdentity({store,config:h.config});await assert.rejects(identity.http('GET',new URL(h.audit.url+'/auth/login')));}}
  finally{provider.controls.metadata={};store.close();}
 });
});

test('enterprise transport and principal binding fail closed at configuration time',()=>{
 const base={profile:'enterprise',principals:[],oidc:{enabled:true,issuer:'https://identity.example.invalid',publicOrigin:'https://audit.example.invalid',clientId:'evidscope',clientSecret:'synthetic-client-secret-32-bytes',bindings:[{id:'admin',tenant:'alpha',role:'admin',subject:'alice'}]}};
 assert.equal(createIdentity({config:base,store:{}}).enabled,true);
 for(const patch of [{issuer:'http://127.0.0.1:3000'},{publicOrigin:'http://127.0.0.1:3000'},{syntheticLocalIdp:true},{bindings:[{id:'admin',tenant:'alpha',role:'worker',subject:'alice'}]},{issuer:'https://id.example/.well-known/openid-configuration'}])assert.throws(()=>createIdentity({config:{...base,oidc:{...base.oidc,...patch}},store:{}}));
 assert.throws(()=>createIdentity({config:{profile:'enterprise'},store:{}}),/requires OIDC/);
});
