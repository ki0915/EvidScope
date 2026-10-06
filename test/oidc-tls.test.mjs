import test from 'node:test';
import assert from 'node:assert/strict';
import {fork,spawnSync} from 'node:child_process';
import {readFileSync,writeFileSync,mkdtempSync,mkdirSync} from 'node:fs';
import {join,resolve} from 'node:path';
import https from 'node:https';
import {initialize} from '../scripts/init.mjs';
import {startOidcProvider} from './oidc-provider.mjs';

test('enterprise OIDC over trusted HTTPS issues Secure host cookies and binds mutations to public origin',{timeout:60000},async t=>{
 mkdirSync('.test-runs',{recursive:true});const dir=mkdtempSync(resolve('.test-runs','oidc-tls-'));
 const host=process.env.EVIDSCOPE_TEST_HOST||'127.0.0.1',urlHost=host==='::1'?'[::1]':host;
 const openssl=process.env.EVIDSCOPE_TEST_OPENSSL||(process.platform==='win32'?'C:\\Program Files\\Git\\usr\\bin\\openssl.exe':'openssl');
 const ca=join(dir,'ca.pem'),keyPath=join(dir,'server.key'),certPath=join(dir,'server.pem'),cnf=join(dir,'openssl.cnf');
 writeFileSync(cnf,'[req]\ndistinguished_name=dn\nx509_extensions=root_ca\n[dn]\n[root_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n');
 function generate(args){const result=spawnSync(openssl,args,{encoding:'utf8',timeout:15000,windowsHide:true});assert.equal(result.error,undefined);assert.equal(result.status,0,result.stderr);}
 generate(['req','-config',cnf,'-x509','-newkey','rsa:2048','-nodes','-sha256','-days','1','-subj','/CN=EvidScope OIDC Synthetic CA','-keyout',join(dir,'ca.key'),'-out',ca]);
 generate(['req','-config',cnf,'-new','-newkey','rsa:2048','-nodes','-sha256','-subj','/CN=localhost','-keyout',keyPath,'-out',join(dir,'server.csr')]);
 const ext=join(dir,'server.ext');writeFileSync(ext,'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\n');
 generate(['x509','-req','-in',join(dir,'server.csr'),'-CA',ca,'-CAkey',join(dir,'ca.key'),'-set_serial','21','-days','1','-sha256','-extfile',ext,'-out',certPath]);
 const provider=await startOidcProvider({host,tls:{cert:readFileSync(certPath),key:readFileSync(keyPath)}});t.after(()=>provider.close());
 const config=initialize(dir);config.profile='enterprise';config.oidc={enabled:true,issuer:provider.issuer,clientId:provider.clientId,clientSecret:provider.clientSecret,publicOrigin:'https://placeholder.invalid',bindings:[{id:'oidc-admin',subject:'alice',tenant:'alpha',role:'admin'}]};
 const save=()=>writeFileSync(join(dir,'config.json'),JSON.stringify(config));save();
 const children=[],cleanEnv={...process.env};delete cleanEnv.NODE_TLS_REJECT_UNAUTHORIZED;delete cleanEnv.NODE_OPTIONS;delete cleanEnv.NODE_EXTRA_CA_CERTS;
 async function stop(child){if(child.exitCode!==null||child.signalCode!==null)return;await new Promise(done=>{const timeout=setTimeout(()=>child.kill(),3000);child.once('exit',()=>{clearTimeout(timeout);done();});child.send('shutdown');});}
 t.after(async()=>{for(const child of children)await stop(child);});
 async function start(mode,extra={}){return new Promise((done,reject)=>{const child=fork('src/server.mjs',[],{env:{...cleanEnv,NODE_EXTRA_CA_CERTS:ca,MODE:mode,HOST:host,PORT:'0',CONFIG_FILE:join(dir,'config.json'),SIGNING_KEY_FILE:join(dir,'signing-private.pem'),DATA_DIR:join(dir,'data'),TLS_CERT_FILE:certPath,TLS_KEY_FILE:keyPath,...extra},execArgv:[],windowsHide:true,stdio:['ignore','pipe','pipe','ipc']});children.push(child);let logs='';child.stdout.on('data',b=>logs+=b);child.stderr.on('data',b=>logs+=b);const timer=setTimeout(()=>{child.kill();reject(Error('OIDC TLS startup timeout: '+logs));},10000);child.once('message',m=>{clearTimeout(timer);done({child,port:m.port,url:`https://${urlHost}:${m.port}`});});child.once('error',e=>{clearTimeout(timer);reject(e);});child.once('exit',code=>{clearTimeout(timer);if(code)reject(Error('OIDC TLS process failed: '+logs));});});}
 let vault=await start('vault');const audit=await start('audit',{VAULT_URL:vault.url});config.oidc.publicOrigin=audit.url;save();const port=vault.port;await stop(vault.child);vault=await start('vault',{PORT:String(port)});
 const jar=new Map();
 // Pin the fixture's valid DNS SAN independently of the intentionally spoofed HTTP Host.
 function request(url,{body,headers={},useCookies=true,trust=true}={}){return new Promise((done,reject)=>{const req=https.request(url,{method:body===undefined?'GET':'POST',servername:'localhost',ca:trust?readFileSync(ca):undefined,headers:{...(useCookies?{cookie:[...jar].map(([k,v])=>`${k}=${v}`).join('; ')}:{}),...(body===undefined?{}:{'content-type':'application/json'}),...headers},timeout:5000},res=>{const chunks=[];res.on('data',b=>chunks.push(b));res.on('end',()=>{for(const cookie of res.headers['set-cookie']||[]){const pair=cookie.split(';')[0],at=pair.indexOf('=');if(cookie.includes('Max-Age=0'))jar.delete(pair.slice(0,at));else jar.set(pair.slice(0,at),pair.slice(at+1));}const raw=Buffer.concat(chunks).toString();done({status:res.statusCode,headers:res.headers,body:raw?JSON.parse(raw):null});});});req.on('error',reject);req.on('timeout',()=>req.destroy(Error('timeout')));req.end(body===undefined?undefined:JSON.stringify(body));});}
 await assert.rejects(request(audit.url+'/auth/config',{trust:false}),error=>/CERT|ISSUER/.test(error.code));
 const first=await request(audit.url+'/auth/login');assert.equal(first.status,302);assert.ok(first.headers['set-cookie'][0].startsWith('__Host-evidscope-flow='));
 const authorization=await request(first.headers.location,{useCookies:false});assert.equal(authorization.status,302);
 const callback=await request(authorization.headers.location);assert.equal(callback.headers.location,'/');
 const sessionCookie=callback.headers['set-cookie'].find(c=>c.startsWith('__Host-evidscope-session='));assert.ok(sessionCookie);for(const attribute of ['Secure','HttpOnly','SameSite=Lax','Path=/'])assert.ok(sessionCookie.includes(attribute));assert.ok(!sessionCookie.includes('Domain='));
 const session=await request(audit.url+'/auth/session');assert.equal(session.status,200);assert.equal(session.body.principal.id,'oidc-admin');
 assert.equal((await request(audit.url+'/api/overview',{useCookies:false,headers:{authorization:'Bearer '+config.principals.find(p=>p.role==='admin').token}})).status,401);
 assert.equal((await request(audit.url+'/auth/logout',{body:{},headers:{'x-evid-csrf':session.body.csrfToken}})).status,403);
 // Spoofed Host and Origin can agree at the gateway but still fail the vault's fixed-origin check.
 assert.equal((await request(audit.url+'/auth/logout',{body:{},headers:{host:'attacker.invalid',origin:'https://attacker.invalid','x-evid-csrf':session.body.csrfToken}})).status,403);
 assert.equal((await request(audit.url+'/auth/logout',{body:{},headers:{origin:audit.url,'x-evid-csrf':session.body.csrfToken}})).status,200);
 assert.equal((await request(audit.url+'/auth/session')).status,401);
});
