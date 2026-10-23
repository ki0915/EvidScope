// Provenance of event-keys-base-9177cee.json. Run from a checkout of commit 9177cee (v1 event envelopes, raw-digest receipts):
//   node <this file> OUT.json
// Builds tenant alpha with three events, erases one through a two-person retention plan and writes the closed evidence.db.
import {createHash,generateKeyPairSync,randomUUID} from 'node:crypto';
import {mkdtempSync,readFileSync,readdirSync,rmSync,writeFileSync} from 'node:fs';
import {gzipSync} from 'node:zlib';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const load=path=>import(pathToFileURL(resolve(process.cwd(),path)).href);
const {createService}=await load('src/service.mjs'),{mac}=await load('src/crypto.mjs');
const dir=mkdtempSync(join(tmpdir(),'evidscope-base-fixture-')),{privateKey}=generateKeyPairSync('ed25519'),token=s=>s.repeat(40).slice(0,40);
const principals=[{id:'alpha-agent',tenant:'alpha',role:'source',kind:'agent',token:token('fa'),hmacSecret:token('fh')},
 {id:'alpha-reviewer',tenant:'alpha',role:'reviewer',token:token('fr')},{id:'alpha-admin',tenant:'alpha',role:'admin',token:token('fm')}];
const service=createService({dataDir:dir,key:privateKey,config:{principals}}),principal=id=>principals.find(p=>p.id===id);
const call=(path,id,body)=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),{authorization:'Bearer '+principal(id).token},
 body===undefined?'':JSON.stringify(body));
const ingest=event=>{
 const body=JSON.stringify(event),stamp=String(Date.now()),nonce=randomUUID(),agent=principal('alpha-agent');
 return service.handle('POST',new URL('/api/ingest','http://local'),{authorization:'Bearer '+agent.token,'x-evid-timestamp':stamp,'x-evid-nonce':nonce,
  'x-evid-signature':mac(agent.hmacSecret,stamp,nonce,body)},body);
};
const occurredAt=new Date().toISOString(),raw={
 erased:{id:'base-erased',actionId:'base-erase-action',traceId:'base-trace',kind:'intent',occurredAt,note:'status-11'},
 kept:{id:'base-kept',actionId:'base-keep-action',traceId:'base-trace',kind:'intent',occurredAt,note:'status-4'},
 kept2:{id:'base-kept-2',actionId:'base-keep-action',traceId:'base-trace',kind:'self_report',occurredAt,note:'status-7'},
};
await call('/api/retention/policy','alpha-reviewer',{retentionSeconds:1,purpose:'base fixture',reason:'synthetic fixture for the event-key migration test'});
for(const event of Object.values(raw))if((await ingest(event)).accepted!==true)throw Error('ingest failed');
await call('/api/retention/holds','alpha-reviewer',{scope:'base-keep-action',reason:'keep two events retained in the fixture'});
await new Promise(done=>setTimeout(done,1100));
const plan=await call('/api/retention/plans','alpha-reviewer',{reason:'erase one synthetic event'});
if(plan.items.length!==1)throw Error('unexpected plan');
await call(`/api/retention/plans/${plan.id}/approve`,'alpha-admin',{reason:'second person'});
await call(`/api/retention/plans/${plan.id}/execute`,'alpha-admin',{});
const exportBundle=service.store.exportBundle('alpha');service.store.close();
const files=readdirSync(dir),db=readFileSync(join(dir,'evidence.db'));
writeFileSync(process.argv[2],JSON.stringify({
 format:'evidscope-test-fixture-v1',
 description:'Vault written by commit 9177cee (v1 event envelopes, raw-digest receipts): tenant alpha, three events, one erased by a retention plan.',
 baseCommit:'9177cee',signingKeyPkcs8Base64:privateKey.export({format:'der',type:'pkcs8'}).toString('base64'),
 principals:principals.map(({token:_token,hmacSecret:_secret,...rest})=>rest),rawEvents:raw,
 evidenceDbGzipBase64:gzipSync(db,{level:9}).toString('base64'),evidenceDbSha256:createHash('sha256').update(db).digest('hex'),
 dataDirFiles:files,exportBundle,
},null,1)+'\n');
rmSync(dir,{recursive:true,force:true});
console.log(JSON.stringify({ok:true,dbBytes:db.length,files}));
