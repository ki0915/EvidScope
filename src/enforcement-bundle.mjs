// What enforcement points pull (docs/kill-switch.md): the tenant's agents and active stop orders as an OPA bundle (Bundle
// Service API: gzip tar with .manifest and data.json under one root, optionally .signatures.json) and as a DSSE-signed JSON
// deny-list for gateways without OPA. Content is a pure function of signed registry and stop-order records, so a revision
// always names the same content. No I/O; node:crypto and node:zlib only.
import {createPrivateKey,createPublicKey,createHash,sign as cryptoSign} from 'node:crypto';
import {gzipSync} from 'node:zlib';
import {canonical} from './crypto.mjs';
import {pae,keyFingerprint} from './dsse.mjs';

export const BUNDLE_ROOT='evidscope';
export const BUNDLE_FORMAT='evidscope-enforcement-bundle-v1';
export const DENY_LIST_FORMAT='evidscope-deny-list-v1';
export const DENY_LIST_PAYLOAD_TYPE='application/vnd.evidscope.deny-list+json';
const strings=v=>Array.isArray(v)?v.filter(x=>typeof x==='string'):[];
const byText=(a,b)=>a<b?-1:a>b?1:0;

// Enforcement view: no names, owners, purposes, reasons or event content; only what a policy needs to allow or deny a call.
export function enforcementState({tenant,revision,entries,orders}){
 const live=orders.filter(o=>o.status==='active').sort((a,b)=>byText(a.id,b.id));
 // Keyed by registry ids and free-text actor names: null-prototype maps, so __proto__, constructor or toString stay data.
 const agents=Object.create(null),actors=Object.create(null),sources=Object.create(null),stopOrders=Object.create(null);
 const sorted=[...entries].sort((a,b)=>byText(a.id,b.id));
 // An active order keeps the sources and actors it stopped (frozen in its target) until it ends, so editing the entry or
 // registering the names again under another entry does not take them out of distribution.
 const names=(own,stops,k)=>[...new Set([...strings(own),...stops.flatMap(o=>strings(o.target?.[k]))])];
 for(const e of sorted){
  const stops=live.filter(o=>o.agentId===e.id);
  agents[e.id]={state:e.state,stopped:stops.some(o=>o.scope==='agent'),
   stopped_tools:[...new Set(stops.filter(o=>o.scope==='tools').flatMap(o=>strings(o.tools)))].sort(byText),
   stop_orders:stops.map(o=>o.id),sources:names(e.sources,stops,'sources'),actors:names(e.actors,stops,'actors'),
   tools:Object.fromEntries((Array.isArray(e.tools)?e.tools:[]).filter(t=>typeof t?.name==='string')
    .map(t=>[t.name,{enforcement:t.enforcement==='required'?'required':'not_required'}]))};
 }
 for(const o of live)if(Object.hasOwn(agents,o.agentId)){
  for(const s of strings(o.target?.sources))sources[s]??=o.agentId;for(const a of strings(o.target?.actors))actors[a]??=o.agentId;
 }
 // One live entry per source and actor (the registry refuses overlaps); a retired entry answers only for names no live entry has.
 for(const retired of [false,true])for(const e of sorted)if((e.state==='retired')===retired){
  for(const s of strings(e.sources))sources[s]??=e.id;for(const a of strings(e.actors))actors[a]??=e.id;
 }
 for(const o of live)stopOrders[o.id]={agent:o.agentId,scope:o.scope,tools:strings(o.tools),issued_at:o.issuedAt};
 return {format:BUNDLE_FORMAT,tenant,revision,agents,actors,sources,stop_orders:stopOrders};
}

export function denyList(state){
 const entries=Object.entries(state.agents).flatMap(([agent,a])=>{
  const all=a.stopped||['suspended','retired'].includes(a.state);
  if(!all&&!a.stopped_tools.length)return [];
  return [{agent,state:a.state,deny:all?'all':'tools',tools:all?[]:a.stopped_tools,sources:a.sources,actors:a.actors,stop_orders:a.stop_orders}];
 });
 return {format:DENY_LIST_FORMAT,tenant:state.tenant,revision:state.revision,entries,
  limitations:['Agents in discovered, draft, testing or approved state are not listed; the OPA bundle carries every state.']};
}
// DSSE envelope over the canonical deny-list bytes, signed with the vault key; gateways verify with src/dsse.mjs openEnvelope.
export function signDenyList(list,key){
 const privateKey=key?.type==='private'?key:createPrivateKey(key),body=Buffer.from(canonical(list),'utf8');
 const sig=cryptoSign(null,pae(DENY_LIST_PAYLOAD_TYPE,body),privateKey);
 return {payloadType:DENY_LIST_PAYLOAD_TYPE,payload:body.toString('base64'),
  signatures:[{keyid:keyFingerprint(createPublicKey(privateKey)),sig:sig.toString('base64')}]};
}

// OPA hashes structured bundle files (.manifest, data.json) over a canonical form: object keys in byte order, no whitespace,
// primitives as Go's encoding/json writes them with HTML escaping off (v1/bundle/hash.go). The files are written in exactly
// that form, so their bytes are what OPA hashes. Strings are made well-formed first (Go would read a lone surrogate as U+FFFD).
const goKeyOrder=(a,b)=>Buffer.compare(Buffer.from(a,'utf8'),Buffer.from(b,'utf8'));
const LINE_SEPARATORS=new RegExp('['+String.fromCharCode(0x2028,0x2029)+']','g');
const goString=s=>JSON.stringify(s.toWellFormed()).replace(LINE_SEPARATORS,c=>'\\'+'u'+c.charCodeAt(0).toString(16));
export function goCanonical(v){
 if(typeof v==='string')return goString(v);
 if(v===null||typeof v==='boolean')return JSON.stringify(v);
 if(typeof v==='number'){if(!Number.isSafeInteger(v))throw TypeError('Bundle numbers must be safe integers');return String(v);}
 if(Array.isArray(v))return '['+v.map(goCanonical).join(',')+']';
 return '{'+Object.keys(v).filter(k=>v[k]!==undefined).sort(goKeyOrder).map(k=>goString(k)+':'+goCanonical(v[k])).join(',')+'}';
}

// ustar archive with regular files only, fixed owner and mode, and the content record's time, so a revision has fixed bytes.
function tarball(files,mtime){
 const blocks=[],octal=(n,width)=>n.toString(8).padStart(width-1,'0')+'\0';
 for(const {name,bytes} of files){
  const header=Buffer.alloc(512);
  if(Buffer.byteLength(name)>100)throw Error('Bundle file name too long');
  header.write(name,0);header.write(octal(0o644,8),100);header.write(octal(0,8),108);header.write(octal(0,8),116);
  header.write(octal(bytes.length,12),124);header.write(octal(mtime,12),136);header.write('        ',148);header.write('0',156);
  header.write('ustar\0',257,'binary');header.write('00',263);
  let sum=0;for(const b of header)sum+=b;header.write(sum.toString(8).padStart(6,'0')+'\0 ',148,'binary');
  blocks.push(header,bytes,Buffer.alloc((512-bytes.length%512)%512));
 }
 blocks.push(Buffer.alloc(1024));return Buffer.concat(blocks);
}

// Bundle signing (.signatures.json): OPA verifies RS*/PS*/ES*/HS* JWTs only (v1/keys), not Ed25519, so the vault key cannot
// sign bundles. A separate RSA or P-256 key does; an HMAC secret is never used because the enforcement point would hold it.
export function bundleSigner(pem,keyId='evidscope'){
 const key=createPrivateKey(pem),type=key.asymmetricKeyType,curve=key.asymmetricKeyDetails?.namedCurve;
 if(!(type==='rsa'&&key.asymmetricKeyDetails.modulusLength>=2048||type==='ec'&&curve==='prime256v1'))
  throw Error('OPA bundle signing key must be RSA (2048 bits or more, RS256) or EC P-256 (ES256)');
 if(typeof keyId!=='string'||!/^[A-Za-z0-9._:-]{1,64}$/.test(keyId))throw Error('Invalid OPA bundle signing key id');
 const alg=type==='rsa'?'RS256':'ES256';
 return {alg,keyId,publicKeyPem:createPublicKey(key).export({format:'pem',type:'spki'}),
  sign:data=>cryptoSign('sha256',data,type==='ec'?{key,dsaEncoding:'ieee-p1363'}:key)};
}
const b64url=value=>Buffer.from(value).toString('base64url');
const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');
function signatures(files,signer){
 const header=b64url(JSON.stringify({alg:signer.alg,kid:signer.keyId,typ:'JWT'}));
 const payload=b64url(JSON.stringify({files:files.map(f=>({name:f.name.replace(/^\//,''),hash:sha256(f.bytes),algorithm:'SHA-256'})),keyid:signer.keyId}));
 return {signatures:[`${header}.${payload}.${b64url(signer.sign(Buffer.from(`${header}.${payload}`)))}`]};
}

export function opaBundle(state,{mtime=0,signer}={}){
 const manifest={revision:state.revision,roots:[BUNDLE_ROOT],metadata:{format:BUNDLE_FORMAT,tenant:state.tenant}};
 const files=[{name:'/.manifest',bytes:Buffer.from(goCanonical(manifest),'utf8')},
  {name:'/data.json',bytes:Buffer.from(goCanonical({[BUNDLE_ROOT]:state}),'utf8')}];
 if(signer)files.push({name:'/.signatures.json',bytes:Buffer.from(JSON.stringify(signatures(files,signer)),'utf8')});
 return gzipSync(tarball(files,Math.max(0,Math.floor(mtime/1000))),{level:9});
}
