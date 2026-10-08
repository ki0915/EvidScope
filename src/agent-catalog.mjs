// Catalog import (docs/agent-registry.md): maps an A2A Agent Card or Backstage catalog entities to registry drafts in the
// discovered state with provenance. Pure; no I/O and no outbound fetch. Imported values are the catalog's self-report: no
// authenticated sources, actors, tools, risk tier or lifecycle state are ever taken from a document. Hostile input (size,
// nesting, prototype keys, YAML features outside the safe subset) is refused, never guessed at.
import {constants,createHash,createPublicKey,verify as verifySignature} from 'node:crypto';
import {canonical} from './crypto.mjs';

export const CATALOG_FORMATS=Object.freeze({a2a:'a2a-agent-card',backstage:'backstage-entity'});
export const CATALOG_LIMITS=Object.freeze({documentBytes:256*1024,documents:20,entities:50,depth:24,nodes:20000,lines:20000,
 signatures:5,keys:10,agentTypes:10});
export const DEFAULT_AGENT_TYPES=Object.freeze(['ai-agent','agent','ai_agent','llm-agent']);
const FORBIDDEN_KEYS=new Set(['__proto__','constructor','prototype']);
const BAD_TEXT=/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069]/u;
const sha256=value=>'sha256:'+createHash('sha256').update(value).digest('hex');
class CatalogError extends Error {constructor(code,message){super(message);this.code=code;}}
const refuse=(code,message)=>{throw new CatalogError(code,message);};
export const isCatalogError=error=>error instanceof CatalogError;
const isObject=v=>!!v&&typeof v==='object'&&!Array.isArray(v);

// Every parsed value is walked once: depth, node count and prototype-polluting keys.
function checkTree(value){
 let nodes=0;const stack=[[value,1]];
 while(stack.length){
  const [v,depth]=stack.pop();if(++nodes>CATALOG_LIMITS.nodes)refuse('too_many_nodes','document has too many values');
  if(v===null||typeof v!=='object')continue;
  if(depth>CATALOG_LIMITS.depth)refuse('too_deep','document nesting is too deep');
  for(const k of Object.keys(v)){if(FORBIDDEN_KEYS.has(k))refuse('forbidden_key',`forbidden key ${k}`);stack.push([v[k],depth+1]);}
 }
 return value;
}
// JSON nesting is measured before JSON.parse so a deep document never reaches a recursive walk.
function parseJson(text){
 let depth=0,inString=false;
 for(let i=0;i<text.length;i++){
  const c=text[i];
  if(inString){if(c==='\\')i++;else if(c==='"')inString=false;continue;}
  if(c==='"')inString=true;
  else if(c==='{'||c==='['){if(++depth>CATALOG_LIMITS.depth)refuse('too_deep','document nesting is too deep');}else if(c==='}'||c===']')depth--;
 }
 let value;try{value=JSON.parse(text);}catch{refuse('invalid_json','document is not valid JSON');}
 return checkTree(value);
}

// YAML: only the block subset catalog files use (mappings, sequences, plain/quoted scalars, one-line flow sequences of
// scalars, | and > block scalars, comments, --- separators). Anchors, aliases, tags, directives, merge keys, complex keys,
// flow mappings and multi-line plain scalars are refused rather than interpreted.
// A mapping key and the rest of its line, or null. Scanned without a backtracking pattern, so a long line stays linear.
function keyOf(line){
 let key,end;
 const quoted=line[0]==='"'?line.match(/^"(?:[^"\\]|\\.)*"/):line[0]==="'"?line.match(/^'(?:[^']|'')*'/):null;
 if(quoted){key=unquote(quoted[0]);end=quoted[0].length;while(line[end]===' '||line[end]==='\t')end++;if(line[end]!==':')return null;}
 else{
  const colon=line.search(/:(?:[ \t]|$)/);if(colon<1)return null;key=line.slice(0,colon).trimEnd();end=colon;
  if(/^[\s#'"&*!|>%@`{}[\],?:]/.test(key)||/^-(?:\s|$)/.test(key)||key.includes(' #'))return null;
 }
 if(end+1<line.length&&line[end+1]!==' '&&line[end+1]!=='\t')return null;
 return {key,rest:line.slice(end+1).trimStart()};
}
function stripComment(s){
 let quote=null;
 for(let i=0;i<s.length;i++){
  const c=s[i];
  if(quote){if(quote==='"'&&c==='\\')i++;else if(c===quote)quote=null;continue;}
  if((c==='"'||c==="'")&&(i===0||/[\s[,]/.test(s[i-1])))quote=c;else if(c==='#'&&(i===0||/\s/.test(s[i-1])))return s.slice(0,i).trimEnd();
 }
 return s.trimEnd();
}
function unquote(s){
 if(s.startsWith("'")){if(!/^'(?:[^']|'')*'$/.test(s))refuse('yaml_unsupported','unterminated single-quoted scalar');return s.slice(1,-1).replace(/''/g,"'");}
 if(!/^"(?:[^"\\]|\\.)*"$/.test(s))refuse('yaml_unsupported','unterminated double-quoted scalar');
 const escapes={'"':'"','\\':'\\','/':'/',n:'\n',t:'\t',r:'\r',b:'\b',f:'\f','0':'\0'};
 return s.slice(1,-1).replace(/\\(u[0-9a-fA-F]{4}|.)/g,(_,e)=>e.length===5?String.fromCharCode(parseInt(e.slice(1),16))
  :Object.hasOwn(escapes,e)?escapes[e]:refuse('yaml_unsupported','unsupported escape in double-quoted scalar'));
}
function scalar(raw){
 const s=raw.trim();
 if(s.startsWith('"')||s.startsWith("'"))return unquote(s);
 if(/^[&*!%@`|>{]/.test(s)||s.startsWith('<<'))refuse('yaml_unsupported',`YAML feature outside the safe subset: ${s.slice(0,20)}`);
 if(s==='{}')return {};
 if(s.startsWith('[')){
  if(!s.endsWith(']'))refuse('yaml_unsupported','multi-line flow sequence');const inner=s.slice(1,-1).trim();if(!inner)return [];
  if(/[[\]{}]/.test(inner.replace(/"(?:[^"\\]|\\.)*"|'(?:[^']|'')*'/g,'')))refuse('yaml_unsupported','nested flow collection');
  return (inner.match(/"(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^,]+/g)||[]).map(x=>x.trim()).filter(x=>x&&x!==',').map(scalar);
 }
 if(s===''||s==='~'||s==='null'||s==='Null'||s==='NULL')return null;
 if(/^(?:true|True|TRUE)$/.test(s))return true;if(/^(?:false|False|FALSE)$/.test(s))return false;
 if(/^-?(?:0|[1-9]\d{0,14})$/.test(s))return Number(s);
 return s;
}
export function parseYamlSubset(text){
 if(text.charCodeAt(0)===0xfeff)text=text.slice(1);
 const all=text.split(/\r?\n/);if(all.length>CATALOG_LIMITS.lines)refuse('too_many_lines','document has too many lines');
 const docs=[[]];
 all.forEach((line,n)=>{
  if(/^---(?:\s|$)/.test(line)){
   const rest=line.slice(3).trim();if(rest&&!rest.startsWith('#'))refuse('yaml_unsupported','content after ---');docs.push([]);return;
  }
  if(/^\.\.\.(?:\s|$)/.test(line)){docs.push([]);return;}
  if(/^%/.test(line))refuse('yaml_unsupported','YAML directives are not supported');
  docs.at(-1).push({n:n+1,raw:line});
 });
 return docs.map(parseDocument).filter(d=>d!==undefined);
}
function parseDocument(raw){
 const lines=[];
 for(const {n,raw:line} of raw){
  const indent=line.match(/^ */)[0].length;
  if(line[indent]==='\t')refuse('yaml_unsupported',`tab indentation at line ${n}`);
  lines.push({n,indent,raw:line,text:stripComment(line.slice(indent))});
 }
 const content=lines.filter(l=>l.text);if(!content.length)return undefined;
 let i=0;const next=()=>{while(i<lines.length&&!lines[i].text)i++;return lines[i];};
 const blockScalar=(indicator,parentIndent)=>{
  if(!/^[|>]-?$/.test(indicator))refuse('yaml_unsupported',`block scalar header ${indicator}`);
  const body=[];let indent=null;
  while(i<lines.length){const l=lines[i];if(l.raw.trim()&&l.indent<=parentIndent)break;
   if(l.raw.trim()&&indent===null)indent=l.indent;body.push(l.raw.trim()?l.raw.slice(indent??0):'');i++;}
  while(body.length&&body.at(-1)==='')body.pop();
  const joined=indicator[0]==='|'?body.join('\n'):body.reduce((out,l)=>out+(l===''?'\n':out&&!out.endsWith('\n')?' '+l:l),'');
  return indicator.endsWith('-')||!joined?joined:joined+'\n';
 };
 // A mapping value may be a sequence at the key's own indentation; a sequence item's may not (that is the next item).
 const value=(rest,indent,depth,item=false)=>{
  if(depth>CATALOG_LIMITS.depth)refuse('too_deep','document nesting is too deep');
  if(rest===''){const l=next();if(l&&(l.indent>indent||!item&&l.indent===indent&&/^-(?:\s|$)/.test(l.text)))return node(l.indent,depth+1);return null;}
  if(/^[|>]/.test(rest))return blockScalar(rest,indent);
  const l=next();if(l&&l.indent>indent)refuse('yaml_unsupported',`multi-line plain scalar or unexpected indentation at line ${l.n}`);
  return scalar(rest);
 };
 // A node at this indentation: a sequence ("- ") or a mapping; a sequence item may open a compact mapping on its own line.
 const node=(indent,depth,first)=>{
  const head=first||next();
  if(/^-(?:\s|$)/.test(head.text)){
   const out=[];
   for(let l=first||next();l&&l.indent===indent&&/^-(?:\s|$)/.test(l.text);l=next()){
    if(out.length>=CATALOG_LIMITS.nodes)refuse('too_many_nodes','document has too many values');
    const rest=l.text.slice(1).trimStart(),inner=l.indent+l.text.length-l.text.slice(1).trimStart().length;
    if(/^-(?:\s|$)/.test(rest))refuse('yaml_unsupported',`nested compact sequence at line ${l.n}`);
    if(rest&&keyOf(rest)){lines[i]={...l,indent:inner,text:rest};out.push(node(inner,depth+1,lines[i]));}else{i++;out.push(value(rest,indent,depth,true));}
    first=undefined;
   }
   return out;
  }
  const out={};
  for(let l=first||next();l&&l.indent===indent;l=next()){
   const m=keyOf(l.text);if(!m)refuse('yaml_unsupported',`expected a mapping key at line ${l.n}`);
   const key=m.key;
   if(key==='<<')refuse('yaml_unsupported','merge keys are not supported');if(FORBIDDEN_KEYS.has(key))refuse('forbidden_key',`forbidden key ${key}`);
   if(Object.hasOwn(out,key))refuse('duplicate_key',`duplicate key ${key} at line ${l.n}`);
   i++;out[key]=value(m.rest,indent,depth);first=undefined;
  }
  return out;
 };
 const root=next();if(root.indent!==0)refuse('yaml_unsupported','document must start at column 0');
 const result=node(0,1);const rest=next();if(rest)refuse('yaml_unsupported',`unexpected content at line ${rest.n}`);
 return checkTree(result);
}

// Values a catalog reports are kept only when they are plain bounded text; anything else is dropped with a reason.
function text(value,max){
 if(typeof value!=='string')return {reason:'not_text'};if(!value.trim())return {reason:'empty'};
 if(value.length>max)return {reason:'too_long'};if(BAD_TEXT.test(value))return {reason:'invalid_characters'};return {value};
}
const A2A_DROPPED={provider:'vendor_is_not_the_accountable_owner',skills:'offered_skills_are_not_tools_used',capabilities:'protocol_detail',
 defaultInputModes:'protocol_detail',defaultOutputModes:'protocol_detail',protocolVersion:'protocol_detail',preferredTransport:'protocol_detail',
 additionalInterfaces:'protocol_detail',supportedInterfaces:'endpoint_kept_in_provenance_only',url:'endpoint_kept_in_provenance_only',
 securitySchemes:'self_reported_security_not_trusted',securityRequirements:'self_reported_security_not_trusted',security:'self_reported_security_not_trusted',
 supportsAuthenticatedExtendedCard:'protocol_detail',documentationUrl:'no_registry_meaning',iconUrl:'no_registry_meaning',signatures:'checked_into_provenance'};
const BACKSTAGE_METADATA_DROPPED={annotations:'no_registry_meaning',labels:'no_registry_meaning',tags:'no_registry_meaning',links:'no_registry_meaning',
 uid:'catalog_computed_not_trusted',etag:'catalog_computed_not_trusted'};
const BACKSTAGE_SPEC_DROPPED={lifecycle:'lifecycle_never_sets_registry_state',system:'not_a_governance_system_id',subcomponentOf:'relation_not_mapped',
 dependsOn:'relation_not_mapped',dependencyOf:'relation_not_mapped',providesApis:'relation_not_mapped',consumesApis:'relation_not_mapped'};

// The A2A identity is the preferred interface address (plus its routing tenant); the card's name may change without
// making it another agent. Credentials, query and fragment never become part of a key.
function endpointOf(card){
 const interfaces=Array.isArray(card.supportedInterfaces)?card.supportedInterfaces.filter(isObject):[];
 const candidates=[...interfaces.map(x=>({url:x.url,tenant:x.tenant,from:'supportedInterfaces'})),{url:card.url,from:'url'}];
 for(const c of candidates){
  if(typeof c.url!=='string'||c.url.length>1000||BAD_TEXT.test(c.url))continue;
  let address=null;
  if(/^[a-z0-9.-]+:\d{1,5}$/i.test(c.url))address=`grpc://${c.url.toLowerCase()}`;
  else try{
   const u=new URL(c.url);if(['https:','http:'].includes(u.protocol)&&u.hostname)address=`${u.protocol}//${u.host}${u.pathname.replace(/\/+$/,'')}`;
  }catch{}
  if(!address)continue;
  const tenant=typeof c.tenant==='string'&&c.tenant&&c.tenant.length<=200&&!BAD_TEXT.test(c.tenant)?c.tenant:null;
  return {address,tenant,from:c.from};
 }
 return null;
}
function hostOf(value){try{const u=new URL(value);return ['https:','http:'].includes(u.protocol)?u.hostname:null;}catch{return null;}}

// Agent Card signatures (A2A spec 8.4): JWS over the RFC 8785 form of the card without `signatures`, checked only against
// keys the importing reviewer supplied. jku is recorded, never fetched. Default-valued fields are not stripped here, so a
// card serialized with them reports `invalid` and must be re-exported without them.
const ALGORITHMS={ES256:{kty:'EC',crv:'P-256',hash:'sha256',dsa:true},ES384:{kty:'EC',crv:'P-384',hash:'sha384',dsa:true},
 ES512:{kty:'EC',crv:'P-521',hash:'sha512',dsa:true},RS256:{kty:'RSA',hash:'sha256'},RS384:{kty:'RSA',hash:'sha384'},RS512:{kty:'RSA',hash:'sha512'},
 PS256:{kty:'RSA',hash:'sha256',pss:true},PS384:{kty:'RSA',hash:'sha384',pss:true},PS512:{kty:'RSA',hash:'sha512',pss:true},
 EdDSA:{kty:'OKP',crv:'Ed25519',hash:null},Ed25519:{kty:'OKP',crv:'Ed25519',hash:null}};
const B64URL=/^[A-Za-z0-9_-]*$/;
const THUMBPRINT_MEMBERS={EC:['crv','kty','x','y'],RSA:['e','kty','n'],OKP:['crv','kty','x']};
// Public members only (a supplied private key is reduced to its public half); the RFC 7638 thumbprint names the key.
export function normalizeKeys(jwks){
 if(jwks===undefined||jwks===null)return [];
 const keys=Array.isArray(jwks?.keys)?jwks.keys:refuse('invalid_keys','keys must be a JWK set {"keys":[...]}');
 if(keys.length>CATALOG_LIMITS.keys)refuse('invalid_keys',`at most ${CATALOG_LIMITS.keys} keys`);
 return keys.map(k=>{
  const members=isObject(k)&&THUMBPRINT_MEMBERS[k.kty];if(!members)refuse('invalid_keys','unsupported key type');
  const pub={};
  for(const m of members){
   if(typeof k[m]!=='string'||k[m].length>2048||(m!=='kty'&&m!=='crv'&&!B64URL.test(k[m])))refuse('invalid_keys','invalid key member');pub[m]=k[m];
  }
  let key;try{key=createPublicKey({key:pub,format:'jwk'});}catch{refuse('invalid_keys','key cannot be imported');}
  const kid=typeof k.kid==='string'&&k.kid.length<=200&&!BAD_TEXT.test(k.kid)?k.kid:null;
  return {kid,kty:pub.kty,crv:pub.crv||null,key,thumbprint:createHash('sha256').update(canonical(pub)).digest('base64url')};
 });
}
function decodeHeader(value){
 if(typeof value!=='string'||!value||value.length>4096||!B64URL.test(value))return null;
 try{const header=JSON.parse(Buffer.from(value,'base64url').toString('utf8'));return isObject(header)?checkTree(header):null;}catch{return null;}
}
export function checkCardSignatures(card,keys){
 if(card.signatures===undefined)return {status:'absent',signatures:[]};
 if(!Array.isArray(card.signatures)||!card.signatures.length)return {status:'malformed',signatures:[]};
 const {signatures,...unsigned}=card,payload=Buffer.from(canonical(unsigned)).toString('base64url');
 const results=signatures.slice(0,CATALOG_LIMITS.signatures).map(s=>{
  const header=isObject(s)?decodeHeader(s.protected):null;
  if(!header||typeof s.signature!=='string'||s.signature.length>2048||!B64URL.test(s.signature))return {status:'malformed'};
  const field=(name,max)=>typeof header[name]==='string'&&header[name].length<=max&&!BAD_TEXT.test(header[name])?header[name]:null;
  const out={alg:field('alg',20),kid:field('kid',200),jku:field('jku',1000)};
  const spec=Object.hasOwn(ALGORITHMS,out.alg)?ALGORITHMS[out.alg]:null;
  if(!spec||header.crit!==undefined||header.b64===false)return {...out,status:'unsupported'};
  const candidates=keys.filter(k=>k.kty===spec.kty&&(!spec.crv||k.crv===spec.crv)&&(!out.kid||!k.kid||k.kid===out.kid));
  if(!candidates.length)return {...out,status:'no_supplied_key'};
  const input=Buffer.from(`${s.protected}.${payload}`),signature=Buffer.from(s.signature,'base64url');
  for(const k of candidates){
   const key=spec.dsa?{key:k.key,dsaEncoding:'ieee-p1363'}
    :spec.pss?{key:k.key,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:constants.RSA_PSS_SALTLEN_DIGEST}:k.key;
   let ok=false;try{ok=verifySignature(spec.hash,input,key,signature);}catch{}
   if(ok)return {...out,status:'verified',keyThumbprint:k.thumbprint};
  }
  return {...out,status:'invalid'};
 });
 const statuses=new Set(results.map(r=>r.status));
 const status=statuses.has('verified')?'verified':statuses.has('invalid')?'invalid':statuses.has('no_supplied_key')?'unverified'
  :statuses.has('unsupported')?'unsupported':'malformed';
 return {status,signatures:results};
}

const slug=value=>String(value).toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'').slice(0,60)||'agent';
const suggestedId=(prefix,name,key)=>`${prefix}.${slug(name)}.${createHash('sha256').update(key).digest('hex').slice(0,10)}`;
function mapText(value,max,field,from,mapped,dropped){
 if(value===undefined)return undefined;const t=text(value,max);
 if(t.value!==undefined){mapped.push({field,from});return t.value;}dropped.push({field:from,reason:t.reason});return undefined;
}
const report=dropped=>dropped.slice(0,100);

function mapAgentCard(card,{keys,locator}){
 if(!isObject(card))refuse('not_an_object','an Agent Card is a JSON object');
 const mapped=[],dropped=[],endpoint=endpointOf(card);
 const name=mapText(card.name,200,'name','name',mapped,dropped);
 if(name===undefined)return {outcome:'rejected',reason:'missing_name',mapped,dropped:report(dropped)};
 if(!endpoint)return {outcome:'rejected',reason:'missing_endpoint',mapped,dropped:report(dropped)};
 const purpose=mapText(card.description,1000,'purpose','description',mapped,dropped);
 const version=mapText(card.version,100,'fingerprint.version','version',mapped,dropped);
 for(const k of Object.keys(card))if(!['name','description','version'].includes(k))dropped.push({field:k,reason:A2A_DROPPED[k]||'unknown_field'});
 const key=`a2a:${endpoint.address}${endpoint.tenant?`#tenant=${endpoint.tenant}`:''}`;
 const locatorHost=hostOf(locator),signature=checkCardSignatures(card,keys);
 const interfaceVersion=Array.isArray(card.supportedInterfaces)?card.supportedInterfaces.find(isObject)?.protocolVersion:card.protocolVersion;
 return {outcome:'mapped',key,suggestedId:suggestedId('a2a',name,key),draft:{name,owner:'',purpose:purpose??'',fingerprintVersion:version??null},
  mapped,dropped:report(dropped),provenance:{format:CATALOG_FORMATS.a2a,formatVersion:text(interfaceVersion,20).value??'unknown',
   endpoint:endpoint.address,...(endpoint.tenant?{endpointTenant:endpoint.tenant}:{}),
   locatorMatchesEndpoint:locatorHost?locatorHost===new URL(endpoint.address.replace(/^grpc:/,'https:')).hostname:null,
   signature:{status:signature.status,signatures:signature.signatures}}};
}

function mapBackstageEntity(entity,agentTypes){
 if(!isObject(entity))return {outcome:'rejected',reason:'not_an_object',mapped:[],dropped:[]};
 const kind=typeof entity.kind==='string'?entity.kind:null,metadata=isObject(entity.metadata)?entity.metadata:{},spec=isObject(entity.spec)?entity.spec:{};
 if(typeof entity.apiVersion!=='string'||!entity.apiVersion.startsWith('backstage.io/')||!kind)
  return {outcome:'rejected',reason:'not_a_backstage_entity',mapped:[],dropped:[]};
 const entityName=typeof metadata.name==='string'&&/^[a-zA-Z0-9]+(?:[-_.][a-zA-Z0-9]+)*$/.test(metadata.name)&&metadata.name.length<=63?metadata.name:null;
 const namespace=metadata.namespace===undefined?'default':typeof metadata.namespace==='string'&&/^[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*$/.test(metadata.namespace)
  &&metadata.namespace.length<=63?metadata.namespace:null;
 if(!entityName||!namespace)return {outcome:'rejected',reason:'invalid_entity_name',mapped:[],dropped:[]};
 const ref=`${kind}:${namespace}/${entityName}`.toLowerCase();
 if(kind.toLowerCase()!=='component'||typeof spec.type!=='string'||!agentTypes.includes(spec.type.toLowerCase()))
  return {outcome:'skipped',reason:'not_an_agent_entity',entityRef:ref,detail:{kind,type:typeof spec.type==='string'?spec.type.slice(0,100):null},
   mapped:[],dropped:[]};
 const mapped=[],dropped=[];
 const title=mapText(metadata.title,200,'name','metadata.title',mapped,dropped);
 const name=title??(mapped.push({field:'name',from:'metadata.name'}),entityName);
 const purpose=mapText(metadata.description,1000,'purpose','metadata.description',mapped,dropped);
 const owner=mapText(spec.owner,200,'owner','spec.owner',mapped,dropped);
 for(const k of Object.keys(entity))if(!['apiVersion','kind','metadata','spec'].includes(k))
  dropped.push({field:k,reason:['relations','status'].includes(k)?'catalog_computed_not_trusted':'unknown_field'});
 for(const k of Object.keys(metadata))if(!['name','namespace','title','description'].includes(k))
  dropped.push({field:`metadata.${k}`,reason:BACKSTAGE_METADATA_DROPPED[k]||'unknown_field'});
 for(const k of Object.keys(spec))if(!['type','owner'].includes(k))dropped.push({field:`spec.${k}`,reason:BACKSTAGE_SPEC_DROPPED[k]||'unknown_field'});
 const key=`backstage:${ref}`;
 return {outcome:'mapped',key,suggestedId:suggestedId('backstage',entityName,key),entityRef:ref,
  draft:{name,owner:owner??'',purpose:purpose??'',fingerprintVersion:null},
  mapped,dropped:report(dropped),provenance:{format:CATALOG_FORMATS.backstage,formatVersion:entity.apiVersion.slice(0,60),entityRef:ref,
   signature:{status:'not_applicable',signatures:[]}}};
}

// A locator is the operator's note of where a document came from. URLs keep scheme, host and path only (no credentials,
// query or fragment, which may carry tokens); anything else is kept as bounded text.
export function normalizeLocator(value){
 if(value===undefined||value===null||value==='')return null;
 const t=text(value,1000);if(t.value===undefined)refuse('invalid_locator','locator must be plain text up to 1000 characters');
 try{const u=new URL(t.value);if(['https:','http:'].includes(u.protocol))return `${u.protocol}//${u.host}${u.pathname}`;}catch{}
 return t.value;
}
export function normalizeAgentTypes(value){
 if(value===undefined||value===null)return [...DEFAULT_AGENT_TYPES];
 if(!Array.isArray(value)||!value.length||value.length>CATALOG_LIMITS.agentTypes||value.some(v=>typeof v!=='string'||!/^[a-z0-9:+#._-]{1,63}$/i.test(v)))
  refuse('invalid_agent_types',`agentTypes is a list of 1-${CATALOG_LIMITS.agentTypes} Backstage spec.type values`);
 return [...new Set(value.map(v=>v.toLowerCase()))];
}

// One submitted document to per-entity mapping results. Each result carries the digests the registry keeps: the bytes as
// submitted (documentDigest) and the parsed entity (entityDigest, the idempotency basis, so whitespace, comments, key
// order or a sibling entity in the same file never create a new version).
export function mapCatalogDocument({format,content,locator},{keys=[],agentTypes=DEFAULT_AGENT_TYPES}={}){
 if(!Object.hasOwn(CATALOG_FORMATS,format))refuse('unknown_format','format is a2a or backstage');
 if(typeof content!=='string')refuse('invalid_content','content is the document text');
 const bytes=Buffer.byteLength(content,'utf8');
 if(bytes>CATALOG_LIMITS.documentBytes)refuse('too_large',`document exceeds ${CATALOG_LIMITS.documentBytes} bytes`);
 const documentDigest=sha256(content),where=normalizeLocator(locator);
 let values;
 if(format==='a2a')values=[parseJson(content)];
 else if(/^\s*[{[]/.test(content)){
  // A JSON entity, a JSON array of entities, or a catalog API response ({"items":[...]}).
  const parsed=parseJson(content);values=Array.isArray(parsed)?parsed:isObject(parsed)&&Array.isArray(parsed.items)&&!parsed.apiVersion?parsed.items:[parsed];
 }else values=parseYamlSubset(content);
 if(values.length>CATALOG_LIMITS.entities)refuse('too_many_entities',`at most ${CATALOG_LIMITS.entities} entities per document`);
 const results=values.map((value,index)=>{
  const result=format==='a2a'?mapAgentCard(value,{keys,locator:where}):mapBackstageEntity(value,agentTypes);
  return {...result,entityIndex:index,entityDigest:sha256(canonical(value))};
 });
 return {format:CATALOG_FORMATS[format],documentDigest,bytes,locator:where,results};
}
