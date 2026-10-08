// Reads A2A Agent Cards and Backstage catalog files (local files or URLs fetched on this machine) and imports them into the
// agent registry as discovered entries (docs/agent-registry.md). Preview is the default and contacts no vault.
//   node scripts/import-agent-catalog.mjs --a2a card.json|https://host/.well-known/agent-card.json --backstage catalog-info.yaml
//     [--jwks keys.json|https://...] [--agent-type ai-agent] [--write-request request.json]
//     [--send --base https://audit.example/ [--dry-run]]   (bearer token in EVIDSCOPE_TOKEN)
import {readFileSync,writeFileSync} from 'node:fs';
import {basename,resolve} from 'node:path';
import {CATALOG_LIMITS,isCatalogError,mapCatalogDocument,normalizeAgentTypes,normalizeKeys} from '../src/agent-catalog.mjs';

const loopback=url=>url.protocol==='http:'&&['127.0.0.1','[::1]','localhost'].includes(url.hostname);
// URLs are fetched here, by the operator, never by the vault: HTTPS (or loopback HTTP), no redirects, bounded size.
async function read(source,{fetchImpl=fetch,timeoutMs=10000}={}){
 if(/^https?:\/\//i.test(source)){
  const url=new URL(source);
  if(url.username||url.password||!(url.protocol==='https:'||loopback(url)))throw Error(`Use an HTTPS URL without credentials: ${url.origin}`);
  const response=await fetchImpl(url,{headers:{accept:'application/json, application/yaml, text/yaml, */*'},redirect:'error',
   signal:AbortSignal.timeout(timeoutMs)});
  if(!response.ok)throw Error(`Fetch failed: HTTP ${response.status} ${url.origin}${url.pathname}`);
  const chunks=[];let size=0;
  for await(const chunk of response.body||[]){
   if((size+=chunk.length)>CATALOG_LIMITS.documentBytes)throw Error(`Document exceeds ${CATALOG_LIMITS.documentBytes} bytes`);chunks.push(chunk);
  }
  return {content:Buffer.concat(chunks).toString('utf8'),locator:`${url.origin}${url.pathname}`};
 }
 const bytes=readFileSync(source);if(bytes.length>CATALOG_LIMITS.documentBytes)throw Error(`Document exceeds ${CATALOG_LIMITS.documentBytes} bytes`);
 return {content:bytes.toString('utf8'),locator:`file:${basename(source)}`};
}
export async function buildImportRequest({a2a=[],backstage=[],jwks,agentTypes,dryRun=false},options){
 const documents=[];
 for(const [format,sources] of [['a2a',a2a],['backstage',backstage]])for(const source of sources)documents.push({format,...await read(source,options)});
 if(!documents.length)throw Error('Give at least one --a2a or --backstage document');
 if(documents.length>CATALOG_LIMITS.documents)throw Error(`At most ${CATALOG_LIMITS.documents} documents per import`);
 const keys=jwks===undefined?undefined:JSON.parse((await read(jwks,options)).content);
 return {documents,...(keys?{keys}:{}),...(agentTypes?.length?{agentTypes}:{}),...(dryRun?{dryRun:true}:{})};
}
// The same mapping the vault runs, without the registry: conflicts and idempotency are known only to the vault (--dry-run).
export function previewImport(request){
 const settings={keys:normalizeKeys(request.keys),agentTypes:normalizeAgentTypes(request.agentTypes)};
 return {mode:'preview',documents:request.documents.map((d,index)=>{
  try{const {results,...document}=mapCatalogDocument(d,settings);return {index,...document,results};}
  catch(error){if(!isCatalogError(error))throw error;return {index,format:d.format,locator:d.locator,rejected:{code:error.code,message:error.message}};}
 })};
}
export async function sendImport(request,{base,token,fetchImpl=fetch,timeoutMs=30000}){
 const url=new URL(base);
 if(url.username||url.password||url.search||url.hash||url.pathname!=='/'||!(url.protocol==='https:'||loopback(url)))
  throw Error('Use undecorated HTTPS or loopback audit base');
 if(!token)throw Error('Set EVIDSCOPE_TOKEN to a reviewer or admin bearer token');
 const response=await fetchImpl(new URL('/api/registry/import',url),{method:'POST',headers:{'content-type':'application/json',authorization:`Bearer ${token}`},
  body:JSON.stringify(request),redirect:'error',signal:AbortSignal.timeout(timeoutMs)});
 const body=await response.json().catch(()=>({error:'non-JSON response'}));
 if(response.status!==200)throw Error(`Import failed: HTTP ${response.status} ${body.error||''}`);
 return {mode:request.dryRun?'dry_run':'imported',...body};
}
const failed=result=>result.mode==='preview'?result.documents.some(d=>d.rejected||d.results?.some(r=>r.outcome==='rejected'))
 :result.summary.rejected+result.summary.conflict+result.summary.rejectedDocuments>0;

if(process.argv[1]&&resolve(process.argv[1])===resolve('scripts/import-agent-catalog.mjs')){
 const args=process.argv.slice(2),all=key=>args.flatMap((a,i)=>a===key?[args[i+1]]:[]),value=key=>all(key)[0];
 if(!args.includes('--a2a')&&!args.includes('--backstage'))
  throw Error('Usage: --a2a card.json|URL --backstage catalog-info.yaml|URL [--jwks keys.json|URL] [--agent-type t] [--write-request f]'
   +' [--send --base URL [--dry-run]]');
 const request=await buildImportRequest({a2a:all('--a2a'),backstage:all('--backstage'),jwks:value('--jwks'),agentTypes:all('--agent-type'),
  dryRun:args.includes('--dry-run')});
 if(value('--write-request'))writeFileSync(value('--write-request'),JSON.stringify(request,null,1)+'\n',{mode:0o600});
 const result=args.includes('--send')?await sendImport(request,{base:value('--base'),token:process.env.EVIDSCOPE_TOKEN}):previewImport(request);
 console.log(JSON.stringify(result,null,2));
 if(failed(result))process.exitCode=1;
}
