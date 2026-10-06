import * as oidc from 'openid-client';
import {randomBytes,randomUUID,createHash,createHmac} from 'node:crypto';
import {digest,equal} from './crypto.mjs';
import {fail,identifier,cleanText} from './model.mjs';
import {createIdentityState} from './identity-state.mjs';

const humanRoles=new Set(['auditor','reviewer','admin']);
const random=()=>randomBytes(32).toString('base64url');
const hash=value=>createHash('sha256').update(value).digest('hex');
function cookies(header){
 const result=new Map();if(typeof header!=='string')return result;
 for(const part of header.split(';')){const at=part.indexOf('=');if(at<0)continue;const name=part.slice(0,at).trim(),value=part.slice(at+1).trim();if(result.has(name))fail(400,'중복 인증 쿠키');result.set(name,value);}
 return result;
}
function address(value,local,originOnly=false,allowQuery=false){
 const url=new URL(value);
 if(url.username||url.password||url.hash||!allowQuery&&url.search||originOnly&&url.pathname!=='/')throw Error('Invalid OIDC address');
 if(url.protocol!=='https:'&&!(local&&url.protocol==='http:'&&['127.0.0.1','[::1]'].includes(url.hostname)))throw Error('OIDC requires HTTPS; HTTP is limited to explicit synthetic loopback');
 return url;
}
function bounded(value,fallback,min,max){const n=value??fallback;if(!Number.isInteger(n)||n<min||n>max)throw Error('Invalid OIDC time limit');return n;}

export function createIdentity({config,store,now=()=>Date.now()}){
 const settings=config.oidc;
 if(!settings?.enabled){if(config.profile==='enterprise')throw Error('Enterprise profile requires OIDC');return {enabled:false,bindings:[],authenticate:()=>null,http:async(method,url)=>url.pathname==='/auth/config'&&method==='GET'?{status:200,body:{mode:'local'}}:undefined,access:()=>undefined};}
 const local=settings.syntheticLocalIdp===true&&config.profile==='synthetic-local';
 if(settings.syntheticLocalIdp===true&&!local)throw Error('Synthetic IdP transport is forbidden in enterprise profile');
 address(settings.issuer,local);
 const issuer=settings.issuer,origin=address(settings.publicOrigin,local,true).origin;
 if(issuer.includes('/.well-known/'))throw Error('Configure the issuer, not a discovery document URL');
 if(typeof settings.clientId!=='string'||!settings.clientId||typeof settings.clientSecret!=='string'||settings.clientSecret.length<16)throw Error('OIDC confidential client settings required');
 const ttl=bounded(settings.sessionTtlSeconds,900,60,3600)*1000,idle=bounded(settings.idleTtlSeconds,300,30,1800)*1000,maxAge=bounded(settings.maxAuthenticationAgeSeconds,300,30,3600);
 const acr=settings.requiredAcrValues??[];if(!Array.isArray(acr)||acr.some(x=>typeof x!=='string'||!x||x.length>200))throw Error('Invalid required ACR values');
 if(!Array.isArray(settings.bindings)||!settings.bindings.length)throw Error('OIDC subject bindings required');
 const bindings=settings.bindings.map(b=>{if(typeof b.subject!=='string'||!b.subject||b.subject.length>256||!humanRoles.has(b.role))throw Error('Invalid OIDC subject binding');return {id:identifier(b.id),tenant:identifier(b.tenant),role:b.role,subject:b.subject,issuer};});
 if(new Set(bindings.map(b=>b.id)).size!==bindings.length||new Set(bindings.map(b=>b.subject)).size!==bindings.length||bindings.some(b=>(config.principals||[]).some(p=>p.id===b.id)))throw Error('OIDC principal or issuer/subject collision');
 const byId=new Map(bindings.map(b=>[b.id,b])),bySubject=new Map(bindings.map(b=>[b.subject,b]));
 const prefix=local?'evidscope-':'__Host-evidscope-',sessionName=prefix+'session',flowName=prefix+'flow';
 const flows=new Map(),sessions=new Map(),csrfKey=randomBytes(32);
 const cookie=(name,value,seconds)=>`${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${seconds}${local?'':'; Secure'}`;
 const response=(status,body={},headers={})=>({status,body,headers});
 const csrf=raw=>createHmac('sha256',csrfKey).update(raw).digest('base64url');
 const callback=origin+'/auth/callback';let clientPromise;
 const allowedOrigins=new Set([new URL(issuer).origin,...(settings.allowedEndpointOrigins||[]).map(v=>address(v,local,true).origin)]);
 const restrictedFetch=async(url,options)=>{
  const target=new URL(typeof url==='string'?url:url.href);
  address(target.href,local,false,true);if(!allowedOrigins.has(target.origin))throw Error('OIDC endpoint origin not configured');
  const res=await fetch(url,{...options,redirect:'error'});
  // Bound metadata, JWKS and token responses before handing them to the protocol library.
  const chunks=[];let bytes=0;for await(const chunk of res.body||[]){bytes+=chunk.length;if(bytes>1024*1024)throw Error('OIDC response limit');chunks.push(chunk);}
  return new Response(Buffer.concat(chunks),{status:res.status,headers:res.headers});
 };
 async function client(){
  if(!clientPromise)clientPromise=oidc.discovery(new URL(issuer),settings.clientId,{id_token_signed_response_alg:'RS256'},oidc.ClientSecretPost(settings.clientSecret),{timeout:4,[oidc.customFetch]:restrictedFetch,execute:[oidc.enableNonRepudiationChecks,...(local?[oidc.allowInsecureRequests]:[])]}).then(c=>{
   const metadata=c.serverMetadata();if(metadata.issuer!==issuer)throw Error('OIDC issuer mismatch');
   for(const name of ['authorization_endpoint','token_endpoint','jwks_uri']){const url=address(metadata[name],local,false,true);if(!allowedOrigins.has(url.origin))throw Error('OIDC endpoint origin not configured');}
   return c;
  }).catch(error=>{clientPromise=null;throw error;});
  return clientPromise;
 }
 let identityState;
 function state(binding){identityState??=createIdentityState(store);return identityState(binding);}
 function cleanup(){const at=now();for(const [key,f] of flows)if(f.expires<=at)flows.delete(key);for(const [key,s] of sessions)if(s.expires<=at||s.lastSeen+idle<=at)sessions.delete(key);}
 function audit(binding,operation,sessionId){store.transaction(()=>store.append(binding.tenant,'identity_session',{id:randomUUID(),principalId:binding.id,operation,...(sessionId?{sessionId}:{})},binding.id));}
 function authenticate(headers,method='GET'){
  const raw=cookies(headers.cookie).get(sessionName);if(!raw)return null;
  if(headers.authorization)fail(400,'인증 자격을 혼합할 수 없습니다');
  cleanup();const s=sessions.get(hash(raw)),binding=s&&byId.get(s.principalId);
  if(!s||!binding)fail(401,'로그인 세션이 없거나 만료되었습니다');
  const access=state(binding);
  if(access.disabled||access.epoch!==s.epoch||digest(binding)!==s.bindingHash){sessions.delete(hash(raw));fail(401,'회수되거나 변경된 권한입니다');}
  if(method!=='GET'&&(headers.origin!==origin||!equal(headers['x-evid-csrf']||'',csrf(raw))))fail(403,'세션 변경 요청의 출처 또는 CSRF 검증 실패');
  s.lastSeen=now();return {id:binding.id,tenant:binding.tenant,role:binding.role,authentication:'oidc',sessionId:s.id};
 }
 async function http(method,url,headers={}){
  const path=url.pathname;
  if(path==='/auth/config'&&method==='GET')return response(200,{mode:'oidc',loginPath:'/auth/login'});
  if(path==='/auth/login'&&method==='GET'){
   cleanup();if(flows.size>=1000)fail(429,'로그인 요청 한도 초과');
   const c=await client(),browser=random(),stateValue=oidc.randomState(),nonce=oidc.randomNonce(),verifier=oidc.randomPKCECodeVerifier();
   const location=oidc.buildAuthorizationUrl(c,{redirect_uri:callback,response_type:'code',scope:'openid',state:stateValue,nonce,code_challenge:await oidc.calculatePKCECodeChallenge(verifier),code_challenge_method:'S256',max_age:String(maxAge),...(acr.length?{acr_values:acr.join(' ')}:{})});
   flows.set(hash(stateValue),{state:stateValue,nonce,verifier,browserHash:hash(browser),expires:now()+300000});
   return response(302,{}, {'location':location.href,'set-cookie':[cookie(flowName,browser,300)]});
  }
  if(path==='/auth/callback'&&method==='GET'){
   try{
    const values=url.searchParams.getAll('state'),browser=cookies(headers.cookie).get(flowName);if(values.length!==1||values[0].length>256||!browser)throw Error('flow');
    const flow=flows.get(hash(values[0]));if(!flow||flow.expires<=now()||!equal(flow.browserHash,hash(browser)))throw Error('flow');
    flows.delete(hash(values[0]));
    const current=new URL(callback);current.search=url.search;
    const tokens=await oidc.authorizationCodeGrant(await client(),current,{pkceCodeVerifier:flow.verifier,expectedState:flow.state,expectedNonce:flow.nonce,idTokenExpected:true,maxAge});
    const claims=tokens.claims(),binding=claims&&bySubject.get(claims.sub);
    if(!binding||claims.iss!==issuer||acr.length&&!acr.includes(claims.acr))throw Error('binding');
    const access=state(binding);if(access.disabled)throw Error('disabled');
    cleanup();if(sessions.size>=10000)throw Error('session_limit');
    const raw=random(),session={id:randomUUID(),principalId:binding.id,bindingHash:digest(binding),epoch:access.epoch,issued:now(),lastSeen:now(),expires:now()+ttl};
    audit(binding,'session_authorized',session.id);
    const previous=cookies(headers.cookie).get(sessionName);if(previous)sessions.delete(hash(previous));
    sessions.set(hash(raw),session);
    return response(302,{}, {'location':'/','set-cookie':[cookie(flowName,'',0),cookie(sessionName,raw,ttl/1000)]});
   }catch{
    // Never expose token responses, claims, authorization codes or callback URLs.
    return response(302,{}, {'location':'/?auth=failed','set-cookie':[cookie(flowName,'',0)]});
   }
  }
  if(path==='/auth/session'&&method==='GET'){
   const p=authenticate(headers);if(!p)fail(401,'로그인이 필요합니다');const raw=cookies(headers.cookie).get(sessionName),s=sessions.get(hash(raw));
   return response(200,{principal:{id:p.id,tenant:p.tenant,role:p.role},csrfToken:csrf(raw),expiresAt:new Date(s.expires).toISOString()});
  }
  if(path==='/auth/logout'&&method==='POST'){
   const p=authenticate(headers,method);if(!p)fail(401,'로그인이 필요합니다');audit(byId.get(p.id),'session_logout',p.sessionId);sessions.delete(hash(cookies(headers.cookie).get(sessionName)));
   return response(200,{loggedOut:true,idpSessionEnded:false},{'set-cookie':[cookie(sessionName,'',0)]});
  }
 }
 function access(p,method,path,body){
  if(!path.startsWith('/api/access'))return undefined;
  if(p.role!=='admin')fail(403,'접근 관리에는 관리자 권한이 필요합니다');
  if(path==='/api/access'&&method==='GET'){
   cleanup();return {subjects:bindings.filter(b=>b.tenant===p.tenant).map(b=>{const current=state(b);return {id:b.id,tenant:b.tenant,role:b.role,disabled:current.disabled,sessionCount:[...sessions.values()].filter(s=>s.principalId===b.id&&s.epoch===current.epoch).length};}),limitations:['설정된 issuer와 subject만 로그인할 수 있습니다. 역할·테넌트는 서버 설정에서 변경합니다.','접근 중지는 새 로그인과 기존 세션 모두에 적용됩니다. 세션 회수만 하면 다시 로그인할 수 있습니다.','로그아웃은 EvidScope 세션을 종료하며 조직 IdP 세션을 종료하지 않습니다.']};
  }
  if(/^\/api\/access\/subjects\/[^/]+$/.test(path)&&method==='POST'){
   const binding=byId.get(decodeURIComponent(path.split('/').at(-1)));if(!binding||binding.tenant!==p.tenant)fail(404,'동일 테넌트 계정을 찾을 수 없습니다');
   if(!['disable','enable','revoke_sessions'].includes(body.action))fail(400,'접근 관리 작업 오류');
   if(binding.id===p.id&&body.action==='disable')fail(409,'자기 계정 접근 중지는 허용하지 않습니다');
   const reason=cleanText(body.reason,1000);if(!reason.trim())fail(400,'접근 변경 사유가 필요합니다');
   const result=store.transaction(()=>{const current=state(binding);return store.put(p,'identity_access',binding.id,{id:binding.id,epoch:current.epoch+1,disabled:body.action==='disable'?true:body.action==='enable'?false:current.disabled,action:body.action,reason,changedBy:p.id,changedAt:new Date(now()).toISOString()});});
   for(const [key,s] of sessions)if(s.principalId===binding.id)sessions.delete(key);return result;
  }
 }
 return {enabled:true,origin,bindings,authenticate,http,access};
}
