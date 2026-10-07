// Pull distribution to enforcement points and propagation evidence (docs/kill-switch.md). Enforcement points authenticate
// with their existing `enforcement` source credential (bearer token) and see only their own tenant:
//   GET  /api/enforcement/opa/bundles/<name>   OPA Bundle Service API (gzip tar, ETag / If-None-Match → 304)
//   GET  /api/enforcement/deny-list            DSSE-signed JSON deny-list for gateways without OPA (same ETag behaviour)
//   POST /api/enforcement/opa/status[/<part>]  OPA Status API report; each activation of an EvidScope revision becomes a
//                                              signed `bundle_activation` record, everything else in the report is dropped
// The vault makes no outbound calls: enforcement points pull, and report what they activated.
import {createHash} from 'node:crypto';
import {canonical} from './crypto.mjs';
import {fail,validateEvent,rawResponse} from './model.mjs';
import {appendSourceEvent,assertBatchAnalysisCapacity,receiptMatch} from './event-ingest.mjs';
import {STOP_ORDER_TYPE,contentRevisions,latestContentRow,parseRevision,revisionOf} from './stop-orders.mjs';
import {denyList,enforcementState,opaBundle,signDenyList} from './enforcement-bundle.mjs';

export const ENFORCEMENT_PREFIX='/api/enforcement/';
const BUNDLE_PATH=/^\/api\/enforcement\/opa\/bundles\/([A-Za-z0-9._-]{1,64})$/;
export const STATUS_PATH=/^\/api\/enforcement\/opa\/status(?:\/[A-Za-z0-9._-]{1,64})?$/;
export const STATUS_MAX_BYTES=64*1024;
const MAX_BUNDLES=64;
// Status fields kept (allowlist): the instance id and OPA version labels, and per bundle its name, active revision and last
// successful activation. Other labels, errors, messages, metrics, plugins, decision-log and discovery status are dropped.
const INSTANCE=/^[A-Za-z0-9._:-]{1,120}$/,VERSION=/^[A-Za-z0-9._+-]{1,40}$/,BUNDLE_NAME=/^[A-Za-z0-9._/:-]{1,128}$/;
const TIME=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)$/;

export const enforcementPoint=p=>{if(p.role!=='source'||p.kind!=='enforcement')fail(403,'집행 지점(enforcement 출처) 자격이 필요합니다');};

export function createEnforcement({store,policyObjects,key,signer,verifiedActions}){
 function snapshot(p){
  return store.read(()=>{
   let result;try{result=store.cachedRegistryRows(p.tenant);}catch(error){if(error?.status)throw error;fail(409,'레지스트리 서명 원장을 검증할 수 없습니다');}
   if(result.oversized)fail(413,'레지스트리 기록 한도 초과: 묶음을 만들 수 없습니다');
   const last=latestContentRow(result.rows),revision=revisionOf(last);
   return {revision,mtime:last?Date.parse(last.recordedAt):0,entries:[...policyObjects(p,'agent_registry').values()],
    orders:[...policyObjects(p,STOP_ORDER_TYPE).values()]};
  });
 }
 // The ETag names the revision (and the signing key when bundles are signed), so an unchanged ledger answers 304.
 const etagOf=(revision,suffix='')=>`"${revision}${suffix}"`;
 const notModified=(headers,etag)=>String(headers['if-none-match']||'').split(',').map(v=>v.trim().replace(/^W\//,'')).includes(etag);
 function serve(p,headers,suffix,render){
  const view=snapshot(p),etag=etagOf(view.revision,suffix);
  if(notModified(headers,etag))return rawResponse(304,{ETag:etag},Buffer.alloc(0));
  return render(view,etag);
 }
 function bundle(p,headers){
  return serve(p,headers,signer?`+${signer.alg}.${signer.keyId}`:'',(view,etag)=>{
   const state=enforcementState({tenant:p.tenant,revision:view.revision,entries:view.entries,orders:view.orders});
   return rawResponse(200,{'Content-Type':'application/gzip',ETag:etag},opaBundle(state,{mtime:view.mtime,signer}));
  });
 }
 function deny(p,headers){
  return serve(p,headers,'',(view,etag)=>{
   const list=denyList(enforcementState({tenant:p.tenant,revision:view.revision,entries:view.entries,orders:view.orders}));
   return rawResponse(200,{'Content-Type':'application/json; charset=utf-8',ETag:etag},Buffer.from(JSON.stringify(signDenyList(list,key)),'utf8'));
  });
 }
 // Status report → activation records. A bundle whose active revision is not one this tenant's ledger produced is ignored
 // (another bundle of the same OPA, or a revision of another tenant); nothing from it is stored.
 function status(p,body){
  let report;try{report=JSON.parse(body);}catch{fail(400,'JSON 형식 오류');}
  if(!report||typeof report!=='object'||Array.isArray(report))fail(400,'OPA 상태 보고는 JSON 객체여야 합니다');
  const labels=report.labels&&typeof report.labels==='object'&&!Array.isArray(report.labels)?report.labels:{};
  if(typeof labels.id!=='string'||!INSTANCE.test(labels.id))fail(400,'OPA 상태 보고에 labels.id(인스턴스 식별자)가 필요합니다');
  const bundles=report.bundles===undefined||report.bundles===null?{}:report.bundles;
  if(typeof bundles!=='object'||Array.isArray(bundles))fail(400,'bundles는 객체여야 합니다');
  if(Object.keys(bundles).length>MAX_BUNDLES)fail(413,`묶음 상태는 최대 ${MAX_BUNDLES}개입니다`);
  const version=typeof labels.version==='string'&&VERSION.test(labels.version)?labels.version:undefined;
  const ignored={},skip=reason=>{ignored[reason]=(ignored[reason]||0)+1;};
  return store.transaction(()=>{
   verifiedActions(p);
   let rows;try{rows=store.cachedRegistryRows(p.tenant);}catch(error){if(error?.status)throw error;fail(409,'레지스트리 서명 원장을 검증할 수 없습니다');}
   if(rows.oversized)fail(413,'레지스트리 기록 한도 초과');
   const revisions=contentRevisions(rows.rows),fresh=[];
   for(const [key,b] of Object.entries(bundles)){
    if(!b||typeof b!=='object'||Array.isArray(b)){skip('invalid');continue;}
    if(!parseRevision(b.active_revision)){skip('foreign_bundle');continue;}
    if(!revisions.has(b.active_revision)){skip('unknown_revision');continue;}
    const name=typeof b.name==='string'?b.name:key,activated=b.last_successful_activation;
    if(!BUNDLE_NAME.test(name)){skip('invalid');continue;}
    if(typeof activated!=='string'||!TIME.test(activated)||!Number.isFinite(Date.parse(activated))){skip('no_activation');continue;}
    const occurredAt=new Date(activated).toISOString();
    const id='opa-activation-'+createHash('sha256').update(canonical([labels.id,name,b.active_revision,occurredAt])).digest('hex').slice(0,40);
    const raw={id,kind:'bundle_activation',occurredAt,actionId:id,traceId:id,enforcementPointId:labels.id,engine:'opa',...(version?{engineVersion:version}:{}),
     bundleName:name,bundleRevision:b.active_revision};
    try{fresh.push(validateEvent(raw,p));}catch{skip('invalid');}
   }
   let accepted=0,duplicates=0;const add=[];
   for(const e of fresh){
    const prev=receiptMatch(store,p.tenant,p.id,e.id,e.fingerprint);
    if(prev==='same'){duplicates++;continue;}
    if(prev){skip('conflict');continue;}
    add.push(e);
   }
   if(add.length)assertBatchAnalysisCapacity(store,p.tenant,add.map(e=>e.actionId));
   for(const e of add){appendSourceEvent(store,p,e);accepted++;}
   return {accepted,duplicates,ignored,instance:labels.id,durability:'sqlite_full_commit'};
  });
 }
 function handle(p,method,url,headers,body){
  const path=url.pathname;if(!path.startsWith(ENFORCEMENT_PREFIX))return undefined;
  enforcementPoint(p);
  if(method==='GET'&&BUNDLE_PATH.test(path))return bundle(p,headers);
  if(method==='GET'&&path==='/api/enforcement/deny-list')return deny(p,headers);
  if(method==='POST'&&STATUS_PATH.test(path))return status(p,body);
  fail(404,'지원하지 않는 집행 지점 경로입니다');
 }
 return {handle};
}
