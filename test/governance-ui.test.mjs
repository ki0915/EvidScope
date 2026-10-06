import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';
import {createHash,webcrypto} from 'node:crypto';

class Element {
  constructor(tag,className='',text=''){this.tagName=tag.toUpperCase();this.className=className;this.ownText=String(text);this.children=[];this.events={};this.value='';}
  get textContent(){return this.ownText+this.children.map(child=>child.textContent).join('');}
  set textContent(value){this.ownText=String(value);this.children=[];}
  set innerHTML(_){throw Error('Unsafe HTML rendering');}
  append(...nodes){this.children.push(...nodes);}
  replaceChildren(...nodes){this.children=[...nodes];this.ownText='';}
  setAttribute(name,value){this[name]=value;}
  addEventListener(name,handler){this.events[name]=handler;}
  querySelector(selector){return walk(this).find(node=>node!==this&&(selector.startsWith('.')?node.className.split(' ').includes(selector.slice(1)):node.tagName===selector.toUpperCase()));}
}
const walk=node=>[node,...node.children.flatMap(walk)];
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const plain=value=>JSON.parse(JSON.stringify(value));
const data=()=>({systems:[{id:'credit',name:'신용평가',owner:'검토자',purpose:'신용평가',markets:['KR']}],requirements:[],tasks:[],governanceDocuments:[]});
function fixture({governance=data(),report,respond}={}){
  const calls=[],downloads=[],notices=[],details=[],state={current:true,closed:0},el=(...args)=>new Element(...args);
  let uploaded;
  const sandbox={el,Node:Element,crypto:webcrypto,btoa,atob,AbortController,setTimeout,clearTimeout,token:'reviewer-token',authEpoch:1,authMode:'local',csrfToken:'',
    document:{createElement:tag=>el(tag),createTextNode:text=>el('#text','',text)},date:value=>value||'미확인',localDate:value=>value||'',label:value=>value,stringify:value=>typeof value==='object'?JSON.stringify(value):String(value),badge:value=>el('span','',value),
    card:(title,description='')=>{const node=el('section'),head=el('div','card-header',title+' '+description);node.append(head);return node;},empty:(title,description)=>el('p','',title+' '+description),limits:items=>el('p','',(items||[]).join(' ')),jsonDetails:(title,value)=>el('details','',title+' '+JSON.stringify(value)),
    table:(headers,rows)=>{const node=el('table');for(const row of [headers,...rows]){const tr=el('tr');tr.append(...row.map(value=>value instanceof Element?value:el('td','',value)));node.append(tr);}return node;},
    FormData:class{constructor(form){this.values=form.values||{};}entries(){return Object.entries(this.values);}},
    fetch:async(path,options)=>{const body=options.body?JSON.parse(options.body):undefined,c={path,method:options.method,headers:options.headers,body:plain(body??null)};calls.push(c);
      let result=await respond?.(c);if(!result){let value={};if(path==='/api/governance')value=governance;else if(path.startsWith('/api/governance/report?'))value=report||{system:governance.systems[0],items:[]};else if(path==='/api/governance/documents'&&options.method==='POST'){uploaded={...body,displayName:body.name,version:1,bytes:Buffer.from(body.contentBase64,'base64').length,retentionUntil:'2031-10-06',verification:{status:'hash_verified_and_retrievable',checkedAt:'2026-10-06'}};value=uploaded;}else if(path.startsWith('/api/governance/documents/'))value=uploaded||governance.governanceDocuments[0];result={status:200,body:value};}
      return {status:result.status,ok:result.status>=200&&result.status<300,json:async()=>result.body};},
    showDetail:(title,node)=>details.push({title,node}),captureDetailContext:()=>({}),isCurrentDetail:()=>state.current,downloadArtifact:(name,type,body)=>downloads.push({name,type,body}),notice:(text,error)=>notices.push({text,error}),clearAuth:()=>{state.current=false;},$:()=>({close(){state.closed++;}}),navigate:async()=>{},inspect:()=>{},
  };
  const source=readFileSync('public/app.js','utf8');
  vm.runInNewContext(source.slice(source.indexOf('function button('),source.indexOf('function badge(')),sandbox);
  vm.runInNewContext(source.slice(source.indexOf('function field('),source.indexOf('function showDetail(')),sandbox);
  vm.runInNewContext(source.slice(source.indexOf('async function governanceView('),source.indexOf('function retentionItems(')),sandbox);
  return {sandbox,calls,downloads,notices,details,state,root:()=>details.at(-1)?.node};
}
const find=(root,name)=>walk(root).find(node=>node.name===name);
const click=async(f,title)=>{const node=walk(f.root()).find(node=>node.tagName==='BUTTON'&&node.textContent===title);assert.ok(node,title);await node.events.click();};
const submit=async(f,values)=>{const form=walk(f.root()).find(node=>node.tagName==='FORM');assert.ok(form);form.values=values;await form.events.submit({preventDefault(){}});return form;};
const selectedFile=(bytes,name='조치.txt')=>({name,type:'text/plain',size:bytes.length,arrayBuffer:async()=>Uint8Array.from(bytes).buffer});

test('document intake computes the actual binary digest, binds its system, and offers verified original download',async()=>{
  const f=fixture(),bytes=Buffer.concat([Buffer.from([0,255,13,10,234,176,128]),Buffer.alloc(9000,171)]);f.sandbox.governanceDocumentEditor(data());
  const input=find(f.root(),'documentFile');input.files=[selectedFile(bytes)];input.events.change();assert.equal(find(f.root(),'name').value,'조치.txt');
  await submit(f,{id:'  plan-v1  ',systemId:'credit',name:'  조치.txt  ',mediaType:'text/plain'});
  assert.deepEqual(f.calls[0].body,{id:'plan-v1',systemId:'credit',name:'조치.txt',mediaType:'text/plain',sha256:sha(bytes),contentBase64:bytes.toString('base64')});assert.equal(f.calls[0].headers.Authorization,'Bearer reviewer-token');
  assert.equal(f.calls[1].path,'/api/governance/documents/plan-v1');assert.match(f.root().textContent,/현재 파일 복구·SHA-256 일치 확인/);assert.match(f.root().textContent,/governance-document:plan-v1/);assert.match(f.root().textContent,/5년 경과 보존 실적을 입증하지 않습니다/);
  await click(f,'검증된 문서 파일 받기');assert.equal(f.calls.at(-1).path,'/api/governance/documents/plan-v1/export');assert.equal(f.downloads.length,1);assert.equal(f.downloads[0].name,'조치.txt');assert.deepEqual(Buffer.from(f.downloads[0].body),bytes);
});

test('dynamic file cap rejects oversized and empty files before reading or posting; default remains64KiB',async()=>{
  for(const size of [0,5]){const governance=data();governance.documentLimits={maximumBytes:4};const f=fixture({governance});f.sandbox.governanceDocumentEditor(governance);let reads=0;find(f.root(),'documentFile').files=[{size,arrayBuffer:async()=>{reads++;return new ArrayBuffer(size);}}];const form=await submit(f,{id:'doc',systemId:'credit',name:'small',mediaType:'text/plain'});assert.match(form.textContent,/1~4바이트/);assert.equal(reads,0);assert.equal(f.calls.length,0);}
  const f=fixture();f.sandbox.governanceDocumentEditor(data());assert.match(f.root().textContent,/65,536바이트/);const input=find(f.root(),'documentFile');input.files=[selectedFile(Buffer.from('a'))];f.state.current=false;const form=await submit(f,{id:'doc',systemId:'credit',name:'a',mediaType:'text/plain'});assert.match(form.textContent,/접속 상태가 변경/);assert.equal(f.calls.length,0);
});

test('document inventory keeps hostile metadata literal and never claims a metadata row proves retrieval',async()=>{
  const governance=data(),hostile='<img src=x onerror=alert(1)>';governance.governanceDocuments=[{id:'doc:@1',displayName:hostile,systemId:'credit',version:2,sha256:'a'.repeat(64),retentionUntil:'2031-10-06'}];const f=fixture({governance}),view=await f.sandbox.governanceView();
  assert.ok(view.textContent.includes(hostile));assert.ok(view.textContent.includes('버전'));assert.equal(walk(view).filter(node=>['IMG','SCRIPT'].includes(node.tagName)).length,0);assert.doesNotMatch(view.textContent,/현재 파일 복구·SHA-256 일치 확인/);
  f.details.push({node:view});await click(f,'복구·해시 확인');assert.equal(f.calls.at(-1).path,'/api/governance/documents/doc%3A%401');assert.match(f.root().textContent,/현재 파일 복구·해시 검증 미확인/);
});

test('changed versions, tampered export bytes and retrieval errors cannot produce a successful download',async()=>{
  const bytes=Buffer.from('original'),document={id:'doc',systemId:'credit',displayName:'원본.txt',version:1,bytes:bytes.length,sha256:sha(bytes),contentBase64:bytes.toString('base64'),verification:{status:'hash_verified_and_retrievable'}};
  for(const [change,reason] of [[{version:2},/개정되었습니다/],[{contentBase64:Buffer.from('tampered').toString('base64')},/크기·해시/]]){const f=fixture({respond:({path})=>({status:200,body:path.endsWith('/export')?{...document,...change}:document})});await f.sandbox.governanceDocumentDetail('doc');await click(f,'검증된 문서 파일 받기');assert.equal(f.downloads.length,0);assert.match(f.notices.at(-1).text,reason);}
  const f=fixture({respond:()=>({status:409,body:{error:'거버넌스 문서를 복구하거나 해시 검증할 수 없습니다'}})});await assert.rejects(f.sandbox.governanceDocumentDetail('doc'),/복구하거나 해시/);assert.equal(f.details.length,0);assert.equal(f.downloads.length,0);
});

test('technical gaps remain visible next to a human sufficient assessment and unknown checks are retained',async()=>{
  const hostile='<script>검증 항목</script>',report={system:{name:'신용평가',owner:'검토자',purpose:'신용평가'},items:[{requirement:{id:'KR-34-OVERSIGHT',title:'사람 감독'},status:'evidence_insufficient',technicalStatus:'oversight_review_record_missing',technicalEvidence:{status:'oversight_review_record_missing',supportsHumanAssessment:false,missingChecks:['oversight_review_record_missing',{code:'future_check',message:hostile},'new_check'],reasons:[{code:'oversight_plan_missing'}],limitations:['보고된 시험 결과만 대조함']},assessment:{applicability:'applicable',assessment:'sufficient',legalReview:'reviewed',owner:'검토자'}}]};
  const f=fixture({report});await f.sandbox.governanceReport('credit',[]);const text=f.root().textContent;
  for(const value of ['기술 증거','사람 평가','현재 모델·정책에 연결된 사람 감독 수행 기록 없음','사람 감독 계획 문서 없음','추가 검증 필요: new_check',hostile,'충분 평가만으로 검증 누락이 해소','법률 검토','보고된 시험 근거'])assert.ok(text.includes(value),value);
  assert.equal(walk(f.root()).filter(node=>node.tagName==='SCRIPT').length,0);assert.equal(f.calls.length,1);assert.equal(f.calls[0].method,'GET');
  const node=f.sandbox.governanceTechnicalEvidence({technicalEvidence:{status:'document_evidence_verified',supportsHumanAssessment:true}});assert.match(node.textContent,/법률 적용·충분성 판단은 별도/);
});

test('typed reported measurements translate alternatives and failure reasons without claiming independent proof or completed effort',()=>{
  const f=fixture(),node=f.sandbox.governanceTechnicalEvidence({technicalEvidence:{status:'authenticated_reported_measurement_supported',supportsHumanAssessment:true,missingChecks:['impact_assessment|impact_effort'],reasons:['generated_output_marking:measurement_not_passed:generationNoticeProvided','notice_pre_delivery:time_order_uncertain','user_protection:system_facts_hash_mismatch'],matchedChecks:[{checkType:'impact_effort',ref:'collector/record',documentHash:'a'.repeat(64),effortOnly:true}]}});
  for(const value of ['인증된 출처의 보고된 측정 근거 연결','기본권 영향평가 내용 또는 영향평가 노력·미완료 계획','생성형 AI 사용 안내','시계 오차로 선후관계 미확정','시스템 사실 버전 불일치','collector/record','a'.repeat(64),'완료했다는 증거가 아닙니다'])assert.ok(node.textContent.includes(value),value);
  assert.doesNotMatch(node.textContent,/독립 실측|준수 통과/);assert.equal(f.sandbox.governanceCheckLabel('unsupported_requirement'),'이 요구사항의 기술 검증 미지원');assert.equal(f.sandbox.governanceCheckLabel('typed_evidence_insufficient'),'보고된 측정·문서·수행 기록의 연결 근거 부족');
  const missing=f.sandbox.governanceTechnicalEvidence({technicalEvidence:{status:'human_applicability_basis_document_missing',supportsHumanAssessment:false,missingChecks:['applicability_basis_document']}});assert.match(missing.textContent,/비적용 판단을 뒷받침할 검증 문서 없음/);assert.match(missing.textContent,/비적용 판단 근거 문서/);assert.equal(f.sandbox.governanceCheckLabel('human_applicability_basis_document_verified'),'사람의 비적용 판단 근거 문서 복구·해시 확인');
});

test('supplier reliance shows reviewed bundle, scope and reviewer as literal text without extending its legal coverage',()=>{
 const f=fixture(),hostile='<img src=x onerror=alert(1)>',node=f.sandbox.governanceTechnicalEvidence({assessment:{assessment:'sufficient'},technicalEvidence:{status:'authenticated_reported_measurement_supported',supportsHumanAssessment:true,matchedChecks:[{checkType:'supplier_risk_reliance',ref:'authority/review',documentHash:'a'.repeat(64),supplierBundleRef:'supplier-bundle:'+hostile,supplierBundleHash:'a'.repeat(64),reviewer:hostile}],reasons:['supplier_risk_reliance:supplier_scope_not_verified','supplier_risk_reliance:measurement_not_passed:fullMeasureScopeReviewed']}});
 for(const text of ['공급사 위험관리 조치 검토','공급사 조치 활용 검토 근거','supplier-bundle:'+hostile,'a'.repeat(64),'담당 검토자',hostile,'제34조제1항제1~3호','사람 감독·문서 보관을 대체하지 않으며','법적 간주·충분성 판단은 별도','공급사 조치 범위·문서 복구 재검토 필요','해당 조치 전체 범위 검토'])assert.ok(node.textContent.includes(text),text);
 assert.equal(walk(node).filter(element=>['IMG','SCRIPT'].includes(element.tagName)).length,0);
 const legacy=f.sandbox.governanceTechnicalEvidence({technicalEvidence:{matchedChecks:[{checkType:'oversight_plan',ref:'old',documentHash:'b'.repeat(64)}]}});assert.ok(!legacy.textContent.includes('공급사 조치 활용 검토 근거'));
});

test('KR-33 optional request status stays visible beside a supported mandatory pre-review',async()=>{
 for(const [status,title,accepted] of [
  ['not_requested','요청하지 않음',false],
  ['request_state_unknown','요청 여부 미확인',false],
  ['request_receipt_missing','요청 접수 근거 없음',false],
  ['request_evidence_insufficient','요청 근거 부족·충돌',false],
  ['request_receipt_supported','요청 접수 보고 근거 연결',true],
 ]){
  const workflow={checkType:'high_impact_confirmation',required:false,status,supportsRequestReceipt:accepted,missingChecks:status==='request_receipt_missing'?['high_impact_confirmation']:[],reasons:status==='request_evidence_insufficient'?['high_impact_confirmation:authority_receipt_source_required']:[],matchedChecks:accepted?[{checkType:'high_impact_confirmation',ref:'authority/request-17',documentHash:'b'.repeat(64)}]:[],limitations:['합성 요청 보고를 실제 정부 접수의 진실성으로 보증하지 않습니다.']};
  const item={requirement:{id:'KR-33',title:'고영향 사전 검토'},status:'human_evidence_assessed',assessment:{applicability:'applicable',assessment:'sufficient',legalReview:'reviewed'},technicalEvidence:{status:'authenticated_reported_measurement_supported',supportsHumanAssessment:true,missingChecks:[],reasons:[],matchedChecks:[{checkType:'high_impact_pre_review',ref:'telemetry/pre-review',documentHash:'a'.repeat(64)}],optionalWorkflows:[workflow]}};
  const report={system:{name:'신용평가',owner:'검토자',purpose:'신용평가'},items:[item]},f=fixture({report});await f.sandbox.governanceReport('credit',[]);const text=f.root().textContent;
  assert.match(text,/사람의 증거 평가를 뒷받침하는 기술 근거가 확인되었습니다/);assert.match(text,/선택적 확인 요청/);assert.ok(text.includes(title),status);assert.match(text,/필수 사전 검토와 별도로 추적/);assert.match(text,/정부 회신·고영향 해당 여부 결정·법적 준수 완료를 의미하지 않습니다/);
  assert.match(text,/telemetry\/pre-review/);assert.ok(text.includes(workflow.limitations[0]));
  if(status==='request_receipt_missing')assert.match(text,/고영향 확인 요청 자료/);
  if(status==='request_evidence_insufficient')assert.match(text,/외부 접수 확인이 가능한 권한 출처 필요/);
  if(accepted){assert.match(text,/authority\/request-17/);assert.ok(text.includes('b'.repeat(64)));assert.match(text,/선택적 요청의 연결 근거/);}
  assert.equal(f.calls.length,1);assert.equal(f.calls[0].method,'GET');
 }
});

test('optional request conflicts retain literal reasons and evidence without executing markup or claiming a reply',()=>{
 const hostile='<img src=x onerror=alert(1)>',f=fixture(),item={assessment:{assessment:'sufficient'},technicalEvidence:{status:'authenticated_reported_measurement_supported',supportsHumanAssessment:true,optionalWorkflows:[{checkType:'high_impact_confirmation',status:'request_evidence_insufficient',supportsRequestReceipt:false,missingChecks:['high_impact_confirmation'],reasons:['high_impact_confirmation:reported_check_fail',{message:hostile}],matchedChecks:[{checkType:'high_impact_confirmation',ref:'authority/'+hostile,documentHash:'c'.repeat(64)}]}]}};
 const node=f.sandbox.governanceTechnicalEvidence(item);assert.match(node.textContent,/보고된 시험 실패/);assert.ok(node.textContent.includes(hostile));assert.ok(node.textContent.includes('authority/'+hostile));assert.ok(node.textContent.includes('c'.repeat(64)));
 assert.equal(walk(node).filter(child=>['IMG','SCRIPT'].includes(child.tagName)).length,0);assert.doesNotMatch(node.textContent,/정부 회신 완료|고영향 결정 완료|준수 통과/);
 const unknown=f.sandbox.governanceTechnicalEvidence({...item,technicalEvidence:{...item.technicalEvidence,optionalWorkflows:[{status:'future_request_state'}]}});assert.match(unknown.textContent,/future_request_state/);
 const inconsistent=f.sandbox.governanceTechnicalEvidence({...item,technicalEvidence:{...item.technicalEvidence,optionalWorkflows:[{status:'request_receipt_supported',supportsRequestReceipt:false}]}});assert.doesNotMatch(inconsistent.textContent,/요청 접수 보고 근거 연결/);
 const old=f.sandbox.governanceTechnicalEvidence({assessment:{assessment:'sufficient'},technicalEvidence:{status:'authenticated_reported_measurement_supported',supportsHumanAssessment:true}});assert.doesNotMatch(old.textContent,/선택적 확인 요청/);
});

test('additional Korean applicability facts preserve unknown, explicit false, zero and separate domains without inferring a bank role',async()=>{
  const f=fixture();f.sandbox.systemEditor({id:'credit',name:'은행 신용평가',hasDomesticAddressOrOffice:false,previousYearTotalRevenueKrw:0,highImpactDomains:['loan_screening']});
  assert.equal(find(f.root(),'hasDomesticAddressOrOffice').value,'false');assert.equal(find(f.root(),'previousYearTotalRevenueKrw').value,'0');assert.equal(find(f.root(),'highImpactDomains').value,'loan_screening');assert.equal(find(f.root(),'krRole_deployer').checked,false);assert.match(f.root().textContent,/금융기관이라는 이유만으로 이용사업자로 분류하지 않고/);
  const additional=walk(f.root()).find(node=>node.className.includes('system-facts-more'));assert.notEqual(additional.open,true);
  for(const key of ['domesticImpact','aiBusinessOperator','defenceOrNationalSecurityOnly','designatedDefenceSecurityWork','hasDomesticAddressOrOffice','priorArticle43OrderFine','governmentOrderPresent','transparencyObvious','artisticCreativeExpression','seriousLifeSafetyRightsRisk','previousYearAiRevenueKrw','domesticDailyAverageUsersLast3Months','providedAt'])assert.ok(find(f.root(),key),key);
  await submit(f,{id:'credit',markets:'KR',dataCategories:'',highImpactDomains:' loan_screening, credit_evaluation ',domesticImpact:'true',aiBusinessOperator:'unknown',hasDomesticAddressOrOffice:'false',previousYearTotalRevenueKrw:'0',previousYearAiRevenueKrw:'',domesticDailyAverageUsersLast3Months:'unknown',providedAt:'2026-10-06T00:00:00Z'});
  const body=f.calls[0].body;assert.equal(body.domesticImpact,true);assert.equal(body.aiBusinessOperator,'unknown');assert.equal(body.hasDomesticAddressOrOffice,false);assert.equal(body.previousYearTotalRevenueKrw,0);assert.equal(body.previousYearAiRevenueKrw,'unknown');assert.equal(body.domesticDailyAverageUsersLast3Months,'unknown');assert.equal(body.governmentOrderPresent,'unknown');assert.deepEqual(body.krRoles,[]);assert.deepEqual(body.highImpactDomains,['loan_screening','credit_evaluation']);assert.equal(body.providedAt,'2026-10-06T00:00:00.000Z');
  for(const value of ['-1','NaN','Infinity'])assert.throws(()=>f.sandbox.systemFactsPayload({previousYearAiRevenueKrw:value}),/AI 관련 매출액/);
});

test('all Korean task closure refusals are rendered in the form without closing it or recording success',async()=>{
  const requirementIds=JSON.parse(readFileSync('data/requirements.json','utf8')).filter(requirement=>requirement.jurisdiction==='KR').map(requirement=>requirement.id);assert.ok(requirementIds.length>=18);
  for(const requirementId of requirementIds){
    const message=`${requirementId}: 검증 가능한 조치 근거가 없어 작업을 종결할 수 없습니다`,f=fixture({respond:()=>({status:409,body:{error:message}})});f.sandbox.governanceTask({id:'task',requirementId,status:'open'});
    const form=await submit(f,{status:'closed',owner:'검토자',note:'종결 검토'});assert.match(form.textContent,/작업을 종결할 수 없습니다/);assert.ok(form.textContent.includes(requirementId));assert.equal(f.state.closed,0);assert.equal(f.notices.length,0);assert.equal(f.calls.length,1);assert.equal(f.calls[0].method,'POST');
  }
});

test('OIDC document intake uses the existing CSRF session and permission failures stay visible',async()=>{
  const f=fixture({respond:()=>({status:403,body:{error:'거버넌스 문서는 검토자 또는 관리자만 접근할 수 있습니다'}})});f.sandbox.authMode='oidc';f.sandbox.csrfToken='session-csrf';f.sandbox.governanceDocumentEditor(data());find(f.root(),'documentFile').files=[selectedFile(Buffer.from('plan'))];
  const form=await submit(f,{id:'plan',systemId:'credit',name:'plan.txt',mediaType:'text/plain'});assert.match(form.textContent,/검토자 또는 관리자/);assert.equal(f.calls[0].headers['X-Evid-CSRF'],'session-csrf');assert.equal(f.calls[0].headers.Authorization,undefined);assert.equal(f.downloads.length,0);assert.equal(f.calls.length,1);
});

test('missing or partial evidence never displays a positive technical confirmation and current Korean roles remain visible',async()=>{
 const f=fixture({governance:{...data(),systems:[{...data().systems[0],role:'unknown',krRoles:['deployer']}]}});
 const node=await f.sandbox.governanceView();assert.match(node.textContent,/인공지능이용사업자/);
 for(const item of [{technicalEvidence:{supportsHumanAssessment:true,status:'external_or_missing'}},{assessment:{assessment:'sufficient'},technicalEvidence:{supportsHumanAssessment:true,status:'event_linked_partial_support'}}]){
  const text=f.sandbox.governanceTechnicalEvidence(item).textContent;assert.match(text,/부족하거나 미확인/);assert.doesNotMatch(text,/기술 근거가 확인되었습니다/);
 }
});
