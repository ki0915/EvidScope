import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';

class Element {
 constructor(tag,className='',text=''){this.tagName=tag;this.className=className;this.ownText=String(text);this.children=[];this.events={};this.value='';}
 get textContent(){return this.ownText+this.children.map(c=>c.textContent).join('');}
 set textContent(value){this.ownText=String(value);this.children=[];}
 set innerHTML(_){throw Error('Unsafe HTML rendering');}
 append(...nodes){this.children.push(...nodes);}
 addEventListener(name,handler){this.events[name]=handler;}
 querySelector(tag){return walk(this).find(n=>n!==this&&n.tagName===tag);}
}
const walk=node=>[node,...node.children.flatMap(walk)];
const plain=value=>JSON.parse(JSON.stringify(value));
function fixture(data={}){
 const calls=[],downloads=[],notices=[],forms=[],details=[];
 const el=(...args)=>new Element(...args);
 const sandbox={el,TextEncoder,document:{createTextNode:text=>el('#text','',text)},date:v=>v||'미확인',localDate:v=>v||'',label:v=>v,
  card:(title,description='')=>el('section','',title+' '+description),empty:(title,description)=>el('p','',title+' '+description),limits:items=>el('p','',(items||[]).join(' ')),
  table:(headers,rows)=>{const table=el('table');for(const row of [headers,...rows]){const tr=el('tr');tr.append(...row.map(value=>value instanceof Element?value:el('td','',value)));table.append(tr);}return table;},
  button:(text,handler)=>{const b=el('button','',text);b.addEventListener('click',handler);return b;},
  field:(title,name,options={})=>{const wrapper=el('label','',title),input=el(options.multiline?'textarea':options.choices?'select':'input');Object.assign(input,{name,value:options.value??options.choices?.[0]?.value??'',type:options.type||'text'});wrapper.append(input);return wrapper;},
  form:(fields,title,submit)=>{const f=el('form');f.append(...fields);f.submit=submit;forms.push(f);return f;},
  api:async(path,method='GET',body)=>{calls.push({path,method,body:plain(body??null)});if(path.startsWith('/api/governance/finance?'))return data;if(path==='/api/governance/finance/report')return {id:'frozen-report',snapshot:{systemId:body.systemId},signature:'signature'};if(path.endsWith('/export'))return {documents:[],id:'bundle'};return {};},
  showDetail:(title,node)=>details.push({title,node}),downloadArtifact:(name,type,body)=>downloads.push({name,type,body}),notice:(text,error)=>notices.push({text,error}),
  $:()=>({close(){}}),navigate:async()=>{},actionDetail:()=>{},governanceReport:()=>{},
 };
 const source=readFileSync('public/app.js','utf8');
 vm.runInNewContext(source.slice(source.indexOf('const systemTriFacts ='),source.indexOf('function governanceTask(')),sandbox);
 return {sandbox,calls,downloads,notices,forms,details,root:()=>details.at(-1).node};
}
const emptyData=()=>({system:{name:'대출 심사',modelId:'credit',modelVersion:'v1'},bundles:[],operations:[],operationalStatus:'execution_evidence_missing',limitations:['법적 적용·충분성 판단은 사람 검토']});
const click=(f,title)=>{const b=walk(f.root()).find(n=>n.tagName==='button'&&n.textContent===title);assert.ok(b,`button ${title}`);return b.events.click();};
const realBundle=(overrides={})=>({id:'real/bundle',synthetic:false,contentHash:'a'.repeat(64),revision:2,supplierId:'supplier',modelId:'credit',modelVersion:'v1',testScope:'대출 심사 보조',provenance:{channel:'supplier_portal',reference:'delivery-42',suppliedAt:'2026-10-06T00:00:00Z'},verification:{issues:['REAL_PROVENANCE_REVIEW_REQUIRED'],documents:[],provenance:{status:'unreviewed',sourceAuthentication:'not_independently_verified'}},...overrides});

test('finance view keeps hostile names, findings and refs literal and labels model/document gaps',async()=>{
 const hostile='<img src=x onerror=alert(1)><script>hostile</script>',data=emptyData();
 data.system.name=hostile;
 data.bundles=[{id:hostile,revision:1,supplierId:hostile,modelId:'credit',modelVersion:'v1',testScope:hostile,retentionUntil:'2031-09-22',verification:{issues:['MODEL_VERSION_MISMATCH','DOCUMENT_EVIDENCE_MISSING','SUPPLIED_MODEL_VERSION_UNKNOWN','SUPPLIED_MODEL_VERSION_MISMATCH','SUPPLIED_PURPOSE_UNKNOWN','SUPPLIED_PURPOSE_MISMATCH'],documents:[{name:hostile,status:'unavailable_or_corrupt'}]}}];
 data.operations=[{actionId:hostile,analysisPending:true,correlationStatus:'system_correlation_uncertain',modelIssues:[{ref:hostile}],events:[{source:hostile,id:'1',kind:'result',attemptId:hostile,modelVersion:'2'}],evaluation:{findings:[{message:hostile,evidence:[hostile]}]}}];
 const f=fixture(data);await f.sandbox.financeEvidenceView('credit',[]);
 assert.ok(f.root().textContent.includes(hostile));assert.equal(walk(f.root()).filter(n=>['script','img'].includes(n.tagName)).length,0);
 for(const text of ['모델 버전 불일치','문서 복구 불가·변조·부족','복구 불가 또는 변조','실제 모델 확인·변경 검토','시스템 연결 불확실','새 증거 분석 대기'])assert.ok(f.root().textContent.includes(text),text);
 for(const text of ['공급 당시 모델 버전 미확인','공급 당시 모델 버전과 현재 사용·증빙 불일치','공급 당시 사용 목적 미확인','공급 당시 목적과 현재 사용·증빙 불일치'])assert.ok(f.root().textContent.includes(text),text);
 assert.equal(f.calls.length,1);assert.equal(f.calls[0].method,'GET');
});

test('empty finance evidence remains missing and signed report is explicitly posted before download',async()=>{
 const f=fixture(emptyData());await f.sandbox.financeEvidenceView('credit/branch',[]);
 assert.equal(f.calls[0].path,'/api/governance/finance?systemId=credit%2Fbranch');
 assert.match(f.root().textContent,/공급사 증빙 없음/);assert.match(f.root().textContent,/실행 증거 없음/);assert.match(f.root().textContent,/무사고나 정상 실행으로 판정하지 않습니다/);
 await click(f,'서명된 검토 보고서 저장·받기');
 assert.deepEqual(f.calls.at(-1),{path:'/api/governance/finance/report',method:'POST',body:{systemId:'credit/branch'}});
 assert.equal(f.downloads.length,1);assert.equal(f.downloads[0].type,'application/json');assert.equal(JSON.parse(f.downloads[0].body).id,'frozen-report');
});

test('supplier JSON import rejects malformed or wrong-system payloads and accepts a verified API roundtrip',async()=>{
 const f=fixture(emptyData());f.sandbox.financeBundleImport('credit',[]);const form=f.forms.at(-1);
 await assert.rejects(form.submit({bundle:'{'}),/올바른 JSON/);
 await assert.rejects(form.submit({bundle:JSON.stringify({systemId:'other'})}),/systemId/);assert.equal(f.calls.length,0);
 const bundle={systemId:'credit',synthetic:true,id:'v1',documents:[]};await form.submit({bundle:JSON.stringify(bundle)});
 assert.deepEqual(f.calls[0],{path:'/api/governance/bundles',method:'POST',body:bundle});assert.equal(f.calls[1].method,'GET');
});

test('approval-only records do not hide the absence of actual execution evidence',async()=>{
 const data=emptyData();data.operations=[{actionId:'approval-only',analysisPending:false,correlationStatus:'explicit_system_reference',modelIssues:[],events:[{source:'authority',id:'approval',kind:'human_approval',attemptId:'1',modelVersion:'v1'}],evaluation:null}];
 const f=fixture(data);await f.sandbox.financeEvidenceView('credit',[]);
 assert.match(f.root().textContent,/실행 증거 없음/);assert.match(f.root().textContent,/approval-only/);
});

test('supplier file chooser enforces its size bound and exports only the selected bundle',async()=>{
 const f=fixture(emptyData());f.sandbox.financeBundleImport('credit',[]);
 const input=walk(f.root()).find(n=>n.name==='bundleFile'),textarea=f.forms.at(-1).querySelector('textarea');
 input.files=[{size:131073,text:async()=>{throw Error('oversize file must not be read');}}];await input.events.change();
 assert.match(f.notices.at(-1).text,/128KiB/);assert.equal(textarea.value,'');assert.equal(f.calls.length,0);
 const content='{"systemId":"credit","synthetic":true}';input.files=[{size:content.length,text:async()=>content}];await input.events.change();assert.equal(textarea.value,content);
 const data=emptyData();data.bundles=[{id:'bundle/one',revision:1,supplierId:'supplier',modelId:'credit',modelVersion:'1',testScope:'test',verification:{issues:[],documents:[]}}];
 const exported=fixture(data);await exported.sandbox.financeEvidenceView('credit',[]);await click(exported,'증빙 JSON 내보내기');
 assert.equal(exported.calls.at(-1).path,'/api/governance/bundles/bundle%2Fone/export');assert.equal(exported.calls.at(-1).method,'GET');assert.equal(exported.downloads[0].name,'supplier-evidence.json');
});

test('approval policy editor preserves false, true and unknown and omits blank end dates',async()=>{
 const f=fixture();f.sandbox.financeApprovalPolicyEditor();const form=f.forms.at(-1);
 for(const [value,expected] of [['false',false],['true',true],['unknown','unknown']]){
  await form.submit({id:'policy',actor:'a',tool:'t',owner:'owner',policyVersion:'1',validFrom:'2026-09-22T00:00:00Z',validUntil:'',approvalRequired:value,destinations:'internal, other, '});
  const call=f.calls.at(-1);assert.equal(call.path,'/api/assets');assert.equal(call.method,'POST');assert.equal(call.body.approvalRequired,expected);assert.deepEqual(call.body.destinations,['internal','other']);assert.equal(call.body.validUntil,undefined);
 }
});

test('Korean fact payload preserves tri-state values and distinct legal roles through the rendered editor',async()=>{
 const f=fixture();f.sandbox.systemEditor({id:'credit',krRoles:['deployer'],substantialModification:false,generative:false});const form=f.forms.at(-1),controls=walk(form);
 assert.equal(controls.find(n=>n.name==='krRole_deployer').checked,true);assert.equal(controls.find(n=>n.name==='krRole_developer').checked,false);
 assert.equal(controls.find(n=>n.name==='substantialModification').value,'false');
 for(const name of ['supplierId','modelId','decisionInfluence','suppliedModelVersion','suppliedPurpose'])assert.ok(controls.some(n=>n.name===name),name);
 await form.submit({id:'credit',markets:' KR, EU ',dataCategories:'synthetic',generative:'false',substantialModification:'false',internalOnly:'unknown',realisticSyntheticMedia:'true',krRole_deployer:'on',euRole_provider:'on',modelVersion:'v2',policyVersion:'',trainingCompute:'0',decisionInfluence:'advisory'});
 const payload=f.calls.at(-1).body;
 assert.deepEqual(payload.krRoles,['deployer']);assert.deepEqual(payload.euRoles,['provider']);assert.deepEqual(payload.markets,['KR','EU']);
 assert.equal(payload.generative,false);assert.equal(payload.substantialModification,false);assert.equal(payload.internalOnly,'unknown');assert.equal(payload.realisticSyntheticMedia,true);assert.equal(payload.trainingCompute,0);assert.equal(payload.policyVersion,'unknown');
 assert.equal(payload.krRole_deployer,undefined);assert.equal(payload.euRole_provider,undefined);
});

test('finance evidence distinguishes real declaration, explicit synthetic fixture and unknown kind',async()=>{
 const data=emptyData();data.bundles=[realBundle(),realBundle({id:'synthetic',synthetic:true}),realBundle({id:'legacy',synthetic:undefined})];
 const f=fixture(data);await f.sandbox.financeEvidenceView('credit',[]);const articles=walk(f.root()).filter(n=>n.tagName==='article');
 assert.match(articles[0].textContent,/실제 공급사 자료로 신고됨/);assert.match(articles[0].textContent,/독립적인 출처 인증은 수행되지 않았습니다/);assert.match(articles[0].textContent,/공급사 포털.*delivery-42.*2026-10-06/);
 assert.match(articles[1].textContent,/합성 시험 자료 · 실제 공급사 증빙 아님/);assert.match(articles[2].textContent,/자료 유형 미확인/);assert.doesNotMatch(articles[2].textContent,/합성 시험 자료/);
 assert.equal(walk(f.root()).filter(n=>n.tagName==='button'&&n.textContent==='출처 검토 기록').length,1);
});

test('hostile provenance metadata and server review are rendered literally without links or HTML',async()=>{
 const hostile='<img src=x onerror=alert(1)><script>hostile</script>',data=emptyData();data.bundles=[realBundle({provenance:{channel:hostile,reference:'https://evil.invalid/'+hostile,suppliedAt:hostile},verification:{issues:[],documents:[],provenance:{status:'reviewed',sourceAuthentication:'not_independently_verified',review:{decision:'verified',reviewer:hostile,reason:hostile,reviewedAt:hostile},reviewHash:'b'.repeat(64)}}})];
 const f=fixture(data);await f.sandbox.financeEvidenceView('credit',[]);assert.ok(f.root().textContent.includes(hostile));assert.match(f.root().textContent,/출처 확인 검토 기록 있음/);assert.match(f.root().textContent,/검토자: <img/);assert.match(f.root().textContent,/검토 사유: <img/);assert.match(f.root().textContent,/수동 확인 진술/);assert.equal(walk(f.root()).filter(n=>['script','img','a'].includes(n.tagName)).length,0);assert.equal(f.calls.length,1);
});

test('real provenance missing, rejected and stale states remain visible with Korean issue labels',async()=>{
 for(const [status,issue,text]of [['unreviewed','REAL_PROVENANCE_REVIEW_REQUIRED','실제 자료 출처 검토 필요'],['rejected','REAL_PROVENANCE_REJECTED','실제 자료 출처 검토 거부'],['stale','REAL_PROVENANCE_REVIEW_STALE','실제 자료 출처 재검토 필요'],['unreviewed','REAL_PROVENANCE_METADATA_MISSING','실제 자료 출처 정보 미확인']]){const data=emptyData();data.bundles=[realBundle({verification:{issues:[issue],documents:[],provenance:{status,sourceAuthentication:'not_independently_verified'}}})];const f=fixture(data);await f.sandbox.financeEvidenceView('credit',[]);assert.ok(f.root().textContent.includes(text));assert.match(f.root().textContent,/독립적인 출처 인증은 수행되지 않았습니다/);}
});

test('provenance form starts unchecked and posts only explicit checks and current bundle hash',async()=>{
 const data=emptyData();data.bundles=[realBundle()];const f=fixture(data);await f.sandbox.financeEvidenceView('credit',[]);await click(f,'출처 검토 기록');const form=f.forms.at(-1),checks=walk(form).filter(n=>n.type==='checkbox');assert.equal(checks.length,3);assert.ok(checks.every(n=>n.checked===false));assert.equal(walk(form).find(n=>n.name==='decision').value,'unverified');
 await form.submit({decision:'unverified',reason:'  전달 근거 미확인  ',supplierIdentityChecked:'on',deliveryReferenceChecked:'true',reviewer:'forged',reviewedAt:'forged'});
 assert.deepEqual(f.calls.at(-2),{path:'/api/governance/bundles/real%2Fbundle/provenance-reviews',method:'POST',body:{bundleHash:'a'.repeat(64),decision:'unverified',reason:'전달 근거 미확인',checks:{supplierIdentityChecked:true,deliveryReferenceChecked:false,modelPurposeScopeChecked:false}}});assert.equal(f.calls.at(-1).method,'GET');assert.match(f.notices.at(-1).text,/수동 출처 검토.*독립적인 출처 인증은 아닙니다/);
});

test('verified provenance requires all three independently selected checks before any POST',async()=>{
 const f=fixture(emptyData());f.sandbox.financeBundleProvenanceReview(realBundle(),'credit',[]);const form=f.forms.at(-1);
 for(const values of [{},{supplierIdentityChecked:'on',deliveryReferenceChecked:'on'},{supplierIdentityChecked:'true',deliveryReferenceChecked:'true',modelPurposeScopeChecked:'true'}])await assert.rejects(form.submit({decision:'verified',reason:'확인',...values}),/모두 확인한 경우/);
 assert.equal(f.calls.length,0);await form.submit({decision:'verified',reason:'세 범위 확인',supplierIdentityChecked:'on',deliveryReferenceChecked:'on',modelPurposeScopeChecked:'on'});assert.deepEqual(f.calls[0].body.checks,{supplierIdentityChecked:true,deliveryReferenceChecked:true,modelPurposeScopeChecked:true});assert.equal(f.calls[0].body.decision,'verified');
});

test('provenance review rejects synthetic scope, missing current hash, invalid decisions and empty reasons',async()=>{
 const f=fixture(emptyData());assert.throws(()=>f.sandbox.financeBundleProvenanceReview(realBundle({synthetic:true}),'credit',[]),/합성 시험/);
 f.sandbox.financeBundleProvenanceReview(realBundle(),'credit',[]);let form=f.forms.at(-1);for(const values of [{decision:'other',reason:'text'},{decision:'rejected',reason:'   '},{decision:'rejected',reason:'x'.repeat(1001)}])await assert.rejects(form.submit(values),/검토 결과|검토 사유/);
 f.sandbox.financeBundleProvenanceReview(realBundle({contentHash:undefined}),'credit',[]);form=f.forms.at(-1);await assert.rejects(form.submit({decision:'rejected',reason:'근거 불일치'}),/증빙 해시/);assert.equal(f.calls.length,0);
});

test('real supplier import keeps explicit provenance metadata and never fetches its reference URL',async()=>{
 const f=fixture(emptyData());f.sandbox.financeBundleImport('credit',[]);assert.match(f.root().textContent,/synthetic:true.*synthetic:false/);assert.match(f.root().textContent,/출처는 별도 수동 검토/);const value={id:'real',systemId:'credit',synthetic:false,provenance:{channel:'email',reference:'https://supplier.invalid/delivery/42'},documents:[]};await f.forms.at(-1).submit({bundle:JSON.stringify(value)});assert.deepEqual(f.calls[0],{path:'/api/governance/bundles',method:'POST',body:value});assert.equal(f.calls.length,2);assert.ok(f.calls.every(v=>v.path.startsWith('/api/')));
});
