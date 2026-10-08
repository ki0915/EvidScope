import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';

class Element {
 constructor(tag,className='',text=''){
  this.tagName=tag.toUpperCase();this.className=className;this.ownText=String(text);this.children=[];this.events={};this.value='';
 }
 get textContent(){return this.ownText+this.children.map(child=>child.textContent).join('');}
 set textContent(value){this.ownText=String(value);this.children=[];}
 set innerHTML(_){throw Error('Unsafe HTML rendering');}
 append(...nodes){this.children.push(...nodes);}
 replaceChildren(...nodes){this.children=[...nodes];this.ownText='';}
 setAttribute(name,value){this[name]=value;}
 addEventListener(name,handler){this.events[name]=handler;}
 querySelector(selector){
  const match=node=>selector.startsWith('.')?node.className.split(' ').includes(selector.slice(1)):node.tagName===selector.toUpperCase();
  return walk(this).find(node=>node!==this&&match(node));
 }
}
const walk=node=>[node,...node.children.flatMap(walk)];
const hostile='<img src=x onerror=alert(1)>';
const status={active:{id:'p1',version:3,status:'active',proposedBy:hostile,approvedBy:'admin',validUntil:'2027-10-08T00:00:00.000Z',
 terms:{classes:[{sourceKind:'telemetry',kind:'*',sensitivity:'any',retentionSeconds:30*86400}],accessLogRetentionSeconds:365*86400,maxPerRun:1000,
  validDays:365,purpose:'routine heartbeats',reason:'x'}},
 policies:[{id:'p2',version:4,status:'proposed',proposedBy:'reviewer'},{id:'p1',version:3,status:'active',proposedBy:hostile,approvedBy:'admin'}],
 scheduler:{enabled:true,intervalMs:3600000,lastRun:{status:'erased',erased:2,at:'2026-10-08T00:00:00.000Z'},nextRunAt:'2026-10-08T01:00:00.000Z'},
 lastDisposition:{seq:9,executedAt:'2026-10-08T00:00:00.000Z',erased:2,policyVersion:3},erasedByClass:{'telemetry/heartbeat/none':2},
 scheduledDispositions:1,rotatedEvents:2,accessLog:{entries:5,prunedThrough:10,oldestEntryAt:'2026-10-01T00:00:00.000Z'},limitations:['원장은 잘리지 않습니다']};

function fixture(){
 const calls=[],details=[],saved=[],el=(...args)=>new Element(...args);
 const sandbox={el,Node:Element,date:value=>value||'미확인',label:value=>value,stringify:value=>typeof value==='object'?JSON.stringify(value):String(value),
  badge:value=>el('span','',value),
  card:(title,description='')=>{const node=el('section'),head=el('div','card-header',title+' '+description);node.append(head);return node;},
  empty:(title,description)=>el('p','',title+' '+description),limits:items=>el('p','',(items||[]).join(' ')),
  table:(headers,rows)=>{
   const node=el('table');
   for(const row of [headers,...rows]){const tr=el('tr');tr.append(...row.map(v=>v instanceof Element?v:el('td','',v)));node.append(tr);}
   return node;
  },
  FormData:class{constructor(form){this.values=form.values||{};}entries(){return Object.entries(this.values);}},
  showDetail:(title,node)=>details.push({title,node}),notice:()=>{},inspect:()=>{},retentionSaved:async message=>{saved.push(message);},
 };
 const source=readFileSync('public/app.js','utf8');
 vm.runInNewContext(source.slice(source.indexOf('function button('),source.indexOf('function badge(')),sandbox);
 vm.runInNewContext(source.slice(source.indexOf('function field('),source.indexOf('function showDetail(')),sandbox);
 vm.runInNewContext(source.slice(source.indexOf('async function rotationCard('),source.indexOf('async function retentionPlanDetail(')),sandbox);
 sandbox.api=async(path,method='GET',body)=>{calls.push(JSON.parse(JSON.stringify({path,method,body})));return method==='GET'?structuredClone(status):{};};
 return {sandbox,calls,details,saved};
}
const click=async(root,title)=>{const node=walk(root).find(n=>n.tagName==='BUTTON'&&n.textContent===title);assert.ok(node,title);await node.events.click();};

test('the retention screen shows the active rotation policy, its runs and erased classes as text, and posts only through the API',async()=>{
 const f=fixture(),node=await f.sandbox.rotationCard(),text=node.textContent;
 for(const part of ['활성 정책 v3','일상 종류 전체','30일','365일','다음 실행 2026-10-08T01:00:00.000Z','파기 2건','telemetry/heartbeat/none','서명된 정리 경계 10',
  '원장은 잘리지 않습니다'])assert.ok(text.includes(part),part);
 assert.ok(text.includes(hostile),'untrusted names are rendered as text, never as markup');
 await click(node,'관리자 승인');
 assert.deepEqual(f.calls.at(-1),{path:'/api/retention/rotation/p2/approve',method:'POST',body:{reason:'관리자 승인 (화면)'}});
 await click(node,'즉시 중지');assert.equal(f.calls.at(-1).path,'/api/retention/rotation/p1/suspend');
 await click(node,'+ 로테이션 정책 제안');
 const form=walk(f.details.at(-1).node).find(n=>n.tagName==='FORM');
 form.values={classes:'[{"sourceKind":"agent","kind":"intent","retentionSeconds":60}]',accessLogDays:'',validDays:'30',purpose:'p',reason:'r'};
 await form.events.submit({preventDefault(){}});
 assert.deepEqual(f.calls.at(-1),{path:'/api/retention/rotation',method:'POST',body:{classes:[{sourceKind:'agent',kind:'intent',retentionSeconds:60}],
  purpose:'p',reason:'r',validDays:30,accessLogRetentionSeconds:null}});
 assert.equal(f.saved.length,3);
});
