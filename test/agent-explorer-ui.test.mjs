import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';
class Element {
 constructor(tag,className='',text=''){this.tagName=tag;this.className=className;this.ownText=String(text);this.children=[];this.events={};this.attributes={};this.style={};this.value='';}
 get textContent(){return this.ownText+this.children.map(c=>c.textContent).join('');}set textContent(value){this.ownText=String(value);this.children=[];}
 append(...nodes){this.children.push(...nodes);}replaceChildren(...nodes){this.ownText='';this.children=nodes;}
 setAttribute(k,v){this.attributes[k]=v;}addEventListener(k,fn){this.events[k]=fn;}querySelector(tag){return walk(this).find(n=>n.tagName===tag);}
 trigger(type){this.events[type]?.();}
}
const walk=n=>[n,...n.children.flatMap(walk)];
test('agent explorer: all 105 actions reachable, chart drilldown, review/state filters and hostile text stay literal',()=>{
 const calls=[];
 const sandbox={el:(...args)=>new Element(...args),card:(title,description)=>new Element('section','',title+description),date:v=>v,reviewBadge:v=>new Element('span','',v),actionDetail:id=>calls.push(id),button:(text,fn,cls)=>{const b=new Element('button',cls,text);b.addEventListener('click',fn);return b;},
  field:(title,name,options={})=>{const n=new Element('label','',title),control=new Element(options.choices?'select':'input');control.name=name;control.value=options.choices?.[0].value||'';n.append(control);return n;},
  table:(headers,rows)=>{const n=new Element('table');for(const row of rows){const tr=new Element('tr');for(const value of row)tr.append(value instanceof Element?value:new Element('td','',value));n.append(tr);}return n;}
 };
 const source=readFileSync('public/app.js','utf8');vm.runInNewContext(source.slice(source.indexOf('const agentPolicyLabels='),source.indexOf('async function agentDetail(')),sandbox);
 const details=Array.from({length:105},(_,i)=>({actionId:i===0?'<script>payload</script>':`action-${i}`,state:i%2?'violation':'unconfirmed',reviewState:i%3?'unreviewed':'stale',reason:'evidence',firstSeen:'2026-09-08T12:00:00Z',bucket:i%2}));
 const root=sandbox.agentActionExplorer({window:{end:'2026-09-08T12:00:00Z'},item:{details},trend:[{at:'2026-09-07T12:00:00Z',end:'2026-09-08T00:00:00Z',actions:53,counts:{unconfirmed:53}},{at:'2026-09-08T00:00:00Z',end:'2026-09-08T12:00:00Z',actions:52,counts:{violation:52}}]});
 const click=text=>walk(root).find(n=>n.tagName==='button'&&n.ownText===text).trigger('click');
 assert.match(root.textContent,/<script>payload<\/script>/);assert.equal(walk(root).filter(n=>n.tagName==='script').length,0);
 for(let i=0;i<5;i++)click('다음 행동 →');assert.match(root.textContent,/101–105 \/ 105/);assert.match(root.textContent,/action-104/);assert.equal(walk(root).find(n=>n.ownText==='다음 행동 →').disabled,true);
 const bar=walk(root).find(n=>n.className==='agent-column');bar.trigger('click');assert.match(root.textContent,/조건 일치 53개 행동/);assert.match(root.textContent,/1–20 \/ 53/);
 const state=walk(root).find(n=>n.name==='state');state.value='violation';walk(root).find(n=>n.className==='toolbar').trigger('change');assert.match(root.textContent,/조건 일치 0개 행동/);assert.match(root.textContent,/0 \/ 0/);
 click('구간 선택 해제');assert.match(root.textContent,/조건 일치 52개 행동/);
 const review=walk(root).find(n=>n.name==='review');review.value='stale';walk(root).find(n=>n.className==='toolbar').trigger('change');assert.match(root.textContent,/조건 일치 17개 행동/);
 click('행동 근거 열기');assert.equal(calls[0],'action-3');
});
