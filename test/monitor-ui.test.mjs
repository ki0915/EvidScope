import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';
class Element {
 constructor(tag){this.tagName=tag;this.children=[];this.attributes={};this.events={};this.value='';this.ownText='';}
 set textContent(v){this.ownText=String(v);this.children=[];}get textContent(){return this.ownText+this.children.map(c=>c.textContent).join('');}
 set innerHTML(v){throw Error('unsafe HTML');}append(...items){for(const item of items){this.children=this.children.filter(x=>x!==item);this.children.push(item);}}
 replaceChildren(...items){this.children=items;this.ownText='';}setAttribute(k,v){this.attributes[k]=v;}addEventListener(k,v){this.events[k]=v;}
 trigger(k){this.events[k]?.();}
}
const all=n=>[n,...n.children.flatMap(all)],byClass=(n,c)=>all(n).find(n=>n.className?.split(' ').includes(c));
const flush=async()=>{for(let i=0;i<5;i++)await Promise.resolve();};
function fixture(fetchData){
 const timers=new Map();let seq=0;const document={hidden:false,events:{},createElement:t=>new Element(t),createElementNS:(_,t)=>new Element(t),addEventListener(k,v){this.events[k]=v;},removeEventListener(k){delete this.events[k];}};
 const sandbox={window:{},document,setTimeout:(fn,ms)=>{timers.set(++seq,{fn,ms});return seq;},clearTimeout:id=>timers.delete(id)};
 vm.runInNewContext(readFileSync('public/live-graphs.js','utf8'),sandbox);
 let current=true;const monitor=sandbox.window.EvidScopeMonitor.mount({fetchData,isCurrent:()=>current});
 return {...monitor,document,timers,invalidate:()=>{current=false;},fire(){const [id,t]=timers.entries().next().value;timers.delete(id);t.fn();}};
}
const data=()=>({generatedAt:'2026-09-08T09:00:05Z',source:'',bucketMs:10000,sources:[{id:'<script>bad</script>',status:'stale'}],points:Array.from({length:60},(_,i)=>({at:new Date(Date.parse('2026-09-08T08:50:10Z')+i*10000).toISOString(),end:'2026-09-08T09:00:05Z',received:i===59?3:0,success:1,failure:0,unknown:0,gaps:0,partial:i===59}))});
test('monitor UI: refresh, range/source queries, pause/resume, errors keep prior series and auth stops retries',async()=>{
 let result=data(),failure=null;const calls=[];const h=fixture(async(...args)=>{calls.push(args);if(failure)throw failure;return result;});await flush();
 assert.equal(calls.length,1);assert.equal(calls[0][0],'1h');assert.match(h.root.textContent,/한 점은 1분간/);assert.equal(h.timers.size,1);assert.equal([...h.timers.values()][0].ms,60000);
 assert.equal(all(h.root).filter(n=>n.tagName==='path').length,5);assert.equal(all(h.root).filter(n=>n.tagName==='script').length,0);assert.match(h.root.textContent,/<script>bad<\/script>/);
 const chart=byClass(h.root,'monitor-chart'),original=chart.children[0];failure=Error('offline');h.fire();await flush();assert.equal(chart.children[0],original);assert.match(h.root.textContent,/조회 실패/);assert.equal([...h.timers.values()][0].ms,120000);
 failure=null;const range=all(h.root).find(n=>n.attributes['aria-label']==='모니터링 시간 범위');range.value='24h';range.trigger('change');await flush();assert.equal(calls.at(-1)[0],'24h');assert.equal([...h.timers.values()][0].ms,300000);range.value='7d';range.trigger('change');await flush();assert.equal([...h.timers.values()][0].ms,900000);range.value='10m';range.trigger('change');await flush();assert.equal([...h.timers.values()][0].ms,30000);
 const source=all(h.root).find(n=>n.attributes['aria-label']==='모니터링 출처');source.value='<script>bad</script>';source.trigger('change');await flush();assert.equal(calls.at(-1)[1],source.value);
 const pause=all(h.root).find(n=>n.tagName==='button'&&n.textContent==='일시정지');pause.trigger('click');assert.equal(h.timers.size,0);assert.match(h.root.textContent,/일시정지/);pause.trigger('click');await flush();assert.equal(h.timers.size,1);
 failure=Object.assign(Error('expired'),{status:401});h.fire();await flush();assert.equal(h.timers.size,0);assert.match(h.root.textContent,/다시 시도/);h.dispose();
});
test('monitor UI: navigation and visibility discard in-flight responses and remove timers/listeners',async()=>{
 let resolve;const h=fixture(()=>new Promise(r=>{resolve=r;}));h.document.hidden=true;h.document.events.visibilitychange();resolve(data());await flush();assert.equal(all(h.root).filter(n=>n.tagName==='path').length,0);assert.equal(h.timers.size,0);
 h.document.hidden=false;h.document.events.visibilitychange();h.invalidate();h.dispose();resolve(data());await flush();assert.equal(h.timers.size,0);assert.equal(h.document.events.visibilitychange,undefined);assert.equal(all(h.root).filter(n=>n.tagName==='path').length,0);
});
test('stock scale: zoom/pan stay bounded, preserve historical window and reset to latest',async()=>{
 const h=fixture(async()=>data());await flush();const click=text=>all(h.root).find(n=>n.tagName==='button'&&n.textContent===text).trigger('click');
 click('＋ 확대');assert.match(byClass(h.root,'monitor-window').textContent,/30\/60/);click('← 이전 구간');assert.match(byClass(h.root,'monitor-window').textContent,/과거 구간 고정/);
 const before=byClass(h.root,'monitor-window').textContent;h.fire();await flush();assert.equal(byClass(h.root,'monitor-window').textContent,before);
 click('최신 따라가기');assert.match(byClass(h.root,'monitor-window').textContent,/최신 구간 따라가는 중/);click('전체 구간');assert.match(byClass(h.root,'monitor-window').textContent,/60\/60/);
 click('차트 넓게 보기');assert.match(h.root.className,/monitor-expanded/);click('기본 화면으로');assert.doesNotMatch(h.root.className,/monitor-expanded/);h.dispose();
});
