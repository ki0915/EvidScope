'use strict';
// All labels originate in the authenticated response and remain text nodes.
window.EvidScopeLiveGraphs = (() => {
  const node = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text !== undefined) n.textContent = String(text); return n; };
  const svg = (tag, attrs, text) => { const n = document.createElementNS('http://www.w3.org/2000/svg', tag); Object.entries(attrs || {}).forEach(([k,v]) => n.setAttribute(k, String(v))); if (text !== undefined) n.textContent = String(text); return n; };
  const button = (text, run, cls) => { const b = node('button', cls, text); b.type = 'button'; b.addEventListener('click', run); return b; };
  const panel = (title, subtitle) => { const c = node('section','card graph-panel'); c.append(node('h2','',title),node('p','muted',subtitle)); return c; };
  const number = n => Number.isFinite(n) ? n.toLocaleString('ko-KR') : '미확인';
  function bars(entries, total, onSelect) {
    const wrap = node('div','graph-bars');
    for (const [name, value, tone, key] of entries) {
      const row = node('div','graph-bar-row');
      const label = onSelect ? button(name, () => onSelect(key),'graph-bar-label') : node('span','graph-bar-label',name);
      const chart = svg('svg',{viewBox:'0 0 300 26',role:'img','aria-label':`${name}: ${value}건 / ${total}건`});
      chart.append(svg('rect',{x:0,y:3,width:300,height:20,rx:4,class:'graph-track'}),svg('rect',{x:0,y:3,width:total ? Math.max(0,value/total*300) : 0,height:20,rx:4,class:`graph-fill ${tone}`}));
      row.append(label,chart,node('strong','graph-value',`${number(value)}건`)); wrap.append(row);
    }
    if (!total) wrap.append(node('p','muted','관측된 행동이 없어 비율을 계산하지 않습니다.'));
    return wrap;
  }
  const outcomeGroups = [
    ['성공·실패 혼재','mixed_results','graph-red'],['서비스 실패 기록','independently_reported_failure','graph-red'],
    ['서비스 성공 기록','independently_reported_success','graph-teal'],['외부 결과 미확인','unconfirmed','graph-amber']
  ];
  function render({ overview, investigations, onOpenAction }) {
    const root = node('div','live-graphs'); const items = investigations.items || []; let selection = null;
    const total = investigations.total ?? items.length;
    const hero = panel('근거가 보이는 AI 관측','막대의 항목을 누르면 해당 행동을 골라 조사할 수 있습니다.');
    hero.append(node('p','graph-scope',`현재 테넌트 · 최근 수신 순 ${items.length} / ${number(total)}개 행동의 스냅샷`));
    hero.append(node('p','muted',items.length < total ? '아래 분포는 최대 100개 행동 표본입니다. 전체 조직의 AI 사용량이나 가시성 비율을 뜻하지 않습니다.' : '수집된 행동 안에서의 분포입니다. 연결되지 않은 AI의 활동은 이 그래프에 포함되지 않습니다.'));
    root.append(hero);
    const grid=node('div','graph-grid'); const outcome=panel('외부 결과는 확인됐나요?','분모: 위에 표시된 행동. 성공·실패 혼재를 따로 표시합니다.');
    const grouped = value => outcomeGroups.some(g=>g[1]===value) ? value : 'unconfirmed';
    outcome.append(bars(outcomeGroups.map(([name,key,tone])=>[name,items.filter(i=>grouped(i.outcome)===key).length,tone,key]),items.length,key=>select('outcome',key)));
    const references=panel('참고 데이터가 보이나요?','참조가 제출됐다는 사실만으로 실제 사용·내용 일치를 보증하지 않습니다.');
    const refKey=i=>i.referenceCount==null?'unknown':i.referenceCount>0?'present':'missing';
    references.append(bars([['참조 기록 있음',items.filter(i=>refKey(i)==='present').length,'graph-teal','present'],['참조 기록 없음',items.filter(i=>refKey(i)==='missing').length,'graph-amber','missing'],['조회 한도로 미확인',items.filter(i=>refKey(i)==='unknown').length,'graph-gray','unknown']],items.length,key=>select('references',key)));
    const review=panel('사람의 검토는 어디까지 왔나요?','현재 근거와 재검토 기한을 기준으로 구분합니다.');
    const reviewGroups=[['미검토','unreviewed','graph-amber'],['재검토 필요','stale','graph-red'],['판단 유보','inconclusive','graph-amber'],['현재 근거 검토됨','reviewed','graph-teal']];
    const reviewKey=i=>reviewGroups.some(g=>g[1]===i.reviewState)?i.reviewState:'unreviewed';
    review.append(bars(reviewGroups.map(([name,key,tone])=>[name,items.filter(i=>reviewKey(i)===key).length,tone,key]),items.length,key=>select('review',key)));
    const sources=panel('등록된 출처의 수신 상태','연결 상태는 등록된 출처 기준이며 미등록 공급자를 포함하지 않습니다.');
    const sourceList=overview.sources||[]; const states=[...new Set(sourceList.map(s=>s.status||'unknown'))];
    const sourceLabels={receiving:'최근 수신됨',stale:'최근 수신 없음',not_connected:'미연결',no_observation:'수신 이력 없음',unknown:'상태 미확인'};
    sources.append(bars(states.map(state=>[sourceLabels[state]||state,sourceList.filter(s=>(s.status||'unknown')===state).length,state==='receiving'?'graph-teal':'graph-amber',state]),sourceList.length));
    sources.append(node('p','muted',`등록 출처 ${sourceList.length}개 · 마지막 수신 시각은 관측 개요에서 확인하세요.`));
    grid.append(outcome,references,review,sources); root.append(grid);
    const details=panel('그래프에서 행동 조사로','표본 안에서 선택한 항목에 해당하는 행동입니다.');
    const selectionText=node('p','graph-scope'); selectionText.setAttribute('aria-live','polite'); const list=node('div','graph-action-list');
    const reset=button('선택 해제 · 전체 표본',()=>select(null,null),'small'); details.append(selectionText,reset,list); root.append(details);
    function select(type,key){selection=type?{type,key}:null;const shown=items.filter(i=>!selection||(type==='outcome'?grouped(i.outcome)===key:type==='references'?refKey(i)===key:reviewKey(i)===key));selectionText.textContent=`${selection?'선택 항목':'전체 표본'} · ${shown.length}개 행동 · 아래 최대 20개 표시`;list.replaceChildren();if(!shown.length)list.append(node('p','muted','해당하는 수집 행동이 없습니다. 안전하다는 뜻은 아닙니다.'));for(const item of shown.slice(0,20)){const row=node('article','graph-action-row');const text=node('div');text.append(node('strong','wrap',`${item.actor||'행위자 미확인'} → ${item.tool||'도구 미확인'}`),node('p','mono wrap',item.actionId),node('p','muted',`참조 ${item.referenceCount==null?'미확인':item.referenceCount+'건'} · ${outcomeGroups.find(g=>g[1]===grouped(item.outcome))[0]}`));row.append(text,button('행동 조사 열기',()=>onOpenAction(item.actionId),'small'));list.append(row);}}
    select(null,null); return root;
  }
  function action(data, onInspect) {
    const events=data.events||[];const refs=Array.isArray(data.references)?data.references:events.flatMap(e=>(e.dataRefs||[]).map(r=>({...r,source:e.source,eventId:e.id})));
    const p=panel('행동 근거 연결도','연결선은 같은 행동 ID에 연결된 기록을 묶습니다. 실제 실행 순서나 인과관계를 추론한 선이 아닙니다.');
    const groups=[['요청·자기보고',events.filter(e=>['intent','self_report'].includes(e.kind))],['도구 실행',events.filter(e=>e.sourceKind==='tool'&&e.kind==='execution')],['독립 결과',events.filter(e=>e.sourceKind==='tool'&&e.kind==='result')],['권한·승인·위임',events.filter(e=>['grant','revoke','human_approval','automated_review','delegation'].includes(e.kind))]];
    const chart=svg('svg',{viewBox:'0 0 840 180',role:'img','aria-label':groups.map(([name,e])=>`${name} ${e.length}건`).join(', ')+`, 참고자료 ${refs.length}건`});
    chart.append(svg('rect',{x:315,y:10,width:210,height:48,rx:8,class:'graph-action-node'}),svg('text',{x:420,y:40,'text-anchor':'middle',class:'graph-node-heading'},'선택한 AI 행동'));
    groups.forEach(([name,list],i)=>{const x=10+i*210;chart.append(svg('path',{d:`M420 58 V82 H${x+95} V108`,class:'graph-link',fill:'none'}),svg('rect',{x,y:108,width:190,height:64,rx:8,class:list.length?'graph-evidence-node':'graph-missing-node'}),svg('text',{x:x+95,y:133,'text-anchor':'middle'},name),svg('text',{x:x+95,y:157,'text-anchor':'middle',class:'graph-node-count'},list.length?`${list.length}건`:'미수집'));});
    p.append(chart); const controls=node('div','graph-evidence-controls');groups.forEach(([name,list])=>controls.append(button(`${name} · ${list.length}건 확인`,()=>onInspect(name,list),'small')));p.append(controls);
    const refList=node('div','graph-reference-list');p.append(node('h3','',`연결된 참고 데이터 · ${refs.length}개 참조`));
    if(!refs.length)refList.append(node('p','graph-gap','참고 데이터가 수집되지 않아 모델이 무엇을 참고했는지 확인할 수 없습니다.'));
    refs.slice(0,12).forEach(ref=>{const b=button(`${ref.id||'식별자 미수집'} · ${ref.version||'버전 미수집'}`,()=>onInspect('자료 참조 · 실제 사용 여부는 별도 확인',ref),'graph-reference');b.append(node('small','',`${ref.source||'출처 미수집'} · ${ref.verification==='self_reported_reference'?'AI 자기보고':ref.verification==='service_reported_reference'?'서비스 보고':'출처 구분 미확인'}`));refList.append(b);});
    if(refs.length>12)refList.append(node('p','muted',`${refs.length-12}개 추가 참조는 아래 전체 참고 데이터에서 확인하세요.`));p.append(refList);return p;
  }
  return {render,action};
})();

window.EvidScopeMonitor = (() => {
 const node=(tag,cls,text)=>{const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=String(text);return n;};
 const svg=(tag,attrs,text)=>{const n=document.createElementNS('http://www.w3.org/2000/svg',tag);for(const [k,v]of Object.entries(attrs))n.setAttribute(k,String(v));if(text!==undefined)n.textContent=String(text);return n;};
 const series=[['received','전체 수신','monitor-teal'],['success','도구 성공','monitor-blue'],['failure','도구 실패','monitor-red'],['unknown','도구 결과 상태 미확인','monitor-amber'],['gaps','출처가 보고한 수집 공백','monitor-purple']];
 const time=value=>new Date(value).toLocaleTimeString('ko-KR',{hour12:false});
 const duration=ms=>ms>=3600000?`${ms/3600000}시간`:ms>=60000?`${ms/60000}분`:`${ms/1000}초`;
 const profiles={'10m':['상세 조사 · 최근 10분',30000,30000],'1h':['운영 모니터링 · 최근 1시간',60000,60000],'24h':['일간 추세 · 최근 24시간',300000,300000],'7d':['주간 검토 · 최근 7일',3600000,900000]};
 function mount({fetchData,isCurrent,dataNotice}) {
  const root=node('section','card monitor-panel');
  root.append(node('p','monitor-eyebrow','LIVE · 목적에 따른 자동 갱신'),node('h2','','AI 수신 흐름'),node('p','muted','시간별 수신 건수를 따라가며 도구 결과와 수집 공백 신호를 함께 확인하세요.'));
  if(dataNotice)root.append(node('p','graph-gap',dataNotice));
  const toolbar=node('div','monitor-toolbar'),range=node('select'),source=node('select'),pause=node('button','small','일시정지');pause.type='button';
  range.setAttribute('aria-label','모니터링 시간 범위');source.setAttribute('aria-label','모니터링 출처');
  for(const [value,[label]]of Object.entries(profiles)){const o=node('option','',label);o.value=value;range.append(o);}range.value='1h';
  const all=node('option','','모든 등록 출처');all.value='';source.append(all);
  toolbar.append(range,source,pause);root.append(toolbar);
  const expand=node('button','small','차트 넓게 보기');expand.type='button';expand.setAttribute('aria-pressed','false');expand.addEventListener('click',()=>{const wide=root.className.includes('monitor-expanded');root.className=wide?'card monitor-panel':'card monitor-panel monitor-expanded';expand.textContent=wide?'차트 넓게 보기':'기본 화면으로';expand.setAttribute('aria-pressed',String(!wide));});toolbar.append(expand);
  const policy=node('p','monitor-policy');root.append(policy);
  function showPolicy(){const [label,bucket,refresh]=profiles[range.value];policy.textContent=`${label} · 한 점은 ${duration(bucket)}간 수신 건수 · 화면은 ${duration(refresh)}마다 갱신. 짧은 변동은 상세 조사에서, 장기 추세는 일간·주간에서 확인하세요. 화면 갱신 간격은 이벤트 수집·탐지 주기와 별개입니다.`;}
  showPolicy();
  const status=node('p','monitor-status','첫 수신 집계를 조회하고 있습니다…');status.setAttribute('role','status');
  const summary=node('div','monitor-summary'),legend=node('div','monitor-legend'),chart=node('div','monitor-chart'),detail=node('p','monitor-detail','차트에 마우스를 올리거나 시간별 표를 펼쳐 수치를 확인하세요.'),health=node('p','muted');
  const enabled=new Set(series.map(s=>s[0]));
  for(const [key,label,cls]of series){const b=node('button',cls,label);b.type='button';b.setAttribute('aria-pressed','true');b.addEventListener('click',()=>{enabled.has(key)?enabled.delete(key):enabled.add(key);b.setAttribute('aria-pressed',String(enabled.has(key)));draw();});legend.append(b);}
  const tableDetails=node('details'),tableTitle=node('summary','','시간별 수치 보기'),tableBody=node('div','monitor-table');tableDetails.append(tableTitle,tableBody);
  const scale=node('div','monitor-scale'),navigator=node('div','monitor-navigator'),windowLabel=node('p','monitor-window');
  const control=(text,fn)=>{const b=node('button','small',text);b.type='button';b.addEventListener('click',fn);return b;};
  const zoomIn=control('＋ 확대',()=>zoomBy(2)),zoomOut=control('− 축소',()=>zoomBy(.5)),earlier=control('← 이전 구간',()=>panBy(-1)),later=control('다음 구간 →',()=>panBy(1)),reset=control('전체 구간',()=>{zoom=1;viewEnd=null;draw();}),follow=control('최신 따라가기',()=>{viewEnd=null;draw();});
  const position=node('input');position.type='range';position.min='0';position.step='1';position.setAttribute('aria-label','차트 시간축 위치');position.addEventListener('input',()=>{if(!data)return;const index=Number(position.value);viewEnd=index>=data.points.length-1?null:data.points[index].at;draw();});
  scale.append(zoomIn,zoomOut,earlier,later,reset,follow);navigator.append(position);root.append(status,summary,legend,scale,chart,detail,windowLabel,navigator,health,tableDetails,node('p','muted','수신 시각 기준 · 현재 보존 중인 기록 · 마지막 구간은 집계 중입니다. 0건은 기록이 없다는 뜻이며, 실제 AI가 활동하지 않았다는 보장은 아닙니다. 도구 결과 상태 미확인은 제출된 결과의 상태 누락·기타 값입니다. 결과 자체가 없는 행동은 아래 행동 분포에서 확인하세요. 파기 시 과거 수치가 바뀔 수 있으며, 감사 시 원본 증거와 대조하세요.'));
  let data=null,timer=null,busy=false,disposed=false,paused=false,revision=0,failures=0,lastAt=null;
  let zoom=1,viewEnd=null,visibleStart=0,visibleEnd=0,visibleCount=0;
  function zoomBy(factor){if(!data)return;zoom=Math.max(1,Math.min(8,zoom*factor));draw();}
  function panBy(direction){if(!data)return;const index=Math.max(visibleCount-1,Math.min(data.points.length-1,visibleEnd+direction*Math.max(1,Math.floor(visibleCount/2))));viewEnd=index===data.points.length-1?null:data.points[index].at;draw();}
  const active=()=>!disposed&&isCurrent();
  const blocked=()=>paused||document.hidden;
  function draw(){
   if(!data)return;
   summary.replaceChildren();for(const [key,label,cls]of series){const box=node('div',cls);box.append(node('small','',label),node('strong','',data.points.reduce((n,p)=>n+p[key],0).toLocaleString('ko-KR')+'건'));summary.append(box);}
   visibleCount=Math.max(2,Math.min(data.points.length,Math.max(8,Math.ceil(data.points.length/zoom))));
   visibleEnd=viewEnd===null?data.points.length-1:data.points.findLastIndex(p=>p.at<=viewEnd);visibleEnd=Math.max(visibleCount-1,visibleEnd);visibleStart=visibleEnd-visibleCount+1;
   const points=data.points.slice(visibleStart,visibleEnd+1),W=1200,H=410,left=28,right=1125,top=30,bottom=365;
   position.min=String(visibleCount-1);position.max=String(data.points.length-1);position.value=String(visibleEnd);position.disabled=visibleCount===data.points.length;
   zoomIn.disabled=visibleCount<=8;zoomOut.disabled=zoom===1;earlier.disabled=visibleStart===0;later.disabled=visibleEnd===data.points.length-1;follow.setAttribute('aria-pressed',String(viewEnd===null));
   const max=Math.max(4,Math.ceil(Math.max(0,...points.flatMap(p=>[...enabled].map(k=>p[k])))/4)*4);
   const x=i=>left+i/(points.length-1)*(right-left),y=v=>bottom-v/max*(bottom-top);
   const stamp=value=>data.range==='7d'||data.range==='24h'?new Date(value).toLocaleString('ko-KR',{month:'numeric',day:'numeric',hour:'2-digit',minute:'2-digit',hour12:false}):time(value);
   const graph=svg('svg',{viewBox:`0 0 ${W} ${H}`,role:'img','aria-label':`수신 시각별 선 그래프, ${duration(data.bucketMs)} 단위. 아래 시간별 표에서 같은 수치를 확인할 수 있습니다.`});
   for(let i=0;i<=4;i++){const yy=top+i*(bottom-top)/4;graph.append(svg('line',{x1:left,x2:right,y1:yy,y2:yy,class:'monitor-grid'}),svg('text',{x:right+12,y:yy+4,'text-anchor':'start',class:'monitor-axis'},Number((max*(4-i)/4).toFixed(1))));}
   for(const i of [0,Math.floor((points.length-1)/4),Math.floor((points.length-1)/2),Math.floor(3*(points.length-1)/4),points.length-1])graph.append(svg('text',{x:x(i),y:395,'text-anchor':i===0?'start':i===points.length-1?'end':'middle',class:'monitor-axis'},stamp(points[i].at)));
   graph.append(svg('text',{x:left,y:14,class:'monitor-axis'},`${duration(data.bucketMs)}당 건수`));
   for(const [key,,cls]of series){if(!enabled.has(key))continue;graph.append(svg('path',{d:points.map((p,i)=>`${i?'L':'M'}${x(i)},${y(p[key])}`).join(' '),class:`monitor-line ${cls}`,fill:'none'}));const last=points.at(-1);graph.append(svg('circle',{cx:x(points.length-1),cy:y(last[key]),r:4,class:`monitor-dot ${cls}`}));}
   const cursor=svg('line',{x1:left,x2:left,y1:top,y2:bottom,class:'monitor-cursor',visibility:'hidden'}),cross=svg('line',{x1:left,x2:right,y1:bottom,y2:bottom,class:'monitor-cursor',visibility:'hidden'});graph.append(cursor,cross);
   points.forEach((p,i)=>{const hit=svg('rect',{x:Math.max(left,x(i)-(right-left)/(points.length-1)/2),y:top,width:(right-left)/(points.length-1),height:bottom-top,class:'monitor-hit'});const inspect=()=>{cursor.setAttribute('x1',x(i));cursor.setAttribute('x2',x(i));cursor.setAttribute('visibility','visible');const primary=[...enabled][0];cross.setAttribute('y1',y(p[primary]||0));cross.setAttribute('y2',y(p[primary]||0));cross.setAttribute('visibility',primary?'visible':'hidden');detail.textContent=`${stamp(p.at)}–${stamp(p.end)}${p.partial?' · 집계 중':''} | `+series.map(([k,l])=>`${l} ${p[k]}건`).join(' · ');};hit.addEventListener('pointerenter',inspect);hit.addEventListener('click',inspect);graph.append(hit);});
   chart.replaceChildren(graph);if(!enabled.size)chart.append(node('p','muted','표시할 선을 위 범례에서 선택하세요.'));
   detail.textContent=`조회 시각 ${time(data.generatedAt)} · 마지막 구간 집계 중 · 선 범례를 눌러 표시를 바꿀 수 있습니다.`;
   windowLabel.textContent=`${stamp(points[0].at)} – ${stamp(points.at(-1).end)} · ${visibleCount}/${data.points.length}개 구간 표시 · ${viewEnd===null?'최신 구간 따라가는 중':'과거 구간 고정'} · 세로축은 표시 구간에 자동 맞춤 · 상단 합계는 선택한 전체 조회 기간 기준`;
   const mini=svg('svg',{viewBox:'0 0 1200 55',role:'img','aria-label':'전체 조회 기간의 수신량과 현재 확대 구간'}),miniMax=Math.max(1,...data.points.map(p=>p.received));
   mini.append(svg('polyline',{points:data.points.map((p,i)=>`${i/(data.points.length-1)*1200},${50-p.received/miniMax*44}`).join(' '),class:'monitor-mini-line',fill:'none'}),svg('rect',{x:visibleStart/data.points.length*1200,y:1,width:visibleCount/data.points.length*1200,height:53,class:'monitor-mini-window'}));navigator.replaceChildren(mini,position);
   const selected=data.sources.filter(s=>!data.source||s.id===data.source),recent=selected.filter(s=>s.status==='receiving').length;
   health.textContent=`출처 수신 상태: 선택한 ${selected.length}개 중 최근 5분 내 수신 ${recent}개 · 미연결/최근 수신 없음 ${selected.length-recent}개. 조회 API 연결과 출처 수집 상태는 별개입니다.`;
   const table=node('table'),thead=node('thead'),hr=node('tr');['수신 시간',...series.map(s=>s[1])].forEach(t=>hr.append(node('th','',t)));thead.append(hr);table.append(thead);const body=node('tbody');for(const p of points){const tr=node('tr');tr.append(node('td','',`${stamp(p.at)}${p.partial?' (집계 중)':''}`));series.forEach(([k])=>tr.append(node('td','',p[k])));body.append(tr);}table.append(body);tableBody.replaceChildren(table);
  }
  function schedule(){if(active()&&!blocked())timer=setTimeout(tick,Math.min(3600000,profiles[range.value][2]*2**Math.min(failures,3)));}
  async function tick(){
   clearTimeout(timer);if(!active()||blocked()||busy)return;
   busy=true;const current=revision;
   try{const next=await fetchData(range.value,source.value);if(!active()||current!==revision||blocked())return;
    data=next;lastAt=next.generatedAt;failures=0;
    const selection=source.value;source.replaceChildren(all);for(const s of data.sources){const o=node('option','',s.id);o.value=s.id;source.append(o);}source.value=selection;
    status.className='monitor-status connected';status.textContent=`자동 갱신 중 · 마지막 성공 ${time(lastAt)} · ${duration(profiles[range.value][2])} 간격`;
    draw();
   }catch(error){if(!active()||current!==revision||blocked())return;failures++;status.className='monitor-status error';status.textContent=`조회 실패 · ${lastAt?'마지막 성공 '+time(lastAt)+' 자료를 유지합니다.':'아직 표시할 데이터가 없습니다.'} ${error.message}`;if([401,403].includes(error.status)){paused=true;pause.textContent='다시 시도';}}
   finally{busy=false;if(active())schedule();}
  }
  function change(){revision++;failures=0;zoom=1;viewEnd=null;showPolicy();data=null;lastAt=null;chart.replaceChildren();summary.replaceChildren();tableBody.replaceChildren();navigator.replaceChildren(position);windowLabel.textContent='';health.textContent='';detail.textContent='';status.textContent=blocked()?'일시정지 · 재개하면 선택한 범위를 조회합니다.':'선택한 범위를 조회하고 있습니다…';clearTimeout(timer);tick();}
  range.addEventListener('change',change);source.addEventListener('change',change);
  pause.addEventListener('click',()=>{paused=!paused;revision++;clearTimeout(timer);pause.textContent=paused?'실시간 재개':'일시정지';status.textContent=paused?`일시정지 · ${lastAt?'마지막 성공 '+time(lastAt):'수신 전'}`:'자동 조회 재개 중…';if(!paused)tick();});
  const visibility=()=>{revision++;clearTimeout(timer);if(document.hidden){status.textContent='탭이 숨겨져 자동 조회가 일시정지됐습니다.';}else if(!paused){status.textContent='자동 조회 재개 중…';tick();}};
  document.addEventListener('visibilitychange',visibility);tick();
  return {root,dispose(){disposed=true;revision++;clearTimeout(timer);document.removeEventListener('visibilitychange',visibility);}};
 }
 return {mount};
})();

