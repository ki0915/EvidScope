/* Independent, static Kubernetes evidence view. No network requests. */
(() => {
 'use strict';
 const el=(tag,text,className)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=String(text);if(className)n.className=className;return n;};
 const svg=(tag,attributes={},text)=>{const n=document.createElementNS('http://www.w3.org/2000/svg',tag);for(const [k,v] of Object.entries(attributes))n.setAttribute(k,String(v));if(text!==undefined)n.textContent=String(text);return n;};
 const number=n=>Number(n).toLocaleString('ko-KR');
 const clock=t=>new Date(t).toISOString().slice(11,19);
 function chart(label,height=120){const n=svg('svg',{viewBox:`0 0 620 ${height}`,role:'img','aria-label':label,class:'k8se-chart'});n.append(svg('title',{},label));return n;}
 function table(headers,rows){const detail=el('details',undefined,'k8se-data');detail.append(el('summary','수치와 출처를 표로 보기'));const wrap=el('div',undefined,'k8se-table-wrap'),t=el('table'),head=el('thead'),tr=el('tr');headers.forEach(h=>tr.append(el('th',h)));head.append(tr);t.append(head);const body=el('tbody');for(const row of rows){const r=el('tr');row.forEach(v=>r.append(el('td',v)));body.append(r);}t.append(body);wrap.append(t);detail.append(wrap);return detail;}
 function card(title,note){const c=el('section',undefined,'k8se-card');c.append(el('h2',title),el('p',note,'k8se-note'));return c;}
 function legend(labels){const list=el('div',undefined,'k8se-legend');labels.forEach(([name,cls])=>list.append(el('span',name,cls)));return list;}
 function render(){
  const root=el('div',undefined,'k8se'),d=window.EvidScopeK8sData;
  if(!d||d.format!=='evidscope-k8s-chart-data-v1'){root.append(el('p','Kubernetes 검증 데이터를 불러오지 못했습니다.','k8se-warning'));return root;}
  const hero=el('header',undefined,'k8se-hero');hero.append(el('p',`${d.snapshotDate} 실측 스냅샷 · 실시간 아님`,'k8se-snapshot'),el('h2','분산과 복구, 관측한 만큼만'),el('p','전용 로컬 Kubernetes 클러스터의 검증 기록입니다. 성공 응답, 실패 요청, 원장 보존을 각각 구분했습니다. 현재 서비스 상태를 나타내지 않습니다.'));root.append(hero);
  const grid=el('div',undefined,'k8se-grid');
  const dist=card('두 Pod가 나눠 처리한 요청','준비 확인 후 각 60건을 새 TLS 연결로 요청했습니다.');
  const controls=el('div',undefined,'k8se-controls');controls.setAttribute('role','group');controls.setAttribute('aria-label','수집과 감사 요청 분산 비교');
  const panel=el('div');panel.setAttribute('aria-live','polite');const buttons=[];
  function showDistribution(index){const row=d.baseline[index];buttons.forEach((b,i)=>b.setAttribute('aria-pressed',String(i===index)));panel.replaceChildren();panel.append(el('p',`${row.label} ${number(row.success)} / ${number(row.total)} 성공 · 실패 ${number(row.failed)}건`,'k8se-result'));
   const g=chart(`${row.label} Pod별 성공 응답: ${row.pods.map(p=>`${p.name} ${p.count}건`).join(', ')}`,70);let x=0;
   row.pods.forEach((p,i)=>{const w=620*p.count/row.total;g.append(svg('rect',{x,y:8,width:w,height:42,class:i%2?'k8se-fill-blue':'k8se-fill-teal'}),svg('text',{x:x+w/2,y:35,'text-anchor':'middle',class:'k8se-bar-value'},`${p.count}건 · ${(100*p.count/row.total).toFixed(0)}%`));x+=w;});panel.append(g);
   const list=el('ul',undefined,'k8se-pods');row.pods.forEach(p=>list.append(el('li',`${p.name} · ${p.count}건`)));panel.append(list,el('p',`관측 ${clock(row.startedAt)}–${clock(row.finishedAt)} UTC. 별도 준비 확인 단계 실패 ${row.preflightFailed}회는 위 60건에 포함하지 않았습니다.`,'k8se-note'),table(['Pod 표시명','성공 응답','출처'],row.pods.map(p=>[p.name,p.count,row.source])));
  }
  d.baseline.forEach((r,i)=>{const b=el('button',r.label);b.type='button';b.addEventListener('click',()=>showDistribution(i));buttons.push(b);controls.append(b);});dist.append(controls,panel,el('p','Pod 헤더는 서버의 식별 주장입니다. 실제 Pod·EndpointSlice 대조 자료와 함께 해석하며, 50:50 분배나 처리 한계를 보장하지 않습니다.','k8se-note'));showDistribution(0);grid.append(dist);
  const hpa=card('감사 Pod 수의 변화','HPA 보고 수와 실제 Ready Pod 수를 관측 시점별로 표시했습니다.');hpa.append(legend([['● HPA 현재 수','k8se-teal-text'],['◇ Ready 수','k8se-blue-text']]));
  const graph=chart('감사 HPA와 Ready Pod 수. '+d.hpa.map(p=>`${clock(p.at)} UTC: HPA ${p.current}, Ready ${p.ready}`).join('; '),255),start=Date.parse(d.hpa[0].at),duration=Date.parse(d.hpa.at(-1).at)-start;
  for(let n=0;n<=3;n++){const y=190-n*45;graph.append(svg('line',{x1:42,x2:594,y1:y,y2:y,class:'k8se-gridline'}),svg('text',{x:25,y:y+4,'text-anchor':'end',class:'k8se-axis'},n));}
  d.hpa.forEach((p,i)=>{const x=54+(Date.parse(p.at)-start)/duration*524,y=190-p.current*45,ry=190-p.ready*45;graph.append(svg('circle',{cx:x,cy:y,r:7,class:'k8se-fill-teal'}),svg('path',{d:`M ${x} ${ry-10} l 10 10 l -10 10 l -10 -10 Z`,class:'k8se-ready-dot'}),svg('text',{x,y:y-17,'text-anchor':'middle',class:'k8se-point-label'},p.current),svg('text',{x,y:213+(i%2)*19,'text-anchor':'middle',class:'k8se-axis'},clock(p.at)));});hpa.append(graph,el('p','시각은 UTC입니다. 점 사이 구간은 측정하지 않아 연결선으로 추정하지 않았습니다.','k8se-note'),el('p',`부하 종료 ${clock(d.hpaTraffic.finishedAt)} UTC 이후에 Ready 3개가 관측됐습니다. 세 번째 Pod가 부하 중 실제 요청을 분담했다는 증거는 아닙니다.`,'k8se-warning'),table(['시각 (UTC)','HPA 현재','HPA 목표','Ready','출처'],d.hpa.map(p=>[clock(p.at),p.current,p.desired,p.ready,p.source])));grid.append(hpa);root.append(grid);
  const requests=card('장애와 부하 중의 요청 결과','막대 길이는 각 실험의 비율입니다. 표본 수가 다른 실험의 처리 용량을 비교하는 그래프가 아닙니다.');requests.append(legend([['성공','k8se-teal-text'],['실패 / 성공 미확인','k8se-red-text']]));
  for(const r of d.requests){const item=el('div',undefined,'k8se-request');item.append(el('h3',r.label),el('p',`${number(r.success)} / ${number(r.total)} 성공 (${(100*r.success/r.total).toFixed(2)}%) · 실패 ${number(r.failed)}건`,'k8se-result'));const c=chart(`${r.label}: 성공 ${r.success}건, 실패 ${r.failed}건, 전체 ${r.total}건`,36),w=620*r.success/r.total;c.append(svg('rect',{x:0,y:2,width:w,height:20,class:'k8se-fill-teal'}),svg('rect',{x:w,y:2,width:620-w,height:20,class:'k8se-fill-red'}));item.append(c,el('p',`${clock(r.startedAt)}–${clock(r.finishedAt)} UTC · 별도 준비 확인 실패 ${r.preflightFailed}회`,'k8se-note'));requests.append(item);}
  requests.append(el('p','작은 실패 비율도 실제 폭으로 표시했습니다. 수집 실패 응답은 미수신을 확정하지 못하므로, 수신 원장 대조 결과를 별도로 확인해야 합니다.','k8se-note'),table(['실험','성공','실패','전체','출처'],d.requests.map(r=>[r.label,r.success,r.failed,r.total,r.source])));root.append(requests);
  const saved=card('Vault 재시작 뒤에도 수신 증거 보존','서명 검증과 이전 원장 연속성 대조 결과입니다.');saved.append(el('p',`${number(d.preservation.events)}건`,'k8se-preserved'),el('p',`서명 검증 ${d.preservation.verified?'통과':'실패'} · 이전 원장 연속성 ${d.preservation.continuityPreserved?'보존 확인':'미확인'}`),el('p','수신·공개된 증거의 보존을 확인했습니다. 원본 행위의 사실성이나 모든 전송 시도의 도착을 보장하는 수치가 아닙니다.','k8se-note'),table(['증거 수','검증 시각 (UTC)','출처'],[[d.preservation.events,clock(d.preservation.at),d.preservation.source]]));root.append(saved);
  root.append(el('p','표에는 reports/의 검증 파일명을 표시합니다. 그래프용 공개 데이터는 원본 보고서의 시각·개수·상태·Pod 표시명만 추출했으며 토큰이나 원문 증거를 포함하지 않습니다.','k8se-footnote'));return root;
 }
 window.EvidScopeK8s=Object.freeze({render});
})();
