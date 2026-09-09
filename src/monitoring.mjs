import {fail} from './model.mjs';

// Operational projection only: no raw evidence or cross-tenant process counters.
export function monitoring(store, principals, tenant, params, now = Date.now()) {
 // Purpose-based defaults, not a universal incident detection SLA.
 const ranges = {'10m':[600000,30000,30000], '1h':[3600000,60000,60000], '24h':[86400000,300000,300000], '7d':[604800000,3600000,900000]};
 const range = params.get('range') || '1h';
 if (!Object.hasOwn(ranges,range)) fail(400,'시간 범위는 10m, 1h, 24h, 7d 중 선택하세요');
 const source = params.get('source') || '';
 const registered = principals.filter(p=>p.tenant===tenant&&p.role==='source');
 if(source&&!registered.some(p=>p.id===source)) fail(400,'조회 가능한 등록 출처가 아닙니다');
 const [duration,step,refreshMs] = ranges[range], end = Math.floor(now/step)*step, start=end-duration+step;
 const rows=store.db.prepare(`SELECT CAST((unixepoch(received)*1000-?)/? AS INTEGER) bucket,
 COUNT(*) received,
 SUM(CASE WHEN json_extract(body,'$.sourceKind')='tool' AND kind='result' AND json_extract(body,'$.status')='success' THEN 1 ELSE 0 END) success,
 SUM(CASE WHEN json_extract(body,'$.sourceKind')='tool' AND kind='result' AND json_extract(body,'$.status')='failure' THEN 1 ELSE 0 END) failure,
 SUM(CASE WHEN json_extract(body,'$.sourceKind')='tool' AND kind='result' AND COALESCE(json_extract(body,'$.status'),'') NOT IN ('success','failure') THEN 1 ELSE 0 END) unknown,
 SUM(CASE WHEN kind='gap' THEN 1 ELSE 0 END) gaps
 FROM events WHERE tenant=? AND received>=? AND received<=? ${source?'AND source=?':''} GROUP BY bucket`).all(start,step,tenant,new Date(start).toISOString(),new Date(now).toISOString(),...(source?[source]:[]));
 const byBucket=new Map(rows.map(row=>[row.bucket,row]));
 const points=Array.from({length:duration/step},(_,i)=>{
  const row=byBucket.get(i);return {at:new Date(start+i*step).toISOString(),end:new Date(Math.min(start+(i+1)*step,now)).toISOString(),partial:i===duration/step-1,...Object.fromEntries(['received','success','failure','unknown','gaps'].map(key=>[key,row?.[key]||0]))};
 });
 const seen=store.db.prepare('SELECT source, MAX(received) lastSeen FROM events WHERE tenant=? GROUP BY source').all(tenant);
 const sources=registered.map(p=>{const lastSeen=seen.find(s=>s.source===p.id)?.lastSeen||null;return {id:p.id,kind:p.kind,lastSeen,status:!lastSeen?'not_connected':now-Date.parse(lastSeen)>300000?'stale':'receiving'};});
 return {range,source,generatedAt:new Date(now).toISOString(),bucketMs:step,refreshMs,points,sources,
 scope:'tenant_retained_event_projection_by_received_time',
 limitations:['수신 시각 기준 현재 보존 중인 조회 사본 집계; 파기 후 과거 수치가 줄 수 있습니다','도구 결과의 상태 미확인은 result 기록의 상태가 없거나 success/failure가 아닌 경우입니다. 결과 자체가 없는 행동의 수가 아닙니다','수신 0은 수집 기록 없음이며 실행 없음·안전·연결 정상의 증명이 아닙니다','운영 집계는 서명된 감사 증거를 대체하지 않습니다']};
}
