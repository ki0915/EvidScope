import {readdirSync,statSync,existsSync,writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {evaluateKrGovernanceEvidence} from '../src/kr-governance-evidence.mjs';
const parent=resolve('.test-runs'),directories=readdirSync(parent,{withFileTypes:true}).filter(d=>d.isDirectory()&&d.name.startsWith('run-')).map(d=>({name:d.name,path:join(parent,d.name),mtime:statSync(join(parent,d.name)).mtimeMs})).sort((a,b)=>b.mtime-a.mtime).slice(0,160),found=[];
for(const dir of directories){
 const file=join(dir.path,'data','evidence.db');if(!existsSync(file))continue;let db;
 try{
  db=new DatabaseSync(file,{readOnly:true});const saved=db.prepare("SELECT body FROM objects WHERE tenant='alpha' AND type='system' AND id='kr-33-http'").get();if(!saved)continue;
  const system=JSON.parse(saved.body),assessments=db.prepare("SELECT body FROM objects WHERE tenant='alpha' AND type='assessment'").all().map(row=>JSON.parse(row.body)).filter(a=>a.systemId==='kr-33-http');
  const checked=assessments.map(assessment=>({id:assessment.id,createdAt:assessment.createdAt,result:evaluateKrGovernanceEvidence(assessment.requirementSnapshot,assessment,{system}),checks:assessment.evidence.filter(e=>e.eventSnapshot?.governanceCheck).map(e=>({ref:e.ref,sourceKind:e.eventSnapshot.sourceKind,occurredAt:e.eventSnapshot.occurredAt,receivedAt:e.eventSnapshot.receivedAt,clockUncertaintyMs:e.eventSnapshot.clockUncertaintyMs,checkType:e.eventSnapshot.governanceCheck.checkType,requestedAt:e.eventSnapshot.governanceCheck.measurements.requestedAt,providedAt:e.eventSnapshot.governanceCheck.measurements.providedAt,reviewedAt:e.eventSnapshot.governanceCheck.measurements.reviewedAt}))}));
  const latest=checked.sort((a,b)=>a.createdAt.localeCompare(b.createdAt)).at(-1);found.push({directory:dir.name,mtime:new Date(dir.mtime).toISOString(),assessmentCount:checked.length,latest});
 }finally{db?.close();}
}
const result={readOnly:true,scanned:directories.length,found};writeFileSync(new URL('./release-012-kr33-retained-timing-20261006.json',import.meta.url),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
