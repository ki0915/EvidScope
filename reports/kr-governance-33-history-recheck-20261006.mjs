import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync,writeFileSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {harness} from '../test/harness.mjs';
import {digest} from '../src/crypto.mjs';

const originalRoot=resolve('.test-runs/run-7uPpS6'),dataDir=join(originalRoot,'data'),config=JSON.parse(readFileSync(join(originalRoot,'config.json'),'utf8'));
const historyQuery="SELECT seq,body,hash FROM ledger WHERE tenant='alpha' AND json_extract(body,'$.type') IN ('supplier_bundle','finance_report','assessment','evaluation') ORDER BY seq";
const db=new DatabaseSync(join(dataDir,'evidence.db'),{readOnly:true}),reports=db.prepare("SELECT body FROM objects WHERE tenant='alpha' AND type='finance_report' ORDER BY id").all().map(r=>JSON.parse(r.body)),before=db.prepare(historyQuery).all();db.close();
assert.equal(reports.length,4);
const h=await harness({vaultOnly:true});
try{
 const legacy=await h.start('vault',{DATA_DIR:dataDir,CONFIG_FILE:join(originalRoot,'config.json'),SIGNING_KEY_FILE:join(originalRoot,'signing-private.pem')});
 const headers={authorization:'Bearer '+config.principals.find(p=>p.tenant==='alpha'&&p.role==='auditor').token},checked=[];
 for(const report of reports){
  const originalItem=report.snapshot.governance.items.find(item=>item.requirement.id==='KR-33');assert.ok(originalItem);assert.equal(originalItem.technicalEvidence.optionalWorkflows,undefined);
  const response=await h.api('/api/governance/finance/reports/'+report.id,{base:legacy.url,headers});assert.equal(response.status,200);assert.deepEqual(response.body,report);
  checked.push({id:report.id,digest:digest(report),oldKr33TechnicalStatus:originalItem.technicalEvidence.status,oldKr33ResponseShapeUnchanged:true});
 }
 const afterDb=new DatabaseSync(join(dataDir,'evidence.db'),{readOnly:true}),after=afterDb.prepare(historyQuery).all();afterDb.close();assert.deepEqual(after,before);
 const result={syntheticOnly:true,scope:'pre-patch signed report HTTP retrieval; no legal verdict',historicalReportsUnchanged:checked,historicalSignedRecordsUnchanged:true,historicalRecordCount:before.length};
 writeFileSync(new URL('./kr-governance-33-history-recheck-20261006.json',import.meta.url),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
}finally{await h.close();}
