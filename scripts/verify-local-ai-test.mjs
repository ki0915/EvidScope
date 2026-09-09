// Separate human-auditor verification step; never provided to the model runtime.
import {readFileSync,writeFileSync} from 'node:fs';
import {verifyBundle} from '../src/crypto.mjs';
const pilot=JSON.parse(readFileSync('reports/local-ai-latest.json','utf8')),config=JSON.parse(readFileSync('.test-runs/ui/config.json','utf8'));
const auditor=config.principals.find(p=>p.id==='alpha-auditor'&&p.role==='auditor');
async function read(path){const r=await fetch('http://127.0.0.1:9082'+path,{headers:{authorization:'Bearer '+auditor.token},redirect:'error',signal:AbortSignal.timeout(20000)});if(r.status!==200)throw Error('Audit read '+r.status);return r.json();}
const action=await read('/api/actions/'+encodeURIComponent(pilot.run)),bundle=await read('/api/export'),verified=verifyBundle(bundle,readFileSync('.test-runs/ui/trust-anchor.pem','utf8'));
const disclosed=(bundle.disclosures||[]).map(d=>d.event).filter(e=>e.actionId===pilot.run);
const receiptsMatch=pilot.events.length===action.events.length&&pilot.events.every(expected=>action.events.some(e=>e.id===expected.id&&e.source===expected.source&&e.kind===expected.kind)&&disclosed.some(e=>e.id===expected.id&&e.source===expected.source));
const report={run:pilot.run,verifiedAt:new Date().toISOString(),pilotPass:pilot.pass,verified,receivedEvents:action.events.length,signedDisclosedEvents:disclosed.length,receiptsMatch,references:action.references.map(r=>({id:r.id,version:r.version,source:r.source,verification:r.verification})),findings:action.evaluations[0]?.findings.map(f=>f.code)||[],pass:pilot.pass&&verified.valid&&verified.tenant==='alpha'&&receiptsMatch,scope:'Human audit query plus signed ledger disclosure verification; does not prove the model used a reference causally or that an external business effect occurred'};
writeFileSync('reports/local-ai-audit-verification.json',JSON.stringify(report,null,2));console.log(JSON.stringify(report));if(!report.pass)process.exitCode=1;
