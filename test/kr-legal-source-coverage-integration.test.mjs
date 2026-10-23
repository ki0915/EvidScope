import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { resolve, sep } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { harness } from './harness.mjs';
import { createService } from '../src/service.mjs';
import { canonical } from '../src/crypto.mjs';
import { krLegalSourceCoverage } from '../src/kr-legal-source-coverage.mjs';
import { verifyFinanceReport } from '../src/report-verifier.mjs';

const requirements = JSON.parse(readFileSync(new URL('../data/requirements.json', import.meta.url), 'utf8'));
const system = {id:'source-coverage-credit',name:'합성 출처 범위 검토',owner:'검토팀',purpose:'대출 검토',markets:['KR'],krRoles:['deployer'],aiBusinessOperator:true,highImpact:'candidate',modelId:'credit-model',modelVersion:'v1',policyVersion:'p1'};

test('real HTTP exposes exact source gaps and freezes them in tenant-bound signed reports across restart', async t => {
  const h = await harness(); t.after(() => h.close());
  assert.equal((await h.api('/api/governance/systems', {body:system,role:'reviewer'})).status,200);
  const expected=krLegalSourceCoverage(requirements),inventory=await h.api('/api/governance'),view=await h.api('/api/governance/report?systemId='+system.id);
  assert.equal(inventory.status,200);assert.equal(view.status,200);
  assert.deepEqual(inventory.body.legalSourceCoverage,expected);assert.deepEqual(view.body.legalSourceCoverage,expected);
  const exported=await h.api('/api/governance/finance/report',{body:{systemId:system.id},role:'reviewer'});
  assert.equal(exported.status,200);const original=exported.body,frozen=canonical(original.snapshot);
  assert.deepEqual(original.snapshot.governance.legalSourceCoverage,expected);
  assert.equal(verifyFinanceReport(original,h.publicKey).valid,true);
  const altered=structuredClone(original);altered.snapshot.governance.legalSourceCoverage.wholeLawComplete=true;
  assert.throws(()=>verifyFinanceReport(altered,h.publicKey),/digest mismatch/);
  assert.equal((await h.api('/api/governance/finance/reports/'+original.id,{tenant:'beta'})).status,404);
  await h.api('/api/governance/systems',{body:{...system,modelVersion:'v2'},role:'reviewer'});
  await h.restart();
  const retained=await h.api('/api/governance/finance/reports/'+original.id);
  assert.equal(retained.status,200);assert.equal(canonical(retained.body.snapshot),frozen);
  assert.equal(verifyFinanceReport(retained.body,h.publicKey).valid,true);
  assert.equal(retained.body.snapshot.system.modelVersion,'v1');
  assert.equal((await h.api('/api/governance/report?systemId='+system.id)).body.system.modelVersion,'v2');
});

test('new source-gap metadata preserves legacy signed history and opens re-review without rewriting human conclusions', async t => {
  const parent=resolve('.test-runs');mkdirSync(parent,{recursive:true});const directory=mkdtempSync(resolve(parent,'coverage-migration-'));
  const {privateKey:key,publicKey:trustedKey}=generateKeyPairSync('ed25519'),principal={id:'reviewer',tenant:'alpha',role:'reviewer',token:'r'.repeat(40)};
  const legacy=requirements.map(({legalSourceGaps,...row})=>row);
  const options={dataDir:directory,key,config:{principals:[principal]},requirements:legacy};
  let service=createService(options);
  t.after(()=>{service.store.close();assert.ok(resolve(directory).startsWith(parent+sep));rmSync(directory,{recursive:true,force:true});});
  const call=(path,body)=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),{authorization:'Bearer '+principal.token},body===undefined?'':JSON.stringify(body));
  await call('/api/governance/systems',system);
  const assessment=await call('/api/governance/assessments',{systemId:system.id,requirementId:'KR-34-RISK',applicability:'applicable',assessment:'insufficient',legalReview:'pending',control:'합성 검토',owner:'검토팀',reason:'추가 근거 확인 대기',nextReviewAt:'2099-01-01T00:00:00Z',evidence:[]});
  const first=await call('/api/governance/finance/report',{systemId:system.id}),frozen=canonical(first.snapshot),oldHash=first.snapshot.governance.legalSourceCoverage.hash;
  service.store.close();service=createService({...options,requirements});
  const current=await call('/api/governance/report?systemId='+system.id),row=current.items.find(item=>item.requirement.id==='KR-34-RISK');
  assert.notEqual(current.legalSourceCoverage.hash,oldHash);assert.equal(current.legalSourceCoverage.unresolvedSources.length,4);
  assert.equal(row.status,'review_required');assert.deepEqual(row.assessment,assessment);
  assert.ok(current.tasks.some(task=>task.requirementId==='KR-34-RISK'&&task.status==='open'&&/규정 출처/.test(task.title)));
  const retained=await call('/api/governance/finance/reports/'+first.id);
  assert.equal(canonical(retained.snapshot),frozen);assert.equal(retained.snapshot.governance.legalSourceCoverage.hash,oldHash);
  assert.equal(verifyFinanceReport(retained,trustedKey).valid,true);
});
