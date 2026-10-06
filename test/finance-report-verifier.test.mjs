import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {harness} from './harness.mjs';
import {verifyFinanceReport} from '../src/report-verifier.mjs';
const execute=promisify(execFile);

test('independent finance verifier CLI accepts a real HTTP export and rejects changed evidence, wrong key and stale external digest',async t=>{
 const h=await harness();t.after(()=>h.close());
 assert.equal((await h.api('/api/governance/systems',{role:'reviewer',body:{id:'verifier-credit',name:'합성 보고서 검증',owner:'검토팀',purpose:'대출 검토',markets:['KR'],krRoles:[],aiBusinessOperator:false,modelId:'credit-model',modelVersion:'v1'}})).status,200);
 const result=await h.api('/api/governance/finance/report',{role:'reviewer',body:{systemId:'verifier-credit'}});assert.equal(result.status,200);const report=result.body;
 const trustedKey=join(h.dir,'trust-anchor.pem'),file=join(h.dir,'finance.json');writeFileSync(file,JSON.stringify(report));
 const invoke=async hash=>execute(process.execPath,[resolve('scripts/verify-finance-report.mjs'),file,trustedKey,...(hash?[hash]:[])],{timeout:10000});
 const unpinned=JSON.parse((await invoke()).stdout);assert.equal(unpinned.valid,true);assert.equal(unpinned.rollbackChecked,false);assert.equal(unpinned.automaticLegalVerdict,false);
 const pinned=JSON.parse((await invoke(report.sha256)).stdout);assert.equal(pinned.rollbackChecked,true);
 await assert.rejects(invoke('0'.repeat(64)),error=>error.code===1&&/External report digest/.test(error.stderr));
 const altered=structuredClone(report);altered.snapshot.system.modelVersion='other-model';writeFileSync(file,JSON.stringify(altered));
 await assert.rejects(invoke(),error=>error.code===1&&/digest mismatch/.test(error.stderr));
 const wrong=generateKeyPairSync('ed25519').publicKey;const embedded=structuredClone(report);embedded.publicKey=wrong.export({format:'pem',type:'spki'});assert.equal(verifyFinanceReport(embedded,h.publicKey).valid,true);
 assert.throws(()=>verifyFinanceReport(report,wrong),/signature invalid/);
 const invalid=structuredClone(report);invalid.signature='A'.repeat(86)+'==';assert.throws(()=>verifyFinanceReport(invalid,h.publicKey),/signature invalid/);
});
