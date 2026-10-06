import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {financialCandidates} from '../scripts/generate-financial-evals.mjs';
import {exportHumanReviewPacket,recordHash,trainingAdmission} from '../scripts/model-training-data.mjs';
import {scoreRoleOutput} from '../src/role-evaluation.mjs';

const requirements=JSON.parse(readFileSync('data/requirements.json','utf8'));
const rows=financialCandidates(requirements);

test('automatic finance examples bind no-approval policy at execution without treating absent approval as a failure',()=>{
 const cases=rows.filter(row=>row.scenario==='automatic_no_approval');
 assert.equal(cases.length,78);
 for(const row of cases){
  const [policy,execution]=row.evidence;
  assert.equal(policy.approvalRequired,false);
  assert.equal(policy.policyVersion,execution.policyVersion);
  assert.ok(Date.parse(policy.validFrom)<=Date.parse(execution.occurredAt));
  assert.ok(Date.parse(execution.occurredAt)<Date.parse(policy.validUntil));
  assert.equal(execution.actorKind,'service');
  assert.equal(scoreRoleOutput(row,row.expectedOutput).passed,true);
  const output=JSON.stringify(row.expectedOutput);
  assert.match(output,row.outputLanguage==='ko'?/승인 누락으로 판단하지 않습니다/:/not an approval-missing finding/);
  assert.doesNotMatch(output,/Obtain the human decision record|검토자 신원·범위·시각을 포함한 사람 판단 기록을 확보/);
 }
});

test('late-received approval examples preserve occurrence ordering, uncertainty bounds and unreviewed provenance',()=>{
 const cases=rows.filter(row=>row.scenario==='late_approval');
 assert.equal(cases.length,78);
 for(const row of cases){
  const [approval,execution]=row.evidence;
  assert.ok(Date.parse(approval.occurredAt)+approval.clockUncertaintyMs<Date.parse(execution.occurredAt)-execution.clockUncertaintyMs);
  assert.ok(Date.parse(approval.validFrom)<=Date.parse(execution.occurredAt));
  assert.ok(Date.parse(execution.occurredAt)<Date.parse(approval.validUntil));
  assert.ok(Date.parse(approval.receivedAt)>Date.parse(execution.receivedAt));
  assert.equal(row.truth.referenceRelations[execution.id],'context_only');
  assert.equal(scoreRoleOutput(row,row.expectedOutput).passed,true);
  assert.match(row.expectedOutput.summary,row.outputLanguage==='ko'?/수집 지연을 사후 승인으로 판단하지 않습니다/:/delayed receipt, not post-execution approval/);
 }
 const packet=exportHumanReviewPacket(rows);
 for(const {record,review} of packet.records){
  assert.equal(review.recordHash,recordHash(record));
  assert.equal(record.humanReviewed,false);
  assert.equal(review.approved,false);
  assert.equal(review.approvedOutput,null);
 }
 assert.equal(trainingAdmission(rows).trainingRunAllowed,false);
});
