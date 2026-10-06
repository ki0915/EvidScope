import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdtempSync, readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {runPortfolioGovernanceDemo} from '../scripts/portfolio-governance-demo.mjs';
import {digest} from '../src/crypto.mjs';

const requirements = JSON.parse(readFileSync(new URL('../data/requirements.json', import.meta.url), 'utf8'));
const obligations = new Map([
  ['KR-34-RISK', 'high_impact_risk_management'],
  ['KR-34-DOCUMENT', 'document_publication_retention'],
  ['KR-34-OVERSIGHT', 'oversight_plan'],
]);
const artifact = (item, name) => JSON.parse(readFileSync(join(item.evidenceDirectory, name), 'utf8'));

test('six governance scenarios pass without network or model transport', async t => {
  let attempts = 0;
  const denied = () => {attempts++; throw Error('Portfolio demo must remain offline');};
  for (const [object, method] of [[globalThis, 'fetch'], [net, 'connect'], [net, 'createConnection'], [net.Server.prototype, 'listen'], [tls, 'connect'], [http, 'request'], [https, 'request']]) t.mock.method(object, method, denied);
  const result = await runPortfolioGovernanceDemo();
  assert.equal(result.passed, true, JSON.stringify(result.cases.filter(item => !item.passed)));
  assert.equal(result.caseCount, 6); assert.equal(result.passedCases, 6);
  assert.equal(attempts, 0); assert.equal(result.modelCalls, 0);
  assert.equal(result.liveFinancialIntegration, false); assert.equal(result.humanReviewPerformed, false);
  assert.equal(result.measurementTrust, 'authenticated_synthetic_report_not_independent_truth');
  assert.equal(result.automaticLegalVerdict, false);
  assert.ok(result.limitations.some(value => value.includes('고정된 합성 시험 결과') && value.includes('독립 실측')));
  assert.match(result.sourceSha256['src/kr-governance-evidence.mjs'], /^[a-f0-9]{64}$/);
  assert.ok(result.cases.every(item => item.checks.length >= 10 && item.checks.every(check => check.passed)));
  for (const item of result.cases) {
    assert.match(readFileSync(join(item.evidenceDirectory, 'public-key.pem'), 'utf8'), /BEGIN PUBLIC KEY/);
    assert.equal(artifact(item, 'supplier-export.json').synthetic, true);
    const before = artifact(item, 'finance-before.json').snapshot;
    const documents = new Map(artifact(item, 'governance-documents-before.json').map(value => [value.id, value]));
    assert.equal(documents.size, 2);
    for (const document of documents.values()) {
      assert.equal(createHash('sha256').update(Buffer.from(document.contentBase64, 'base64')).digest('hex'), document.sha256);
      assert.equal(document.version, 1);
      assert.ok(Date.parse(document.retentionUntil) >= Date.parse(document.receivedAt) + 365 * 5 * 86400000);
    }
    const measurements = artifact(item, 'measurement-records.json');
    assert.equal(measurements.length, 3);
    assert.deepEqual(new Set(measurements.map(event => event.governanceCheck.checkType)), new Set(obligations.values()));
    for (const event of measurements) {
      assert.equal(event.source, 'synthetic-measurements'); assert.equal(event.sourceKind, 'telemetry');
      assert.equal(event.assurance, 'authenticated_service_record'); assert.equal(event.payload.originalContentStored, false);
      assert.equal(event.clockUncertaintyMs, 0); assert.ok(Date.parse(event.occurredAt) <= Date.parse(event.receivedAt));
      assert.equal(event.governanceCheck.result, 'pass'); assert.equal(event.governanceCheck.systemHash, digest(before.system));
    }
    for (const [id, type] of obligations) {
      const row = before.governance.items.find(value => value.requirement.id === id);
      const linked = row.assessment.evidence.find(value => value.eventSnapshot?.governanceCheck?.checkType === type);
      assert.ok(linked, `A document alone must not support ${id}`);
      const event = linked.eventSnapshot;
      const original = measurements.find(value => linked.ref === `${value.source}/${value.id}`);
      assert.equal(linked.verification, 'linked_verified_minimized_record');
      assert.equal(linked.eventSnapshotHash, digest(event)); assert.match(linked.contentHash, /^[a-f0-9]{64}$/);
      assert.deepEqual(event.governanceCheck, original.governanceCheck);
      assert.equal(event.receivedAt, original.receivedAt); assert.equal(event.occurredAt, original.occurredAt);
      assert.equal(event.sourceKind, original.sourceKind); assert.equal(event.clockUncertaintyMs, 0);
      for (const field of ['systemId', 'modelId', 'modelVersion', 'policyVersion']) assert.equal(event[field], field === 'systemId' ? before.system.id : before.system[field]);
      assert.equal(event.governanceCheck.requirementHash, digest(requirements.find(value => value.id === id)));
      const documentEvidence = row.assessment.evidence.find(value => value.verification === 'governance_document_verified_at_assessment' && value.contentHash === event.governanceCheck.documentHash);
      assert.ok(documentEvidence, 'Measurements must link actual vault bytes instead of the supplier bundle hash');
      const document = documents.get(documentEvidence.ref.slice('governance-document:'.length));
      assert.equal(documentEvidence.contentHash, document.sha256); assert.equal(documentEvidence.documentSnapshotHash, document.snapshotHash);
      assert.equal(documentEvidence.version, String(document.version));
      assert.equal(row.assessment.assessment, 'sufficient'); assert.equal(row.assessment.legalReview, 'pending');
      assert.equal(row.legalStatus, 'pending'); assert.equal(row.technicalEvidence.automaticLegalVerdict, false);
      assert.equal(row.technicalEvidence.measurementTrust, 'authenticated_reported_measurement_not_independent_truth');
      if (id === 'KR-34-OVERSIGHT' && item.id === 'oversight-record-missing') {
        assert.equal(row.status, 'evidence_insufficient'); assert.deepEqual(row.technicalEvidence.missingChecks, ['human_oversight_review']);
        assert.ok(row.technicalEvidence.matchedChecks.some(value => value.checkType === 'oversight_plan'));
        assert.equal(row.assessment.evidence.some(value => value.eventSnapshot?.kind === 'human_oversight_review'), false);
      } else {
        assert.equal(row.technicalStatus, 'authenticated_reported_measurement_supported');
        assert.deepEqual(row.technicalEvidence.missingChecks, []); assert.deepEqual(row.technicalEvidence.reasons, []);
        if (id === 'KR-34-OVERSIGHT') {
          const review = row.assessment.evidence.find(value => value.eventSnapshot?.kind === 'human_oversight_review').eventSnapshot;
          assert.equal(review.sourceKind, 'authority'); assert.equal(review.reviewer, 'synthetic-human');
          assert.equal(review.modelVersion, before.system.modelVersion); assert.equal(review.policyVersion, before.system.policyVersion);
          assert.equal(review.clockUncertaintyMs, 0); assert.ok(Date.parse(review.occurredAt) <= Date.parse(review.receivedAt));
        }
      }
    }
    const publication = measurements.find(value => value.governanceCheck.checkType === 'document_publication_retention').governanceCheck.measurements;
    assert.deepEqual(publication.publishedSections, ['risk_management', 'explanation', 'user_protection', 'oversight_name_contact']);
    assert.deepEqual(publication.excludedSections, []); assert.equal(publication.retentionYears, 5);
    for (const name of ['supplier_only_risk_not_supported', 'document_only_publication_not_supported', 'submitted_human_conclusions_preserved', 'supplier_only_conclusion_history_preserved', 'invalid_measurement_hmac_rejected', 'other_tenant_document_and_assessment_access_rejected', 'other_tenant_has_no_portfolio_events', 'financial_snapshot_signature', 'altered_financial_snapshot_rejected', 'altered_ledger_rejected', 'historical_signed_report_preserved']) assert.ok(item.checks.some(value => value.name === name && value.passed), name);
    if (item.id === 'oversight-plan-revised') {
      const revised = artifact(item, 'governance-documents-after.json').find(value => value.id === 'portfolio-oversight-plan');
      assert.equal(revised.version, 2); assert.notEqual(revised.sha256, documents.get(revised.id).sha256);
      assert.equal(item.after['KR-34-DOCUMENT'].supportsHumanAssessment, false);
      assert.equal(item.after['KR-34-OVERSIGHT'].supportsHumanAssessment, false);
    }
    if (['model-changed', 'purpose-changed'].includes(item.id)) for (const id of obligations.keys()) {
      assert.equal(item.after[id].supportsHumanAssessment, false);
      assert.ok(item.after[id].reasons.some(value => value.endsWith('system_facts_hash_mismatch')));
    }
  }
});

test('CLI produces a report and refuses to overwrite an existing deliverable', () => {
  const output = join(mkdtempSync(join(tmpdir(), 'evidscope-portfolio-cli-')), 'result.json');
  const run = spawnSync(process.execPath, ['scripts/portfolio-governance-demo.mjs', '--output', output], {encoding: 'utf8', timeout: 30000, windowsHide: true});
  assert.equal(run.status, 0, run.stderr + run.stdout);
  const original = readFileSync(output, 'utf8'); assert.equal(JSON.parse(original).passedCases, 6);
  const repeated = spawnSync(process.execPath, ['scripts/portfolio-governance-demo.mjs', '--output', output], {encoding: 'utf8', timeout: 30000, windowsHide: true});
  assert.notEqual(repeated.status, 0); assert.equal(readFileSync(output, 'utf8'), original);
});
