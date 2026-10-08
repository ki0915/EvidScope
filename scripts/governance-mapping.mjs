// Command line of the governance mapping task (docs/governance-model.md). Writes only new files ({flag: 'wx'}).
//   build --out data/governance-mapping/v1/dataset.jsonl          the derived + drafted dataset (deterministic)
//   review-sheet --data D --out sheet.tsv                          drafted rows for a bulk approve/reject pass
//   import-decisions --data D --sheet filled.tsv --reviewer ID --reviewed-at ISO --attest-pii-reviewed --attest-source-consent --out R
//   export-reviewed --data D --bundle export.json --trust-anchor vault.pem --out R   apply the console's signed review decisions
//   admission --data R                                             training admission for this task
//   training-set --data R --out train.jsonl [--shakedown]          tune/validation rows in the runtime prompt format; --shakedown:
//                                                                  derived rows only, for a never-promotable VRAM/time run
//   factsheet --kind training --receipt training-receipt.json --training-set train.jsonl [--adapter-gguf F] --out F
//   factsheet --kind evaluation --report report.json --out F       a factsheet request to record in the console (실험 비교)
//   factsheet --kind promotion --receipt promotion.dsse.json [--report report.json] --out F
//   requests --data R --variant V --out requests.jsonl             test-split requests for scripts/governance_mapping_batch.py
//   report --data R --runs DIR --prepared-by NAME --out report.json   DIR/<variant>.outputs.json + DIR/<variant>.receipt.json
//   gate --report report.json                                      promotion gate (exit 0 only when eligible)
//   status                                                         the status the console reads
//   promote --report R --approval A --adapter-file F --key reviewer-ed25519.key --out receipt.dsse.json   signed by the approver
//   retrieval-recall --data R                                      share of gold requirements among the retrieved candidates
import {createHash, createPrivateKey, createPublicKey, sign as cryptoSign} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {canonical, verifyBundle} from '../src/crypto.mjs';
import {VARIANTS, retrieveRequirements} from '../src/governance-mapping.mjs';
import {QUEUE_DECISION_TYPE, applyQueueDecisions, applyReviewDecisions, buildDataset, governanceAdmission, reviewSheet, shakedownRows, toJsonl,
  trainingRows} from '../src/governance-mapping-data.mjs';
import {evaluationFactsheetRequest, promotionFactsheetRequest, trainingFactsheetRequest} from '../src/governance-factsheets.mjs';
import {DATASET_ID} from '../src/governance-review-queue.mjs';
import {ALL_VARIANTS, MODEL_VARIANTS, assessGovernanceReport, baselineOutput, buildComparisonReport, variantRequests} from '../src/governance-mapping-eval.mjs';
import {governanceModelStatus, promoteGovernanceCandidate} from '../src/governance-model.mjs';
import {keyFingerprint} from '../src/dsse.mjs';

const readRows = path => readFileSync(path, 'utf8').split('\n').filter(Boolean).map(line => JSON.parse(line)).sort((a, b) => (a.id < b.id ? -1 : 1));
const jsonl = toJsonl;
const readJson = path => JSON.parse(readFileSync(path, 'utf8'));
const write = (path, text) => writeFileSync(path, text, {flag: 'wx'});
function options(args, flags = []) {
  const out = {};
  for (let i = 0; i < args.length; i++) {
    const name = args[i].replace(/^--/, '');
    if (!args[i].startsWith('--')) throw Error('unexpected argument ' + args[i]);
    if (flags.includes(name)) { out[name] = true; continue; }
    if (args[i + 1] === undefined || args[i + 1].startsWith('--')) throw Error('missing value for ' + args[i]);
    out[name] = args[++i];
  }
  return out;
}
function parseSheet(text) {
  const [header, ...lines] = text.replace(/\r\n/g, '\n').split('\n').filter(Boolean), columns = header.split('\t');
  const at = name => { const i = columns.indexOf(name); if (i < 0) throw Error('review sheet column missing: ' + name); return i; };
  const id = at('id'), decision = at('decision'), note = at('note');
  return lines.map(line => line.split('\t')).filter(cells => (cells[decision] || '').trim())
    .map(cells => ({id: cells[id], decision: cells[decision].trim().toLowerCase(), note: cells[note] || ''}));
}

// The approving reviewer runs this with their own Ed25519 key; the key's public half must be listed in promotion-trust.json.
async function promote(o) {
  const key = createPrivateKey(readFileSync(o.key)), signer = {keyid: keyFingerprint(createPublicKey(key)), sign: m => cryptoSign(null, m, key)};
  const envelope = await promoteGovernanceCandidate({report: JSON.parse(readFileSync(o.report, 'utf8')), approval: JSON.parse(readFileSync(o.approval, 'utf8')),
    signer, adapterFile: o['adapter-file']});
  write(o.out, JSON.stringify(envelope, null, 1) + '\n');
  return {written: o.out, keyid: signer.keyid, next: 'record receiptPath/receiptSha256/reportPath/reportSha256 in governance-mapping.json and the role fields'};
}

// The decisions come from the vault's signed export (GET /api/export, the console's 감사 내보내기), checked against the vault's
// public key; each decision is applied only to the row content it was made on (applyQueueDecisions).
function exportReviewed(o) {
  const bundle = readJson(o.bundle), publicKey = createPublicKey(readFileSync(o['trust-anchor']));
  verifyBundle(bundle, publicKey, undefined, {chainOnly: true});
  if (o.tenant !== undefined && bundle.checkpoint.tenant !== o.tenant) throw Error('export_tenant_mismatch');
  const decisions = bundle.records.filter(r => r.type === QUEUE_DECISION_TYPE).map(r => {
    const d = r.payload;
    if (d?.reviewerId !== r.principal || !['reviewer', 'admin'].includes(d.reviewerRole)
      || d.datasetId !== DATASET_ID) throw Error('review_decision_record_invalid: ' + d?.id);
    return d;
  });
  const result = applyQueueDecisions(readRows(o.data), decisions);
  write(o.out, jsonl(result.rows));
  return {tenant: bundle.checkpoint.tenant, checkpoint: {count: bundle.checkpoint.count, head: bundle.checkpoint.head}, decisions: decisions.length,
    approved: result.approved, rejected: result.rejected.length, skipped: result.skipped, stillUnreviewed: result.unreviewed,
    admission: governanceAdmission(result.rows)};
}
function factsheet(o) {
  let request;
  if (o.kind === 'training') {
    request = trainingFactsheetRequest({receipt: readJson(o.receipt), trainingSet: readFileSync(o['training-set']),
      adapterGgufSha256: o['adapter-gguf'] ? createHash('sha256').update(readFileSync(o['adapter-gguf'])).digest('hex') : null});
  } else if (o.kind === 'evaluation') request = evaluationFactsheetRequest(readJson(o.report));
  else if (o.kind === 'promotion') request = promotionFactsheetRequest(readJson(o.receipt), o.report ? readJson(o.report) : null);
  else throw Error('kind must be training, evaluation or promotion');
  write(o.out, JSON.stringify(request) + '\n');
  return {written: o.out, kind: o.kind, next: 'record it in the console: AI 검토실 > 실험 비교 > 팩트시트 기록 (POST /api/governance-model/factsheets)'};
}

export function runGovernanceMappingCommand(argv) {
  const [command, ...rest] = argv;
  if (command === 'build') { const o = options(rest), rows = buildDataset(); write(o.out, jsonl(rows)); return {rows: rows.length}; }
  if (command === 'review-sheet') { const o = options(rest); write(o.out, reviewSheet(readRows(o.data))); return {written: o.out}; }
  if (command === 'import-decisions') {
    const o = options(rest, ['attest-pii-reviewed', 'attest-source-consent']);
    const result = applyReviewDecisions(readRows(o.data), parseSheet(readFileSync(o.sheet, 'utf8')), {reviewerId: o.reviewer, reviewedAt: o['reviewed-at'],
      piiReviewed: o['attest-pii-reviewed'] === true, sourceConsent: o['attest-source-consent'] === true});
    write(o.out, jsonl(result.rows));
    return {approved: result.approved, rejected: result.rejected.length, stillUnreviewed: result.unreviewed, admission: governanceAdmission(result.rows)};
  }
  if (command === 'export-reviewed') return exportReviewed(options(rest));
  if (command === 'admission') return governanceAdmission(readRows(options(rest).data));
  if (command === 'training-set') {
    const o = options(rest, ['shakedown']), rows = o.shakedown ? shakedownRows(readRows(o.data)) : trainingRows(readRows(o.data));
    write(o.out, jsonl(rows));
    return {rows: rows.length, runMode: o.shakedown ? 'shakedown' : 'candidate',
      ...(o.shakedown ? {notice: 'shakedown: derived rows only; the adapter is never promotable and is not a quality result'} : {})};
  }
  if (command === 'factsheet') return factsheet(options(rest));
  if (command === 'requests') {
    const o = options(rest);
    if (!MODEL_VARIANTS.includes(o.variant)) throw Error('variant must be one of ' + MODEL_VARIANTS.join(', '));
    const requests = variantRequests(readRows(o.data).filter(r => r.split === 'test'), o.variant);
    write(o.out, requests.map(r => canonical(r)).join('\n') + '\n');
    return {requests: requests.length, variant: o.variant};
  }
  if (command === 'report') {
    const o = options(rest), rows = readRows(o.data).filter(r => r.split === 'test'), variants = {};
    for (const v of ['always_abstain', 'rules_only']) variants[v] = {outputs: Object.fromEntries(rows.map(r => [r.id, baselineOutput(v, r)]))};
    for (const v of MODEL_VARIANTS) {
      let outputs;
      try { outputs = JSON.parse(readFileSync(join(o.runs, `${v}.outputs.json`), 'utf8')); }
      catch (error) { if (v === 'candidate' && error.code === 'ENOENT') continue; throw error; }
      variants[v] = {outputs, receipt: JSON.parse(readFileSync(join(o.runs, `${v}.receipt.json`), 'utf8'))};
    }
    const report = buildComparisonReport(rows, variants, {preparedBy: o['prepared-by']});
    write(o.out, JSON.stringify(report, null, 1) + '\n');
    return {variants: Object.keys(report.variants), gateItems: report.gateItems, gate: report.variants.candidate ? assessGovernanceReport(report) : null};
  }
  if (command === 'gate') return assessGovernanceReport(JSON.parse(readFileSync(options(rest).report, 'utf8')));
  if (command === 'status') return governanceModelStatus();
  if (command === 'promote') return promote(options(rest));
  if (command === 'retrieval-recall') {
    const rows = readRows(options(rest).data), out = {};
    for (const r of rows.filter(x => !x.truth.abstain)) {
      const ids = new Set(retrieveRequirements(r.prompt).map(c => c.id)), o = out[r.split] ??= {gold: 0, retrieved: 0};
      for (const m of r.truth.mappings) { o.gold++; if (ids.has(m.requirementId)) o.retrieved++; }
    }
    return Object.fromEntries(Object.entries(out).map(([s, o]) => [s, {...o, recall: o.retrieved / o.gold}]));
  }
  throw Error(`usage: governance-mapping.mjs <${['build', 'review-sheet', 'import-decisions', 'export-reviewed', 'admission', 'training-set', 'requests',
    'report', 'gate', 'status', 'retrieval-recall', 'promote', 'factsheet'].join('|')}> ...`
    + ` (variants: ${[...ALL_VARIANTS].join(', ')}; prompt variants: ${VARIANTS.join(', ')})`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const result = await runGovernanceMappingCommand(process.argv.slice(2));
    process.stdout.write(JSON.stringify(result, null, 1) + '\n');
    if (process.argv[2] === 'gate' && !result.eligible) process.exitCode = 2;
    if (process.argv[2] === 'admission' && !result.admitted) process.exitCode = 2;
  } catch (error) {
    process.stderr.write(JSON.stringify({error: error.message, ...(error.admission ? {admission: error.admission} : {})}) + '\n');
    process.exitCode = 1;
  }
}
