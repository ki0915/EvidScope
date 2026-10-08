// Command line of the governance mapping task (docs/governance-model.md). Writes only new files ({flag: 'wx'}).
//   build --out data/governance-mapping/v1/dataset.jsonl          the derived + drafted dataset (deterministic)
//   review-sheet --data D --out sheet.tsv                          drafted rows for a bulk approve/reject pass
//   import-decisions --data D --sheet filled.tsv --reviewer ID --reviewed-at ISO --attest-pii-reviewed --attest-source-consent --out R
//   admission --data R                                             training admission for this task
//   training-set --data R --out train.jsonl                        tune/validation rows in the runtime prompt format
//   requests --data R --variant V --out requests.jsonl             test-split requests for scripts/governance_mapping_batch.py
//   report --data R --runs DIR --prepared-by NAME --out report.json   DIR/<variant>.outputs.json + DIR/<variant>.receipt.json
//   gate --report report.json                                      promotion gate (exit 0 only when eligible)
//   status                                                         the status the console reads
//   promote --report R --approval A --adapter-file F --key reviewer-ed25519.key --out receipt.dsse.json   signed by the approver
//   retrieval-recall --data R                                      share of gold requirements among the retrieved candidates
import {createPrivateKey, createPublicKey, sign as cryptoSign} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {canonical} from '../src/crypto.mjs';
import {VARIANTS, retrieveRequirements} from '../src/governance-mapping.mjs';
import {applyReviewDecisions, buildDataset, governanceAdmission, reviewSheet, trainingRows} from '../src/governance-mapping-data.mjs';
import {ALL_VARIANTS, MODEL_VARIANTS, assessGovernanceReport, baselineOutput, buildComparisonReport, variantRequests} from '../src/governance-mapping-eval.mjs';
import {governanceModelStatus, promoteGovernanceCandidate} from '../src/governance-model.mjs';
import {keyFingerprint} from '../src/dsse.mjs';

const readRows = path => readFileSync(path, 'utf8').split('\n').filter(Boolean).map(line => JSON.parse(line)).sort((a, b) => (a.id < b.id ? -1 : 1));
const jsonl = rows => rows.map(r => JSON.stringify(r)).join('\n') + '\n';
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
  if (command === 'admission') return governanceAdmission(readRows(options(rest).data));
  if (command === 'training-set') { const o = options(rest), rows = trainingRows(readRows(o.data)); write(o.out, jsonl(rows)); return {rows: rows.length}; }
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
  throw Error(`usage: governance-mapping.mjs <${['build', 'review-sheet', 'import-decisions', 'admission', 'training-set', 'requests', 'report', 'gate',
    'status', 'retrieval-recall', 'promote'].join('|')}> ... (variants: ${[...ALL_VARIANTS].join(', ')}; prompt variants: ${VARIANTS.join(', ')})`);
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
