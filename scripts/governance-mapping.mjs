// Command line of the governance mapping task (docs/governance-model.md). Writes only new files ({flag: 'wx'}).
//   build --out data/governance-mapping/v1/dataset.jsonl          the derived + drafted dataset (deterministic)
//   review-sheet --data D --out sheet.tsv                          drafted rows for a bulk approve/reject pass
//   import-decisions --data D --sheet filled.tsv --reviewer ID --reviewed-at ISO --attest-pii-reviewed --attest-source-consent --out R
//   export-reviewed --data D --bundle export.json --trust-anchor vault.pem --out R   apply the console's signed review decisions
//   admission --data R                                             training admission for this task
//   training-set --data R --out train.jsonl [--shakedown] [--abstain-weight N]  tune/validation rows in the runtime prompt format; --shakedown:
//                                                                  derived rows only, for a never-promotable VRAM/time run
//   factsheet --kind training --receipt training-receipt.json --training-set train.jsonl [--adapter-gguf F] --out F
//   factsheet --kind evaluation --report report.json --out F       a factsheet request to record in the console (실험 비교)
//   factsheet --kind promotion --receipt promotion.dsse.json [--report report.json] --out F
//   requests --data R --variant V --out requests.jsonl             test-split requests for scripts/governance_mapping_batch.py
//   report --data R --runs DIR --prepared-by NAME --out report.json   DIR/<variant>.outputs.json + DIR/<variant>.receipt.json
//   gate --report report.json                                      promotion gate (exit 0 only when eligible)
//   status                                                         the status the console reads
//   promote --report R --approval A --adapter-file F --key reviewer-ed25519.key --out receipt.dsse.json   signed by the approver
//   retrieval-recall --data R [--k 1,3,5,8]                        share of gold requirements among the retrieved candidates, the prompt's
//                                                                  candidates and the k nearest examples' answers (the prompt's retrieval
//                                                                  ceiling); for must-abstain rows from a not-aligned ISMS-P criterion, how
//                                                                  often the prompt's outOfScope list (or the k closest) names it, by
//                                                                  split, language and kind (title rows, source-table sentence rows)
//   embed-texts --data R --out texts.jsonl                         every prompt, catalog and out-of-scope pool text, once, for
//                                                                  scripts/governance_mapping_embed.py (with --embeddings F: how many F lacks)
//   any command: --embeddings F                                    rank examples and candidates with the vectors in F (hybrid retrieval)
import {createHash, createPrivateKey, createPublicKey, sign as cryptoSign} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {canonical, verifyBundle} from '../src/crypto.mjs';
import {LIMITS, VARIANTS, buildMappingRequest, governanceCatalog, governanceEmbeddings, nearestExamples, normalizeMappingItem, outOfScopePool,
  retrieveOutOfScope, retrieveRequirements, setGovernanceEmbeddings} from '../src/governance-mapping.mjs';
import {embeddingTexts, loadEmbeddings, vectorFor} from '../src/governance-embeddings.mjs';
import {QUEUE_DECISION_TYPE, applyQueueDecisions, applyReviewDecisions, baseDerivation, buildDataset, derivedItems, governanceAdmission,
  governanceExamples, itemOf, outOfScopeSources, reviewSheet, shakedownRows, toJsonl, trainingRows} from '../src/governance-mapping-data.mjs';
import {localTablesFor, sourceTableStatus} from '../src/governance-mapping-sources.mjs';
import {evaluationFactsheetRequest, promotionFactsheetRequest, trainingFactsheetRequest} from '../src/governance-factsheets.mjs';
import {DATASET_ID} from '../src/governance-review-queue.mjs';
import {ALL_VARIANTS, CALIBRATED, DETERMINISTIC_BASELINES, MODEL_VARIANTS, assessGovernanceReport, baselineOutputs, buildComparisonReport,
  outOfScopeSiblingAnswers, variantRequests} from '../src/governance-mapping-eval.mjs';
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
  const ei = rest.indexOf('--embeddings');
  if (ei >= 0) {
    if (!rest[ei + 1] || rest[ei + 1].startsWith('--')) throw Error('--embeddings needs a file');
    setGovernanceEmbeddings(loadEmbeddings(rest[ei + 1]));
    rest.splice(ei, 2);
  }
  if (command === 'build') {
    // --local-tables DIR|none: where the local-only source tables are (default: the module's directory); the shipped file is built with none.
    const o = options(rest), localTables = o['local-tables'] === 'none' ? false : o['local-tables'], rows = buildDataset({localTables});
    write(o.out, jsonl(rows));
    return {rows: rows.length, derived: rows.filter(r => r.labelSource === 'derived_mapping_table').length, sources: sourceTableStatus({localTables})};
  }
  if (command === 'sources') {
    const o = options(rest), localTables = o['local-tables'] === 'none' ? false : o['local-tables'], rules = {};
    for (const i of derivedItems(undefined, {localTables})) {
      const r = rules[i.derivation.rule] ??= {rows: 0, abstain: 0, injection: 0};
      r.rows++;
      if (i.truth.abstain) r.abstain++;
      if (i.injection) r.injection++;
    }
    return {tables: sourceTableStatus({localTables}), rules};
  }
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
    // --abstain-weight N (candidate mode only): tune-split abstain rows repeated N-1 more times, see trainingRows.
    const o = options(rest, ['shakedown']), abstainWeight = o['abstain-weight'] === undefined ? 1 : Number(o['abstain-weight']);
    if (o.shakedown && o['abstain-weight'] !== undefined) throw Error('abstain_weight_invalid');
    const rows = o.shakedown ? shakedownRows(readRows(o.data)) : trainingRows(readRows(o.data), {abstainWeight});
    write(o.out, jsonl(rows));
    return {rows: rows.length, runMode: o.shakedown ? 'shakedown' : 'candidate', abstainWeight, abstainCopies: rows.filter(r => r.weightCopy).length,
      ...(o.shakedown ? {notice: 'shakedown: derived rows only; the adapter is never promotable and is not a quality result'} : {})};
  }
  if (command === 'factsheet') return factsheet(options(rest));
  if (command === 'requests') {
    // --split validation: the candidate's requests for the abstention calibration (report --validation-runs); default test.
    const o = options(rest), split = o.split ?? 'test';
    if (!MODEL_VARIANTS.includes(o.variant)) throw Error('variant must be one of ' + MODEL_VARIANTS.join(', '));
    if (!['test', 'validation'].includes(split)) throw Error('--split must be test or validation');
    if (split === 'validation' && o.variant !== 'candidate') throw Error('validation requests are only made for the candidate');
    const requests = variantRequests(readRows(o.data).filter(r => r.split === split), o.variant);
    write(o.out, requests.map(r => canonical(r)).join('\n') + '\n');
    return {requests: requests.length, variant: o.variant, split};
  }
  if (command === 'report') {
    // --validation-runs DIR: the candidate's validation-split run (outputs, receipt and logprobs from the batch runner's --logprobs)
    // together with candidate.logprobs.json in --runs; the report then carries the abstention calibration and the calibrated candidate.
    const o = options(rest), all = readRows(o.data), rows = all.filter(r => r.split === 'test'), variants = {};
    const readJson = file => JSON.parse(readFileSync(file, 'utf8'));
    for (const v of DETERMINISTIC_BASELINES) variants[v] = {outputs: baselineOutputs(rows, v)};
    for (const v of MODEL_VARIANTS) {
      let outputs;
      try { outputs = readJson(join(o.runs, `${v}.outputs.json`)); }
      catch (error) { if (v === 'candidate' && error.code === 'ENOENT') continue; throw error; }
      variants[v] = {outputs, receipt: readJson(join(o.runs, `${v}.receipt.json`))};
    }
    let calibration = null;
    if (o['validation-runs']) {
      if (!variants.candidate) throw Error('--validation-runs needs the candidate run in --runs');
      const dir = o['validation-runs'];
      calibration = {validation: {rows: all.filter(r => r.split === 'validation'), outputs: readJson(join(dir, 'candidate.outputs.json')),
        logprobs: readJson(join(dir, 'candidate.logprobs.json')), receipt: readJson(join(dir, 'candidate.receipt.json'))},
      logprobs: readJson(join(o.runs, 'candidate.logprobs.json')), ...(o['min-kept'] ? {minKept: Number(o['min-kept'])} : {})};
    }
    const report = buildComparisonReport(rows, variants, {preparedBy: o['prepared-by'], calibration});
    write(o.out, JSON.stringify(report, null, 1) + '\n');
    const c = report.calibration;
    // Informational, not part of the report: per model variant, must-abstain answers beside a listed out-of-scope criterion.
    const siblings = Object.fromEntries(Object.keys(report.variants).filter(v => MODEL_VARIANTS.includes(v) || v === CALIBRATED)
      .map(v => [v, outOfScopeSiblingAnswers(rows, report.variants[v].outputs, variantRequests(rows, v === CALIBRATED ? 'candidate' : v))]));
    return {variants: Object.keys(report.variants), gateItems: report.gateItems, gate: report.variants.candidate ? assessGovernanceReport(report) : null,
      calibration: c ? {threshold: c.threshold, reached: c.reached, chosen: c.chosen} : null, outOfScopeSiblings: siblings};
  }
  if (command === 'gate') return assessGovernanceReport(JSON.parse(readFileSync(options(rest).report, 'utf8')));
  if (command === 'status') return governanceModelStatus();
  if (command === 'promote') return promote(options(rest));
  if (command === 'embed-texts') {
    // The out-of-scope pool texts (74) joined the list with the outOfScope prompt field; a file made before then lacks them, and the
    // out-of-scope ranking stays TF-IDF until the file is remade from this list. The pool is the one the dataset's requests use: with
    // the local KISA guide its texts carry the Korean criterion sentences, so a file made for the shipped dataset does not cover them.
    const o = options(rest), rows = readRows(o.data), catalog = governanceCatalog(), index = governanceEmbeddings();
    const pool = outOfScopePool({catalog, localTables: localTablesFor(rows)});
    const texts = embeddingTexts([...rows.map(r => r.prompt), ...catalog.entries.map(e => e.text), ...pool.entries.map(e => e.text)]);
    write(o.out, texts.map(t => canonical(t)).join('\n') + '\n');
    return {texts: texts.length, rows: rows.length, catalogEntries: catalog.entries.length, outOfScopeEntries: pool.entries.length,
      missingFromEmbeddings: index ? texts.filter(t => !vectorFor(index, t.text)).length : null,
      outOfScopeMissingFromEmbeddings: index ? pool.entries.filter(e => !vectorFor(index, e.text)).length : null};
  }
  if (command === 'retrieval-recall') {
    const o = options(rest), rows = readRows(o.data), ks = String(o.k || '1,3,5,8').split(',').map(Number), out = {}, outside = {};
    const localTables = localTablesFor(rows), examples = governanceExamples({localTables});
    if (ks.some(k => !Number.isInteger(k) || k < 1)) throw Error('--k must list positive integers');
    const index = governanceEmbeddings();
    const request = r => buildMappingRequest(itemOf(r), {variant: 'candidate', examples, excludeId: r.id, localTables});
    for (const r of rows.filter(x => !x.truth.abstain)) {
      const ids = new Set(retrieveRequirements(r.prompt).map(c => c.id)), listed = new Set(request(r).candidates);
      const s = out[r.split] ??= {gold: 0, retrieved: 0, inPrompt: 0, examplesHit: Object.fromEntries(ks.map(k => [k, 0]))};
      const near = nearestExamples(r.prompt, examples, {k: Math.max(...ks), excludeId: r.id});
      for (const m of r.truth.mappings) {
        s.gold++;
        if (ids.has(m.requirementId)) s.retrieved++;
        if (listed.has(m.requirementId)) s.inPrompt++;
        for (const k of ks) if (near.slice(0, k).some(n => n.example.requirementIds.includes(m.requirementId))) s.examplesHit[k]++;
      }
    }
    // Offline proxy for the outOfScope list: the source criterion of a must-abstain row is among the LIMITS.outOfScope the prompt
    // lists (listed), or among the k closest (atK, the same ranking). Counted by language and by the kind of row (the base rule, an
    // injection resolved to the row it extends): title rows (isms-not-aligned) are "ISMS-P 인증기준 <number> <title>", the pool entry's
    // own words, and hit by construction; sentence rows (prowler-*, kisa-*) are the source tables' checklist, evidence and defect text.
    const cell = () => ({rows: 0, listed: 0, atK: Object.fromEntries(ks.map(k => [k, 0]))});
    for (const r of rows) {
      const sources = outOfScopeSources(r);
      if (!sources.length) continue;
      const kind = baseDerivation(r).rule === 'isms-not-aligned' ? 'title' : 'sentence';
      const listed = request(r).outOfScope, byLanguage = (outside[r.split] ??= {})[r.language] ??= {all: cell(), title: cell(), sentence: cell()};
      const ranked = retrieveOutOfScope(normalizeMappingItem(itemOf(r)).text, {k: Math.max(...ks), localTables}).map(x => x.id);
      for (const s of [byLanguage.all, byLanguage[kind]]) {
        s.rows++;
        if (sources.some(id => listed.includes(id))) s.listed++;
        for (const k of ks) if (sources.some(id => ranked.slice(0, k).includes(id))) s.atK[k]++;
      }
    }
    const share = s => ({rows: s.rows, listed: s.listed, recall: s.rows ? s.listed / s.rows : null,
      recallAtK: Object.fromEntries(ks.map(k => [k, s.rows ? s.atK[k] / s.rows : null]))});
    const splits = Object.fromEntries(Object.entries(out).map(([split, s]) => [split, {...s, recall: s.retrieved / s.gold,
      promptRecall: s.inPrompt / s.gold, examplesRecall: Object.fromEntries(ks.map(k => [k, s.examplesHit[k] / s.gold]))}]));
    const embeddings = index ? {sha256: index.model.sha256, file: index.model.file ?? null, texts: index.vectors.size} : null;
    const pool = outOfScopePool({localTables}), covered = index ? pool.entries.filter(e => vectorFor(index, e.text)).length : 0;
    const outOfScope = {k: LIMITS.outOfScope, method: covered ? 'hybrid' : 'tfidf', embeddedPoolTexts: covered, kisaGuide: !!pool.sources.kisaGuide,
      splits: Object.fromEntries(Object.entries(outside).map(([split, byLanguage]) => [split, Object.fromEntries(Object.entries(byLanguage)
        .map(([language, s]) => [language, {...share(s.all), title: share(s.title), sentence: share(s.sentence)}]))]))};
    return {method: index ? 'hybrid' : 'tfidf', embeddings, examples: examples.length, splits, outOfScope};
  }
  throw Error(`usage: governance-mapping.mjs <${['build', 'review-sheet', 'import-decisions', 'export-reviewed', 'admission', 'training-set', 'requests',
    'report', 'gate', 'status', 'retrieval-recall', 'embed-texts', 'sources', 'promote', 'factsheet'].join('|')}> ...`
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
