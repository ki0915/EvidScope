#!/usr/bin/env node
// The audit dataset builder (src/audit-dataset.mjs): one records file any model can be trained or tested from.
//   node scripts/audit-dataset.mjs build --out DIR [--fold r7 | --held a,b --val c,d] [--per-threat 30] [--per-benign 30]
//     [--public set[:part]=FILE ...] [--public-test 'set:family|...'] [--public-val 'set:family|...'] [--test-sets a,b] [--rjudge FILE]
//   node scripts/audit-dataset.mjs export --in DIR --format chat|classification|pairs --split train|validation|test --out FILE
//     [--mask-share 0.3] [--strip-share 0.3]
//   node scripts/audit-dataset.mjs score --in DIR --answers FILE [--split test]
// build: designed scenarios (catalog + contrast, variants as the rounds make them) split by family for one fold, plus public sets read
// with src/external-agent-sets.mjs. Public sets marked test-only, and whole sets named in --test-sets, stay test; the rest train except the
// families named in --public-test / --public-val. A set given twice (two files of one set) is reported as set, set#2, ..., and a record
// whose id an earlier file already gave is counted, not added again. With --rjudge, R-Judge is added as test records and every
// non-R-Judge public record that repeats an R-Judge session (externalOverlap) is dropped and counted, so R-Judge stays a test nothing was
// shaped on; a public test record that repeats a public training record is dropped the same way. Writes DIR/records.jsonl (id order) and
// DIR/manifest.json; prints counts only (records hold test commands and dataset text).
// export: model-specific rows from records. chat rows match the round builder's train.jsonl rows (src/audit-dataset.mjs tests).
// score: answers as JSONL {id, verdict, type?, evidence?} graded per source with scoreRecords.
import {createHash} from 'node:crypto';
import {existsSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {canonical} from '../src/crypto.mjs';
import {chatMessages, chatTarget, classificationRow, datasetManifest, designedRecord, preferencePair, publicRecord, scoreRecords}
  from '../src/audit-dataset.mjs';
import {EXTERNAL_SETS, externalOverlap, externalRecords} from '../src/external-agent-sets.mjs';
import {familyOf} from '../src/session-inference.mjs';
import {buildVariantCatalog} from '../src/session-variants.mjs';
import {composeCatalog, loadCatalog, loadRules} from '../src/threat-scenarios.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const cmd = args[0];
const opt = (name, def) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : def; };
const all = name => args.flatMap((a, i) => (a === name ? [args[i + 1]] : []));
const list = v => (v ? v.split(',').map(x => x.trim()).filter(Boolean) : []);
const families = v => (v ? v.split('|').map(x => x.trim()).filter(Boolean) : []);
const fail = message => { console.error(message); process.exit(1); };
const readJsonl = f => readFileSync(f, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
const sha = s => createHash('sha256').update(s).digest('hex');

if (cmd === 'build') {
  const out = opt('--out');
  if (!out) fail('build needs --out DIR');
  if (existsSync(join(out, 'records.jsonl'))) fail('records exist: ' + out);
  const rules = loadRules(opt('--rules', join(root, 'data/risk-rules/ai-agent-baseline.json')));
  const splits = JSON.parse(readFileSync(join(root, 'data/threat-scenarios/v1/round-splits.json'), 'utf8')).rounds;
  const fold = opt('--fold');
  if (fold && !splits[fold]) fail('unknown fold ' + fold);
  const held = fold ? splits[fold].held : list(opt('--held')), val = fold ? splits[fold].val : list(opt('--val'));
  const catalog = composeCatalog(loadCatalog(join(root, 'data/threat-scenarios/v1/catalog.json')),
    loadCatalog(join(root, 'data/threat-scenarios/v1/contrast.json')));
  const variants = buildVariantCatalog(catalog, rules, {perThreat: Number(opt('--per-threat', '30')), perBenign: Number(opt('--per-benign', '30')),
    poolExclude: [...held, ...val]});
  const foldName = fold ?? (held.length || val.length ? 'custom' : null);
  const splitOf = f => (held.includes(f) ? 'test' : val.includes(f) ? 'validation' : 'train');
  const records = variants.scenarios.map(s => designedRecord(s, rules, {split: splitOf(familyOf(s)), fold: foldName}));
  const report = {designed: records.length, public: {}};
  const testFams = new Set(families(opt('--public-test'))), valFams = new Set(families(opt('--public-val')));
  const testSets = new Set(list(opt('--test-sets'))), ids = new Set(records.map(r => r.id));
  const rjudge = opt('--rjudge') ? externalRecords('rjudge', readFileSync(opt('--rjudge'), 'utf8')).records : [];
  for (const spec of all('--public')) {
    // set:part=FILE names one part of a set (ASSEBench's safety file): its ids become set:part-<id>, as the round builder does.
    const [name, file] = [spec.slice(0, spec.indexOf('=')), spec.slice(spec.indexOf('=') + 1)];
    const [set, part] = name.split(':');
    if (!EXTERNAL_SETS[set]) fail('unknown public set ' + set);
    if (set === 'rjudge') fail('pass R-Judge with --rjudge; it is test-only');
    const text = readFileSync(file, 'utf8');
    const read = externalRecords(set, text), skipped = read.skipped;
    const rs = part ? read.records.map(r => ({...r, id: r.id.replace(`${set}:`, `${set}:${part}-`)})) : read.records;
    const overlap = rjudge.length ? externalOverlap(rs, rjudge) : new Set();
    const testOnly = EXTERNAL_SETS[set].use === 'external test only' || testSets.has(set);
    let kept = 0, repeated = 0;
    for (const r of rs) {
      if (overlap.has(r.id)) continue;
      if (ids.has(r.id)) { repeated++; continue; }
      ids.add(r.id);
      const split = testOnly || testFams.has(r.family) ? 'test' : valFams.has(r.family) ? 'validation' : 'train';
      records.push(publicRecord(r, {split, fold: foldName})); kept++;
    }
    let key = name;
    for (let n = 2; report.public[key]; n++) key = `${name}#${n}`;
    report.public[key] = {fileSha256: sha(text), records: rs.length, skipped, rjudgeOverlapDropped: overlap.size, repeated, kept,
      test: testOnly};
  }
  // A public test record that repeats a public training record (same request, opening, actions or close wording) leaves the dataset.
  const trainPublic = records.filter(r => r.source.kind !== 'designed' && r.split !== 'test');
  const leaked = externalOverlap(records.filter(r => r.source.kind !== 'designed' && r.split === 'test'), trainPublic);
  if (leaked.size) records.splice(0, records.length, ...records.filter(r => !leaked.has(r.id)));
  report.testOverlapDropped = leaked.size;
  for (const r of rjudge) records.push(publicRecord(r, {split: 'test', fold: foldName}));
  if (rjudge.length) report.public.rjudge = {records: rjudge.length, kept: rjudge.length};
  records.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  mkdirSync(out, {recursive: true});
  writeFileSync(join(out, 'records.jsonl'), records.map(r => canonical(r)).join('\n') + '\n', {flag: 'wx'});
  const manifest = {...datasetManifest(records, {name: opt('--name', 'evidscope-audit-sessions'), version: opt('--version', '1'),
    note: opt('--note')}), fold: foldName, held, val, build: report};
  writeFileSync(join(out, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', {flag: 'wx'});
  console.log(JSON.stringify(manifest, null, 2));
} else if (cmd === 'export') {
  const dir = opt('--in'), format = opt('--format'), split = opt('--split'), out = opt('--out');
  if (!dir || !format || !split || !out) fail('export needs --in DIR --format F --split S --out FILE');
  const records = readJsonl(join(dir, 'records.jsonl')).filter(r => r.split === split);
  const share = (id, s, salt) => s > 0 && createHash('sha256').update(salt + id.replace(/^designed:/, '')).digest()[0] < Math.round(s * 256);
  const maskShare = Number(opt('--mask-share', '0')), stripShare = Number(opt('--strip-share', '0'));
  const rows = [];
  let tooLong = 0;
  for (const r of records) {
    const copies = [[{}, '']];
    if (r.source.kind === 'designed' && r.steps.some(s => s.findings.length)) {
      if (share(r.id, maskShare, '')) copies.push([{maskCodes: true}, '~masked']);
      if (share(r.id, stripShare, 'strip:')) copies.push([{stripFindings: true}, '~stripped']);
    }
    for (const [opts, suffix] of copies) {
      const id = r.id + suffix;
      if (format === 'classification') { if (!suffix) rows.push(classificationRow(r)); continue; }
      const messages = chatMessages(r, opts);
      if (!messages) { tooLong++; continue; }
      const target = canonical(chatTarget(r));
      if (format === 'chat') rows.push({id, family: r.family, source: r.source.dataset, labelSource: r.labelSource, messages, target});
      else if (format === 'pairs') rows.push({...preferencePair(r, opts), id});
      else fail('unknown format ' + format);
    }
  }
  writeFileSync(out, rows.map(x => JSON.stringify(x)).join('\n') + '\n', {flag: 'wx'});
  console.log(JSON.stringify({records: records.length, rows: rows.length, tooLong, format, split, sha256: sha(readFileSync(out))}));
} else if (cmd === 'score') {
  const dir = opt('--in'), file = opt('--answers'), split = opt('--split', 'test');
  if (!dir || !file) fail('score needs --in DIR --answers FILE');
  const records = readJsonl(join(dir, 'records.jsonl')).filter(r => r.split === split);
  const answers = Object.fromEntries(readJsonl(file).map(a => [a.id, a]));
  const bySource = {};
  for (const r of records) (bySource[r.source.dataset] ||= []).push(r);
  console.log(JSON.stringify({split, all: scoreRecords(records, answers),
    bySource: Object.fromEntries(Object.entries(bySource).map(([k, rs]) => [k, scoreRecords(rs, answers)]))}, null, 2));
} else {
  fail('usage: audit-dataset.mjs build --out DIR [...] | export --in DIR --format chat|classification|pairs --split S --out F | score --in DIR'
    + ' --answers F');
}
