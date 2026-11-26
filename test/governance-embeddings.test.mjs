import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {EMBEDDINGS_SCHEMA_VERSION, cosine, embeddingTexts, parseEmbeddings, rrfFuse, textDigest} from '../src/governance-embeddings.mjs';
import {LIMITS, buildMappingRequest, governanceCatalog, nearestExamples, outOfScopePool, outOfScopeRetrievalMethod, retrievalMethod,
  retrieveOutOfScope, retrieveRequirements, setGovernanceEmbeddings} from '../src/governance-mapping.mjs';
import {runGovernanceMappingCommand} from '../scripts/governance-mapping.mjs';

// Governance-mapping tests see only the shipped source tables; a local-only (KOGL) table on this machine must not change them.
process.env.EVIDSCOPE_GOVERNANCE_LOCAL_TABLES ??= '.test-runs/no-local-tables';
const dataset = 'data/governance-mapping/v1/dataset.jsonl';
const bank = Object.freeze([
  {id: 'ex-a', text: '접근권한 검토 이력과 계정 목록을 분기마다 확인한 기록', requirementIds: ['ISMS-P-2.5.6'], abstain: false},
  {id: 'ex-b', text: '특권 계정 사용 승인 대장과 사용 로그', requirementIds: ['ISMS-P-2.5.5'], abstain: false},
  {id: 'ex-c', text: '서버 접속기록을 1년 보관하고 월 1회 검토한 결과', requirementIds: ['ISMS-P-2.9.4'], abstain: false},
]);
const query = '분기별 접근권한 검토 이력 확인 결과';
const file = (vectors, dims = 3) => ({schemaVersion: EMBEDDINGS_SCHEMA_VERSION, vectors,
  model: {file: 'test.gguf', sha256: 'a'.repeat(64), dims, pooling: 'cls'}});
const vec = (text, v) => [textDigest(text), v];

test('embeddings file: schema, digest keys and dimensions are checked; vectors come back unit length', () => {
  const index = parseEmbeddings(file(Object.fromEntries([vec(query, [3, 0, 0]), vec(bank[2].text, [0, 2, 0])])));
  assert.equal(index.dims, 3);
  assert.deepEqual([...index.vectors.get(textDigest(query))], [1, 0, 0]);
  assert.equal(cosine(index.vectors.get(textDigest(query)), index.vectors.get(textDigest(bank[2].text))), 0);
  assert.match(index.digest, /^[a-f0-9]{64}$/);
  assert.throws(() => parseEmbeddings({...file({}), schemaVersion: 2}), /embeddings_file_invalid/);
  assert.equal(parseEmbeddings(file({})).vectors.size, 0, 'a file with no vectors parses; every lookup then falls back to TF-IDF');
  assert.throws(() => parseEmbeddings(file({}, 0)), /embeddings_file_invalid/, 'dims 0 (the embed script wrote nothing) is refused');
  assert.throws(() => parseEmbeddings(file(Object.fromEntries([vec(query, [1, 0])]))), /embeddings_vector_invalid/);
  assert.throws(() => parseEmbeddings(file({notadigest: [1, 0, 0]})), /embeddings_vector_invalid/);
  assert.throws(() => parseEmbeddings(file(Object.fromEntries([vec(query, [1, 0, NaN])]))), /embeddings_vector_invalid/);
});

test('reciprocal rank fusion: ids present in several lists add up, ties break on id, fields of the first appearance are kept', () => {
  const fused = rrfFuse([[{id: 'a', score: 9, from: 'lexical'}, {id: 'b', score: 8}], [{id: 'b', score: 0.9, from: 'semantic'}, {id: 'c', score: 0.8}]]);
  assert.deepEqual(fused.map(f => f.id), ['b', 'a', 'c']);
  assert.equal(fused[0].from, undefined);
  assert.equal(fused[1].from, 'lexical');
  assert.ok(Math.abs(fused[0].score - (1 / 61 + 1 / 62)) < 1e-12);
  assert.deepEqual(rrfFuse([[{id: 'z'}, {id: 'y'}], [{id: 'y'}, {id: 'z'}]]).map(f => f.id), ['y', 'z'], 'equal fused scores order by id');
});

test('nearest examples: without a vector for the query the ranking is TF-IDF; with vectors it is the fusion of both rankings', () => {
  const lexical = nearestExamples(query, bank, {k: 3, embeddings: null});
  assert.equal(lexical[0].example.id, 'ex-a', 'word overlap favours the access-rights example');
  // The file knows the query and every example; semantically the query is closest to ex-c, then ex-b, then ex-a.
  const index = parseEmbeddings(file(Object.fromEntries([vec(query, [1, 0, 0]), vec(bank[0].text, [0, 0, 1]), vec(bank[1].text, [1, 1, 0]),
    vec(bank[2].text, [1, 0.1, 0])])));
  const hybrid = nearestExamples(query, bank, {k: 3, embeddings: index});
  const expected = rrfFuse([lexical.map(x => ({id: x.example.id})), [{id: 'ex-c'}, {id: 'ex-b'}, {id: 'ex-a'}]]).map(x => x.id);
  assert.deepEqual(hybrid.map(x => x.example.id), expected);
  assert.notDeepEqual(hybrid.map(x => x.example.id), lexical.map(x => x.example.id));
  assert.equal(retrievalMethod(query, {embeddings: index}), 'hybrid');
  assert.equal(retrievalMethod('a text the file never saw', {embeddings: index}), 'tfidf');
  const partial = parseEmbeddings(file(Object.fromEntries([vec(query, [1, 0, 0])])));
  assert.deepEqual(nearestExamples(query, bank, {k: 3, embeddings: partial}).map(x => x.example.id), lexical.map(x => x.example.id),
    'no example vectors: lexical order');
  assert.ok(!nearestExamples(query, bank, {k: 3, embeddings: index, excludeId: 'ex-c'}).some(x => x.example.id === 'ex-c'));
  assert.deepEqual(nearestExamples(query, bank, {k: 3, embeddings: index}).map(x => x.example.id), hybrid.map(x => x.example.id), 'deterministic');
});

test('requirement candidates fuse the same way, and the request records which retrieval it used', () => {
  const catalog = governanceCatalog(), lexical = retrieveRequirements(query, {embeddings: null});
  assert.equal(lexical.length, LIMITS.candidates);
  const last = lexical.at(-1).id, lastText = catalog.byId.get(last).text;
  const index = parseEmbeddings(file(Object.fromEntries([vec(query, [1, 0, 0]), vec(lastText, [1, 0, 0])])));
  const hybrid = retrieveRequirements(query, {embeddings: index});
  assert.equal(hybrid[0].id, last, 'the one entry with a matching vector rises to the top');
  const item = {kind: 'document_excerpt', text: query, locators: ['doc:1']};
  // The file has no out-of-scope pool text (as every file made before the pool): that ranking degrades to TF-IDF and says so.
  assert.deepEqual(buildMappingRequest(item, {variant: 'retrieval', embeddings: index}).retrieval,
    {method: 'hybrid', embeddings: 'a'.repeat(64), outOfScope: 'tfidf'});
  assert.deepEqual(buildMappingRequest(item, {variant: 'retrieval', embeddings: null}).retrieval, {method: 'tfidf', embeddings: null, outOfScope: 'tfidf'});
  assert.deepEqual(buildMappingRequest(item, {variant: 'retrieval', embeddings: index}).outOfScope,
    buildMappingRequest(item, {variant: 'retrieval', embeddings: null}).outOfScope);
  assert.equal(buildMappingRequest(item, {variant: 'zero_shot', embeddings: index}).retrieval, null);
  assert.ok(buildMappingRequest(item, {variant: 'retrieval', embeddings: index}).candidates.includes(last));
});

test('out-of-scope criteria fuse the same way when the file covers pool texts; the catalog ranking is untouched by them', () => {
  const pool = outOfScopePool(), lexical = retrieveOutOfScope(query, {embeddings: null});
  assert.equal(lexical.length, LIMITS.outOfScope);
  const outsider = pool.entries.find(e => !lexical.some(x => x.id === e.id));
  const index = parseEmbeddings(file(Object.fromEntries([vec(query, [1, 0, 0]), vec(outsider.text, [1, 0, 0])])));
  const hybrid = retrieveOutOfScope(query, {embeddings: index});
  // Fusion: the outsider scores 1/61 (semantic rank 1) plus its lexical share, above the lexical first (1/61) and second (1/62).
  assert.deepEqual(hybrid.map(x => x.id), [outsider.id, ...lexical.slice(0, LIMITS.outOfScope - 1).map(x => x.id)]);
  assert.equal(outOfScopeRetrievalMethod(query, {embeddings: index}), 'hybrid');
  assert.equal(outOfScopeRetrievalMethod('a text the file never saw', {embeddings: index}), 'tfidf');
  const item = {kind: 'document_excerpt', text: query, locators: ['doc:1']}, request = buildMappingRequest(item, {variant: 'retrieval', embeddings: index});
  assert.deepEqual(request.retrieval, {method: 'hybrid', embeddings: 'a'.repeat(64), outOfScope: 'hybrid'});
  assert.ok(request.outOfScope.includes(outsider.id));
  assert.deepEqual(request.candidates, buildMappingRequest(item, {variant: 'retrieval', embeddings: parseEmbeddings(file(
    Object.fromEntries([vec(query, [1, 0, 0])])))}).candidates, 'pool vectors never move a catalog candidate');
});

test('embed-texts lists every prompt, catalog and out-of-scope text once in digest order; retrieval-recall reports the ceilings', () => {
  mkdirSync('.test-runs', {recursive: true});
  const dir = mkdtempSync(resolve('.test-runs/governance-embed-'));
  const out = runGovernanceMappingCommand(['embed-texts', '--data', dataset, '--out', join(dir, 'texts.jsonl')]);
  const lines = readFileSync(join(dir, 'texts.jsonl'), 'utf8').trim().split('\n').map(l => JSON.parse(l));
  assert.equal(lines.length, out.texts);
  assert.equal(out.outOfScopeEntries, 74);
  assert.deepEqual([out.missingFromEmbeddings, out.outOfScopeMissingFromEmbeddings], [null, null]);
  assert.ok(out.texts >= out.catalogEntries + out.outOfScopeEntries && out.texts <= out.rows + out.catalogEntries + out.outOfScopeEntries);
  const listed = new Set(lines.map(l => l.text));
  assert.ok(outOfScopePool().entries.every(e => listed.has(e.text)), 'every pool text is listed for the embed script');
  assert.ok(lines.every((l, i) => l.digest === textDigest(l.text) && (i === 0 || lines[i - 1].digest < l.digest)));
  // A file made from the list before the pool existed: the pool texts are exactly what it lacks.
  const old = lines.filter(l => !outOfScopePool().entries.some(e => e.text === l.text));
  writeFileSync(join(dir, 'old-embeddings.json'), JSON.stringify(file(Object.fromEntries(old.map(l => [l.digest, [1, 0, 0]])))));
  const missing = runGovernanceMappingCommand(['embed-texts', '--embeddings', join(dir, 'old-embeddings.json'), '--data', dataset,
    '--out', join(dir, 'texts-again.jsonl')]);
  setGovernanceEmbeddings(null);
  assert.deepEqual([missing.missingFromEmbeddings, missing.outOfScopeMissingFromEmbeddings], [74, 74]);
  assert.deepEqual(embeddingTexts(['b', 'a', 'b', '']), embeddingTexts(['a', 'b']));
  const recall = runGovernanceMappingCommand(['retrieval-recall', '--data', dataset, '--k', '1,5']);
  assert.equal(recall.method, 'tfidf');
  assert.equal(recall.embeddings, null);
  assert.ok(recall.examples > 0);
  for (const split of ['tune', 'validation', 'test']) {
    const s = recall.splits[split];
    assert.ok(s.gold > 0 && s.retrieved <= s.gold && s.examplesHit[1] <= s.examplesHit[5] && s.examplesHit[5] <= s.gold);
    assert.ok(s.retrieved <= s.inPrompt && s.inPrompt <= s.gold);
    assert.equal(s.examplesRecall[5], s.examplesHit[5] / s.gold);
  }
  // Offline proxy of the outOfScope list on the committed dataset (TF-IDF). Its Korean must-abstain rows are all title rows
  // ("ISMS-P 인증기준 <number> <title>", the pool entry's own words), listed by construction; the source-table sentence rows are the
  // English Prowler ones, which match their criterion through the English alias in 7 of 10 (8 of 10 among the 5 closest).
  const oos = recall.outOfScope, {ko, en} = oos.splits.test;
  assert.deepEqual([oos.k, oos.method, oos.embeddedPoolTexts, oos.kisaGuide], [LIMITS.outOfScope, 'tfidf', 0, false]);
  assert.deepEqual([ko.rows, ko.listed, ko.title.rows, ko.title.listed, ko.sentence.rows, ko.sentence.recall], [16, 16, 16, 16, 0, null]);
  assert.deepEqual([en.rows, en.listed, en.recall, en.title.rows, en.sentence.rows, en.sentence.listed], [30, 21, 0.7, 0, 30, 21]);
  assert.deepEqual(en.sentence.recallAtK, {1: 19 / 30, 5: 25 / 30});
  for (const byLanguage of Object.values(oos.splits)) {
    for (const s of Object.values(byLanguage)) {
      assert.equal(s.rows, s.title.rows + s.sentence.rows);
      assert.equal(s.listed, s.title.listed + s.sentence.listed);
      assert.ok(s.recallAtK[1] <= s.recallAtK[5]);
    }
  }
  const first = lines.find(l => l.text === lines[0].text);
  writeFileSync(join(dir, 'embeddings.json'), JSON.stringify(file({[first.digest]: [1, 0, 0]})));
  const withFile = runGovernanceMappingCommand(['retrieval-recall', '--embeddings', join(dir, 'embeddings.json'), '--data', dataset, '--k', '1']);
  assert.equal(withFile.method, 'hybrid');
  assert.equal(withFile.embeddings.texts, 1);
  setGovernanceEmbeddings(null);
  assert.throws(() => runGovernanceMappingCommand(['retrieval-recall', '--data', dataset, '--k', '0']), /--k/);
});

// A stand-in for llama-server: /health, /props and /v1/embeddings; vectors are a deterministic function of the text.
const STUB = `#!/usr/bin/env python3
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
port = int(sys.argv[sys.argv.index("--port") + 1]); log = sys.argv[0] + ".log"
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def reply(self, value):
        data = json.dumps(value).encode(); self.send_response(200); self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        self.reply({"status": "ok"} if self.path == "/health" else {"build_info": "stub"})
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        with open(log, "a") as f: f.write(json.dumps({"argv": sys.argv[1:], "n": len(body["input"])}) + "\\n")
        self.reply({"object": "list", "data": [{"object": "embedding", "index": i, "embedding": [len(t) % 7 + 1.0, 0.5, float(i)]}
                                               for i, t in enumerate(body["input"])]})
HTTPServer(("127.0.0.1", port), H).serve_forever()
`;
const bundled = resolve('.local/python/python.exe');
const python = process.env.EVIDSCOPE_PYTHON || (existsSync(bundled) ? bundled : 'python3');
const run = args => spawnSync(python, ['-I', '-B', 'scripts/governance_mapping_embed.py', ...args], {encoding: 'utf8', timeout: 120000});

test('embed script: starts the server with --embeddings, keys vectors by the text digest, refuses edited lines', {skip: process.platform === 'win32'}, () => {
  mkdirSync('.test-runs', {recursive: true});
  const dir = mkdtempSync(resolve('.test-runs/governance-embed-py-')), server = join(dir, 'llama-server');
  writeFileSync(server, STUB);
  chmodSync(server, 0o755);
  writeFileSync(join(dir, 'model.gguf'), 'not a model');
  const texts = embeddingTexts(['가나다', 'evidence text', '세 번째 문장']);
  writeFileSync(join(dir, 'texts.jsonl'), texts.map(t => JSON.stringify(t)).join('\n') + '\n');
  const common = ['--out', join(dir, 'embeddings.json'), '--operator', 'operator-a', '--server-bin', server, '--model', join(dir, 'model.gguf'),
    '--start-timeout', '30', '--batch', '2', '--pause-ratio', '0'];
  const r = run(['--texts', join(dir, 'texts.jsonl'), ...common]);
  assert.equal(r.status, 0, r.stderr);
  const index = parseEmbeddings(readFileSync(join(dir, 'embeddings.json'), 'utf8'));
  assert.equal(index.vectors.size, 3);
  assert.equal(index.dims, 3);
  assert.ok(texts.every(t => index.vectors.has(t.digest)));
  const summary = JSON.parse(r.stdout);
  assert.equal(summary.embedded, 3);
  assert.equal(summary.failures, 0);
  const log = readFileSync(server + '.log', 'utf8').trim().split('\n').map(l => JSON.parse(l));
  assert.deepEqual(log.map(x => x.n), [2, 1]);
  assert.ok(log[0].argv.includes('--embeddings') && log[0].argv.includes('--pooling') && log[0].argv.includes('cls'));
  writeFileSync(join(dir, 'edited.jsonl'), texts.map((t, i) => JSON.stringify(i ? t : {...t, text: t.text + '!'})).join('\n') + '\n');
  const edited = run(['--texts', join(dir, 'edited.jsonl'), '--out', join(dir, 'edited.json'), ...common.slice(2)]);
  assert.notEqual(edited.status, 0);
  assert.match(edited.stderr, /text_line_invalid/);
  const again = run(['--texts', join(dir, 'texts.jsonl'), ...common]);
  assert.notEqual(again.status, 0, 'an existing output file is never overwritten');
});
