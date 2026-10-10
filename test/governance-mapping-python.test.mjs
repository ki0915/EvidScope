import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {runGovernanceMappingCommand} from '../scripts/governance-mapping.mjs';
import {buildComparisonReport, hashOf, measurementProblem, variantRequests} from '../src/governance-mapping-eval.mjs';

const bundled = resolve('.local/python/python.exe');
const python = process.env.EVIDSCOPE_PYTHON || (existsSync(bundled) ? bundled : 'python3');
const run = (args, options = {}) => spawnSync(python, ['-I', '-B', ...args], {encoding: 'utf8', timeout: 120000, ...options});
const dataset = 'data/governance-mapping/v1/dataset.jsonl';
const testRows = readFileSync(dataset, 'utf8').trim().split('\n').map(l => JSON.parse(l))
  .filter(r => r.split === 'test').sort((a, b) => (a.id < b.id ? -1 : 1));

// A stand-in for llama-server: same endpoints, records each request body, answers every item with an abstention.
const STUB = `#!/usr/bin/env python3
import json, os, sys
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
        with open(log, "a") as f: f.write(json.dumps({"lora": body.get("lora"), "argv": sys.argv[1:], "format": body.get("response_format")}) + "\\n")
        n = sum(1 for _ in open(log))
        if os.path.exists(sys.argv[0] + ".mixed") and n % 3 == 2:
            self.send_response(500); self.send_header("content-length", "0"); self.end_headers(); return
        finish = "length" if os.path.exists(sys.argv[0] + ".mixed") and n % 3 == 1 else "stop"
        self.reply({"choices": [{"finish_reason": finish, "message": {"content": "{\\"abstain\\":true,\\"mappings\\":[]}"}}],
                    "usage": {"prompt_tokens": 9, "completion_tokens": 3}})
HTTPServer(("127.0.0.1", port), H).serve_forever()
`;

function fixture() {
  mkdirSync('.test-runs', {recursive: true});
  const dir = mkdtempSync(resolve('.test-runs/governance-batch-')), server = join(dir, 'llama-server');
  writeFileSync(server, STUB);
  chmodSync(server, 0o755);
  writeFileSync(join(dir, 'model.gguf'), 'not a model');
  writeFileSync(join(dir, 'adapter.gguf'), 'not an adapter');
  return {dir, server};
}
const batch = (f, variant, extra = []) => run(['scripts/governance_mapping_batch.py', '--requests', join(f.dir, `${variant}.requests.jsonl`),
  '--variant', variant,
  '--out', join(f.dir, `${variant}.outputs.json`), '--receipt', join(f.dir, `${variant}.receipt.json`), '--operator', 'operator-a', '--server-bin', f.server,
  '--model', join(f.dir, 'model.gguf'), '--start-timeout', '30', ...extra]);

test('batch runner: binds the exact request bytes, the outputs and the model; the report recomputes the same hashes',
  {skip: process.platform === 'win32'}, () => {
  const f = fixture();
  runGovernanceMappingCommand(['requests', '--data', dataset, '--variant', 'retrieval_constrained', '--out',
    join(f.dir, 'retrieval_constrained.requests.jsonl')]);
  const r = batch(f, 'retrieval_constrained');
  assert.equal(r.status, 0, r.stderr);
  const receipt = JSON.parse(readFileSync(join(f.dir, 'retrieval_constrained.receipt.json'), 'utf8'));
  const outputs = JSON.parse(readFileSync(join(f.dir, 'retrieval_constrained.outputs.json'), 'utf8'));
  assert.equal(receipt.count, testRows.length);
  assert.equal(receipt.failures, 0);
  assert.equal(receipt.requestsSha256, hashOf(variantRequests(testRows, 'retrieval_constrained')));
  assert.equal(receipt.outputsSha256, hashOf(outputs));
  assert.equal(receipt.modelSha256, createHash('sha256').update('not a model').digest('hex'));
  assert.equal(receipt.adapterSha256, null);
  assert.equal(receipt.isolation.verified, receipt.isolation.networkInterfaces.length === 1 && receipt.isolation.networkInterfaces[0] === 'lo');
  const report = buildComparisonReport(testRows, {always_abstain: {outputs}, rules_only: {outputs: Object.fromEntries(testRows.map(x => [x.id, '']))},
    zero_shot: {outputs, receipt}, retrieval: {outputs, receipt}, retrieval_constrained: {outputs, receipt}}, {preparedBy: 'operator-a'});
  assert.match(measurementProblem(report, 'retrieval_constrained'), /isolation_not_verified|base_model_mismatch/);
  assert.equal(report.variants.retrieval_constrained.requestsSha256, receipt.requestsSha256);
  const log = readFileSync(f.server + '.log', 'utf8').trim().split('\n').map(l => JSON.parse(l));
  assert.ok(log.every(x => x.lora === null && !x.argv.includes('--lora')));
});

test('batch runner: the candidate run loads the adapter without applying it and asks for it per request; edited requests are refused',
  {skip: process.platform === 'win32'}, () => {
    const f = fixture();
    runGovernanceMappingCommand(['requests', '--data', dataset, '--variant', 'candidate', '--out', join(f.dir, 'candidate.requests.jsonl')]);
    assert.notEqual(batch(f, 'candidate').status, 0, 'adapter requests need --lora');
    const r = batch(f, 'candidate', ['--lora', join(f.dir, 'adapter.gguf')]);
    assert.equal(r.status, 0, r.stderr);
    const receipt = JSON.parse(readFileSync(join(f.dir, 'candidate.receipt.json'), 'utf8'));
    assert.equal(receipt.adapterSha256, createHash('sha256').update('not an adapter').digest('hex'));
    const log = readFileSync(f.server + '.log', 'utf8').trim().split('\n').map(l => JSON.parse(l));
    assert.ok(log.every(x => x.lora?.length === 1 && x.lora[0].id === 0 && x.lora[0].scale === 1));
    assert.ok(log[0].argv.includes('--lora-init-without-apply'));
    const lines = readFileSync(join(f.dir, 'candidate.requests.jsonl'), 'utf8').split('\n');
    writeFileSync(join(f.dir, 'zero_shot.requests.jsonl'), [JSON.stringify(JSON.parse(lines[0]), null, 1).replace(/\n/g, ' '), ...lines.slice(1)].join('\n'));
    const edited = batch(f, 'zero_shot');
    assert.notEqual(edited.status, 0);
    assert.match(edited.stderr, /request_line_not_canonical|variant_mismatch/);
  });

test('trainer: admission refuses test rows, short datasets and invalid targets; prompt tokens are masked', () => {
  const f = fixture(), file = join(f.dir, 'train.jsonl');
  const row = (id, split, target = '{"abstain":true,"mappings":[]}') => JSON.stringify({id, task: 'governance-mapping', taskVersion: 1,
    roleId: 'governance-assistant',
    split, familyId: id, catalogDigest: 'd', labelSource: 'derived_mapping_table', reviewedPayloadHash: null,
    messages: [{role: 'system', content: 's'}, {role: 'user', content: 'u'}], target});
  writeFileSync(file, [row('a', 'tune'), row('b', 'test'), row('c', 'validation', '{"abstain":false,"mappings":[]}')].join('\n') + '\n');
  const code = `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("t", "scripts/train-governance-mapping-lora.py")
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
rows, gate = t.admission(sys.argv[1])
class Tok:
    eos_token_id = 0
    def apply_chat_template(self, messages, tokenize=False, add_generation_prompt=True): return "<s>" + messages[1]["content"] + "<think>"
    def encode(self, text, add_special_tokens=False): return [ord(c) for c in text]
encoded = t.encode_row(Tok(), {"id": "a", "messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "uu"}], "target": "{}"})
print(json.dumps({"gate": gate, "masked": encoded["labels"].count(-100), "prefix": len("<s>uu<think>"), "total": len(encoded["input_ids"]),
  "validTarget": [t.valid_target('{"abstain":true,"mappings":[]}'), t.valid_target('{"abstain":false,"mappings":[]}'), t.valid_target("x")]}))
`;
  const r = run(['-c', code, file]);
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout.trim().split('\n').at(-1));
  assert.equal(out.gate.admitted, false);
  for (const reason of ['split_invalid_or_test_present', 'target_invalid', 'eligible_counts_below_policy']) {
    assert.ok(out.gate.reasons.includes(reason), reason);
  }
  assert.equal(out.masked, out.prefix);
  assert.equal(out.total, out.prefix + '\n</think>\n{}'.length + 1);
  assert.deepEqual(out.validTarget, [true, false, false]);
  const check = run(['scripts/train-governance-mapping-lora.py', '--data', file, '--check-only']);
  assert.equal(check.status, 2);
});

test('trainer: triton is reported unavailable before transformers or peft import bitsandbytes (the image has no C compiler)', () => {
  const src = readFileSync('scripts/train-governance-mapping-lora.py', 'utf8'), off = src.indexOf('torch_triton.has_triton = lambda: False');
  assert.ok(off > 0);
  assert.ok(off < src.indexOf('from transformers import AutoTokenizer, AutoModelForCausalLM'));
  assert.ok(off < src.indexOf('from peft import'));
});

test('batch runner: constrained requests carry the schema where llama-server reads it; cut replies are scored, errors are counted by reason',
  {skip: process.platform === 'win32'}, () => {
  const [constrained] = variantRequests(testRows.slice(0, 1), 'retrieval_constrained'), [loose] = variantRequests(testRows.slice(0, 1), 'retrieval');
  assert.equal(constrained.response_format.type, 'json_schema');
  assert.equal(constrained.response_format.json_schema.strict, true);
  assert.equal(constrained.response_format.json_schema.schema.type, 'object');
  assert.equal(constrained.response_format.schema, undefined);
  assert.deepEqual(loose.response_format, {type: 'json_object'});
  const f = fixture();
  writeFileSync(f.server + '.mixed', '');
  runGovernanceMappingCommand(['requests', '--data', dataset, '--variant', 'retrieval_constrained', '--out',
    join(f.dir, 'retrieval_constrained.requests.jsonl')]);
  const r = batch(f, 'retrieval_constrained', ['--pause-ratio', '0']);
  assert.equal(r.status, 2);
  const receipt = JSON.parse(readFileSync(join(f.dir, 'retrieval_constrained.receipt.json'), 'utf8'));
  const outputs = JSON.parse(readFileSync(join(f.dir, 'retrieval_constrained.outputs.json'), 'utf8'));
  const every = k => testRows.filter((_, i) => (i + 1) % 3 === k).length;
  assert.equal(receipt.truncated, every(1));
  assert.equal(receipt.failures, every(2));
  assert.deepEqual(receipt.failureReasons, {HTTPError: every(2)});
  assert.equal(Object.values(outputs).filter(o => o === '').length, every(2));
  const log = readFileSync(f.server + '.log', 'utf8').trim().split('\n').map(l => JSON.parse(l));
  assert.ok(log.every(x => x.format.json_schema.schema.type === 'object'));
  assert.equal(batch(f, 'retrieval_constrained', ['--pause-ratio', '9']).status, 2);
});
