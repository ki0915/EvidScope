import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {runGovernanceMappingCommand} from '../scripts/governance-mapping.mjs';
import {canonical} from '../src/crypto.mjs';
import {buildComparisonReport, hashOf, measurementProblem, variantRequests} from '../src/governance-mapping-eval.mjs';
import {primaryModelPolicy} from '../src/model-policy.mjs';

// Governance-mapping tests see only the shipped source tables; a local-only (KOGL) table on this machine must not change them.
process.env.EVIDSCOPE_GOVERNANCE_LOCAL_TABLES ??= '.test-runs/no-local-tables';

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
        with open(log, "a") as f: f.write(json.dumps({"lora": body.get("lora"), "argv": sys.argv[1:], "format": body.get("response_format"),
                                                    "logprobs": body.get("logprobs"), "top_logprobs": body.get("top_logprobs")}) + "\\n")
        n = sum(1 for _ in open(log))
        if os.path.exists(sys.argv[0] + ".mixed") and n % 3 == 2:
            self.send_response(500); self.send_header("content-length", "0"); self.end_headers(); return
        finish = "length" if os.path.exists(sys.argv[0] + ".mixed") and n % 3 == 1 else "stop"
        choice = {"finish_reason": finish, "message": {"content": "{\\"abstain\\":true,\\"mappings\\":[]}"}}
        if body.get("logprobs"):
            pieces = ["{\\"", "abstain", "\\":true,\\"", "mappings", "\\":[]}"]
            choice["logprobs"] = {"content": [{"token": t, "logprob": -0.25 * (i + 1), "bytes": list(t.encode()), "top_logprobs": []}
                                              for i, t in enumerate(pieces)]}
        prompt = 9
        if os.path.exists(sys.argv[0] + ".long"):
            prompt = int(sys.argv[sys.argv.index("-c") + 1]) - body["max_tokens"] + (1 if n % 4 == 0 else 0)
        self.reply({"choices": [choice], "usage": {"prompt_tokens": prompt, "completion_tokens": 3}})
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
    nearest_example: {outputs},
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

test('batch runner: --logprobs stores each reply token with its log-probability in micro-nats and binds the file in the receipt',
  {skip: process.platform === 'win32'}, () => {
    const f = fixture(), rows = testRows.slice(0, 4), file = join(f.dir, 'candidate.logprobs.json');
    writeFileSync(join(f.dir, 'candidate.requests.jsonl'), variantRequests(rows, 'candidate').map(r => canonical(r)).join('\n') + '\n');
    const r = batch(f, 'candidate', ['--lora', join(f.dir, 'adapter.gguf'), '--logprobs', file, '--pause-ratio', '0']);
    assert.equal(r.status, 0, r.stderr);
    const logprobs = JSON.parse(readFileSync(file, 'utf8')), receipt = JSON.parse(readFileSync(join(f.dir, 'candidate.receipt.json'), 'utf8'));
    assert.deepEqual(Object.keys(logprobs).sort(), rows.map(x => x.id).sort());
    assert.deepEqual(logprobs[rows[0].id], [['{"', -250000], ['abstain', -500000], ['":true,"', -750000], ['mappings', -1000000], ['":[]}', -1250000]]);
    assert.equal(logprobs[rows[0].id].map(t => t[0]).join(''), '{"abstain":true,"mappings":[]}');
    assert.equal(receipt.logprobsSha256, hashOf(logprobs));
    assert.deepEqual(receipt.logprobs, {file: 'candidate.logprobs.json', topLogprobs: 1, scale: 1000000});
    const log = readFileSync(f.server + '.log', 'utf8').trim().split('\n').map(l => JSON.parse(l));
    assert.ok(log.every(x => x.logprobs === true && x.top_logprobs === 1));
    assert.notEqual(batch(f, 'candidate', ['--lora', join(f.dir, 'adapter.gguf'), '--logprobs', file]).status, 0, 'an existing logprobs file is kept');
    const plain = fixture();
    writeFileSync(join(plain.dir, 'candidate.requests.jsonl'), readFileSync(join(f.dir, 'candidate.requests.jsonl')));
    assert.equal(batch(plain, 'candidate', ['--lora', join(plain.dir, 'adapter.gguf'), '--pause-ratio', '0']).status, 0);
    const without = JSON.parse(readFileSync(join(plain.dir, 'candidate.receipt.json'), 'utf8'));
    assert.equal(without.logprobsSha256, null);
    assert.equal(without.logprobs, null);
    const plainLog = readFileSync(plain.server + '.log', 'utf8').trim().split('\n').map(l => JSON.parse(l));
    assert.ok(plainLog.every(x => x.logprobs === null));
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

test('trainer: the session task admits version 2 targets (verdict, type, evidence) and refuses version 1 rows', () => {
  const code = `
import importlib.util, json
spec = importlib.util.spec_from_file_location("t", "scripts/train-governance-mapping-lora.py")
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
v = t.valid_session_target
print(json.dumps({"version": t.TASKS["session-inference"][2], "checks": [
  v('{"verdict":"violation","type":"exfiltration","evidenceActionIds":["a1"]}'),
  v('{"verdict":"clean","type":null,"evidenceActionIds":[]}'),
  v('{"verdict":"clean","type":null,"evidenceActionIds":["a1"]}'),
  v('{"verdict":"violation","type":null,"evidenceActionIds":["a1"]}'),
  v('{"verdict":"violation","type":"exfiltration","requirementIds":[],"evidenceActionIds":["a1"],"confidence":0.9}')]}))
`;
  const r = run(['-c', code]);
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout.trim().split('\n').at(-1));
  assert.equal(out.version, 2);
  assert.deepEqual(out.checks, [true, true, false, false, false]);
  const f = fixture(), file = join(f.dir, 'session.jsonl');
  const row = (id, taskVersion) => JSON.stringify({id, task: 'session-inference', taskVersion, roleId: 'session-auditor', split: 'tune',
    familyId: id, catalogDigest: 'd', labelSource: 'derived_mapping_table', reviewedPayloadHash: null, runMode: 'candidate',
    messages: [{role: 'system', content: 's'}, {role: 'user', content: 'u'}], target: '{"evidenceActionIds":[],"type":null,"verdict":"clean"}'});
  writeFileSync(file, [row('a', 2), row('b', 1)].join('\n') + '\n');
  const gate = run(['-c', `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("t", "scripts/train-governance-mapping-lora.py")
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
print(json.dumps(t.admission(sys.argv[1], task="session-inference")[1]))
`, file]);
  assert.equal(gate.status, 0, gate.stderr);
  assert.ok(JSON.parse(gate.stdout.trim().split('\n').at(-1)).reasons.includes('task_invalid'));
});

test('trainer: public benchmark rows are admitted for the session judge only, with no evidence; a rented GPU trains only that', () => {
  const f = fixture(), file = join(f.dir, 'public.jsonl');
  const row = (id, extra = {}) => JSON.stringify({id, task: 'session-inference', taskVersion: 2, roleId: 'session-auditor', split: 'tune',
    familyId: 'bench:a', catalogDigest: 'd', labelSource: 'public_dataset', reviewedPayloadHash: null, runMode: 'candidate',
    messages: [{role: 'system', content: 's'}, {role: 'user', content: 'u'}],
    target: '{"evidenceActionIds":[],"type":"fraud","verdict":"violation"}', ...extra});
  const gate = (rows, task = 'session-inference') => {
    writeFileSync(file, rows.join('\n') + '\n');
    const r = run(['-c', `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("t", "scripts/train-governance-mapping-lora.py")
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
print(json.dumps(t.admission(sys.argv[1], task=sys.argv[2])[1]))
`, file, task]);
    assert.equal(r.status, 0, r.stderr);
    return JSON.parse(r.stdout.trim().split('\n').at(-1)).reasons;
  };
  assert.ok(!gate([row('a')]).some(x => x.includes('provenance') || x.includes('public_dataset')));
  assert.ok(gate([row('b', {target: '{"evidenceActionIds":["a1"],"type":"fraud","verdict":"violation"}'})]).includes('public_dataset_row_invalid'));
  assert.ok(gate([row('c', {reviewedPayloadHash: 'e'.repeat(64)})]).includes('public_dataset_row_invalid'));
  const host = run(['-c', `
import importlib.util, json, os, types
spec = importlib.util.spec_from_file_location("t", "scripts/train-governance-mapping-lora.py")
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
def check(env, task="session-inference", rented=True, rows=({"labelSource": "public_dataset"},)):
    os.environ.pop("EVIDSCOPE_RENTED_GPU", None); os.environ.pop("EVIDSCOPE_ISOLATED", None); os.environ.update(env)
    try:
        t.check_host(types.SimpleNamespace(rented_gpu=rented, task=task, shakedown=False), list(rows)); return "ok"
    except RuntimeError as e:
        return str(e)
print(json.dumps([check({"EVIDSCOPE_RENTED_GPU": "1"}), check({}), check({"EVIDSCOPE_RENTED_GPU": "1"}, task="governance-mapping"),
  check({"EVIDSCOPE_RENTED_GPU": "1"}, rows=({"labelSource": "claude_drafted"},)), check({"EVIDSCOPE_ISOLATED": "1"}, rented=False)]))
`]);
  assert.equal(host.status, 0, host.stderr);
  assert.deepEqual(JSON.parse(host.stdout.trim().split('\n').at(-1)), ['ok', 'rented_gpu_run_invalid', 'rented_gpu_run_invalid', 'rented_gpu_rows_invalid',
    existsSync('/etc/podinfo/uid') ? 'ok' : 'isolated_training_job_required']);
});

test('trainer: triton is reported unavailable before transformers or peft import bitsandbytes (the image has no C compiler)', () => {
  const src = readFileSync('scripts/train-governance-mapping-lora.py', 'utf8'), off = src.indexOf('torch_triton.has_triton = lambda: False');
  assert.ok(off > 0);
  assert.ok(off < src.indexOf('from transformers import AutoTokenizer, AutoModelForCausalLM'));
  assert.ok(off < src.indexOf('from peft import'));
});

test('trainer: thermal pacing cools in place, is bounded per step, honours a stop request and never stops training itself', () => {
  const code = `
import importlib.util, json
spec = importlib.util.spec_from_file_location("t", "scripts/train-governance-mapping-lora.py")
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
class Clock:
    def __init__(self): self.now = 0.0; self.sleeps = []
    def monotonic(self): return self.now
    def sleep(self, seconds): self.sleeps.append(seconds); self.now += seconds
def pacer(temps, max_wait=300.0, stop_after=None):
    clock, logs, values = Clock(), [], iter(temps)
    def read():
        value = next(values)
        if isinstance(value, Exception): raise value
        return value
    stop = (lambda: clock.now >= stop_after) if stop_after is not None else (lambda: False)
    return t.ThermalPacer(read, 70, 65, max_wait, should_stop=stop, clock=clock.monotonic, sleep=clock.sleep, emit=logs.append), clock, logs
out = {}
p, c, logs = pacer([69]); out["cool"] = [p.pace(1), c.sleeps, logs, p.summary()]
p, c, logs = pacer([72, 70, 67, 65]); out["hot"] = [p.pace(2), c.sleeps, logs, p.summary()]
p, c, logs = pacer([74] * 50, max_wait=5.0); out["deadline"] = [p.pace(3), c.sleeps, logs, p.summary()]
p, c, logs = pacer([73] * 50, stop_after=4); out["stop"] = [p.pace(4), c.sleeps, p.summary()]
p, c, logs = pacer([RuntimeError("thermal_nvml_init_failed:9"), OSError("libnvidia-ml.so.1: cannot open"), 71, RuntimeError("x")])
out["unreadable"] = [p.pace(5), p.pace(6), p.pace(7), c.sleeps, logs, p.summary()]
p, c, logs = pacer([], max_wait=0); out["off"] = [p.pace(8), logs, p.summary()]
p, c, logs = pacer([76], stop_after=0); out["stopAtStart"] = [p.pace(9), c.sleeps, logs, p.summary()]
print(json.dumps(out))
`;
  const r = run(['-c', code]);
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout.trim().split('\n').at(-1));
  const summary = extra => ({triggerC: 70, targetC: 65, maxWaitSeconds: 300, waits: 0, waitSeconds: 0, maxTemperatureC: null, deadlineHits: 0,
    readFailures: 0, ...extra});
  // Below the trigger: no wait, but the reading still counts toward the maximum seen.
  assert.deepEqual(out.cool, [0, [], [], summary({maxTemperatureC: 69})]);
  // At or above the trigger: sleep-poll down to the target (hysteresis), one log line per wait.
  assert.deepEqual(out.hot, [6, [2, 2, 2], [{thermalWait: {optimizerStep: 2, fromC: 72, toC: 65, seconds: 6, reachedTarget: true}}],
    summary({waits: 1, waitSeconds: 6, maxTemperatureC: 72})]);
  // A GPU that does not cool is waited on for at most maxWaitSeconds, then training continues (the external 75 C guard is the hard stop).
  assert.deepEqual(out.deadline, [5, [2, 2, 1], [{thermalWait: {optimizerStep: 3, fromC: 74, toC: 74, seconds: 5, reachedTarget: false}}],
    summary({maxWaitSeconds: 5, waits: 1, waitSeconds: 5, maxTemperatureC: 74, deadlineHits: 1})]);
  // A stop request (SIGTERM from the guard) ends the wait so the checkpoint is saved within docker stop's grace period.
  assert.deepEqual(out.stop, [4, [2, 2], summary({waits: 1, waitSeconds: 4, maxTemperatureC: 73})]);
  // An unreadable sensor logs one warning and skips pacing; it never raises.
  const [first, second, third, sleeps, logs, stats] = out.unreadable;
  assert.deepEqual([first, second, third, sleeps], [0, 0, 2, [2]]);
  assert.deepEqual(logs.map(l => Object.keys(l)[0]), ['warning', 'thermalWait']);
  assert.equal(logs[0].warning, 'thermal_pacing_unavailable');
  assert.match(logs[0].error, /thermal_nvml_init_failed:9/);
  assert.deepEqual(logs[1].thermalWait, {optimizerStep: 7, fromC: 71, toC: null, seconds: 2, reachedTarget: false});
  assert.deepEqual(stats, summary({waits: 1, waitSeconds: 2, maxTemperatureC: 71, readFailures: 3}));
  // --thermal-max-wait-seconds 0 turns pacing off without reading the sensor.
  assert.deepEqual(out.off, [0, [], summary({maxWaitSeconds: 0})]);
  // A stop already requested (the guard's SIGTERM on a hot GPU) is not counted or logged as a thermal wait.
  assert.deepEqual(out.stopAtStart, [0, [], [], summary({maxTemperatureC: 76})]);
});

test('trainer: thermal flags are range-checked, the helper is bound into the checkpoint identity and every micro-batch paces after its rest', () => {
  const f = fixture(), file = join(f.dir, 'train.jsonl');
  writeFileSync(file, '');
  for (const [flags, message] of [[['--thermal-trigger-c', '75'], /target < trigger <= 74/], [['--thermal-target-c', '70'], /target < trigger <= 74/],
    [['--thermal-target-c', '39', '--thermal-trigger-c', '50'], /40 <= target/], [['--thermal-max-wait-seconds', '-1'], /between 0 and 1800/],
    [['--thermal-max-wait-seconds', '1801'], /between 0 and 1800/], [['--thermal-trigger-c', '72.5'], /invalid int value/]]) {
    const r = run(['scripts/train-governance-mapping-lora.py', '--data', file, '--check-only', ...flags]);
    assert.equal(r.status, 2, flags.join(' '));
    assert.match(r.stderr, message, flags.join(' '));
  }
  const accepted = run(['scripts/train-governance-mapping-lora.py', '--data', file, '--check-only', '--thermal-trigger-c', '74', '--thermal-target-c', '60',
    '--thermal-max-wait-seconds', '0']);
  assert.equal(accepted.status, 2, 'flags accepted; the empty data file is refused by admission instead');
  assert.equal(accepted.stderr, '');
  assert.equal(JSON.parse(accepted.stdout.trim()).admitted, false);

  const base = join(f.dir, 'base');
  mkdirSync(base);
  writeFileSync(join(base, 'artifact-lock.json'), '{}');
  const code = `
import importlib.util, json, sys
from pathlib import Path
from types import SimpleNamespace
spec = importlib.util.spec_from_file_location("t", "scripts/train-governance-mapping-lora.py")
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
args = SimpleNamespace(base_revision="a" * 40, data=sys.argv[1], gpu_memory_fraction=0.65, shakedown=False)
print(json.dumps({"identity": t.identity_for(args, Path(sys.argv[2])), "recipe": t.RECIPE, "defaults": t.THERMAL_PACING}))
`;
  const r = run(['-c', code, file, base]);
  assert.equal(r.status, 0, r.stderr);
  const {identity, recipe, defaults} = JSON.parse(r.stdout.trim().split('\n').at(-1));
  const sha = path => createHash('sha256').update(readFileSync(path)).digest('hex');
  assert.equal(identity.thermalHelperSha256, sha('scripts/public-qa-thermal.py'));
  assert.equal(identity.kbitHelperSha256, sha('scripts/public-qa-kbit.py'));
  // Pacing only sleeps: its settings are not part of the identity (like --pause-ratio), so they may differ between resumes.
  assert.ok(!Object.keys(identity).some(k => /thermal(?!HelperSha256)|pause/i.test(k)));
  for (const [k, v] of Object.entries(recipe)) assert.deepEqual(identity[k], v);
  assert.deepEqual(defaults, {triggerC: 68, targetC: 63, maxWaitSeconds: 300, pollSeconds: 2});

  const src = readFileSync('scripts/train-governance-mapping-lora.py', 'utf8');
  assert.ok(src.includes('thermal = load_helper("governance_thermal", "public-qa-thermal.py")'));
  assert.ok(src.includes('ThermalPacer(thermal.read_gpu_temperature, args.thermal_trigger_c, args.thermal_target_c, args.thermal_max_wait_seconds'));
  // The wait ends on the same stop flag the SIGTERM handler sets, so docker stop's grace period still sees a saved checkpoint.
  const flag = src.indexOf('stop = {"requested": False}'), pacerAt = src.indexOf('pacer = ThermalPacer(');
  assert.ok(flag > 0 && flag < pacerAt && src.slice(pacerAt, src.indexOf('\n\n', pacerAt)).includes('should_stop=lambda: stop["requested"]'));
  assert.ok(src.includes('signal.signal(signal.SIGTERM, lambda *_: stop.update(requested=True))'));
  // Every micro-batch rests, then paces by temperature (on_substep_end for the first ones, on_step_end for the last); the optimizer
  // step then honours a stop request.
  const restFn = src.slice(src.indexOf('def rest(self, step):'), src.indexOf('def on_substep_end'));
  const sleep = restFn.indexOf('* args.pause_ratio)'), pace = restFn.indexOf('pacer.pace(step)');
  const mark = restFn.indexOf('self.burst_started = time.monotonic()');
  assert.ok(sleep > 0 && sleep < pace && pace < mark, 'rest sleeps, then paces, then restarts the burst clock');
  const substep = src.slice(src.indexOf('def on_substep_end'), src.indexOf('def on_step_end'));
  assert.ok(substep.includes('self.rest(state.global_step)'));
  const callback = src.slice(src.indexOf('def on_step_end'), src.indexOf('def on_save'));
  const rest = callback.indexOf('self.rest(state.global_step)'), stop = callback.indexOf('if stop["requested"]:');
  assert.ok(rest > 0 && rest < stop, 'the step callback rests and paces, then honours a stop request');
  assert.ok(src.slice(src.indexOf('def on_step_begin'), src.indexOf('def rest(self, step):')).includes('self.burst_started = time.monotonic()'));
  assert.match(src, /"totalSeconds": round\(time\.monotonic\(\) - started, 1\),\s*"thermalPacing": pacer\.summary\(\)\}/);
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

test('batch runner: measures at the runtime context; a prompt leaving less than max_tokens of it fails as the runtime refuses it',
  {skip: process.platform === 'win32'}, () => {
  const {numCtx, numPredict} = primaryModelPolicy().generation, f = fixture();
  writeFileSync(f.server + '.long', '');
  runGovernanceMappingCommand(['requests', '--data', dataset, '--variant', 'retrieval', '--out', join(f.dir, 'retrieval.requests.jsonl')]);
  const r = batch(f, 'retrieval', ['--pause-ratio', '0']);
  assert.equal(r.status, 2);
  const receipt = JSON.parse(readFileSync(join(f.dir, 'retrieval.receipt.json'), 'utf8'));
  const outputs = JSON.parse(readFileSync(join(f.dir, 'retrieval.outputs.json'), 'utf8'));
  // The stub reports numCtx - max_tokens prompt tokens (exactly the budget) and one more on every fourth request.
  const over = testRows.filter((_, i) => (i + 1) % 4 === 0).length;
  assert.equal(receipt.server.contextTokens, numCtx);
  assert.deepEqual([receipt.failures, receipt.failureReasons, receipt.truncated], [over, {prompt_budget_exceeded: over}, 0]);
  assert.equal(receipt.usage.maxPromptTokens, numCtx - numPredict + 1);
  assert.equal(Object.values(outputs).filter(o => o === '').length, over);
  const log = readFileSync(f.server + '.log', 'utf8').trim().split('\n').map(l => JSON.parse(l));
  assert.ok(log.every(x => x.argv[x.argv.indexOf('-c') + 1] === String(numCtx)), 'the default --ctx is the runtime context');
});
