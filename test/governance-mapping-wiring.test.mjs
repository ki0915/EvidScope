import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {initialize} from '../scripts/init.mjs';
import {createService} from '../src/service.mjs';
import {runAssistance} from '../src/assistance-runner.mjs';
import {createPrimaryInference} from '../src/isolated-inference-client.mjs';
import {primaryModelPolicy} from '../src/model-policy.mjs';
import {governanceModelStatus, provenanceOf} from '../src/governance-model.mjs';
import {CONTAINER, TRAINER_FILES, createDockerTrainingLauncher, dockerCreateArgs, isolationProblems, trainingSpec} from '../src/governance-training.mjs';
import {COOLING, latestSealedCheckpoint, runGovernanceTraining} from '../scripts/governance-mapping-train.mjs';

// Governance-mapping tests see only the shipped source tables; a local-only (KOGL) table on this machine must not change them.
process.env.EVIDSCOPE_GOVERNANCE_LOCAL_TABLES ??= '.test-runs/no-local-tables';

const model = primaryModelPolicy().model;
const evaluation = {version: 2, status: 'evaluated', authority: 'matched_at_event_time', findings: [], coverage: {totalFindings: 0, truncated: false}};

function service(t, governanceModel) {
  mkdirSync('.test-runs', {recursive: true});
  const dir = mkdtempSync(resolve('.test-runs/governance-wiring-')), config = initialize(dir);
  const s = createService({dataDir: join(dir, 'data'), config, key: readFileSync(join(dir, 'signing-private.pem'), 'utf8'),
    requirements: JSON.parse(readFileSync('data/requirements.json', 'utf8')), governanceModel});
  t.after(() => s.store.close());
  const token = id => config.principals.find(p => p.id === id).token;
  const call = async (id, method, path, body) => s.handle(method, new URL('http://localhost' + path), {authorization: 'Bearer ' + token(id)},
    body === undefined ? '' : JSON.stringify(body));
  const now = new Date().toISOString();
  const base = {tenant: 'alpha', actor: 'agent', actionId: 'gm', traceId: 'gm', receivedAt: now, occurredAt: now, policyVersion: 'p1'};
  s.store.transaction(() => {
    for (const event of [{...base, id: 'gma', source: 'alpha-agent', sourceKind: 'agent', kind: 'intent', fingerprint: 'gma',
      assurance: 'authenticated_self_report'},
      {...base, id: 'gmt', source: 'alpha-tool', sourceKind: 'tool', kind: 'execution', fingerprint: 'gmt', assurance: 'authenticated_service_record'}]) {
      const record = s.store.append('alpha', 'event', event, event.source);
      s.store.project({...event, seq: record.seq, hash: record.hash});
    }
    s.store.db.prepare('INSERT INTO actions VALUES(?,?,?,?)').run('alpha', 'gm', 2, 2);
    const e = {...evaluation, actionId: 'gm', id: 'evaluation-gm'};
    s.store.append('alpha', 'evaluation', e, 'worker');
    s.store.db.prepare('INSERT INTO evaluations(tenant,action_id,version,body) VALUES(?,?,?,?)').run('alpha', 'gm', 2, JSON.stringify(e));
  });
  return {s, call};
}
async function preparedPackage(call, mappingInput) {
  const c = await call('alpha-reviewer', 'POST', '/api/cases', {title: 'governance mapping', actionId: 'gm', owner: 'reviewer'});
  const context = await call('alpha-reviewer', 'GET', `/api/cases/${c.id}/review-context`);
  const profile = (await call('alpha-reviewer', 'GET', '/api/assistance/profiles')).items.find(p => p.id === 'governance-assistant');
  const request = {caseId: c.id, contextHash: context.contextHash, profileId: 'governance-assistant', profileVersion: profile.version,
    selectedEvidenceRefs: ['alpha-tool/gmt'], ...(mappingInput ? {mappingInput} : {})};
  return {request, context};
}
const text = '에이전트 게이트웨이가 모든 도구 호출을 자동으로 서명 원장에 기록하며, 기록 기능을 끄는 설정이 없다.';

test('model off: a mapping input is refused and the console status says why', async t => {
  const {call} = service(t, () => governanceModelStatus());
  const {request} = await preparedPackage(call, {kind: 'document_excerpt', text});
  await assert.rejects(call('alpha-reviewer', 'POST', '/api/assistance/packages', request), e => e.status === 409 && /꺼져/.test(e.message));
  await assert.rejects(call('alpha-reviewer', 'POST', '/api/assistance/packages', {...request, mappingInput: {kind: 'structured', text}}),
    e => e.status === 400);
  const runtime = await call('alpha-auditor', 'GET', '/api/model-runtime');
  assert.equal(runtime.governanceModel.mode, 'off');
  assert.deepEqual(runtime.governanceModel.reasons, ['no_measured_report']);
  assert.equal(runtime.governanceModel.humanConfirmationRequired, true);
});

test('base mode: package freezes provenance, runner sends the constrained request, a second person confirms', async t => {
  const status = {...governanceModelStatus(), mode: 'base_retrieval_constrained', reasons: [], evaluation: {reportSha256: 'f'.repeat(64)}};
  const {s, call} = service(t, () => status);
  const {request} = await preparedPackage(call, {kind: 'document_excerpt', text});
  await assert.rejects(call('alpha-reviewer', 'POST', '/api/assistance/packages', {...request, profileId: 'evidence-organizer', profileVersion: 2}),
    e => e.status === 400);
  const pkg = await call('alpha-reviewer', 'POST', '/api/assistance/packages', request);
  const task = pkg.governanceSnapshot.mappingTask;
  assert.deepEqual([task.mode, task.variant, task.adapter], ['base_retrieval_constrained', 'retrieval_constrained', false]);
  assert.deepEqual(task.item.locators, ['evidence:alpha-tool/gmt']);
  assert.deepEqual(task.provenance, provenanceOf(status));
  const dispatched = await call('alpha-reviewer', 'POST', `/api/assistance/packages/${pkg.id}/dispatch`, {contextHash: pkg.contextHash});
  const originalFetch = globalThis.fetch, requests = [];
  globalThis.fetch = async (url, options = {}) => {
    const u = new URL(url);
    try {
      const body = await s.handle(options.method || 'GET', u, {authorization: options.headers.authorization}, options.body || '');
      return new Response(JSON.stringify(body), {status: 200});
    } catch (error) { return new Response(JSON.stringify({error: error.message}), {status: error.status || 500}); }
  };
  const infer = async q => {
    requests.push(q);
    return {content: JSON.stringify({abstain: false, mappings: [
      {requirementId: 'EU-AIA-12-1', relation: 'supports', evidenceLocator: 'evidence:alpha-tool/gmt', confidence: 'high'},
      {requirementId: 'ISMS-P-2.9.4', relation: 'supports', evidenceLocator: 'evidence:alpha-tool/gmt', confidence: 'medium'}]}),
    providerReport: {model, modelDigest: null, quantizationLevel: null, inputTokens: 1, outputTokens: 1, totalDurationNs: 1}};
  };
  try {
    const submitted = await runAssistance({credential: dispatched.credential, baseUrl: 'http://127.0.0.1:9', infer});
    assert.equal(submitted.state, 'completed');
  } finally { globalThis.fetch = originalFetch; }
  assert.equal(requests.length, 1);
  assert.equal(requests[0].adapter, false);
  assert.deepEqual(requests[0].schema.properties.mappings.items.properties.evidenceLocator.enum, ['evidence:alpha-tool/gmt']);
  const run = await call('alpha-reviewer', 'GET', `/api/assistance/runs/${dispatched.run.id}`);
  assert.equal(run.draft.mappings.length, 2);
  assert.ok(run.draft.mappings.every(m => m.provenance.source === 'model' && m.provenance.modelSha256 === status.model.ggufSha256));
  assert.equal(run.draft.findings.length, 0);
  const review = (who, body) => call(who, 'POST', `/api/assistance/runs/${run.id}/review`, {contextHash: run.contextHash, ...body});
  await assert.rejects(review('alpha-reviewer', {action: 'accept'}), e => e.status === 403);
  const forged = {...run.draft, mappings: [{...run.draft.mappings[0], requirementId: 'KR-33'}]};
  delete forged.fixture;
  const draftOnly = d => Object.fromEntries(['summary', 'findings', 'uncertainties', 'limitations', 'recommendedFollowUps', 'abstained', 'mappings']
    .map(k => [k, d[k]]));
  await assert.rejects(review('alpha-admin', {action: 'accept', editedDraft: draftOnly(forged)}), e => e.status === 400);
  const accepted = await review('alpha-admin', {action: 'accept', editedDraft: draftOnly({...run.draft, mappings: [run.draft.mappings[1]]})});
  assert.deepEqual(accepted.draft.mappings.map(m => m.requirementId), ['ISMS-P-2.9.4']);
});

test('runner fails the run on an invalid model output instead of repairing it', async t => {
  const status = {...governanceModelStatus(), mode: 'base_retrieval_constrained', reasons: []};
  const {s, call} = service(t, () => status);
  const {request} = await preparedPackage(call, {kind: 'finding_note', text});
  const pkg = await call('alpha-reviewer', 'POST', '/api/assistance/packages', request);
  const dispatched = await call('alpha-reviewer', 'POST', `/api/assistance/packages/${pkg.id}/dispatch`, {contextHash: pkg.contextHash});
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options = {}) => {
    const headers = {authorization: options.headers.authorization};
    try { return new Response(JSON.stringify(await s.handle(options.method || 'GET', new URL(url), headers, options.body || '')));
    } catch (error) { return new Response(JSON.stringify({error: error.message}), {status: error.status || 500}); }
  };
  try {
    const result = await runAssistance({credential: dispatched.credential, baseUrl: 'http://127.0.0.1:9', infer: async () => ({
      content: JSON.stringify({abstain: false, mappings: [{requirementId: 'EU-AIA-99', relation: 'supports', evidenceLocator: 'evidence:alpha-tool/gmt',
        confidence: 'high'}]}), providerReport: {model, modelDigest: null, quantizationLevel: null, inputTokens: 1, outputTokens: 1, totalDurationNs: 1}})});
    assert.equal(result.state, 'failed');
  } finally { globalThis.fetch = originalFetch; }
  const run = await call('alpha-reviewer', 'GET', `/api/assistance/runs/${dispatched.run.id}`);
  assert.equal(run.errorCode, 'model_mapping_output_invalid');
});

test('inference client asks for the loaded adapter only when told to', async () => {
  const calls = [];
  const transport = async (m, path, payload) => {
    calls.push(payload);
    if (path === '/apply-template') return {prompt: 'p'};
    if (path === '/tokenize') return {tokens: [1, 2]};
    return {model, choices: [{message: {content: '{}'}, finish_reason: 'stop'}], usage: {prompt_tokens: 2, completion_tokens: 1}};
  };
  const infer = createPrimaryInference(undefined, {transport}), messages = [{role: 'system', content: 's'}, {role: 'user', content: 'u'}];
  await infer({messages, schema: {type: 'object'}});
  assert.equal(calls[2].lora, undefined);
  await infer({messages, schema: {type: 'object'}, adapter: true});
  assert.deepEqual(calls[5].lora, [{id: 0, scale: 1}]);
});

function trainingFixture() {
  mkdirSync('.test-runs', {recursive: true});
  const dir = mkdtempSync(resolve('.test-runs/governance-train-')), base = join(dir, 'base'), work = join(dir, 'work'), checkpoints = join(dir, 'ckpt');
  for (const d of [base, work, checkpoints]) mkdirSync(d);
  writeFileSync(join(base, 'artifact-lock.json'), JSON.stringify({repository: 'fdtn-ai/Foundation-Sec-1.1-8B-Instruct', revision: 'a'.repeat(40), files: []}));
  writeFileSync(join(dir, 'train.jsonl'), '{}\n');
  return {image: 'sha256:' + 'b'.repeat(64), baseDir: base, baseRevision: 'a'.repeat(40), dataFile: join(dir, 'train.jsonl'), checkpointsDir: checkpoints,
    scriptsDir: resolve('scripts'), workDir: work};
}
const NAME = 'evidscope-governance-train-00000000-0000-0000-0000-000000000000';
function inspected(spec, change = x => x) {
  const mount = (source, target, rw = false) => ({Type: 'bind', Source: source, Destination: target, RW: rw, Propagation: 'rprivate'});
  return change({Image: spec.image, Config: {User: CONTAINER.user, Image: spec.image}, Mounts: [mount(spec.baseDir, CONTAINER.base),
    mount(spec.dataFile, CONTAINER.data), mount(join(spec.workDir, 'podinfo'), CONTAINER.podinfo), mount(spec.checkpointsDir, CONTAINER.checkpoints, true),
    ...TRAINER_FILES.map(f => mount(join(spec.scriptsDir, f), `${CONTAINER.app}/${f}`))],
  HostConfig: {NetworkMode: 'none', ReadonlyRootfs: true, Privileged: false, CapDrop: ['ALL'], CapAdd: null, SecurityOpt: ['no-new-privileges'],
    Memory: CONTAINER.memory, MemorySwap: CONTAINER.memory, PidsLimit: CONTAINER.pids, NanoCpus: CONTAINER.nanoCpus, IpcMode: 'private', PidMode: '',
    UTSMode: '', Devices: [], DeviceRequests: [{DeviceIDs: ['0'], Capabilities: [['gpu']]}], Tmpfs: {'/tmp': 'rw,nosuid,nodev,size=2g'}}});
}

test('training launcher: offline, read-only container verified before start; stop removes only that container', async () => {
  const spec = trainingSpec(trainingFixture());
  assert.throws(() => trainingSpec({...trainingFixture(), image: 'evidscope/qlora-training:latest'}), /training_image_digest_required/);
  assert.throws(() => trainingSpec({...trainingFixture(), gpuMemoryFraction: 0.9}), /gpu_memory_fraction_invalid/);
  const args = dockerCreateArgs(spec, NAME);
  for (const flag of [['--network', 'none'], ['--cap-drop', 'ALL'], ['--security-opt', 'no-new-privileges'], ['--user', CONTAINER.user]]) {
    assert.equal(args[args.indexOf(flag[0]) + 1], flag[1]);
  }
  assert.ok(args.includes('--read-only') && args.includes(`EVIDSCOPE_DATASET_SHA256=${spec.datasetSha256}`));
  assert.equal(args.filter(a => a.startsWith('type=bind') && !a.endsWith(',readonly')).length, 1);
  assert.deepEqual(isolationProblems(inspected(spec), spec), []);
  assert.ok(isolationProblems(inspected(spec, x => { x.HostConfig.NetworkMode = 'bridge'; return x; }), spec).includes('network_not_none'));
  assert.ok(isolationProblems(inspected(spec, x => { x.Mounts[0].RW = true; return x; }), spec).includes(`mount_unexpected:${CONTAINER.base}`));
  assert.ok(isolationProblems(inspected(spec, x => { x.Mounts.push({Type: 'bind', Destination: '/host', RW: true}); return x; }), spec)
    .includes('mount_set_unexpected'));

  const docker = (info, log) => (program, a) => {
    log.push(a.slice(0, 2).join(' '));
    if (a[0] === 'create') return 'e'.repeat(64) + '\n';
    if (a[0] === 'inspect') { if (log.includes('rm ' + 'e'.repeat(64))) throw Error('No such object'); return JSON.stringify([info()]); }
    return '';
  };
  const badLog = [], bad = createDockerTrainingLauncher({spec, execute: docker(() => inspected(spec, x => { x.HostConfig.ReadonlyRootfs = false; return x; }),
    badLog), newName: () => NAME});
  await assert.rejects(bad.start(), /container_isolation_unverified: root_filesystem_writable/);
  assert.ok(badLog.includes('rm --force') && !badLog.some(x => x.startsWith('start')));

  let state = 'running';
  const log = [], logs = id => `trainer output of ${id}\n`;
  const launcher = createDockerTrainingLauncher({spec, newName: () => NAME, logs, execute: docker(() => ({...inspected(spec),
    State: {Running: state === 'running', Status: state === 'running' ? 'running' : 'exited', ExitCode: 0}}), log)});
  const workload = await launcher.start();
  assert.equal(workload.isolation, 'verified_before_start');
  assert.equal(readFileSync(join(spec.workDir, 'podinfo', 'uid'), 'utf8').trim(), NAME);
  assert.deepEqual(await launcher.observe(workload), {state: 'running'});
  state = 'exited';
  assert.equal((await launcher.observe(workload)).state, 'succeeded');
  await launcher.stop(workload);
  assert.equal(readFileSync(join(spec.workDir, `${NAME}.log`), 'utf8'), `trainer output of ${'e'.repeat(64)}\n`);
  assert.deepEqual(await launcher.observe(workload), {state: 'absent', terminationConfirmed: true});
  assert.deepEqual(log.filter(x => /^(create|start|stop|rm)/.test(x)), ['create --name', 'start ' + 'e'.repeat(64), 'stop --time', 'rm ' + 'e'.repeat(64)]);
  const check = await runGovernanceTraining(['--image', spec.image, '--base-dir', spec.baseDir, '--base-revision', spec.baseRevision, '--data', spec.dataFile,
    '--checkpoints-dir', spec.checkpointsDir, '--work-dir', spec.workDir, '--check-only'], {probe: async () => { throw Error('no host'); }});
  assert.deepEqual(check.decision, {allowed: false, reasons: ['host_resource_probe_unavailable']});
  assert.equal(check.dockerArgs[0], 'create');
  assert.equal(check.policy, 'active_use');
  const idle = await runGovernanceTraining(['--image', spec.image, '--base-dir', spec.baseDir, '--base-revision', spec.baseRevision, '--data', spec.dataFile,
    '--checkpoints-dir', spec.checkpointsDir, '--work-dir', spec.workDir, '--check-only', '--idle-only'], {probe: async () => { throw Error('no host'); }});
  assert.equal(idle.policy, 'idle_only');
});

test('training runner: a run stopped for GPU heat resumes from its newest sealed checkpoint once the GPU cools; idle-only does not', async () => {
  const spec = trainingSpec(trainingFixture()), run = join(spec.checkpointsDir, 'governance-mapping', 'run');
  assert.equal(latestSealedCheckpoint(spec), null);
  for (const [step, sealed] of [[5, true], [40, true], [45, false]]) {
    mkdirSync(join(run, `checkpoint-${step}`), {recursive: true});
    if (sealed) writeFileSync(join(run, `checkpoint-${step}`, 'checkpoint-complete.json'), '{}');
  }
  assert.equal(latestSealedCheckpoint(spec), 'governance-mapping/run/checkpoint-40');
  const argv = ['--image', spec.image, '--base-dir', spec.baseDir, '--base-revision', spec.baseRevision, '--data', spec.dataFile,
    '--checkpoints-dir', spec.checkpointsDir, '--work-dir', spec.workDir];
  const heat = {state: 'stopped_for_host_activity', reason: 'gpu_temperature_high', reasons: ['gpu_temperature_high'], terminationConfirmed: true};
  const temps = [82, 70, 65], waits = [], launched = [];
  const results = [heat, {state: 'stopped', reason: 'completed', terminationConfirmed: true}];
  const deps = {probe: async () => ({gpu: {temperatureC: temps.shift()}}), wait: async ms => { waits.push(ms); },
    launcherFor: ({spec: s}) => { launched.push(s.resumeCheckpoint); return {}; }, guardFor: () => ({run: async () => results.shift()})};
  const out = await runGovernanceTraining(argv, deps);
  assert.equal(out.result.reason, 'completed');
  assert.deepEqual(out.resumedAfter, ['gpu_temperature_high']);
  assert.deepEqual(launched, [null, 'governance-mapping/run/checkpoint-40']);
  assert.deepEqual(waits, [COOLING.pollMs, COOLING.pollMs]);

  const idleLaunched = [], idle = await runGovernanceTraining([...argv, '--idle-only'], {...deps, guardFor: () => ({run: async () => heat}),
    launcherFor: ({spec: s}) => { idleLaunched.push(s.resumeCheckpoint); return {}; }});
  assert.equal(idle.result.reason, 'gpu_temperature_high');
  assert.deepEqual(idleLaunched, [null]);
  let tries = 0;
  const capped = await runGovernanceTraining(argv, {...deps, probe: async () => ({gpu: {temperatureC: 60}}),
    guardFor: () => ({run: async () => { tries++; return heat; }})});
  assert.equal(capped.resumedAfter.length, COOLING.maxResumes);
  assert.equal(tries, COOLING.maxResumes + 1);
});
