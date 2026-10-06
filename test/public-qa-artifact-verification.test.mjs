import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, statSync, rmSync, symlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {verifyPublicQaArtifact} from '../scripts/verify-public-qa-artifact.mjs';
import {QA_BASE_REVISION, QA_IMAGE, QA_NAMESPACE} from '../scripts/public-qa-workload.mjs';

const sha = value => createHash('sha256').update(value).digest('hex');
const write = (path, value) => writeFileSync(path, JSON.stringify(value));
function fixture(t, {stageTwo = false} = {}) {
  const steps = stageTwo ? 40 : 20, stage = stageTwo ? 'public_qa_stage2' : 'public_qa_stage1';
  const root = mkdtempSync(join(tmpdir(), 'public-qa-verify-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  const run = join(root, 'run'), candidate = join(run, 'candidate');
  mkdirSync(candidate, {recursive: true});
  writeFileSync(join(root, 'data.jsonl'), '{"originalAnswer":"답"}\n');
  const datasetSha256 = sha(readFileSync(join(root, 'data.jsonl')));
  write(join(root, 'manifest.json'), {datasetSha256, counts: {train: 320, validation: 64}, heldoutUsed: false, stage: 'public_qa_stage1', license: 'CC-BY-SA-4.0', upstreamRevision: '3efd98708a40ff49251fddde35453f8fbb11f536'});
  write(join(root, 'lock.json'), {repository: 'fdtn-ai/Foundation-Sec-8B-Reasoning', revision: QA_BASE_REVISION});
  const codeData = {'train-public-qa.py': 'trainer', 'training_artifacts.py': 'artifact', 'train-foundation-lora.py': 'binding', 'resource-pilot.py': 'pilot'};
  const runtimeSha256 = sha(JSON.stringify(codeData)), runtimeConfigMap = `public-qa-runtime-${runtimeSha256.slice(0, 16)}`;
  write(join(root, 'runtime-configmap.json'), {kind: 'ConfigMap', immutable: true, metadata: {name: runtimeConfigMap, annotations: {'evidscope.io/code-sha256': runtimeSha256}}, data: codeData});
  const inputs = {data: 'data.jsonl', manifest: 'manifest.json', lock: 'lock.json', datasetSha256,
    manifestSha256: sha(readFileSync(join(root, 'manifest.json'))), artifactLockSha256: sha(readFileSync(join(root, 'lock.json'))), runtimeSha256, runtimeConfigMap,
    runtimeFiles: Object.fromEntries(Object.entries(codeData).map(([name, value]) => [name, sha(value)]))};
  const identity = {baseRepository: 'fdtn-ai/Foundation-Sec-8B-Reasoning', baseRevision: QA_BASE_REVISION, image: QA_IMAGE,
    datasetSha256, manifestSha256: inputs.manifestSha256, baseArtifactLockSha256: inputs.artifactLockSha256,
    trainerSha256: sha('trainer'), artifactHelperSha256: sha('artifact'), bindingHelperSha256: sha('binding'),
    stage, rank: 8, sequenceLength: 1024, batchSize: 1, gradientAccumulationSteps: 16,
    seed: 42, learningRate: 0.0001, maxSteps: steps, gpuMemoryFraction: 0.65};
  const runId = stageTwo ? 'public-qa-stage2-test' : 'public-qa-test', spec = {volumes: [{name: 'runtime', configMap: {name: runtimeConfigMap}}], containers: [{image: QA_IMAGE,
    command: ['python', '/runtime/train-public-qa.py'], args: ['--max-steps', String(steps), '--output', `/checkpoints/runs/${runId}`, '--base-revision', QA_BASE_REVISION],
    volumeMounts: [{name: 'runtime', mountPath: '/runtime', readOnly: true}], env: Object.entries({EVIDSCOPE_TRAINING_IMAGE: QA_IMAGE, EVIDSCOPE_DATASET_SHA256: datasetSha256,
      EVIDSCOPE_BASE_REVISION: QA_BASE_REVISION, EVIDSCOPE_BASE_ARTIFACT_LOCK_SHA256: inputs.artifactLockSha256}).map(([name, value]) => ({name, value}))}]};
  const manifest = {metadata: {name: runId}, spec: {template: {spec}}};
  const controller = {schemaVersion: 1, mode: `explicit_${stage.replace('public_qa', 'public_human_qa')}`, state: 'process_completed', exit: {exitCode: 0},
    terminationConfirmed: true, admission: {allowed: true}, qualityClaimAllowed: false, automaticGovernanceGateClaimed: false,
    jobUid: 'job-uid', podUid: 'pod-uid', inputs, runId, manifest, manifestSha256: sha(JSON.stringify(manifest)), livePodSpec: spec};
  const controllerPath = join(root, 'controller-receipt.json');
  write(controllerPath, controller);
  const logPath = join(root, 'training.log');
  const optimizerRecords = Array.from({length: steps}, (_, index) => ({optimizerStep: index + 1, actualOptimizerUpdates: index + 1, skippedOptimizerUpdates: 0, cudaPeakAllocatedBytes: 6_000_000_000, cudaPeakReservedBytes: 7_000_000_000}));
  const writeLog = (records = optimizerRecords) => writeFileSync(logPath, '{"baseValidationLoss":1.5}\n\r  0%|          | 0/20 [00:00<?, ?it/s]' + records.map(record => JSON.stringify(record)).join('\n') + '\n');
  writeLog();
  const metrics = {train_loss: 1.2, eval_loss: 1.3, base_eval_loss: 1.5}, receipt = {schemaVersion: 2, status: `trained_${stage}`, globalStep: steps, identity,
    trainingRunCompleted: true, qualityClaimAllowed: false, promotionAllowed: false, heldOutTestUsedForTraining: false,
    localHumanReviewPerformed: false, sourceLicense: 'CC-BY-SA-4.0', targetFormat: 'exact_human_answer_json_without_generated_reasoning', trainingMetrics: metrics};
  write(join(candidate, 'adapter_config.json'), {r: 8});
  writeFileSync(join(candidate, 'adapter_model.safetensors'), 'test fixture bytes, not trained weights');
  const seal = () => {
    write(join(candidate, 'training-receipt.json'), receipt);
    const files = readdirSync(candidate).filter(name => name !== 'candidate-complete.json').sort().map(path => ({path, bytes: statSync(join(candidate, path)).size, sha256: sha(readFileSync(join(candidate, path)))}));
    write(join(candidate, 'candidate-complete.json'), {schemaVersion: 1, globalStep: steps, identity, metrics, files});
  };
  seal();
  return {root, run, candidate, controller, controllerPath, receipt, seal, optimizerRecords, writeLog, logPath,
    verify: () => verifyPublicQaArtifact({runDirectory: run, controllerReceipt: controllerPath, workspace: root})};
}

function resumedFixture(t) {
  const f = fixture(t), sourceRunId = 'public-qa-stage1-20260922-r2';
  const sourceIdentity = {...f.receipt.identity, trainerSha256: sha('previous trainer'), artifactHelperSha256: sha('previous helper')};
  const checkpoint = join(f.root, '.local/training/runs', sourceRunId, 'checkpoint-5');
  mkdirSync(checkpoint, {recursive: true});
  for (const name of ['adapter_config.json', 'adapter_model.safetensors', 'optimizer.pt', 'scheduler.pt', 'rng_state.pth', 'scaler.pt', 'training_args.bin']) writeFileSync(join(checkpoint, name), `parent fixture ${name}`);
  write(join(checkpoint, 'trainer_state.json'), {global_step: 5});
  const parentFiles = readdirSync(checkpoint).sort().map(path => ({path, bytes: statSync(join(checkpoint, path)).size, sha256: sha(readFileSync(join(checkpoint, path)))}));
  const markerPath = join(checkpoint, 'checkpoint-complete.json');
  write(markerPath, {schemaVersion: 1, identity: sourceIdentity, globalStep: 5, files: parentFiles});
  const provenance = {schemaVersion: 1, sourceRunId, sourceGlobalStep: 5, sourceIdentity,
    targetIdentity: structuredClone(f.receipt.identity), sourceCheckpointMarkerSha256: sha(readFileSync(markerPath)),
    allowedCodeChanges: Object.fromEntries(['trainerSha256', 'artifactHelperSha256'].map(field => [field, {from: sourceIdentity[field], to: f.receipt.identity[field]}]))};
  mkdirSync(join(f.root, 'reports'));
  const evidencePath = join(f.root, 'reports/public-qa-interrupted-checkpoint-20260922.json');
  const adapter = parentFiles.find(file => file.path === 'adapter_model.safetensors');
  const evidence = {verified: true, globalStep: 5, sourceRun: sourceRunId, weightUpdatesPresent: true, allLoraBTensorsFinite: true,
    adapterSha256: adapter.sha256, adapterBytes: adapter.bytes,
    optimizerStateVerification: {verified: true, gpuUsed: false, stateCount: 256, allActualAdamSteps: 5}};
  write(evidencePath, evidence);
  const codePath = join(f.root, 'runtime-configmap.json'), code = JSON.parse(readFileSync(codePath));
  code.data['public_qa_resume.py'] = 'resume helper';
  const runtimeSha256 = sha(JSON.stringify(code.data)), runtimeConfigMap = `public-qa-runtime-${runtimeSha256.slice(0, 16)}`;
  code.metadata.name = runtimeConfigMap; code.metadata.annotations['evidscope.io/code-sha256'] = runtimeSha256; write(codePath, code);
  Object.assign(f.controller.inputs, {runtimeSha256, runtimeConfigMap, runtimeFiles: Object.fromEntries(Object.entries(code.data).map(([name, value]) => [name, sha(value)]))});
  const spec = f.controller.livePodSpec, container = spec.containers[0];
  spec.volumes[0].configMap.name = runtimeConfigMap;
  container.args.push('--resume-from-checkpoint', `/checkpoints/runs/${sourceRunId}/checkpoint-5`, '--resume-provenance', '/resume/provenance.json');
  container.volumeMounts.push({name: 'resume-provenance', mountPath: '/resume', readOnly: true});
  spec.volumes.push({name: 'resume-provenance', configMap: {name: ''}});
  container.env.push({name: 'EVIDSCOPE_RESUME_PROVENANCE_SHA256', value: ''});
  const syncProvenance = () => {
    write(join(f.root, 'provenance.json'), provenance);
    const hash = sha(readFileSync(join(f.root, 'provenance.json')));
    f.controller.inputs.resumeProvenance = {value: provenance, localPath: 'provenance.json', sha256: hash};
    write(join(f.root, 'resume-configmap.json'), {apiVersion: 'v1', kind: 'ConfigMap', immutable: true,
      metadata: {name: `public-qa-resume-${hash.slice(0, 16)}`, namespace: QA_NAMESPACE}, data: {'provenance.json': readFileSync(join(f.root, 'provenance.json'), 'utf8')}});
    spec.volumes.at(-1).configMap.name = `public-qa-resume-${hash.slice(0, 16)}`;
    container.env.at(-1).value = hash;
    f.receipt.resumeLineage = {provenanceSha256: hash, sourceRunId: provenance.sourceRunId, sourceGlobalStep: provenance.sourceGlobalStep,
      sourceCheckpointMarkerSha256: provenance.sourceCheckpointMarkerSha256, sourceIdentity: provenance.sourceIdentity};
    f.controller.manifestSha256 = sha(JSON.stringify(f.controller.manifest));
    write(f.controllerPath, f.controller); f.seal();
  };
  const writeLog = (records = f.optimizerRecords.slice(5)) => {
    f.writeLog(records);
    writeFileSync(f.logPath, JSON.stringify({resumedGlobalStep: 5, optimizerStateCount: 256, schedulerLastEpoch: 5}) + '\n'
      + JSON.stringify({resumeRngStateLoaded: `/checkpoints/runs/${sourceRunId}/checkpoint-5`}) + '\n' + readFileSync(f.logPath, 'utf8'));
  };
  syncProvenance(); writeLog();
  return {...f, writeLog, provenance, checkpoint, markerPath, evidencePath, evidence, syncProvenance};
}

function stageTwoFixture(t) {
  const f = fixture(t, {stageTwo: true}), sourceRunId = 'public-qa-resume-20260928-r1';
  const sourceIdentity = {...f.receipt.identity, stage: 'public_qa_stage1', maxSteps: 20, trainerSha256: sha('old trainer')};
  const sourceData = {'train-public-qa.py': 'old trainer', 'training_artifacts.py': 'artifact', 'train-foundation-lora.py': 'binding',
    'resource-pilot.py': 'old pilot', 'public_qa_resume.py': 'old resume'};
  const targetData = {...sourceData, 'train-public-qa.py': 'trainer', 'resource-pilot.py': 'new pilot', 'public_qa_resume.py': 'new resume'};
  const code = data => {const hash = sha(JSON.stringify(data)); return {kind: 'ConfigMap', immutable: true,
    metadata: {name: `public-qa-runtime-${hash.slice(0, 16)}`, annotations: {'evidscope.io/code-sha256': hash}}, data};};
  const sourceCode = code(sourceData), targetCode = code(targetData);
  const sourceRoot = join(f.root, '.local/training/public-qa-run', sourceRunId); mkdirSync(sourceRoot, {recursive: true});
  write(join(sourceRoot, 'runtime-configmap.json'), sourceCode); write(join(f.root, 'runtime-configmap.json'), targetCode);
  const hashes = data => Object.fromEntries(Object.entries(data).map(([name, value]) => [name, sha(value)]));
  Object.assign(f.controller.inputs, {runtimeSha256: sha(JSON.stringify(targetData)), runtimeConfigMap: targetCode.metadata.name, runtimeFiles: hashes(targetData)});
  const checkpoint = join(f.root, '.local/training/runs', sourceRunId, 'checkpoint-20');
  const sealCheckpoint = (path, identity, step, adapterBytes = step === 40 ? readFileSync(join(f.candidate, 'adapter_model.safetensors')) : undefined) => {
    mkdirSync(path, {recursive: true});
    for (const name of ['adapter_config.json', 'adapter_model.safetensors', 'optimizer.pt', 'scheduler.pt', 'rng_state.pth', 'scaler.pt', 'training_args.bin']) writeFileSync(join(path, name), name === 'adapter_model.safetensors' && adapterBytes !== undefined ? adapterBytes : `checkpoint fixture ${step} ${name}`);
    write(join(path, 'trainer_state.json'), {global_step: step});
    const files = readdirSync(path).filter(name => name !== 'checkpoint-complete.json').sort().map(name => ({path: name, bytes: statSync(join(path, name)).size, sha256: sha(readFileSync(join(path, name)))}));
    write(join(path, 'checkpoint-complete.json'), {schemaVersion: 1, identity, globalStep: step, files});
  };
  sealCheckpoint(checkpoint, sourceIdentity, 20);
  for (const step of [30, 40]) sealCheckpoint(join(f.run, `checkpoint-${step}`), f.receipt.identity, step);
  const provenance = {schemaVersion: 2, sourceRunId, targetRunId: f.controller.runId, sourceGlobalStep: 20, sourceIdentity,
    targetIdentity: structuredClone(f.receipt.identity), sourceCheckpointMarkerSha256: sha(readFileSync(join(checkpoint, 'checkpoint-complete.json'))),
    allowedCodeChanges: {trainerSha256: {from: sourceIdentity.trainerSha256, to: f.receipt.identity.trainerSha256}},
    sourceRuntimeSha256: sha(JSON.stringify(sourceData)), sourceRuntimeFiles: hashes(sourceData), targetRuntimeFiles: hashes(targetData),
    allowedRuntimeCodeChanges: Object.fromEntries(['train-public-qa.py', 'resource-pilot.py', 'public_qa_resume.py'].map(name => [name, {from: sha(sourceData[name]), to: sha(targetData[name])}])),
    extension: {kind: 'bounded_max_steps_extension', fromStage: 'public_qa_stage1', toStage: 'public_qa_stage2', fromMaxSteps: 20, toMaxSteps: 40,
      reason: 'trainer_dynamic_padding_selective_completion_logits_stage2_resume_verifier_and_resource_pilot'}};
  const spec = f.controller.livePodSpec, container = spec.containers[0]; spec.volumes[0].configMap.name = targetCode.metadata.name;
  container.args.push('--resume-from-checkpoint', `/checkpoints/runs/${sourceRunId}/checkpoint-20`, '--resume-provenance', '/resume/provenance.json');
  container.volumeMounts.push({name: 'resume-provenance', mountPath: '/resume', readOnly: true});
  spec.volumes.push({name: 'resume-provenance', configMap: {name: ''}}); container.env.push({name: 'EVIDSCOPE_RESUME_PROVENANCE_SHA256', value: ''});
  const syncProvenance = () => {
    write(join(f.root, 'provenance.json'), provenance); const hash = sha(readFileSync(join(f.root, 'provenance.json')));
    f.controller.inputs.resumeProvenance = {value: provenance, localPath: 'provenance.json', sha256: hash};
    write(join(f.root, 'resume-configmap.json'), {apiVersion: 'v1', kind: 'ConfigMap', immutable: true,
      metadata: {name: `public-qa-resume-${hash.slice(0, 16)}`, namespace: QA_NAMESPACE}, data: {'provenance.json': readFileSync(join(f.root, 'provenance.json'), 'utf8')}});
    spec.volumes.at(-1).configMap.name = `public-qa-resume-${hash.slice(0, 16)}`; container.env.at(-1).value = hash;
    const {targetIdentity, allowedCodeChanges, ...lineage} = provenance;
    f.receipt.resumeLineage = {...lineage, provenanceSha256: hash};
    f.controller.manifestSha256 = sha(JSON.stringify(f.controller.manifest)); write(f.controllerPath, f.controller); f.seal();
  };
  const records = f.optimizerRecords.slice(20).map(record => ({...record, learningRate: record.optimizerStep === 40 ? 0 : 0.00005}));
  const writeLog = (values = records) => {f.writeLog(values); writeFileSync(f.logPath,
    JSON.stringify({resumedGlobalStep: 20, optimizerStateCount: 256, schedulerLastEpoch: 20}) + '\n'
    + JSON.stringify({resumeRngStateLoaded: `/checkpoints/runs/${sourceRunId}/checkpoint-20`}) + '\n' + readFileSync(f.logPath, 'utf8'));};
  syncProvenance(); writeLog();
  return {...f, checkpoint, provenance, syncProvenance, sourceRoot, records, writeLog, sealCheckpoint};
}

test('bound stage1 candidate verifies without claiming quality or promotion', async t => {
  const f = fixture(t), result = await f.verify();
  assert.equal(result.verified, true); assert.equal(result.globalStep, 20);
  assert.equal(result.actualOptimizerUpdates, 20); assert.equal(result.skippedOptimizerUpdates, 0);
  assert.match(result.trainingLogSha256, /^[a-f0-9]{64}$/);
  assert.equal(result.qualityClaimAllowed, false); assert.equal(result.promotionAllowed, false);
});
test('changed adapter bytes or an unlisted file fails exact inventory', async t => {
  const f = fixture(t);
  writeFileSync(join(f.candidate, 'adapter_model.safetensors'), 'tampered');
  await assert.rejects(f.verify(), /candidate_artifact_changed/);
  f.seal(); writeFileSync(join(f.candidate, 'unlisted.txt'), 'extra');
  await assert.rejects(f.verify(), /candidate_artifact_changed/);
});
test('partial or symlinked artifacts cannot be sealed into an acceptable run', async t => {
  const f = fixture(t);
  writeFileSync(join(f.run, 'checkpoint.partial'), 'unfinished');
  await assert.rejects(f.verify(), /artifact_partial_file/);
  rmSync(join(f.run, 'checkpoint.partial'));
  // Directory junctions need no Windows developer-mode symlink privilege.
  const outside = join(f.root, 'outside'); mkdirSync(outside);
  symlinkSync(outside, join(f.run, 'linked'), process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(f.verify(), /artifact_symlink_forbidden/);
});
test('resealed wrong stage, step, or promotion flag still fails', async t => {
  const f = fixture(t);
  for (const [field, value] of [['status', 'trained_candidate'], ['globalStep', 19], ['promotionAllowed', true]]) {
    const previous = f.receipt[field]; f.receipt[field] = value; f.seal();
    await assert.rejects(f.verify(), /candidate_receipt_mismatch/);
    f.receipt[field] = previous;
  }
});
test('successful exit without confirmed cleanup and resource pilots cannot pass', async t => {
  const f = fixture(t);
  f.controller.terminationConfirmed = false; write(f.controllerPath, f.controller);
  await assert.rejects(f.verify(), /controller_execution_not_verified/);
  f.controller.terminationConfirmed = true; f.controller.mode = 'explicit_zero_learning_rate_resource_pilot'; write(f.controllerPath, f.controller);
  await assert.rejects(f.verify(), /controller_execution_not_verified/);
});
test('resealed candidate with another runtime or base is rejected', async t => {
  const f = fixture(t), identity = f.receipt.identity;
  identity.trainerSha256 = 'f'.repeat(64); f.seal();
  await assert.rejects(f.verify(), /candidate_runtime_identity_mismatch/);
  identity.baseRevision = 'f'.repeat(40); f.seal();
  await assert.rejects(f.verify(), /candidate_execution_identity_mismatch/);
});
test('changed original data or runtime sidecar fails execution binding', async t => {
  const f = fixture(t), original = readFileSync(join(f.root, 'data.jsonl'));
  writeFileSync(join(f.root, 'data.jsonl'), 'different data');
  await assert.rejects(f.verify(), /candidate_input_binding_mismatch/);
  writeFileSync(join(f.root, 'data.jsonl'), original);
  const codePath = join(f.root, 'runtime-configmap.json'), code = JSON.parse(readFileSync(codePath));
  code.data['train-public-qa.py'] = 'changed code'; write(codePath, code);
  await assert.rejects(f.verify(), /candidate_runtime_binding_mismatch/);
});
test('step numbers cannot conceal skipped optimizer updates or missing counters', async t => {
  const f = fixture(t);
  for (const change of [record => { record.actualOptimizerUpdates = 19; record.skippedOptimizerUpdates = 1; },
    record => { delete record.actualOptimizerUpdates; }, record => { record.skippedOptimizerUpdates = 1; }]) {
    const records = structuredClone(f.optimizerRecords); change(records.at(-1)); f.writeLog(records);
    await assert.rejects(f.verify(), /actual_optimizer_updates_not_verified/);
  }
});
test('missing, repeated, reordered, malformed, and truncated optimizer records fail', async t => {
  const f = fixture(t);
  for (const records of [f.optimizerRecords.slice(1), [...f.optimizerRecords, f.optimizerRecords.at(-1)],
    [f.optimizerRecords[1], f.optimizerRecords[0], ...f.optimizerRecords.slice(2)]]) {
    f.writeLog(records); await assert.rejects(f.verify(), /actual_optimizer_updates_not_verified/);
  }
  f.writeLog(); writeFileSync(f.logPath, readFileSync(f.logPath, 'utf8') + '{"optimizerStep":');
  await assert.rejects(f.verify(), /optimizer_log_record_invalid/);
});
test('resealed candidate requires a finite baseline evaluation loss', async t => {
  const f = fixture(t);
  delete f.receipt.trainingMetrics.base_eval_loss; f.seal();
  await assert.rejects(f.verify(), /candidate_metrics_invalid/);
  f.receipt.trainingMetrics.base_eval_loss = Infinity; f.seal();
  await assert.rejects(f.verify(), /candidate_metrics_invalid/);
});

test('sealed five-step parent plus fifteen actual resumed updates verifies twenty total', async t => {
  const f = resumedFixture(t), result = await f.verify();
  assert.equal(result.actualOptimizerUpdates, 20); assert.equal(result.optimizerUpdatesThisRun, 15);
  assert.equal(result.resumeLineage.sourceGlobalStep, 5); assert.equal(result.promotionAllowed, false);
});

test('resume rejects provenance byte changes and a false parent marker', async t => {
  const f = resumedFixture(t);
  writeFileSync(join(f.root, 'provenance.json'), 'changed');
  await assert.rejects(f.verify(), /resume_provenance_changed/);
  f.provenance.sourceCheckpointMarkerSha256 = 'f'.repeat(64); f.syncProvenance();
  await assert.rejects(f.verify(), /resume_parent_marker_mismatch/);
});

test('resume rejects unapproved identity changes even with mutually matching receipts', async t => {
  const f = resumedFixture(t);
  f.provenance.sourceIdentity.learningRate = 0.0002; f.syncProvenance();
  await assert.rejects(f.verify(), /resume_unapproved_identity_change/);
  f.provenance.allowedCodeChanges.learningRate = {from: 0.0002, to: 0.0001}; f.syncProvenance();
  await assert.rejects(f.verify(), /resume_code_changes_invalid/);
});

test('resume requires unchanged parent optimizer bytes and verified five Adam updates', async t => {
  const f = resumedFixture(t), optimizerPath = join(f.checkpoint, 'optimizer.pt'), original = readFileSync(optimizerPath);
  writeFileSync(optimizerPath, 'changed optimizer');
  await assert.rejects(f.verify(), /resume_parent_artifact_changed/);
  writeFileSync(optimizerPath, original);
  f.evidence.optimizerStateVerification.allActualAdamSteps = 4; write(f.evidencePath, f.evidence);
  await assert.rejects(f.verify(), /resume_parent_optimizer_updates_not_verified/);
});

test('resume rejects wrong source step, missing updates, skipped updates, and extra records', async t => {
  const f = resumedFixture(t);
  f.provenance.sourceGlobalStep = 4; f.syncProvenance();
  await assert.rejects(f.verify(), /resume_provenance_identity_mismatch/);
  f.provenance.sourceGlobalStep = 5; f.syncProvenance();
  for (const records of [f.optimizerRecords.slice(6), f.optimizerRecords, f.optimizerRecords.slice(5).map(record => ({...record, skippedOptimizerUpdates: 1}))]) {
    f.writeLog(records); await assert.rejects(f.verify(), /actual_optimizer_updates_not_verified/);
  }
});

test('fresh executions cannot conceal resume arguments or a resume lineage', async t => {
  const f = fixture(t);
  f.receipt.resumeLineage = {sourceGlobalStep: 5}; f.seal();
  await assert.rejects(f.verify(), /resume_lineage_without_provenance/);
  delete f.receipt.resumeLineage; f.seal();
  f.controller.livePodSpec.containers[0].args.push('--resume-from-checkpoint', '/arbitrary');
  f.controller.manifestSha256 = sha(JSON.stringify(f.controller.manifest)); write(f.controllerPath, f.controller);
  await assert.rejects(f.verify(), /controller_unverified_resume/);
});

test('resume verifies applied provenance bytes and actual optimizer, scheduler, and RNG restoration', async t => {
  const f = resumedFixture(t), path = join(f.root, 'resume-configmap.json'), original = readFileSync(path);
  const cm = JSON.parse(original); cm.metadata.namespace = 'unrelated'; write(path, cm);
  await assert.rejects(f.verify(), /resume_configmap_binding_mismatch/);
  writeFileSync(path, original);
  const log = readFileSync(f.logPath, 'utf8');
  for (const changed of [log.replace('"optimizerStateCount":256', '"optimizerStateCount":255'),
    log.replace('"schedulerLastEpoch":5', '"schedulerLastEpoch":4'), log.split('\n').filter(line => !line.includes('resumeRngStateLoaded')).join('\n')]) {
    writeFileSync(f.logPath, changed); await assert.rejects(f.verify(), /resume_loaded_state_not_verified/);
  }
});

test('stage2 verifies checkpoint20 lineage, twenty new updates, checkpoint30/40 and candidate', async t => {
  const f = stageTwoFixture(t), result = await f.verify();
  assert.equal(result.globalStep, 40); assert.equal(result.actualOptimizerUpdates, 40);
  assert.equal(result.optimizerUpdatesThisRun, 20); assert.equal(result.resumeLineage.sourceGlobalStep, 20);
  assert.deepEqual(result.checkpoints.map(value => value.globalStep), [30, 40]);
  assert.ok(result.checkpoints.every(value => /^[a-f0-9]{64}$/.test(value.markerSha256)));
  assert.equal(result.qualityClaimAllowed, false); assert.equal(result.promotionAllowed, false);
});

test('stage2 cannot pass as stage1 or without schema2 and exact source and target scope', async t => {
  const f = stageTwoFixture(t);
  f.controller.mode = 'explicit_public_human_qa_stage1'; write(f.controllerPath, f.controller);
  await assert.rejects(f.verify(), /candidate_step_invalid/);
  f.controller.mode = 'explicit_public_human_qa_stage2';
  for (const [field, value] of [['schemaVersion', 1], ['sourceGlobalStep', 19], ['sourceRunId', 'public-qa-other'], ['targetRunId', 'public-qa-stage2-other']]) {
    const old = f.provenance[field]; f.provenance[field] = value; f.syncProvenance();
    await assert.rejects(f.verify(), /resume_provenance_identity_mismatch/); f.provenance[field] = old;
  }
  f.syncProvenance(); delete f.controller.inputs.resumeProvenance; write(f.controllerPath, f.controller);
  await assert.rejects(f.verify(), /stage2_resume_required/);
});

test('stage2 rejects an altered parent checkpoint and incomplete or altered new checkpoints', async t => {
  const f = stageTwoFixture(t), parent = join(f.checkpoint, 'optimizer.pt'), original = readFileSync(parent);
  writeFileSync(parent, 'changed parent state'); await assert.rejects(f.verify(), /resume_parent_artifact_changed/);
  writeFileSync(parent, original);
  for (const step of [30, 40]) {
    const path = join(f.run, `checkpoint-${step}`, 'optimizer.pt'), bytes = readFileSync(path);
    writeFileSync(path, 'changed child state'); await assert.rejects(f.verify(), /resume_parent_artifact_changed/); writeFileSync(path, bytes);
  }
  rmSync(join(f.run, 'checkpoint-30', 'scaler.pt'));
  await assert.rejects(f.verify(), /resume_parent_artifact_changed/);
});

test('stage2 rejects cross-run checkpoint identity and marker step even if resealed', async t => {
  const f = stageTwoFixture(t), path = join(f.run, 'checkpoint-40', 'checkpoint-complete.json'), marker = JSON.parse(readFileSync(path));
  marker.identity = {...marker.identity, datasetSha256: 'f'.repeat(64)}; write(path, marker);
  await assert.rejects(f.verify(), /resume_parent_marker_mismatch/);
  marker.identity = f.receipt.identity; marker.globalStep = 39; write(path, marker);
  await assert.rejects(f.verify(), /resume_parent_marker_mismatch/);
});

test('stage2 rejects a self-consistent checkpoint40 whose adapter differs from the sealed candidate', async t => {
  const f = stageTwoFixture(t);
  f.sealCheckpoint(join(f.run, 'checkpoint-40'), f.receipt.identity, 40, Buffer.from('different final checkpoint adapter'));
  await assert.rejects(f.verify(), /stage2_final_checkpoint_adapter_mismatch/);
});

test('stage2 rejects unapproved identity, runtime and extension changes', async t => {
  const f = stageTwoFixture(t);
  f.provenance.sourceIdentity.learningRate = 0.0002; f.syncProvenance();
  await assert.rejects(f.verify(), /resume_unapproved_identity_change/);
  f.provenance.sourceIdentity.learningRate = 0.0001;
  f.provenance.allowedRuntimeCodeChanges['training_artifacts.py'] = {from: 'a'.repeat(64), to: 'b'.repeat(64)}; f.syncProvenance();
  await assert.rejects(f.verify(), /resume_runtime_changes_invalid/);
  delete f.provenance.allowedRuntimeCodeChanges['training_artifacts.py'];
  f.provenance.extension.toMaxSteps = 80; f.syncProvenance();
  await assert.rejects(f.verify(), /resume_extension_contract_invalid/);
});

test('stage2 binds preserved source runtime bytes and exact target runtime hashes', async t => {
  const f = stageTwoFixture(t), path = join(f.sourceRoot, 'runtime-configmap.json'), original = readFileSync(path), code = JSON.parse(original);
  code.data['train-public-qa.py'] = 'tampered source'; write(path, code);
  await assert.rejects(f.verify(), /resume_source_runtime_invalid/); writeFileSync(path, original);
  f.provenance.targetRuntimeFiles['public_qa_resume.py'] = 'f'.repeat(64); f.syncProvenance();
  await assert.rejects(f.verify(), /resume_source_runtime_invalid/);
});

test('stage2 requires exactly ordered steps21..40 and non-skipped optimizer updates', async t => {
  const f = stageTwoFixture(t);
  for (const records of [f.records.slice(1), [...f.records, f.records.at(-1)], [...f.records].reverse(),
    f.records.map((record, index) => index === 0 ? {...record, optimizerStep: 20} : record),
    f.records.map((record, index) => index === 19 ? {...record, actualOptimizerUpdates: 39, skippedOptimizerUpdates: 1} : record)]) {
    f.writeLog(records); await assert.rejects(f.verify(), /actual_optimizer_updates_not_verified/);
  }
});

test('stage2 zero learning rate cannot disguise nominal updates and restore must be step20', async t => {
  const f = stageTwoFixture(t);
  for (const learningRate of [0, null, -0.1, 0.001]) {
    f.writeLog(f.records.map((record, index) => index === 0 ? {...record, learningRate} : record));
    await assert.rejects(f.verify(), /stage2_learning_rate_not_active/);
  }
  f.writeLog(); writeFileSync(f.logPath, readFileSync(f.logPath, 'utf8').replace('"schedulerLastEpoch":20', '"schedulerLastEpoch":19'));
  await assert.rejects(f.verify(), /resume_loaded_state_not_verified/);
});

test('stage2 requires final termination and the recorded live pod must use the same resume and forty steps', async t => {
  const f = stageTwoFixture(t);
  f.controller.terminationConfirmed = false; write(f.controllerPath, f.controller);
  await assert.rejects(f.verify(), /controller_execution_not_verified/); f.controller.terminationConfirmed = true;
  f.controller.livePodSpec = structuredClone(f.controller.livePodSpec);
  const args = f.controller.livePodSpec.containers[0].args, stepIndex = args.indexOf('--max-steps') + 1;
  args[stepIndex] = '20'; write(f.controllerPath, f.controller);
  await assert.rejects(f.verify(), /controller_training_arguments_mismatch/); args[stepIndex] = '40';
  args[args.indexOf('--resume-from-checkpoint') + 1] = '/checkpoints/runs/public-qa-other/checkpoint-20'; write(f.controllerPath, f.controller);
  await assert.rejects(f.verify(), /controller_resume_execution_mismatch/);
});
