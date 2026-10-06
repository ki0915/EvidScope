import {createHash} from 'node:crypto';
import {createReadStream, lstatSync, readFileSync, readdirSync, mkdirSync, writeFileSync} from 'node:fs';
import {resolve, dirname, join, relative} from 'node:path';
import {pathToFileURL} from 'node:url';
import {isDeepStrictEqual} from 'node:util';
import {QA_BASE_REVISION, QA_IMAGE, QA_NAMESPACE} from './public-qa-workload.mjs';

const sha = value => createHash('sha256').update(value).digest('hex');
const requireTrue = (value, message) => { if (!value) throw Error(message); };
const json = path => JSON.parse(readFileSync(path, 'utf8').replace(/^\uFEFF/, ''));
const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
async function fileHash(path) {
  const hash = createHash('sha256');
  for await (const block of createReadStream(path)) hash.update(block);
  return hash.digest('hex');
}
function safeTree(root) {
  const result = [];
  function visit(path) {
    const stat = lstatSync(path);
    requireTrue(!stat.isSymbolicLink(), 'artifact_symlink_forbidden');
    requireTrue(!path.endsWith('.partial'), 'artifact_partial_file');
    if (stat.isDirectory()) for (const entry of readdirSync(path).sort()) visit(join(path, entry));
    else { requireTrue(stat.isFile(), 'artifact_special_file_forbidden'); result.push(path); }
  }
  visit(root);
  return result;
}

async function verifyCheckpoint(checkpoint, identity, step, expectedMarkerHash) {
  safeTree(checkpoint);
  const markerPath = join(checkpoint, 'checkpoint-complete.json'), marker = json(markerPath);
  requireTrue((!expectedMarkerHash || await fileHash(markerPath) === expectedMarkerHash)
    && marker.schemaVersion === 1 && marker.globalStep === step
    && isDeepStrictEqual(marker.identity, identity), 'resume_parent_marker_mismatch');
  const actual = [];
  for (const file of safeTree(checkpoint).filter(file => file !== markerPath)) {
    actual.push({path: relative(checkpoint, file).replaceAll('\\', '/'), bytes: lstatSync(file).size, sha256: await fileHash(file)});
  }
  actual.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  requireTrue(isDeepStrictEqual(actual, marker.files), 'resume_parent_artifact_changed');
  requireTrue(['adapter_config.json', 'adapter_model.safetensors', 'trainer_state.json', 'optimizer.pt', 'scheduler.pt', 'rng_state.pth', 'scaler.pt', 'training_args.bin']
    .every(name => actual.some(file => file.path === name && file.bytes > 0))
    && json(join(checkpoint, 'trainer_state.json')).global_step === step, 'resume_parent_state_incomplete');
  return {files: actual, markerSha256: await fileHash(markerPath), globalStep: step};
}

async function verifyStageTwoResume(inputs, receipt, identity, workspace, runId) {
  const resume = inputs.resumeProvenance, p = resume.value;
  const fields = ['schemaVersion', 'sourceIdentity', 'targetIdentity', 'sourceCheckpointMarkerSha256', 'sourceRunId', 'targetRunId',
    'sourceGlobalStep', 'allowedCodeChanges', 'sourceRuntimeSha256', 'sourceRuntimeFiles', 'targetRuntimeFiles', 'allowedRuntimeCodeChanges', 'extension'];
  requireTrue(p.schemaVersion === 2 && p.sourceGlobalStep === 20 && p.sourceRunId === 'public-qa-resume-20260928-r1'
    && p.targetRunId === runId && /^public-qa-stage2-[a-z0-9-]{1,28}$/.test(runId)
    && isDeepStrictEqual(Object.keys(p).sort(), fields.sort()) && digest(p.sourceCheckpointMarkerSha256)
    && isDeepStrictEqual(p.targetIdentity, identity), 'resume_provenance_identity_mismatch');
  const source = p.sourceIdentity, change = p.allowedCodeChanges?.trainerSha256;
  requireTrue(isDeepStrictEqual(Object.keys(p.allowedCodeChanges || {}), ['trainerSha256'])
    && digest(source?.trainerSha256) && source.trainerSha256 !== identity.trainerSha256
    && isDeepStrictEqual(change, {from: source.trainerSha256, to: identity.trainerSha256}), 'resume_code_changes_invalid');
  requireTrue(source.stage === 'public_qa_stage1' && source.maxSteps === 20
    && isDeepStrictEqual({...source, stage: 'public_qa_stage2', maxSteps: 40, trainerSha256: identity.trainerSha256}, identity), 'resume_unapproved_identity_change');
  requireTrue(isDeepStrictEqual(p.extension, {kind: 'bounded_max_steps_extension', fromStage: 'public_qa_stage1', toStage: 'public_qa_stage2',
    fromMaxSteps: 20, toMaxSteps: 40, reason: 'trainer_dynamic_padding_selective_completion_logits_stage2_resume_verifier_and_resource_pilot'}), 'resume_extension_contract_invalid');
  const sourceCodePath = resolve(workspace, '.local/training/public-qa-run', p.sourceRunId, 'runtime-configmap.json');
  requireTrue(lstatSync(sourceCodePath).isFile() && !lstatSync(sourceCodePath).isSymbolicLink(), 'resume_source_runtime_invalid');
  const sourceCode = json(sourceCodePath), sourceHash = sha(JSON.stringify(sourceCode.data));
  requireTrue(sourceCode.kind === 'ConfigMap' && sourceCode.immutable === true && sourceHash === p.sourceRuntimeSha256
    && sourceCode.metadata?.name === `public-qa-runtime-${sourceHash.slice(0, 16)}`
    && sourceCode.metadata?.annotations?.['evidscope.io/code-sha256'] === sourceHash
    && isDeepStrictEqual(Object.fromEntries(Object.entries(sourceCode.data).map(([name, value]) => [name, sha(value)])), p.sourceRuntimeFiles)
    && isDeepStrictEqual(p.targetRuntimeFiles, inputs.runtimeFiles), 'resume_source_runtime_invalid');
  const changed = ['public_qa_resume.py', 'resource-pilot.py', 'train-public-qa.py'];
  requireTrue(isDeepStrictEqual(Object.keys(p.allowedRuntimeCodeChanges || {}).sort(), changed)
    && isDeepStrictEqual(Object.keys(p.sourceRuntimeFiles).sort(), Object.keys(p.targetRuntimeFiles).sort()), 'resume_runtime_changes_invalid');
  for (const [name, from] of Object.entries(p.sourceRuntimeFiles)) {
    const to = p.targetRuntimeFiles[name];
    requireTrue(digest(from) && digest(to) && (changed.includes(name)
      ? from !== to && isDeepStrictEqual(p.allowedRuntimeCodeChanges[name], {from, to})
      : from === to), 'resume_runtime_changes_invalid');
  }
  for (const [field, name] of [['trainerSha256', 'train-public-qa.py'], ['artifactHelperSha256', 'training_artifacts.py'], ['bindingHelperSha256', 'train-foundation-lora.py']]) {
    requireTrue(source[field] === p.sourceRuntimeFiles[name], 'resume_source_runtime_invalid');
  }
  const lineage = {schemaVersion: 2, provenanceSha256: resume.sha256, sourceRunId: p.sourceRunId, targetRunId: runId,
    sourceCheckpointMarkerSha256: p.sourceCheckpointMarkerSha256, sourceGlobalStep: 20, sourceIdentity: source,
    sourceRuntimeSha256: p.sourceRuntimeSha256, sourceRuntimeFiles: p.sourceRuntimeFiles, targetRuntimeFiles: p.targetRuntimeFiles,
    allowedRuntimeCodeChanges: p.allowedRuntimeCodeChanges, extension: p.extension};
  requireTrue(isDeepStrictEqual(receipt.resumeLineage, lineage), 'resume_lineage_mismatch');
  await verifyCheckpoint(resolve(workspace, '.local/training/runs', p.sourceRunId, 'checkpoint-20'), source, 20, p.sourceCheckpointMarkerSha256);
  return lineage;
}

async function verifyResume(inputs, receipt, identity, workspace, runId) {
  const resume = inputs.resumeProvenance;
  if (!resume) {
    requireTrue(identity.stage !== 'public_qa_stage2', 'stage2_resume_required');
    requireTrue(receipt.resumeLineage == null, 'resume_lineage_without_provenance');
    return null;
  }
  requireTrue(digest(resume.sha256) && typeof resume.localPath === 'string', 'resume_provenance_invalid');
  const path = resolve(workspace, resume.localPath);
  requireTrue(lstatSync(path).isFile() && !lstatSync(path).isSymbolicLink()
    && await fileHash(path) === resume.sha256 && isDeepStrictEqual(json(path), resume.value), 'resume_provenance_changed');
  const provenance = resume.value;
  if (identity.stage === 'public_qa_stage2') return verifyStageTwoResume(inputs, receipt, identity, workspace, runId);
  requireTrue(provenance.schemaVersion === 1 && provenance.sourceGlobalStep === 5
    && isDeepStrictEqual(Object.keys(provenance).sort(), ['schemaVersion', 'sourceIdentity', 'targetIdentity', 'sourceCheckpointMarkerSha256', 'sourceRunId', 'sourceGlobalStep', 'allowedCodeChanges'].sort())
    && /^public-qa-[a-z0-9-]{1,35}$/.test(provenance.sourceRunId)
    && digest(provenance.sourceCheckpointMarkerSha256)
    && isDeepStrictEqual(provenance.targetIdentity, identity), 'resume_provenance_identity_mismatch');
  const allowed = ['artifactHelperSha256', 'trainerSha256'];
  requireTrue(isDeepStrictEqual(Object.keys(provenance.allowedCodeChanges || {}).sort(), allowed), 'resume_code_changes_invalid');
  const expected = structuredClone(provenance.sourceIdentity);
  for (const field of allowed) {
    const change = provenance.allowedCodeChanges[field];
    requireTrue(change && digest(change.from) && digest(change.to) && change.from !== change.to
      && isDeepStrictEqual(Object.keys(change).sort(), ['from', 'to'])
      && expected?.[field] === change.from && identity[field] === change.to, 'resume_code_changes_invalid');
    expected[field] = change.to;
  }
  requireTrue(isDeepStrictEqual(expected, identity), 'resume_unapproved_identity_change');
  requireTrue(isDeepStrictEqual(receipt.resumeLineage, {
    provenanceSha256: resume.sha256, sourceRunId: provenance.sourceRunId,
    sourceCheckpointMarkerSha256: provenance.sourceCheckpointMarkerSha256,
    sourceGlobalStep: 5, sourceIdentity: provenance.sourceIdentity,
  }), 'resume_lineage_mismatch');
  const checkpoint = resolve(workspace, '.local/training/runs', provenance.sourceRunId, 'checkpoint-5');
  const {files: actual} = await verifyCheckpoint(checkpoint, provenance.sourceIdentity, 5, provenance.sourceCheckpointMarkerSha256);
  // This is the preserved CPU inspection of the same adapter and Adam state,
  // not a fresh interpretation of arbitrary pickle data in the host process.
  const evidencePath = resolve(workspace, 'reports/public-qa-interrupted-checkpoint-20260922.json');
  requireTrue(lstatSync(evidencePath).isFile() && !lstatSync(evidencePath).isSymbolicLink(), 'resume_parent_evidence_invalid');
  const evidence = json(evidencePath), optimizer = evidence.optimizerStateVerification;
  requireTrue(evidence.verified === true && evidence.globalStep === 5 && evidence.sourceRun === provenance.sourceRunId
    && evidence.weightUpdatesPresent === true && evidence.allLoraBTensorsFinite === true
    && evidence.adapterSha256 === actual.find(file => file.path === 'adapter_model.safetensors').sha256
    && evidence.adapterBytes === actual.find(file => file.path === 'adapter_model.safetensors').bytes
    && optimizer?.verified === true && optimizer.gpuUsed === false
    && optimizer.stateCount === 256 && optimizer.allActualAdamSteps === 5, 'resume_parent_optimizer_updates_not_verified');
  return {sourceRunId: provenance.sourceRunId, sourceGlobalStep: 5, provenanceSha256: resume.sha256,
    sourceCheckpointMarkerSha256: provenance.sourceCheckpointMarkerSha256,
    sourceOptimizerEvidenceSha256: await fileHash(evidencePath)};
}

// Controller receipts are local execution records, not cryptographic attestations.
// This verifies their persisted bindings and exported bytes; it does not certify
// answer quality, legal compliance, or truthfulness of a forged receipt bundle.
export async function verifyPublicQaArtifact({runDirectory, controllerReceipt, workspace = process.cwd()}) {
  const run = resolve(runDirectory), controllerPath = resolve(controllerReceipt);
  safeTree(run);
  requireTrue(lstatSync(controllerPath).isFile() && !lstatSync(controllerPath).isSymbolicLink(), 'controller_file_invalid');
  const controller = json(controllerPath), candidate = join(run, 'candidate');
  const stageTwo = controller.mode === 'explicit_public_human_qa_stage2';
  const stage = stageTwo ? 'public_qa_stage2' : 'public_qa_stage1', totalSteps = stageTwo ? 40 : 20;
  requireTrue(controller.schemaVersion === 1 && controller.mode === `explicit_public_human_qa_${stageTwo ? 'stage2' : 'stage1'}`
    && controller.state === 'process_completed' && controller.exit?.exitCode === 0
    && controller.terminationConfirmed === true && controller.admission?.allowed === true
    && controller.qualityClaimAllowed === false && controller.automaticGovernanceGateClaimed === false
    && typeof controller.jobUid === 'string' && controller.jobUid.length > 0
    && typeof controller.podUid === 'string' && controller.podUid.length > 0
    && !controller.error && !controller.cleanupError && !controller.creationUncertain,
  'controller_execution_not_verified');
  const markerPath = join(candidate, 'candidate-complete.json'), marker = json(markerPath);
  requireTrue(marker.schemaVersion === 1 && marker.globalStep === totalSteps, 'candidate_step_invalid');
  const actual = [];
  for (const file of safeTree(candidate).filter(path => path !== markerPath)) {
    actual.push({path: relative(candidate, file).replaceAll('\\', '/'), bytes: lstatSync(file).size, sha256: await fileHash(file)});
  }
  actual.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  requireTrue(isDeepStrictEqual(marker.files, actual), 'candidate_artifact_changed');
  requireTrue(['adapter_config.json', 'adapter_model.safetensors', 'training-receipt.json'].every(name => actual.some(file => file.path === name && file.bytes > 0)), 'candidate_files_incomplete');
  const receipt = json(join(candidate, 'training-receipt.json'));
  requireTrue(receipt.schemaVersion === 2 && receipt.status === `trained_${stage}`
    && receipt.globalStep === totalSteps && receipt.trainingRunCompleted === true
    && receipt.qualityClaimAllowed === false && receipt.promotionAllowed === false
    && receipt.heldOutTestUsedForTraining === false && receipt.localHumanReviewPerformed === false
    && receipt.sourceLicense === 'CC-BY-SA-4.0'
    && receipt.targetFormat === 'exact_human_answer_json_without_generated_reasoning'
    && isDeepStrictEqual(receipt.identity, marker.identity)
    && isDeepStrictEqual(receipt.trainingMetrics, marker.metrics), 'candidate_receipt_mismatch');
  requireTrue(Number.isFinite(receipt.trainingMetrics?.train_loss) && Number.isFinite(receipt.trainingMetrics?.eval_loss)
    && Number.isFinite(receipt.trainingMetrics?.base_eval_loss), 'candidate_metrics_invalid');
  const logPath = join(dirname(controllerPath), 'training.log');
  requireTrue(lstatSync(logPath).isFile() && !lstatSync(logPath).isSymbolicLink(), 'training_log_invalid');
  const optimizerRecords = [];
  const resumeStates = [], resumeRng = [];
  for (const line of readFileSync(logPath, 'utf8').split(/\r?\n|\r/)) {
    for (const [key, records] of [['resumedGlobalStep', resumeStates], ['resumeRngStateLoaded', resumeRng]]) {
      if (!line.includes(`"${key}"`)) continue;
      const start = line.indexOf(`{"${key}":`);
      requireTrue(start >= 0, 'resume_log_record_invalid');
      try { records.push(JSON.parse(line.slice(start))); } catch { throw Error('resume_log_record_invalid'); }
    }
    if (!line.includes('"optimizerStep"')) continue;
    // stderr progress bars may precede a stdout JSON callback in kubectl logs.
    const start = line.indexOf('{"optimizerStep":');
    requireTrue(start >= 0, 'optimizer_log_record_invalid');
    let record;
    try { record = JSON.parse(line.slice(start)); } catch { throw Error('optimizer_log_record_invalid'); }
    optimizerRecords.push(record);
  }
  const inputs = controller.inputs, identity = marker.identity;
  requireTrue(inputs && identity && identity.baseRepository === 'fdtn-ai/Foundation-Sec-8B-Reasoning'
    && identity.baseRevision === QA_BASE_REVISION && identity.image === QA_IMAGE
    && identity.stage === stage && identity.rank === 8 && identity.sequenceLength === 1024
    && identity.batchSize === 1 && identity.gradientAccumulationSteps === 16 && identity.seed === 42
    && identity.learningRate === 0.0001 && identity.maxSteps === totalSteps
    && identity.gpuMemoryFraction > 0 && identity.gpuMemoryFraction <= 0.65, 'candidate_execution_identity_mismatch');
  const resume = await verifyResume(inputs, receipt, identity, workspace, controller.runId);
  const initialStep = resume?.sourceGlobalStep || 0;
  if (resume) {
    const resumeCodePath = join(dirname(controllerPath), 'resume-configmap.json');
    requireTrue(lstatSync(resumeCodePath).isFile() && !lstatSync(resumeCodePath).isSymbolicLink(), 'resume_configmap_invalid');
    const resumeCode = json(resumeCodePath);
    requireTrue(resumeCode.apiVersion === 'v1' && resumeCode.kind === 'ConfigMap' && resumeCode.immutable === true
      && resumeCode.metadata?.name === `public-qa-resume-${resume.provenanceSha256.slice(0, 16)}`
      && resumeCode.metadata?.namespace === QA_NAMESPACE
      && isDeepStrictEqual(Object.keys(resumeCode.data || {}), ['provenance.json'])
      && sha(resumeCode.data['provenance.json']) === resume.provenanceSha256, 'resume_configmap_binding_mismatch');
    requireTrue(resumeStates.length === 1 && resumeStates[0].resumedGlobalStep === initialStep
      && resumeStates[0].optimizerStateCount === 256 && resumeStates[0].schedulerLastEpoch === initialStep
      && resumeRng.length === 1 && resumeRng[0].resumeRngStateLoaded === `/checkpoints/runs/${resume.sourceRunId}/checkpoint-${initialStep}`, 'resume_loaded_state_not_verified');
  } else requireTrue(resumeStates.length === 0 && resumeRng.length === 0, 'controller_unverified_resume');
  requireTrue(optimizerRecords.length === totalSteps - initialStep && optimizerRecords.every((record, index) =>
    record.optimizerStep === initialStep + index + 1 && record.actualOptimizerUpdates === initialStep + index + 1
    && record.skippedOptimizerUpdates === 0), 'actual_optimizer_updates_not_verified');
  if (stageTwo) requireTrue(optimizerRecords.every(record => Number.isFinite(record.learningRate)
    && record.learningRate >= 0 && record.learningRate <= identity.learningRate
    && (record.optimizerStep === totalSteps || record.learningRate > 0)), 'stage2_learning_rate_not_active');
  const checkpoints = [];
  if (stageTwo) {
    for (const step of [30, 40]) checkpoints.push(await verifyCheckpoint(join(run, `checkpoint-${step}`), identity, step));
    const finalAdapter = checkpoints.at(-1).files.find(file => file.path === 'adapter_model.safetensors');
    const candidateAdapter = actual.find(file => file.path === 'adapter_model.safetensors');
    requireTrue(finalAdapter.sha256 === candidateAdapter.sha256, 'stage2_final_checkpoint_adapter_mismatch');
  }
  for (const [field, inputField, fileField] of [
    ['datasetSha256', 'datasetSha256', 'data'], ['manifestSha256', 'manifestSha256', 'manifest'],
    ['baseArtifactLockSha256', 'artifactLockSha256', 'lock'],
  ]) {
    requireTrue(digest(identity[field]) && identity[field] === inputs[inputField]
      && identity[field] === await fileHash(resolve(workspace, inputs[fileField])), 'candidate_input_binding_mismatch');
  }
  const sourceManifest = json(resolve(workspace, inputs.manifest));
  requireTrue(sourceManifest.datasetSha256 === identity.datasetSha256 && sourceManifest.counts?.train === 320
    && sourceManifest.counts?.validation === 64 && sourceManifest.heldoutUsed === false
    && sourceManifest.stage === 'public_qa_stage1' && sourceManifest.license === 'CC-BY-SA-4.0'
    && sourceManifest.upstreamRevision === '3efd98708a40ff49251fddde35453f8fbb11f536', 'candidate_dataset_scope_mismatch');
  const baseLock = json(resolve(workspace, inputs.lock));
  requireTrue(baseLock.repository === identity.baseRepository && baseLock.revision === identity.baseRevision, 'candidate_base_lock_mismatch');
  const codePath = join(dirname(controllerPath), 'runtime-configmap.json');
  requireTrue(!lstatSync(codePath).isSymbolicLink(), 'runtime_symlink_forbidden');
  const code = json(codePath), codeHash = sha(JSON.stringify(code.data));
  requireTrue(code.kind === 'ConfigMap' && code.immutable === true && codeHash === inputs.runtimeSha256
    && code.metadata?.annotations?.['evidscope.io/code-sha256'] === codeHash
    && code.metadata?.name === `public-qa-runtime-${codeHash.slice(0, 16)}`
    && code.metadata.name === inputs.runtimeConfigMap, 'candidate_runtime_binding_mismatch');
  requireTrue(isDeepStrictEqual(Object.fromEntries(Object.entries(code.data).map(([name, value]) => [name, sha(value)])), inputs.runtimeFiles), 'candidate_runtime_files_mismatch');
  for (const [field, name] of [['trainerSha256', 'train-public-qa.py'], ['artifactHelperSha256', 'training_artifacts.py'], ['bindingHelperSha256', 'train-foundation-lora.py']]) {
    requireTrue(digest(identity[field]) && identity[field] === inputs.runtimeFiles[name], 'candidate_runtime_identity_mismatch');
  }
  requireTrue(sha(JSON.stringify(controller.manifest)) === controller.manifestSha256
    && controller.manifest?.metadata?.name === controller.runId, 'controller_manifest_changed');
  for (const spec of [controller.manifest.spec.template.spec, controller.livePodSpec]) {
    const container = spec?.containers?.[0];
    const env = Object.fromEntries((container?.env || []).map(({name, value}) => [name, value]));
    requireTrue(container?.image === identity.image && isDeepStrictEqual(container.command, ['python', '/runtime/train-public-qa.py'])
      && spec.volumes?.some(volume => volume.name === 'runtime' && volume.configMap?.name === inputs.runtimeConfigMap)
      && container.volumeMounts?.some(volume => volume.name === 'runtime' && volume.mountPath === '/runtime' && volume.readOnly === true)
      && env.EVIDSCOPE_TRAINING_IMAGE === identity.image && env.EVIDSCOPE_DATASET_SHA256 === identity.datasetSha256
      && env.EVIDSCOPE_BASE_REVISION === identity.baseRevision
      && env.EVIDSCOPE_BASE_ARTIFACT_LOCK_SHA256 === identity.baseArtifactLockSha256, 'controller_runtime_execution_mismatch');
    const args = container.args || [], argument = name => args[args.indexOf(name) + 1];
    requireTrue(argument('--max-steps') === String(totalSteps) && argument('--output') === `/checkpoints/runs/${controller.runId}`
      && argument('--base-revision') === identity.baseRevision, 'controller_training_arguments_mismatch');
    if (resume) {
      requireTrue(argument('--resume-from-checkpoint') === `/checkpoints/runs/${resume.sourceRunId}/checkpoint-${initialStep}`
        && argument('--resume-provenance') === '/resume/provenance.json'
        && env.EVIDSCOPE_RESUME_PROVENANCE_SHA256 === resume.provenanceSha256
        && spec.volumes?.some(volume => volume.name === 'resume-provenance'
          && volume.configMap?.name === `public-qa-resume-${resume.provenanceSha256.slice(0, 16)}`)
        && container.volumeMounts?.some(volume => volume.name === 'resume-provenance' && volume.mountPath === '/resume' && volume.readOnly === true)
        && digest(inputs.runtimeFiles['public_qa_resume.py']), 'controller_resume_execution_mismatch');
    } else requireTrue(!args.includes('--resume-from-checkpoint') && !args.includes('--resume-provenance')
      && !env.EVIDSCOPE_RESUME_PROVENANCE_SHA256, 'controller_unverified_resume');
  }
  return {schemaVersion: 1, verified: true, verifiedAt: new Date().toISOString(), runId: controller.runId,
    artifactSha256: await fileHash(markerPath), controllerSha256: await fileHash(controllerPath),
    runtimeConfigMapSha256: await fileHash(codePath), trainingLogSha256: await fileHash(logPath),
    identity, globalStep: totalSteps, actualOptimizerUpdates: totalSteps, skippedOptimizerUpdates: 0, fileCount: actual.length,
    optimizerUpdatesThisRun: totalSteps - initialStep, resumeLineage: resume,
    checkpoints: checkpoints.map(({markerSha256, globalStep}) => ({markerSha256, globalStep})),
    trainingRunCompleted: true, terminationConfirmed: true, qualityClaimAllowed: false, promotionAllowed: false,
    verificationScope: 'Exported candidate integrity and local execution bindings; no model quality or legal compliance certification.',
    candidateDirectory: candidate, trainingMetrics: receipt.trainingMetrics};
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [runDirectory, controllerReceipt, output = 'reports/public-qa-artifact-verification.json'] = process.argv.slice(2);
  let result;
  try {
    requireTrue(runDirectory && controllerReceipt, 'usage: node scripts/verify-public-qa-artifact.mjs RUN_DIRECTORY CONTROLLER_RECEIPT [REPORT_PATH]');
    result = await verifyPublicQaArtifact({runDirectory, controllerReceipt});
  } catch (error) { result = {schemaVersion: 1, verified: false, trainingRunCompleted: false, qualityClaimAllowed: false, promotionAllowed: false, error: error.message}; process.exitCode = 2; }
  mkdirSync(dirname(resolve(output)), {recursive: true});
  writeFileSync(output, JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify(result));
}
