// Guarded governance-mapping QLoRA run on the operator's Windows PC with Docker Desktop (docs/governance-model-runbook.md).
//   node scripts/governance-mapping-train.mjs [--image repo@sha256:<digest>] --base-dir D --base-revision <40 hex> --data train.jsonl
//        --checkpoints-dir D --work-dir D [--resume governance-mapping/run/checkpoint-N] [--check-only] [--shakedown]
// --shakedown: a run on the derived rows only (training-set --shakedown) to measure VRAM and time before the human review is done.
// Its adapter goes to governance-mapping/shakedown, is never promotable and is not a quality result.
// The image defaults to the pinned public-QA training image (same packages, already on the PC; no new build).
// --check-only prints the spec, the docker arguments and the host decision without creating a container.
// Training starts only when the idle-host guard allows it and stops (with a checkpoint) when the PC is needed or after one hour.
import {pathToFileURL, fileURLToPath} from 'node:url';
import {dirname} from 'node:path';
import {createIdleTrainingGuard, trainingStartDecision} from '../src/training-resource-guard.mjs';
import {createDockerTrainingLauncher, dockerCreateArgs, trainingSpec} from '../src/governance-training.mjs';
import {probeWindowsHostResources} from './training-host-check.mjs';
import {QA_IMAGE} from './public-qa-workload.mjs';

const KEYS = {'--image': 'image', '--base-dir': 'baseDir', '--base-revision': 'baseRevision', '--data': 'dataFile', '--checkpoints-dir': 'checkpointsDir',
  '--work-dir': 'workDir', '--resume': 'resumeCheckpoint'};

export async function runGovernanceTraining(argv, {probe = () => probeWindowsHostResources(), launcherFor = createDockerTrainingLauncher,
  guardFor = createIdleTrainingGuard, signal} = {}) {
  const options = {scriptsDir: dirname(fileURLToPath(import.meta.url))};
  let checkOnly = false;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--check-only') { checkOnly = true; continue; }
    if (argv[i] === '--shakedown') { options.runMode = 'shakedown'; continue; }
    const key = KEYS[argv[i]];
    if (!key || options[key] !== undefined || !argv[i + 1] || argv[i + 1].startsWith('--')) {
      throw Error('usage: see the header of scripts/governance-mapping-train.mjs');
    }
    options[key] = argv[++i];
  }
  const spec = trainingSpec({image: QA_IMAGE, ...options});
  if (checkOnly) {
    let decision;
    try { decision = trainingStartDecision(await probe()); } catch { decision = {allowed: false, reasons: ['host_resource_probe_unavailable']}; }
    return {mode: 'check-only', spec, dockerArgs: dockerCreateArgs(spec, 'evidscope-governance-train-00000000-0000-0000-0000-000000000000'), decision};
  }
  const result = await guardFor({probe, launcher: launcherFor({spec})}).run({signal});
  return {mode: 'execution', spec, result};
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const controller = new AbortController(), cancel = () => controller.abort();
  process.on('SIGINT', cancel);
  process.on('SIGTERM', cancel);
  try {
    const out = await runGovernanceTraining(process.argv.slice(2), {signal: controller.signal});
    process.stdout.write(JSON.stringify(out, null, 1) + '\n');
    process.exitCode = out.mode === 'check-only' ? (out.decision.allowed ? 0 : 2) : out.result.reason === 'completed' ? 0 : 2;
  } catch (error) {
    process.stdout.write(JSON.stringify({started: false, error: error.message, terminationConfirmed: error.terminationConfirmed === true}) + '\n');
    process.exitCode = 2;
  }
}
