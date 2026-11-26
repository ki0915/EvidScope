// Guarded governance-mapping QLoRA run on the operator's Windows PC with Docker Desktop (docs/governance-model-runbook.md).
//   node scripts/governance-mapping-train.mjs [--image repo@sha256:<digest>] --base-dir D --base-revision <40 hex> --data train.jsonl
//        --checkpoints-dir D --work-dir D [--resume governance-mapping/run/checkpoint-N] [--check-only] [--shakedown] [--idle-only]
// --shakedown: a run on the derived rows only (training-set --shakedown) to measure VRAM and time before the human review is done.
// Its adapter goes to governance-mapping/shakedown, is never promotable and is not a quality result.
// The image defaults to the pinned public-QA training image (same packages, already on the PC; no new build).
// --check-only prints the spec, the docker arguments and the host decision without creating a container.
// By the owner's choice (2026-10-10) training runs while the PC is in use (TRAINING_ACTIVE_USE_POLICY): it needs only enough free
// VRAM and a safe GPU temperature, and stops with a checkpoint on memory pressure, overheating or after one hour.
// --idle-only restores the earlier rule (start only on an idle PC, stop when it is used).
// Under the active-use policy a run stopped for GPU heat or the one-hour limit is resumed from its newest sealed checkpoint
// once the GPU is at or below 65 C (at most six resumes, waiting at most 30 minutes each time).
import {pathToFileURL, fileURLToPath} from 'node:url';
import {existsSync, readdirSync} from 'node:fs';
import {dirname, join} from 'node:path';
import {TRAINING_ACTIVE_USE_POLICY, TRAINING_RESOURCE_POLICY, createIdleTrainingGuard, trainingStartDecision} from '../src/training-resource-guard.mjs';
import {RUN_DIRS, createDockerTrainingLauncher, dockerCreateArgs, trainingSpec} from '../src/governance-training.mjs';
import {probeWindowsHostResources} from './training-host-check.mjs';
import {QA_IMAGE} from './public-qa-workload.mjs';

export const COOLING = Object.freeze({resumeAtOrBelowC: 65, pollMs: 30000, maxWaitMs: 1800000, maxResumes: 6});
const RESUMABLE = new Set(['gpu_temperature_high', 'runtime_deadline']);

// Newest checkpoint the trainer sealed (checkpoint-complete.json) for this run mode, as a path relative to the checkpoints directory.
export function latestSealedCheckpoint(spec) {
  const dir = RUN_DIRS[spec.runMode ?? 'candidate'], root = join(spec.checkpointsDir, dir);
  if (!existsSync(root)) return null;
  const steps = readdirSync(root).filter(n => /^checkpoint-[1-9][0-9]*$/.test(n) && existsSync(join(root, n, 'checkpoint-complete.json')))
    .map(n => Number(n.slice('checkpoint-'.length)));
  return steps.length ? `${dir}/checkpoint-${Math.max(...steps)}` : null;
}

async function cooled(probe, wait, signal) {
  for (let waited = 0; waited <= COOLING.maxWaitMs; waited += COOLING.pollMs) {
    if (signal?.aborted) return false;
    try { if ((await probe()).gpu.temperatureC <= COOLING.resumeAtOrBelowC) return true; } catch {}
    await wait(COOLING.pollMs);
  }
  return false;
}

const KEYS = {'--image': 'image', '--base-dir': 'baseDir', '--base-revision': 'baseRevision', '--data': 'dataFile', '--checkpoints-dir': 'checkpointsDir',
  '--work-dir': 'workDir', '--resume': 'resumeCheckpoint'};

export async function runGovernanceTraining(argv, {probe = () => probeWindowsHostResources(), launcherFor = createDockerTrainingLauncher,
  guardFor = createIdleTrainingGuard, wait = ms => new Promise(r => setTimeout(r, ms)), signal} = {}) {
  const options = {scriptsDir: dirname(fileURLToPath(import.meta.url))};
  let checkOnly = false, policy = TRAINING_ACTIVE_USE_POLICY;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--check-only') { checkOnly = true; continue; }
    if (argv[i] === '--shakedown') { options.runMode = 'shakedown'; continue; }
    if (argv[i] === '--idle-only') { policy = TRAINING_RESOURCE_POLICY; continue; }
    const key = KEYS[argv[i]];
    if (!key || options[key] !== undefined || !argv[i + 1] || argv[i + 1].startsWith('--')) {
      throw Error('usage: see the header of scripts/governance-mapping-train.mjs');
    }
    options[key] = argv[++i];
  }
  let spec = trainingSpec({image: QA_IMAGE, ...options});
  if (checkOnly) {
    let decision;
    try { decision = trainingStartDecision(await probe(), {policy}); } catch { decision = {allowed: false, reasons: ['host_resource_probe_unavailable']}; }
    const dockerArgs = dockerCreateArgs(spec, 'evidscope-governance-train-00000000-0000-0000-0000-000000000000');
    return {mode: 'check-only', policy: policy.mode, spec, dockerArgs, decision};
  }
  const stops = [];
  for (;;) {
    const result = await guardFor({probe, launcher: launcherFor({spec}), policy}).run({signal});
    const why = result.reason ?? result.reasons?.find(r => RESUMABLE.has(r));
    if (policy !== TRAINING_ACTIVE_USE_POLICY || !RESUMABLE.has(why) || stops.length >= COOLING.maxResumes || !await cooled(probe, wait, signal)) {
      return {mode: 'execution', policy: policy.mode, spec, result, resumedAfter: stops};
    }
    stops.push(why);
    spec = trainingSpec({image: QA_IMAGE, ...options, resumeCheckpoint: latestSealedCheckpoint(spec) ?? spec.resumeCheckpoint});
  }
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
