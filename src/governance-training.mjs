// Docker launcher for the governance-mapping QLoRA run on the operator's PC (docs/governance-model-runbook.md).
// The container is created, inspected and only then started: no network, read-only root, every capability dropped,
// fixed memory/pids/cpu limits, one GPU, inputs mounted read-only and exactly one writable checkpoint directory.
// createIdleTrainingGuard (src/training-resource-guard.mjs) drives start/observe/stop; nothing here downloads anything.
import {createHash, randomUUID} from 'node:crypto';
import {execFileSync, spawnSync} from 'node:child_process';
import {existsSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {isAbsolute, join, resolve} from 'node:path';

export const TRAINER_FILES = Object.freeze(['train-governance-mapping-lora.py', 'training_artifacts.py', 'train-public-qa.py', 'public-qa-kbit.py']);
export const CONTAINER = Object.freeze({user: '10001:10001', memory: 12 * 1024 ** 3, pids: 256, nanoCpus: 2e9, app: '/opt/evidscope',
  base: '/models/base', data: '/dataset/train.jsonl', checkpoints: '/checkpoints', podinfo: '/etc/podinfo'});
const IMAGE = /^(?:[a-zA-Z0-9./:_-]+@)?sha256:[a-f0-9]{64}$/;
const REVISION = /^[a-f0-9]{40}$/;
const NAME = /^evidscope-governance-train-[a-f0-9-]{36}$/;
export const BASE_REPOSITORY = 'fdtn-ai/Foundation-Sec-1.1-8B-Instruct';

const fail = code => { throw Object.assign(Error(code), {code}); };
const fileSha = path => createHash('sha256').update(readFileSync(path)).digest('hex');

// runMode "shakedown" trains on the derived rows only (training-set --shakedown) into its own output directory; the trainer then
// writes a shakedown adapter that is never promotable (docs/governance-model-runbook.md).
export const RUN_DIRS = Object.freeze({candidate: 'governance-mapping/run', shakedown: 'governance-mapping/shakedown'});
// Every input is an absolute host path; the digests the trainer re-checks are computed here from the same bytes.
export function trainingSpec({image, baseDir, baseRevision, dataFile, checkpointsDir, scriptsDir, workDir, resumeCheckpoint = null, gpuMemoryFraction = 0.65,
  runMode = 'candidate'}) {
  if (!IMAGE.test(image || '')) fail('training_image_digest_required');
  if (!REVISION.test(baseRevision || '')) fail('base_revision_required');
  if (!Object.hasOwn(RUN_DIRS, runMode)) fail('run_mode_invalid');
  for (const p of [baseDir, dataFile, checkpointsDir, scriptsDir, workDir]) if (typeof p !== 'string' || !isAbsolute(p)) fail('absolute_paths_required');
  if (!(gpuMemoryFraction >= 0.1 && gpuMemoryFraction <= 0.65)) fail('gpu_memory_fraction_invalid');
  if (resumeCheckpoint !== null && !(typeof resumeCheckpoint === 'string' && resumeCheckpoint.startsWith(RUN_DIRS[runMode] + '/')
    && /^checkpoint-[1-9][0-9]*$/.test(resumeCheckpoint.slice(RUN_DIRS[runMode].length + 1)))) fail('checkpoint_path_invalid');
  const modes = new Set(readFileSync(dataFile, 'utf8').split('\n').filter(Boolean).map(line => JSON.parse(line).runMode ?? 'candidate'));
  if (modes.size !== 1 || !modes.has(runMode)) fail('training_set_run_mode_mismatch');
  const lock = JSON.parse(readFileSync(join(baseDir, 'artifact-lock.json'), 'utf8'));
  if (lock.repository !== BASE_REPOSITORY || lock.revision !== baseRevision) fail('base_artifact_lock_mismatch');
  return {image, baseDir: resolve(baseDir), baseRevision, dataFile: resolve(dataFile), checkpointsDir: resolve(checkpointsDir),
    scriptsDir: resolve(scriptsDir), workDir: resolve(workDir), resumeCheckpoint, gpuMemoryFraction, runMode,
    datasetSha256: fileSha(dataFile), baseLockSha256: fileSha(join(baseDir, 'artifact-lock.json')),
    trainerSha256: Object.fromEntries(TRAINER_FILES.map(f => [f, fileSha(join(scriptsDir, f))]))};
}

export function dockerCreateArgs(spec, name) {
  if (!NAME.test(name)) fail('container_name_invalid');
  const ro = (host, target) => ['--mount', `type=bind,source=${host},target=${target},readonly`];
  const env = {EVIDSCOPE_ISOLATED: '1', HF_HUB_OFFLINE: '1', TRANSFORMERS_OFFLINE: '1', HF_HUB_DISABLE_TELEMETRY: '1', WANDB_DISABLED: 'true',
    PYTHONDONTWRITEBYTECODE: '1', TOKENIZERS_PARALLELISM: 'false', OMP_NUM_THREADS: '2', MKL_NUM_THREADS: '2', HOME: '/tmp',
    EVIDSCOPE_BASE_REPOSITORY: BASE_REPOSITORY, EVIDSCOPE_BASE_REVISION: spec.baseRevision, EVIDSCOPE_DATASET_SHA256: spec.datasetSha256,
    EVIDSCOPE_BASE_ARTIFACT_LOCK_SHA256: spec.baseLockSha256, EVIDSCOPE_TRAINING_IMAGE: spec.image};
  const args = ['create', '--name', name, '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
    '--pids-limit', String(CONTAINER.pids), '--memory', String(CONTAINER.memory), '--memory-swap', String(CONTAINER.memory), '--cpus', '2',
    '--gpus', 'device=0', '--user', CONTAINER.user, '--tmpfs', '/tmp:rw,nosuid,nodev,size=2g', '--ipc', 'private',
    '--label', 'evidscope.io/component=governance-training', '--workdir', CONTAINER.app, '--entrypoint', 'python',
    ...Object.entries(env).flatMap(([k, v]) => ['--env', `${k}=${v}`]),
    ...ro(spec.baseDir, CONTAINER.base), ...ro(spec.dataFile, CONTAINER.data), ...ro(join(spec.workDir, 'podinfo'), CONTAINER.podinfo),
    ...TRAINER_FILES.flatMap(f => ro(join(spec.scriptsDir, f), `${CONTAINER.app}/${f}`)),
    '--mount', `type=bind,source=${spec.checkpointsDir},target=${CONTAINER.checkpoints}`,
    spec.image, `${CONTAINER.app}/train-governance-mapping-lora.py`, '--data', CONTAINER.data, '--model-dir', CONTAINER.base,
    '--base-revision', spec.baseRevision, '--gpu-memory-fraction', String(spec.gpuMemoryFraction),
    '--output', `${CONTAINER.checkpoints}/${RUN_DIRS[spec.runMode ?? 'candidate']}`, ...(spec.runMode === 'shakedown' ? ['--shakedown'] : [])];
  if (spec.resumeCheckpoint) args.push('--resume-from-checkpoint', `${CONTAINER.checkpoints}/${spec.resumeCheckpoint}`);
  return args;
}

// `docker inspect` of the created container must show exactly the isolation asked for, before it is ever started.
export function isolationProblems(info, spec) {
  const h = info?.HostConfig || {}, c = info?.Config || {}, problems = [];
  const check = (ok, code) => { if (!ok) problems.push(code); };
  check(h.NetworkMode === 'none', 'network_not_none');
  check(h.ReadonlyRootfs === true, 'root_filesystem_writable');
  check(h.Privileged === false, 'privileged');
  check(Array.isArray(h.CapDrop) && h.CapDrop.map(x => String(x).toUpperCase()).includes('ALL') && !(h.CapAdd || []).length, 'capabilities_not_dropped');
  check((h.SecurityOpt || []).some(x => /^no-new-privileges(:true)?$/.test(x)), 'new_privileges_allowed');
  check(h.Memory === CONTAINER.memory && h.MemorySwap === CONTAINER.memory, 'memory_limit_missing');
  check(h.PidsLimit === CONTAINER.pids && h.NanoCpus === CONTAINER.nanoCpus, 'process_limits_missing');
  check(!h.PidMode && !h.UTSMode && h.IpcMode === 'private' && !(h.Devices || []).length, 'host_namespace_or_device_shared');
  check((h.DeviceRequests || []).length === 1 && (h.DeviceRequests[0].DeviceIDs || []).join() === '0', 'gpu_request_unexpected');
  check(c.User === CONTAINER.user, 'user_not_unprivileged');
  check(info?.Image === spec.image.replace(/^.*@/, '') || info?.Config?.Image === spec.image, 'image_mismatch');
  const expected = new Map([[CONTAINER.base, [spec.baseDir, false]], [CONTAINER.data, [spec.dataFile, false]],
    [CONTAINER.podinfo, [join(spec.workDir, 'podinfo'), false]], [CONTAINER.checkpoints, [spec.checkpointsDir, true]],
    ...TRAINER_FILES.map(f => [`${CONTAINER.app}/${f}`, [join(spec.scriptsDir, f), false]])]);
  const mounts = (info?.Mounts || []).filter(m => m.Destination !== '/tmp');
  check(mounts.length === expected.size, 'mount_set_unexpected');
  for (const m of mounts) {
    const want = expected.get(m.Destination);
    check(want && m.Type === 'bind' && m.RW === want[1] && (m.Propagation || 'rprivate') === 'rprivate', `mount_unexpected:${m.Destination}`);
  }
  check(h.Tmpfs && Object.keys(h.Tmpfs).join() === '/tmp', 'tmpfs_unexpected');
  return [...new Set(problems)];
}

const run = (program, args) => execFileSync(program, args, {encoding: 'utf8', timeout: 60000, maxBuffer: 4 * 1024 * 1024, windowsHide: true,
  stdio: ['ignore', 'pipe', 'pipe']});
// The trainer writes progress and errors to stdout and stderr; keep both, since the container is removed right after.
const containerLogs = id => { const r = spawnSync('docker', ['logs', '--tail', '400', id], {encoding: 'utf8', timeout: 60000, windowsHide: true});
  return (r.stdout || '') + (r.stderr || ''); };

// launcher.start → create + inspect + start; observe → running/succeeded/failed/absent; stop → stop + remove that container id only.
export function createDockerTrainingLauncher({spec, execute = run, logs = containerLogs, newName = () => `evidscope-governance-train-${randomUUID()}`}) {
  const inspect = id => { try { return JSON.parse(execute('docker', ['inspect', id]))[0]; } catch { return null; } };
  return {
    async start() {
      const name = newName(), podinfo = join(spec.workDir, 'podinfo');
      mkdirSync(podinfo, {recursive: true});
      writeFileSync(join(podinfo, 'uid'), name + '\n');
      if (!existsSync(spec.checkpointsDir)) fail('checkpoints_dir_missing');
      const id = execute('docker', dockerCreateArgs(spec, name)).trim();
      if (!/^[a-f0-9]{64}$/.test(id)) fail('container_create_unconfirmed');
      const problems = isolationProblems(inspect(id), spec);
      if (problems.length) {
        try { execute('docker', ['rm', '--force', id]); } catch {}
        throw Object.assign(Error('container_isolation_unverified: ' + problems.join(',')), {problems});
      }
      execute('docker', ['start', id]);
      return {uid: id, name, isolation: 'verified_before_start'};
    },
    async observe(workload) {
      const info = inspect(workload.uid);
      if (!info) return {state: 'absent', terminationConfirmed: true};
      if (info.State?.Running) return {state: 'running'};
      if (info.State?.Status === 'exited') return {state: info.State.ExitCode === 0 ? 'succeeded' : 'failed', exitCode: info.State.ExitCode};
      return {state: info.State?.Status || 'unknown'};
    },
    async stop(workload) {
      try { execute('docker', ['stop', '--time', '60', workload.uid]); } catch {}
      try { writeFileSync(join(spec.workDir, `${workload.name}.log`), logs(workload.uid)); } catch {}
      execute('docker', ['rm', workload.uid]);
    },
  };
}
