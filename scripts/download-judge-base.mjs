// 판정 모델 오케스트라의 모델 내려받기(2026-10-17 계획). 허용된 저장소만, 40자리 리비전에 고정해 받고, 파일마다 허깅페이스가 밝힌
// 해시로 검증한 뒤 학습기(train-governance-mapping-lora.py verify_bindings)가 읽는 artifact-lock.json을 쓴다. 큰 파일은 LFS sha256, 작은
// 파일은 git blob sha1(oid)로 검증한다. 가중치·토크나이저·설정·라이선스만 받는다(README·예제 코드는 받지 않는다).
// 학습할 1차 판정 후보(JUDGE_BASES)는 학습기가 조각 색인을 검증하므로 model.safetensors.index.json이 있어야 하고, 학습 없이 그대로 쓰는
// 모델(AS_IS_MODELS, 글 검사)은 가중치 파일 하나여도 된다.
//   node scripts/download-judge-base.mjs --repository R --plan                          받을 파일과 크기만 보여 준다(리비전은 main의 현재 커밋)
//   node scripts/download-judge-base.mjs --repository R --revision SHA --out DIR --download   실제로 받는다(사용자 승인 뒤에만)
import {createHash} from 'node:crypto';
import {createReadStream, existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {spawn} from 'node:child_process';
import {pathToFileURL} from 'node:url';

export const JUDGE_BASES = Object.freeze(['Qwen/Qwen3-4B-Instruct-2507']);
export const AS_IS_MODELS = Object.freeze(['kakaocorp/kanana-safeguard-prompt-2.1b']);
const KEEP = new Set(['config.json', 'generation_config.json', 'tokenizer.json', 'tokenizer_config.json', 'special_tokens_map.json',
  'added_tokens.json', 'vocab.json', 'merges.txt', 'chat_template.jinja', 'model.safetensors.index.json', 'LICENSE', 'LICENSE.txt']);
const kept = path => KEEP.has(path) || /^model(-\d{5}-of-\d{5})?\.safetensors$/.test(path);
const REQUIRED = ['config.json', 'tokenizer.json', 'tokenizer_config.json', 'model.safetensors.index.json'];
const REQUIRED_AS_IS = ['config.json', 'tokenizer.json', 'tokenizer_config.json', 'model.safetensors'];

// 허깅페이스 tree 목록에서 받을 파일을 고른다. 하위 폴더·안 쓰는 파일은 뺀다. 학습할 기반 모델에 학습기가 요구하는 파일이 없거나(단일
// model.safetensors만 있는 저장소 등) 색인의 가중치 조각이 목록에 없으면 거부한다. asIs: 그대로 쓰는 모델이라 단일 가중치 파일을 받는다.
// 반환: [{path, bytes, sha256|null, gitOid}].
export function selectFiles(tree, index, {asIs = false} = {}) {
  const files = tree.filter(e => e.type === 'file' && kept(e.path))
    .map(e => ({path: e.path, bytes: e.lfs?.size ?? e.size, sha256: e.lfs?.oid ?? null, gitOid: e.lfs ? null : e.oid}))
    .sort((a, b) => a.path.localeCompare(b.path));
  const names = new Set(files.map(f => f.path));
  const missing = (asIs && !names.has('model.safetensors.index.json') ? REQUIRED_AS_IS : REQUIRED).filter(n => !names.has(n));
  if (missing.length) throw Object.assign(Error('judge_base_files_missing'), {missing});
  if (index) {
    const shards = [...new Set(Object.values(index.weight_map || {}))];
    const absent = shards.filter(n => !names.has(n));
    if (!shards.length || absent.length) throw Object.assign(Error('judge_base_shards_missing'), {absent});
  }
  for (const f of files) {
    if (!Number.isSafeInteger(f.bytes) || f.bytes <= 0) throw Object.assign(Error('judge_base_size_invalid'), {path: f.path});
    const digestOk = f.sha256 ? /^[a-f0-9]{64}$/.test(f.sha256) : /^[a-f0-9]{40}$/.test(f.gitOid || '');
    if (!digestOk) throw Object.assign(Error('judge_base_digest_invalid'), {path: f.path});
  }
  return files;
}

// git이 파일 내용에 매기는 이름(blob sha1). LFS가 아닌 작은 파일은 허깅페이스가 이 값만 알려 준다.
export const gitBlobOid = buf => createHash('sha1').update(`blob ${buf.length}\0`).update(buf).digest('hex');
export async function digestFile(path) {
  const h = createHash('sha256');
  for await (const chunk of createReadStream(path)) h.update(chunk);
  return h.digest('hex');
}

// 학습기가 읽는 잠금 파일(download-training-base.mjs와 같은 형식): 저장소, 리비전, 파일별 sha256·크기.
export const lockFor = (repository, revision, verified) => ({repository, revision,
  files: verified.map(f => ({path: f.path, sha256: f.sha256, bytes: f.bytes}))});

const api = async url => {
  const res = await fetch(url, {headers: {accept: 'application/json'}});
  if (!res.ok) throw Object.assign(Error('huggingface_request_failed'), {status: res.status, url});
  return res.json();
};

async function listing(repository, revision) {
  const tree = await api(`https://huggingface.co/api/models/${repository}/tree/${revision}`);
  const index = tree.some(e => e.path === 'model.safetensors.index.json')
    ? await api(`https://huggingface.co/${repository}/resolve/${revision}/model.safetensors.index.json`) : null;
  return selectFiles(tree, index, {asIs: AS_IS_MODELS.includes(repository)});
}

function curl(url, partial) {
  const bin = process.platform === 'win32' ? 'curl.exe' : 'curl';
  return new Promise((done, reject) => {
    const child = spawn(bin, ['--fail', '--location', '--retry', '3', '--retry-delay', '2', '--connect-timeout', '30', '--speed-limit', '1024',
      '--speed-time', '90', '--continue-at', '-', '--output', partial, '--silent', '--show-error', url],
    {windowsHide: true, stdio: ['ignore', 'ignore', 'pipe']});
    let err = '';
    child.stderr.on('data', v => { err = (err + v).slice(-500); });
    child.on('error', reject);
    child.on('exit', c => (c === 0 ? done() : reject(Object.assign(Error('download_failed'), {url, code: c, stderr: err}))));
  });
}

async function verify(file, path) {
  if (statSync(path).size !== file.bytes) return null;
  if (file.sha256) return (await digestFile(path)) === file.sha256 ? file.sha256 : null;
  const buf = readFileSync(path);
  return gitBlobOid(buf) === file.gitOid ? createHash('sha256').update(buf).digest('hex') : null;
}

export async function downloadJudgeBase(repository, revision, out) {
  const dir = resolve(out);
  mkdirSync(dir, {recursive: true});
  const verified = [];
  for (const file of (await listing(repository, revision)).sort((a, b) => a.bytes - b.bytes)) {
    const target = join(dir, file.path), partial = target + '.partial';
    if (!existsSync(target)) {
      if (existsSync(partial) && statSync(partial).size > file.bytes) throw Object.assign(Error('partial_larger_than_source'), {path: file.path});
      console.log(JSON.stringify({event: 'downloading', file: file.path, bytes: file.bytes}));
      await curl(`https://huggingface.co/${repository}/resolve/${revision}/${file.path}`, partial);
      if (!(await verify(file, partial))) throw Object.assign(Error('download_digest_mismatch'), {path: file.path});
      renameSync(partial, target);
    }
    const sha256 = await verify(file, target);
    if (!sha256) throw Object.assign(Error('local_digest_mismatch'), {path: file.path});
    verified.push({path: file.path, sha256, bytes: file.bytes});
    console.log(JSON.stringify({event: 'verified', file: file.path, bytes: file.bytes}));
  }
  verified.sort((a, b) => a.path.localeCompare(b.path));
  const bytes = JSON.stringify(lockFor(repository, revision, verified));
  const lockPath = join(dir, 'artifact-lock.json');
  if (existsSync(lockPath) && readFileSync(lockPath, 'utf8') !== bytes) throw Error('existing_artifact_lock_mismatch');
  if (!existsSync(lockPath)) writeFileSync(lockPath, bytes, {flag: 'wx'});
  return {repository, revision, directory: dir, files: verified.length, bytes: verified.reduce((s, f) => s + f.bytes, 0),
    artifactLockSha256: createHash('sha256').update(bytes).digest('hex')};
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2);
  const opt = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
  const repository = opt('--repository');
  const allowed = [...JUDGE_BASES, ...AS_IS_MODELS];
  if (!allowed.includes(repository)) { console.error(`--repository must be one of ${allowed.join(', ')}`); process.exit(1); }
  if (args.includes('--plan')) {
    const revision = (await api(`https://huggingface.co/api/models/${repository}`)).sha;
    const files = await listing(repository, revision);
    console.log(JSON.stringify({repository, revision, files: files.map(f => ({path: f.path, bytes: f.bytes})),
      totalBytes: files.reduce((s, f) => s + f.bytes, 0)}));
  } else if (args.includes('--download')) {
    const revision = opt('--revision'), out = opt('--out');
    if (!/^[a-f0-9]{40}$/.test(revision || '') || !out) { console.error('--download needs --revision <40 hex> and --out DIR'); process.exit(1); }
    console.log(JSON.stringify(await downloadJudgeBase(repository, revision, out)));
  } else {
    console.error('usage: download-judge-base.mjs --repository R (--plan | --download --revision SHA --out DIR)');
    process.exit(1);
  }
}
