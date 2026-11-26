// The model downloader of the judge plan (scripts/download-judge-base.mjs): only the allowed repositories, only the files the
// trainer or the screening service reads, every file bound to the digest Hugging Face publishes. A base the session judge trains on
// must ship sharded weights with their index (the trainer verifies them); a model used as it is may ship one weights file.
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {existsSync} from 'node:fs';
import {resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {AS_IS_MODELS, JUDGE_BASES, gitBlobOid, lockFor, selectFiles} from '../scripts/download-judge-base.mjs';

const sha = c => c.repeat(64), oid = c => c.repeat(40);
const small = (path, size = 100) => ({type: 'file', path, size, oid: oid('a')});
const large = (path, size = 4e9) => ({type: 'file', path, size: 135, oid: oid('b'), lfs: {oid: sha('c'), size}});
const names = files => files.map(f => f.path).sort();
const common = [small('config.json'), small('tokenizer.json'), small('tokenizer_config.json'), small('README.md'), small('.gitattributes'),
  {type: 'directory', path: 'assets', size: 0, oid: oid('d')}];

test('the plan downloads Qwen3-4B to train and kanana as it is; the dropped agent-safety base is not allowed', () => {
  assert.deepEqual(JUDGE_BASES, ['Qwen/Qwen3-4B-Instruct-2507']);
  assert.deepEqual(AS_IS_MODELS, ['kakaocorp/kanana-safeguard-prompt-2.1b']);
  assert.ok(![...JUDGE_BASES, ...AS_IS_MODELS].includes('thu-coai/ShieldAgent'));
  const r = spawnSync(process.execPath, ['scripts/download-judge-base.mjs', '--repository', 'thu-coai/ShieldAgent', '--plan'], {encoding: 'utf8'});
  assert.equal(r.status, 1);
  assert.match(r.stderr, /must be one of/);
});

test('a training base keeps weights, tokenizer, settings and licence, and needs its shard index', () => {
  const tree = [...common, small('LICENSE'), small('merges.txt'), small('vocab.json'), small('model.safetensors.index.json'),
    large('model-00001-of-00002.safetensors'), large('model-00002-of-00002.safetensors', 1e8)];
  const index = {weight_map: {a: 'model-00001-of-00002.safetensors', b: 'model-00002-of-00002.safetensors'}};
  const files = selectFiles(tree, index);
  assert.deepEqual(names(files), ['LICENSE', 'config.json', 'merges.txt', 'model-00001-of-00002.safetensors',
    'model-00002-of-00002.safetensors', 'model.safetensors.index.json', 'tokenizer.json', 'tokenizer_config.json', 'vocab.json']);
  const shard = files.find(f => f.path === 'model-00001-of-00002.safetensors');
  assert.deepEqual([shard.bytes, shard.sha256, shard.gitOid], [4e9, sha('c'), null]);
  const licence = files.find(f => f.path === 'LICENSE');
  assert.deepEqual([licence.sha256, licence.gitOid], [null, oid('a')]);
  assert.throws(() => selectFiles(tree.filter(e => e.path !== 'model-00002-of-00002.safetensors'), index), /judge_base_shards_missing/);
  const single = [...common, large('model.safetensors')];
  assert.throws(() => selectFiles(single, null), /judge_base_files_missing/);
});

test('a model used as it is may ship one weights file, but not without it or with an unverifiable digest', () => {
  const single = [...common, small('special_tokens_map.json'), small('generation_config.json'), large('model.safetensors', 4174003008)];
  const files = selectFiles(single, null, {asIs: true});
  assert.deepEqual(names(files), ['config.json', 'generation_config.json', 'model.safetensors', 'special_tokens_map.json',
    'tokenizer.json', 'tokenizer_config.json']);
  assert.throws(() => selectFiles(common, null, {asIs: true}), /judge_base_files_missing/);
  const bad = single.map(e => (e.path === 'model.safetensors' ? {...e, lfs: {oid: 'x', size: 10}} : e));
  assert.throws(() => selectFiles(bad, null, {asIs: true}), /judge_base_digest_invalid/);
});

test('small files are checked by their git blob name and the lock lists every file with its sha256', () => {
  const buf = Buffer.from('{"model_type":"qwen3"}\n');
  const expected = createHash('sha1').update(`blob ${buf.length}\0${buf}`).digest('hex');
  assert.equal(gitBlobOid(buf), expected);
  assert.deepEqual(lockFor('Qwen/Qwen3-4B-Instruct-2507', 'f'.repeat(40), [{path: 'config.json', sha256: sha('1'), bytes: 23}]),
    {repository: 'Qwen/Qwen3-4B-Instruct-2507', revision: 'f'.repeat(40), files: [{path: 'config.json', sha256: sha('1'), bytes: 23}]});
});

const bundled = resolve('.local/python/python.exe');
const python = process.env.EVIDSCOPE_PYTHON || (existsSync(bundled) ? bundled : 'python3');

test('the trainer lets the session task train on Qwen3-4B, keeps governance mapping on its base and refuses other bases', () => {
  const code = `
import importlib.util, json
spec = importlib.util.spec_from_file_location("t", "scripts/train-governance-mapping-lora.py")
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
class A:
    def __init__(self, task, repo): self.task, self.base_repository = task, repo
def pick(task, repo):
    try: return t.base_repository_for(A(task, repo))
    except RuntimeError as e: return str(e)
print(json.dumps({"bases": list(t.SESSION_BASE_REPOSITORIES), "qwen": pick("session-inference", "Qwen/Qwen3-4B-Instruct-2507"),
  "shield": pick("session-inference", "thu-coai/ShieldAgent"), "mapping": pick("governance-mapping", "Qwen/Qwen3-4B-Instruct-2507")}))
`;
  const r = spawnSync(python, ['-I', '-B', '-c', code], {encoding: 'utf8', timeout: 120000});
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout.trim().split('\n').at(-1));
  assert.deepEqual(out.bases, ['fdtn-ai/Foundation-Sec-1.1-8B-Instruct', 'Qwen/Qwen3-4B-Instruct-2507']);
  assert.equal(out.qwen, 'Qwen/Qwen3-4B-Instruct-2507');
  assert.equal(out.shield, 'base_repository_not_allowed_for_task');
  assert.equal(out.mapping, 'base_repository_not_allowed_for_task');
});
