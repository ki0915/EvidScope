#!/usr/bin/env node
// 실제 기록으로 판정 오케스트라 돌리기(src/real-sessions.mjs). 세 단계, 모두 PC 안에서:
//   node scripts/real-session-eval.mjs prepare --out DIR [--agent claude-code|codex|all] [--claude-dir D] [--codex-dir D] [--since ISO]
//        [--until ISO] [--window N] [--no-sidechains]
//     에이전트 기록을 읽어 세션·구간을 만들고 DIR/windows.local.json(구간 입력: 명령·경로 원문 포함)과 DIR/requests.local.jsonl(두 판정자가
//     읽는 배치 요청)을 쓴다. 화면에는 개수만.
//   node scripts/real-session-eval.mjs second --dir DIR --first PREFIX [--first-threshold N]
//     첫 판정자 출력(PREFIX.outputs.json·.logprobs.json)을 보고 둘째 판정자가 필요한 구간만 DIR/second.requests.local.jsonl로.
//   node scripts/real-session-eval.mjs score --dir DIR --first PREFIX --second PREFIX [--first-threshold N] [--second-threshold N] [--name NAME]
//     오케스트라 결과를 DIR/NAME.json(기본 summary, 숫자와 규칙 코드 이름만)과 DIR/NAME.review.local.json(경보가 남은 구간의 id·세션·코드·
//     판정, 원문 없음)으로. 문턱을 준 결과와 안 준 결과를 다른 NAME으로 나란히 남길 수 있다.
// 문턱(마이크로냇 정수)은 설계 세트 검증으로 고른 값을 그대로 준다. 없으면 문턱 없이(모델 판정 그대로) 채점한다.
// 파일은 덮어쓰지 않는다(이미 있으면 멈춘다).
import {existsSync, readFileSync, writeFileSync} from 'node:fs';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {canonical} from '../src/crypto.mjs';
import {defaultHistoryDir} from '../src/agent-history.mjs';
import {loadRules} from '../src/threat-scenarios.mjs';
import {conductWindow, realWindows, REAL_WINDOW, reviewList, secondJudgeWindows, summarizeReal, windowPredict, windowRequest}
  from '../src/real-sessions.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2), cmd = args[0];
const opt = (name, def) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : def; };
const fail = message => { console.error(message); process.exit(1); };
const readJson = f => JSON.parse(readFileSync(f, 'utf8'));
const write = (file, text) => writeFileSync(file, text, {flag: 'wx'});
const time = name => {
  const v = opt(name);
  if (v === undefined) return undefined;
  const t = new Date(v);
  if (!Number.isFinite(t.getTime())) fail(`${name} needs an ISO time`);
  return t;
};
const threshold = name => {
  const v = opt(name);
  if (v === undefined) return undefined;
  if (!/^-?\d+$/.test(v)) fail(`${name} is an integer (micro-nats)`);
  return Number(v);
};
const judge = (prefix, name) => {
  if (!prefix) fail(`${name} PREFIX is required`);
  return {outputs: readJson(`${prefix}.outputs.json`), logprobs: existsSync(`${prefix}.logprobs.json`) ? readJson(`${prefix}.logprobs.json`) : undefined};
};
const loadWindows = dir => readJson(join(dir, 'windows.local.json')).windows;
const rules = loadRules(opt('--rules', join(root, 'data/risk-rules/ai-agent-baseline.json')));
const print = v => console.log(JSON.stringify(v, null, 2));

if (cmd === 'prepare') {
  const out = opt('--out');
  if (!out || !existsSync(out)) fail('prepare needs --out DIR (an existing, empty folder)');
  const which = opt('--agent', 'all'), window = Number(opt('--window', REAL_WINDOW));
  if (!['claude-code', 'codex', 'all'].includes(which)) fail('--agent is claude-code, codex or all');
  const agents = [];
  if (which !== 'codex') agents.push({agent: 'claude-code', dir: opt('--claude-dir', defaultHistoryDir('claude-code'))});
  if (which !== 'claude-code') agents.push({agent: 'codex', dir: opt('--codex-dir', defaultHistoryDir('codex'))});
  const {windows, stats} = await realWindows(agents, rules, {since: time('--since'), until: time('--until'), window,
    sidechains: !args.includes('--no-sidechains')});
  write(join(out, 'windows.local.json'), JSON.stringify({window, rulePack: rules.length, windows}) + '\n');
  write(join(out, 'requests.local.jsonl'), windows.map(w => canonical(windowRequest(w))).join('\n') + (windows.length ? '\n' : ''));
  print({window, agents: stats, windows: windows.length, ruleFlaggedWindows: windows.filter(w => w.input.actions.some(a => a.findings.length)).length});
} else if (cmd === 'second') {
  const dir = opt('--dir');
  if (!dir) fail('second needs --dir DIR');
  const windows = loadWindows(dir), first = judge(opt('--first'), '--first');
  const need = secondJudgeWindows(windows, windowPredict(first.outputs, {logprobs: first.logprobs, threshold: threshold('--first-threshold')}));
  write(join(dir, 'second.requests.local.jsonl'), need.map(w => canonical(windowRequest(w))).join('\n') + (need.length ? '\n' : ''));
  print({windows: windows.length, firstOutputs: Object.keys(first.outputs).length, secondNeeded: need.length});
} else if (cmd === 'score') {
  const dir = opt('--dir');
  if (!dir) fail('score needs --dir DIR');
  const windows = loadWindows(dir), a = judge(opt('--first'), '--first'), b = judge(opt('--second'), '--second');
  const thresholds = {first: threshold('--first-threshold') ?? null, second: threshold('--second-threshold') ?? null};
  const judges = {first: windowPredict(a.outputs, {logprobs: a.logprobs, threshold: thresholds.first ?? undefined}),
    second: windowPredict(b.outputs, {logprobs: b.logprobs, threshold: thresholds.second ?? undefined})};
  const results = windows.map(w => conductWindow(w, judges));
  const summary = {thresholds, ...summarizeReal(windows, results)};
  const name = opt('--name', 'summary');
  if (!/^[a-z0-9-]+$/.test(name)) fail('--name is lower-case letters, digits and dashes');
  write(join(dir, `${name}.json`), JSON.stringify(summary, null, 2) + '\n');
  write(join(dir, `${name}.review.local.json`), JSON.stringify(reviewList(windows, results), null, 2) + '\n');
  print(summary);
} else {
  fail('usage: real-session-eval.mjs prepare --out DIR [--agent A] [--since ISO] [--until ISO] [--window N] [--no-sidechains]'
    + ' | second --dir DIR --first PREFIX [--first-threshold N]'
    + ' | score --dir DIR --first PREFIX --second PREFIX [--first-threshold N] [--second-threshold N] [--name NAME]');
}
