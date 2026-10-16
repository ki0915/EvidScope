#!/usr/bin/env node
// 세션 추론 태스크(개선 계획 2단계) CLI.
//   node scripts/session-inference.mjs baseline                규칙만 / 규칙+시퀀스 기준선 점수(JSON to stdout). 세션 모델이 넘어야 하는 바닥선.
//   node scripts/session-inference.mjs input SCENARIO_ID        한 세션의 모델 입력 요약과 골드 답안(검사용)
//   node scripts/session-inference.mjs schema                   강제 출력 JSON 스키마
//   node scripts/session-inference.mjs splits                   계열 단위 train/validation/unseen 분할(누수 방지 확인)
// Flags: --rules F, --catalog F, --held F,F (unseen 계열), --val F,F (validation 계열).
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {loadRules, loadCatalog} from '../src/threat-scenarios.mjs';
import {sessionInput, sessionText, sessionGold, baselinePredict, scoreSessions, SESSION_OUTPUT_SCHEMA, splitByFamily, familyOf}
  from '../src/session-inference.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const cmd = args[0];
const opt = (name, def) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : def; };
const list = v => (v ? v.split(',').map(x => x.trim()).filter(Boolean) : []);
const rules = loadRules(opt('--rules', join(root, 'data/risk-rules/ai-agent-baseline.json')));
const catalog = loadCatalog(opt('--catalog', join(root, 'data/threat-scenarios/v1/catalog.json')));
const print = v => console.log(JSON.stringify(v, null, 2));

if (cmd === 'baseline') {
  print({rulePackVersion: catalog.rulePackVersion, sessions: catalog.scenarios.length,
    rules_only: scoreSessions(catalog.scenarios, rules, s => baselinePredict(s, rules, {withSequence: false})),
    rules_sequence: scoreSessions(catalog.scenarios, rules, s => baselinePredict(s, rules, {withSequence: true}))});
} else if (cmd === 'input') {
  const s = catalog.scenarios.find(x => x.id === args[1]);
  if (!s) { console.error('unknown scenario id: ' + args[1]); process.exit(1); }
  console.log(sessionText(sessionInput(s, rules)));
  console.log('\ngold: ' + JSON.stringify(sessionGold(s, rules)));
} else if (cmd === 'schema') {
  print(SESSION_OUTPUT_SCHEMA);
} else if (cmd === 'splits') {
  const split = splitByFamily(catalog.scenarios, {heldOutFamilies: list(opt('--held')), validationFamilies: list(opt('--val'))});
  print({families: split.families,
    train: split.train.map(s => ({id: s.id, family: familyOf(s)})), validation: split.validation.map(s => ({id: s.id, family: familyOf(s)})),
    unseen: split.unseen.map(s => ({id: s.id, family: familyOf(s)}))});
} else {
  console.error('usage: session-inference.mjs baseline|input ID|schema|splits [--rules F] [--catalog F] [--held F,F] [--val F,F]');
  process.exit(1);
}
