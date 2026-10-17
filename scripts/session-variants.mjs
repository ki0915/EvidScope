#!/usr/bin/env node
// 세션 학습용 변형 카탈로그 빌더(scripts/session-training-set.mjs의 --catalog 입력). 설계 시나리오를 정상 활동으로 감싸 세션 수를 늘린다.
//   node scripts/session-variants.mjs --out F --pool-exclude a,b [--contrast F] [--per-threat N] [--per-benign N] [--rules F] [--catalog F]
// 카탈로그와 같은 형식의 JSON을 파일에 쓴다(시험용 명령이 들어 있어 화면에는 개수만 낸다). flag 'wx'로 덮어쓰기 방지. 섞은 뒤에도 연쇄 경보와
// 골드가 베이스와 같은 변형만 남는다. --pool-exclude: 잡음 풀에서 뺄 정상 계열(학습 세트의 --held와 --val 계열을 모두 넣는다). 빈 값이면
// 거부한다 -- 잡음 풀이 평가 계열을 끌어오는 누수(적대적 감사 2026-10-17)를 기본값으로 막기 위해서다. --contrast: 대조 카탈로그를 합친다.
import {writeFileSync} from 'node:fs';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {loadRules, loadCatalog, composeCatalog} from '../src/threat-scenarios.mjs';
import {buildVariantCatalog} from '../src/session-variants.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const opt = (name, def) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : def; };
const out = opt('--out');
if (!out) { console.error('session-variants needs --out FILE'); process.exit(1); }
const rules = loadRules(opt('--rules', join(root, 'data/risk-rules/ai-agent-baseline.json')));
const base = loadCatalog(opt('--catalog', join(root, 'data/threat-scenarios/v1/catalog.json')));
const catalog = opt('--contrast') ? composeCatalog(base, loadCatalog(opt('--contrast'))) : base;
const poolExclude = (opt('--pool-exclude') || '').split(',').map(x => x.trim()).filter(Boolean);
if (!poolExclude.length) { console.error('session-variants needs --pool-exclude with the held-out and validation families'); process.exit(1); }
const unknown = poolExclude.filter(id => !catalog.scenarios.some(s => s.id === id));
if (unknown.length) { console.error('unknown --pool-exclude ids: ' + unknown.join(',')); process.exit(1); }
const v = buildVariantCatalog(catalog, rules, {perThreat: Number(opt('--per-threat', '30')), perBenign: Number(opt('--per-benign', '30')), poolExclude});
writeFileSync(out, JSON.stringify(v), {flag: 'wx'});
const byClass = {};
for (const s of v.scenarios) byClass[s.class] = (byClass[s.class] || 0) + 1;
console.log(JSON.stringify({scenarios: v.scenarios.length, dropped: v.dropped, families: new Set(v.scenarios.map(s => s.familyId)).size,
  poolFamilies: v.poolFamilies, byClass, out}, null, 2));
