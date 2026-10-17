#!/usr/bin/env node
// 세션 학습용 변형 카탈로그 빌더(scripts/session-training-set.mjs의 --catalog 입력). 설계 시나리오를 정상 활동으로 감싸 세션 수를 늘린다.
//   node scripts/session-variants.mjs --out F [--per-threat N] [--per-benign N] [--rules F] [--catalog F]
// 카탈로그와 같은 형식의 JSON을 파일에 쓴다(시험용 명령이 들어 있어 화면에는 개수만 낸다). flag 'wx'로 덮어쓰기 방지. 라벨 보존 변형만 남는다.
import {writeFileSync} from 'node:fs';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {loadRules, loadCatalog} from '../src/threat-scenarios.mjs';
import {buildVariantCatalog} from '../src/session-variants.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const opt = (name, def) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : def; };
const out = opt('--out');
if (!out) { console.error('session-variants needs --out FILE'); process.exit(1); }
const rules = loadRules(opt('--rules', join(root, 'data/risk-rules/ai-agent-baseline.json')));
const catalog = loadCatalog(opt('--catalog', join(root, 'data/threat-scenarios/v1/catalog.json')));
const v = buildVariantCatalog(catalog, rules, {perThreat: Number(opt('--per-threat', '30')), perBenign: Number(opt('--per-benign', '30'))});
writeFileSync(out, JSON.stringify(v), {flag: 'wx'});
const byClass = {};
for (const s of v.scenarios) byClass[s.class] = (byClass[s.class] || 0) + 1;
console.log(JSON.stringify({scenarios: v.scenarios.length, droppedVariantCount: v.droppedVariantCount, families: new Set(v.scenarios.map(s => s.familyId)).size,
  byClass, out}, null, 2));
