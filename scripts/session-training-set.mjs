#!/usr/bin/env node
// 세션 추론 태스크(개선 계획 2단계) 학습 세트 빌더. 격리 트레이너 train-governance-mapping-lora.py --task session-inference 입력(JSONL).
//   node scripts/session-training-set.mjs --out F [--run-mode candidate|shakedown] [--held a,b] [--val c,d] [--mask-share 0.3] [--rules F] [--catalog F]
// --held: 처음 보는 계열(평가용, 학습에서 제외). --val: validation 계열. 나머지는 tune. catalogDigest는 카탈로그 파일 바이트의 sha256(모든 행 동일).
// 요청·골드처럼 target에는 시험용 명령 원문이 들어 있어 화면에는 개수만 낸다(파일에만 쓴다). flag 'wx'로 덮어쓰기를 막는다.
// --mask-share: 이 비율의 세션에 경보 이름을 가린 사본을 더한다(모델이 이름 대신 행동·대상을 읽게, 적대적 감사 2026-10-17).
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {loadRules, loadCatalog} from '../src/threat-scenarios.mjs';
import {sessionTrainingSet} from '../src/session-inference.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const opt = (name, def) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : def; };
const list = v => (v ? v.split(',').map(x => x.trim()).filter(Boolean) : []);
const out = opt('--out');
if (!out) { console.error('session-training-set needs --out FILE'); process.exit(1); }
const runMode = opt('--run-mode', 'candidate');
if (runMode !== 'candidate' && runMode !== 'shakedown') { console.error('--run-mode must be candidate or shakedown'); process.exit(1); }
const rulesPath = opt('--rules', join(root, 'data/risk-rules/ai-agent-baseline.json'));
const catalogPath = opt('--catalog', join(root, 'data/threat-scenarios/v1/catalog.json'));
const rules = loadRules(rulesPath);
const catalog = loadCatalog(catalogPath);
const catalogDigest = createHash('sha256').update(readFileSync(catalogPath)).digest('hex');

// poolFamilies: 변형 카탈로그가 기록한 잡음 풀 계열. 검증·평가 계열이 들어 있으면 sessionTrainingSet이 거부한다(누수).
const maskShare = Number(opt('--mask-share', '0'));
if (!(maskShare >= 0 && maskShare <= 1)) { console.error('--mask-share must be between 0 and 1'); process.exit(1); }
const {rows, families, counts, duplicatesDropped} = sessionTrainingSet(catalog.scenarios, rules,
  {runMode, heldOutFamilies: list(opt('--held')), validationFamilies: list(opt('--val')), catalogDigest, poolFamilies: catalog.poolFamilies, maskShare});
writeFileSync(out, rows.map(r => JSON.stringify(r)).join('\n') + '\n', {flag: 'wx'});
// 트레이너 admission이 쓰는 최소값(candidate: tune>=300, validation>=50; shakedown: 각 1). 여기선 안내만 하고 판정은 트레이너가 한다.
const minTune = runMode === 'shakedown' ? 1 : 300, minVal = runMode === 'shakedown' ? 1 : 50;
console.log(JSON.stringify({runMode, maskShare, counts, duplicatesDropped, families, catalogDigest, out,
  meetsTrainerMinimums: counts.tune >= minTune && counts.validation >= minVal}, null, 2));
