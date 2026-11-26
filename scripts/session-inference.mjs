#!/usr/bin/env node
// 세션 추론 태스크(개선 계획 2단계) CLI.
//   node scripts/session-inference.mjs baseline                규칙만 / 규칙+시퀀스 기준선 점수(JSON to stdout). 세션 모델이 넘어야 하는 바닥선.
//   node scripts/session-inference.mjs input SCENARIO_ID        한 세션의 모델 입력 요약과 골드 답안(검사용)
//   node scripts/session-inference.mjs schema                   강제 출력 JSON 스키마
//   node scripts/session-inference.mjs splits                   계열 단위 train/validation/unseen 분할(누수 방지 확인)
//   node scripts/session-inference.mjs requests --variant V --out F [--mask|--strip]   배치 러너 요청(--mask: 경보 이름을 가린, --strip: 소견을
//                                                                 모두 뺀 견고성 시험용)
//   node scripts/session-inference.mjs score-outputs --outputs F [--logprobs F] [--train-catalog F] [--cal-catalog F --cal-outputs F --cal-logprobs F]
//                                                                 모델 출력 채점 + 기준선 + 게이트 + 경보 처리 원칙 결과
//   node scripts/session-inference.mjs external-requests --set assebench|rjudge --file F --out F [--families 'a|b'] [--variant V]
//                                                                 공개 세트 요청(--families: 그 응용 시나리오만, ASSEBench의 평가용 시나리오)
//   node scripts/session-inference.mjs external-score --set S --file F --outputs F [--logprobs F] [--families 'a|b'] [--threshold N]
//                                                                 공개 세트 판정 채점(라벨은 세트의 원래 라벨, 화면에는 숫자만)
// Flags: --rules F, --catalog F, --contrast F (대조 카탈로그를 합침), --held F,F (unseen 계열), --val F,F (validation 계열), --mask (가린 이름으로 채점),
// --strip (소견을 뺀 프롬프트로 채점).
// --train-catalog: 학습에 쓴 (변형) 카탈로그. 주면 허용 목록 기준선(학습 정상 세션에 나온 코드는 무시)을 함께 이겨야 게이트를 통과한다.
// --logprobs: 배치 러너 --logprobs 파일. 판정 확신도(판정 단어의 확률)를 읽는다. --cal-*: 검증 세트의 카탈로그·출력·logprobs로 기권 문턱을
// 고른다(평가 세트로는 고르지 않는다). --threshold N: 이미 고른 문턱(마이크로냇 정수)을 직접 준다.
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {loadRules, loadCatalog, composeCatalog} from '../src/threat-scenarios.mjs';
import {scoreDispositions} from '../src/session-disposition.mjs';
import {readFileSync, writeFileSync} from 'node:fs';
import {canonical} from '../src/crypto.mjs';
import {EXTERNAL_SETS, externalPrompt, externalRecords, externalRequest, scoreExternal} from '../src/external-agent-sets.mjs';
import {sessionInput, sessionText, sessionGold, baselinePredict, scoreSessions, SESSION_OUTPUT_SCHEMA, splitByFamily, familyOf,
  sessionRequestLines, predictFromOutputs, assessSessionModel, allowlistPredict, sessionCounts, calibrateSessionThreshold}
  from '../src/session-inference.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const cmd = args[0];
const opt = (name, def) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : def; };
const list = v => (v ? v.split(',').map(x => x.trim()).filter(Boolean) : []);
// 공개 세트의 시나리오 이름에는 쉼표가 있어(예: "Legal, Compliance & Audit") '|'로 나눈다.
const families = v => (v ? v.split('|').map(x => x.trim()).filter(Boolean) : []);
const rules = loadRules(opt('--rules', join(root, 'data/risk-rules/ai-agent-baseline.json')));
const baseCatalog = loadCatalog(opt('--catalog', join(root, 'data/threat-scenarios/v1/catalog.json')));
const catalog = opt('--contrast') ? composeCatalog(baseCatalog, loadCatalog(opt('--contrast'))) : baseCatalog;
const print = v => console.log(JSON.stringify(v, null, 2));
const readJson = f => JSON.parse(readFileSync(f, 'utf8'));
const maskCodes = args.includes('--mask'), stripFindings = args.includes('--strip');
// 공개 세트의 기록(--families가 있으면 그 시나리오만, 한 번에 다 못 넣는 긴 기록과 애매한 기록은 뺀다: 학습 쪽 splitExternal과 같은 규칙).
const externalSet = () => {
  const set = opt('--set'), file = opt('--file');
  if (!Object.hasOwn(EXTERNAL_SETS, set) || !file) { console.error('--set assebench|rjudge and --file F are required'); process.exit(1); }
  const wanted = new Set(families(opt('--families')).map(f => `${set}:${f}`));
  const {records} = externalRecords(set, readFileSync(file, 'utf8'));
  return records.filter(r => !r.ambiguous && externalPrompt(r) && (!wanted.size || wanted.has(r.family)));
};

if (cmd === 'baseline') {
  print({rulePackVersion: catalog.rulePackVersion, sessions: catalog.scenarios.length,
    rules_only: scoreSessions(catalog.scenarios, rules, s => baselinePredict(s, rules, {withSequence: false})),
    rules_sequence: scoreSessions(catalog.scenarios, rules, s => baselinePredict(s, rules, {withSequence: true}))});
} else if (cmd === 'input') {
  const s = catalog.scenarios.find(x => x.id === args[1]);
  if (!s) { console.error('unknown scenario id: ' + args[1]); process.exit(1); }
  console.log(sessionText(sessionInput(s, rules)));
  console.log('\ngold: ' + JSON.stringify(sessionGold(s, rules)));
} else if (cmd === 'requests') {
  // 격리 배치 러너(scripts/governance_mapping_batch.py) 입력. 파일에만 쓰고 화면에는 개수만 낸다(요청에는 시험용 명령 원문이 들어 있다).
  const variant = opt('--variant', 'zero_shot'), out = opt('--out');
  if (!out) { console.error('requests needs --out FILE'); process.exit(1); }
  writeFileSync(out, sessionRequestLines(catalog.scenarios, rules, {variant, maskCodes, stripFindings}), {flag: 'wx'});
  print({variant, maskCodes, stripFindings, requests: catalog.scenarios.length, out});
} else if (cmd === 'external-requests') {
  const out = opt('--out'), records = externalSet();
  if (!out) { console.error('external-requests needs --out FILE'); process.exit(1); }
  writeFileSync(out, records.map(r => canonical(externalRequest(r, {variant: opt('--variant', 'zero_shot')}))).join('\n') + '\n', {flag: 'wx'});
  print({set: opt('--set'), requests: records.length, violations: records.filter(r => r.verdict === 'violation').length, out});
} else if (cmd === 'external-score') {
  const records = externalSet();
  const logprobs = opt('--logprobs') ? readJson(opt('--logprobs')) : undefined;
  const threshold = opt('--threshold') !== undefined ? Number(opt('--threshold')) : undefined;
  if (threshold !== undefined && !logprobs) { console.error('a threshold needs --logprobs'); process.exit(1); }
  const outputs = readJson(opt('--outputs'));
  print({set: opt('--set'), threshold: threshold ?? null, model: scoreExternal(records, outputs, {logprobs, threshold}),
    model_without_abstain: scoreExternal(records, outputs, {logprobs})});
} else if (cmd === 'score-outputs') {
  // 모델 출력({id: content})을 채점해 기준선·게이트와 함께 요약만 낸다(개별 출력 원문은 내지 않는다).
  const file = opt('--outputs');
  if (!file) { console.error('score-outputs needs --outputs FILE'); process.exit(1); }
  const outputs = readJson(file);
  const logprobs = opt('--logprobs') ? readJson(opt('--logprobs')) : undefined;
  // 기권 문턱: 검증 세트로 고르거나(--cal-*) 직접 받는다(--threshold). 없으면 기권 없이(모델 판정 그대로) 채점한다.
  let calibration = null, threshold;
  if (opt('--cal-catalog')) {
    calibration = calibrateSessionThreshold(readJson(opt('--cal-catalog')).scenarios, rules, readJson(opt('--cal-outputs')),
      readJson(opt('--cal-logprobs')), {maskCodes, stripFindings});
    threshold = calibration.threshold ?? undefined;
  } else if (opt('--threshold') !== undefined) threshold = Number(opt('--threshold'));
  if (threshold !== undefined && !logprobs) { console.error('a threshold needs --logprobs'); process.exit(1); }
  const modelPredict = predictFromOutputs(outputs, rules, {logprobs, threshold, maskCodes, stripFindings});
  const rawPredict = predictFromOutputs(outputs, rules, {logprobs, maskCodes, stripFindings});
  const model = scoreSessions(catalog.scenarios, rules, modelPredict);
  const raw = scoreSessions(catalog.scenarios, rules, rawPredict);
  const rulesOnly = scoreSessions(catalog.scenarios, rules, s => baselinePredict(s, rules, {withSequence: false}));
  const rulesSeq = scoreSessions(catalog.scenarios, rules, s => baselinePredict(s, rules, {withSequence: true}));
  const pick = r => ({verdictF1: r.verdict.f1, verdictPrecision: r.verdict.precision, threatRecall: r.threatRecall,
    threatClearedRate: r.threatClearedRate, typeAccuracy: r.typeAccuracy, hardNegativeFalsePositiveRate: r.hardNegativeFalsePositiveRate,
    knownGapClearedRate: r.knownGapClearedRate, requirementF1: r.requirement.f1, requirementPrecision: r.requirementPrecision,
    evidenceF1: r.evidence.f1, answeredAccuracy: r.answeredAccuracy, answerRate: r.answerRate, schemaValidRate: r.schemaValidRate});
  const baselines = {rules_only: rulesOnly, rules_sequence: rulesSeq};
  const predicts = {model: modelPredict, rules_sequence: s => baselinePredict(s, rules, {withSequence: true})};
  if (opt('--train-catalog')) {
    // 허용 목록은 학습(tune) 계열에서만 만든다: --held/--val 계열을 빼야 평가 정답을 미리 보지 않는다.
    const train = splitByFamily(loadCatalog(opt('--train-catalog')).scenarios,
      {heldOutFamilies: list(opt('--held')), validationFamilies: list(opt('--val'))}).train;
    const allow = allowlistPredict(train, rules);
    baselines.allowlist = scoreSessions(catalog.scenarios, rules, allow);
    predicts.allowlist = allow;
  }
  const counts = sessionCounts(catalog.scenarios, rules);
  const gate = assessSessionModel(model, baselines, {counts});
  // 경보 처리 원칙(모델은 경보를 못 지우고, 보호 경보는 낮추지도 못한다)을 적용한 시스템 결과.
  const dispositions = Object.fromEntries(Object.entries(predicts).map(([k, f]) => [k, scoreDispositions(catalog.scenarios, rules, f)]));
  // 확신도 분포(판정 단어 확률을 0.1 단위로): v1처럼 두 값에 몰리면 확신도가 정보가 없다는 뜻이다.
  const confidence = {};
  for (const s of catalog.scenarios) {
    const c = rawPredict(s).confidence;
    const bin = c === null ? 'none' : (Math.min(9, Math.floor(c * 10)) / 10).toFixed(1);
    confidence[bin] = (confidence[bin] || 0) + 1;
  }
  print({sessions: model.sessions, counts, threshold: threshold ?? null, calibration, confidence, model: pick(model), model_without_abstain: pick(raw),
    ...Object.fromEntries(Object.entries(baselines).map(([k, v]) => [k, pick(v)])),
    dispositions, perSession: model.perSession.map(p => ({id: p.id, gold: p.gold, predicted: p.predicted, ok: p.verdictCorrect})),
    gate: {eligible: gate.eligible, reasons: gate.reasons}});
} else if (cmd === 'schema') {
  print(SESSION_OUTPUT_SCHEMA);
} else if (cmd === 'splits') {
  const split = splitByFamily(catalog.scenarios, {heldOutFamilies: list(opt('--held')), validationFamilies: list(opt('--val'))});
  print({families: split.families,
    train: split.train.map(s => ({id: s.id, family: familyOf(s)})), validation: split.validation.map(s => ({id: s.id, family: familyOf(s)})),
    unseen: split.unseen.map(s => ({id: s.id, family: familyOf(s)}))});
} else {
  console.error('usage: session-inference.mjs baseline|input ID|schema|splits|requests --variant V --out F [--mask|--strip]|score-outputs --outputs F'
    + ' [--logprobs F] [--cal-catalog F --cal-outputs F --cal-logprobs F | --threshold N] [--rules F] [--catalog F] [--held F,F] [--val F,F]'
    + '|external-requests --set S --file F --out F [--families "a|b"]|external-score --set S --file F --outputs F [--logprobs F] [--threshold N]');
  process.exit(1);
}
